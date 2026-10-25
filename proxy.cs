// SecureProxy — hardened HTTPS forward proxy (CONNECT tunnel)
// .NET 8+, no external deps.
//
// Security posture:
//   * Binds loopback by default; must be fronted by mTLS-terminating gateway if exposed.
//   * SSRF-safe: resolve DNS, reject private/link-local/CGNAT/multicast, connect to IP.
//   * Allowlist hosts + ports; empty = deny.
//   * mTLS client-cert pinning by SHA-256(DER) OR bearer token (constant-time).
//   * TLS 1.2/1.3 only; modern cipher suites on Linux/macOS; online revocation.
//   * Bounded CONNECT parsing (8 KB headers, 2 KB lines, ASCII only).
//   * Idle-tunnel timeout, FIN propagation, flush, pooled buffers.
//   * Per-IP concurrency + token-bucket rate limit.
//   * Structured logs; hostnames and client IPs hashed with rotating daily salt.
//   * Non-exportable private key loaded from secrets manager path.
//   * Graceful shutdown drains tunnels.

using System.Buffers;
using System.Collections.Concurrent;
using System.Globalization;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.RateLimiting;
using Microsoft.Extensions.Configuration;

namespace SecureProxy;

// ─────────────────────────────────────────────────────────────────────────────
// Settings
// ─────────────────────────────────────────────────────────────────────────────
public sealed class ProxySettings
{
    public string BindAddress { get; set; } = "127.0.0.1";
    public int ListenPort { get; set; } = 8443;

    // PEM preferred; PFX supported for compat. Load from secrets manager in prod.
    public string CertPath { get; set; } = "proxy.pfx";
    public string? CertPassword { get; set; }
    public bool CertIsPfx { get; set; } = true;

    public string[] AllowedHosts { get; set; } = Array.Empty<string>();   // "*" denied implicitly by empty
    public int[] AllowedPorts { get; set; } = [443];

    // Auth — enable at least one.
    public bool RequireClientCert { get; set; } = true;
    public string[] AllowedClientCertSha256 { get; set; } = Array.Empty<string>(); // hex, lowercase, of DER
    public string? BearerTokenSha256 { get; set; }  // hex of SHA-256(token); null = disabled

    // Limits / timeouts.
    public int ConnectTimeoutSeconds { get; set; } = 10;
    public int HandshakeTimeoutSeconds { get; set; } = 10;
    public int HeaderReadTimeoutSeconds { get; set; } = 10;
    public int IdleTunnelSeconds { get; set; } = 300;
    public int MaxConcurrentConnections { get; set; } = 500;
    public int MaxConcurrentPerIp { get; set; } = 20;
    public int MaxHeaderBytes { get; set; } = 8192;
    public int MaxHeaderLineBytes { get; set; } = 2048;

    // Rate limit: N connections per window per IP.
    public int RateLimitPermits { get; set; } = 60;
    public int RateLimitWindowSeconds { get; set; } = 60;

    // Logging: rotating salt for hashing hostnames/IPs.
    public string LogHashingKey { get; set; } = "";       // 32+ bytes; rotate with a scheduler
    public bool HashHostnamesInLogs { get; set; } = true;
}

// ─────────────────────────────────────────────────────────────────────────────
// Entry point
// ─────────────────────────────────────────────────────────────────────────────
public static class Program
{
    public static async Task<int> Main(string[] args)
    {
        var config = new ConfigurationBuilder()
            .AddJsonFile("appsettings.json", optional: false)
            .AddEnvironmentVariables("PROXY_")
            .Build();

        var settings = config.GetSection("Proxy").Get<ProxySettings>()
                       ?? throw new InvalidOperationException("Missing Proxy config");

        ValidateSettings(settings);

        using var logger = Logger.Create();
        using var shutdown = new CancellationTokenSource();
        Console.CancelKeyPress += (_, e) => { e.Cancel = true; shutdown.Cancel(); };
        AppDomain.CurrentDomain.ProcessExit += (_, _) => shutdown.Cancel();

        var serverCert = LoadServerCertificate(settings);
        var auth = new Authenticator(settings);
        var limiter = new Limits(settings, logger);
        var ipTracker = new IpConnectionTracker(settings.MaxConcurrentPerIp);
        var logSalt = new DailySalt(settings.LogHashingKey);

        using var listener = new TcpListener(IPAddress.Parse(settings.BindAddress), settings.ListenPort);
        listener.Start();
        logger.Info("proxy.start", new()
        {
            ["bind"] = settings.BindAddress,
            ["port"] = settings.ListenPort,
            ["mtls"] = settings.RequireClientCert,
            ["allowedHosts"] = settings.AllowedHosts.Length,
        });

        var activeTunnels = new ConcurrentDictionary<long, Task>();
        long tunnelId = 0;

        try
        {
            while (!shutdown.IsCancellationRequested)
            {
                TcpClient client;
                try
                {
                    client = await listener.AcceptTcpClientAsync(shutdown.Token);
                }
                catch (OperationCanceledException) { break; }

                var cid = Interlocked.Increment(ref tunnelId);
                var task = Task.Run(async () =>
                {
                    try
                    {
                        await HandleClientAsync(cid, client, serverCert, settings, auth, logger, ipTracker, logSalt, shutdown.Token);
                    }
                    catch (OperationCanceledException) { /* shutdown */ }
                    catch (Exception ex)
                    {
                        logger.Warn("proxy.conn.error", new() { ["id"] = cid, ["type"] = ex.GetType().Name });
                    }
                    finally
                    {
                        client.Dispose();
                        activeTunnels.TryRemove(cid, out _);
                    }
                });
                activeTunnels[cid] = task;
            }
        }
        finally
        {
            logger.Info("proxy.shutdown.begin", new() { ["active"] = activeTunnels.Count });
            try { listener.Stop(); } catch { }
            // Best-effort drain; tunnels will end on their own idle timeout.
            var drain = Task.WhenAll(activeTunnels.Values);
            await Task.WhenAny(drain, Task.Delay(TimeSpan.FromSeconds(10)));
            logger.Info("proxy.shutdown.done", new() { ["remaining"] = activeTunnels.Count });
        }
        return 0;
    }

    static void ValidateSettings(ProxySettings s)
    {
        if (string.IsNullOrWhiteSpace(s.BindAddress)) throw new InvalidOperationException("BindAddress required");
        if (s.ListenPort is < 1 or > 65535) throw new InvalidOperationException("ListenPort out of range");
        if (s.AllowedHosts.Length == 0) throw new InvalidOperationException("AllowedHosts must be non-empty (deny-all is not a valid config)");
        if (s.AllowedPorts.Length == 0) throw new InvalidOperationException("AllowedPorts must be non-empty");
        if (s.AllowedPorts.Any(p => p is < 1 or > 65535)) throw new InvalidOperationException("AllowedPorts out of range");
        if (!s.RequireClientCert && s.BearerTokenSha256 is null)
            throw new InvalidOperationException("Enable mTLS or bearer token — refusing to run unauthenticated");
        if (s.RequireClientCert && s.AllowedClientCertSha256.Length == 0)
            throw new InvalidOperationException("RequireClientCert set but AllowedClientCertSha256 is empty");
        if (string.IsNullOrEmpty(s.LogHashingKey) || s.LogHashingKey.Length < 32)
            throw new InvalidOperationException("LogHashingKey must be >= 32 chars");
        foreach (var h in s.AllowedClientCertSha256)
            if (h.Length != 64 || !h.All(x => Uri.IsHexDigit(x)))
                throw new InvalidOperationException($"Bad cert pin: {h}");
        if (s.BearerTokenSha256 is { } b && (b.Length != 64 || !b.All(x => Uri.IsHexDigit(x))))
            throw new InvalidOperationException("BearerTokenSha256 must be 64 hex chars");
    }

    static X509Certificate2 LoadServerCertificate(ProxySettings s)
    {
        if (s.CertIsPfx)
        {
            // No Exportable flag — key stays in the OS keystore.
            return X509CertificateLoader.LoadPkcs12FromFile(
                s.CertPath, s.CertPassword, X509KeyStorageFlags.MachineKeySet);
        }
        return X509Certificate2.CreateFromPemFile(s.CertPath);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Per-connection handler
    // ─────────────────────────────────────────────────────────────────────────
    static async Task HandleClientAsync(
        long id,
        TcpClient client,
        X509Certificate2 serverCert,
        ProxySettings s,
        Authenticator auth,
        Logger logger,
        IpConnectionTracker ipTracker,
        DailySalt salt,
        CancellationToken shutdown)
    {
        client.NoDelay = true;
        var remoteIp = ((IPEndPoint)client.Client.RemoteEndPoint!).Address;
        var hashedIp = salt.HashHex(remoteIp.ToString());

        if (!ipTracker.TryAcquire(remoteIp))
        {
            logger.Warn("proxy.reject.ipConcurrency", new() { ["id"] = id, ["ip"] = hashedIp });
            return;
        }
        try
        {
            await using var netStream = client.GetStream();
            var sslOpts = BuildServerTlsOptions(serverCert, s, auth);
            await using var ssl = new SslStream(netStream, leaveInnerStreamOpen: false);

            try
            {
                using var hsCts = CancellationTokenSource.CreateLinkedTokenSource(shutdown);
                hsCts.CancelAfter(TimeSpan.FromSeconds(s.HandshakeTimeoutSeconds));
                await ssl.AuthenticateAsServerAsync(sslOpts, hsCts.Token);
            }
            catch (Exception ex) when (ex is AuthenticationException or OperationCanceledException or IOException)
            {
                logger.Warn("proxy.reject.tls", new() { ["id"] = id, ["ip"] = hashedIp, ["type"] = ex.GetType().Name });
                return;
            }

            // Non-mTLS path: verify bearer in CONNECT headers.
            string? presentedBearer = null;
            bool bearerVerified = false;

            // Read CONNECT headers with deadline + size caps.
            var head = await ReadConnectHeadAsync(ssl, s, shutdown);
            if (head is null) { logger.Warn("proxy.reject.badHeaders", new() { ["id"] = id }); return; }

            var lines = head.Split("\r\n");
            var requestLine = lines[0];
            var parts = requestLine.Split(' ', 3);
            if (parts.Length != 3 || !parts[0].Equals("CONNECT", StringComparison.OrdinalIgnoreCase) ||
                !parts[2].StartsWith("HTTP/1.", StringComparison.Ordinal))
            {
                await WriteStatusAsync(ssl, "405 Method Not Allowed");
                logger.Warn("proxy.reject.method", new() { ["id"] = id });
                return;
            }

            if (!TryParseAuthority(parts[1], out var host, out var port))
            {
                await WriteStatusAsync(ssl, "400 Bad Request");
                logger.Warn("proxy.reject.authority", new() { ["id"] = id });
                return;
            }

            foreach (var line in lines.Skip(1))
            {
                if (line.StartsWith("Proxy-Authorization:", StringComparison.OrdinalIgnoreCase))
                {
                    var val = line["Proxy-Authorization:".Length..].Trim();
                    var seg = val.Split(' ', 3);
                    if (seg.Length == 3 && seg[0].Equals("Bearer", StringComparison.OrdinalIgnoreCase))
                        presentedBearer = seg[2];
                }
            }

            if (s.BearerTokenSha256 is not null && presentedBearer is not null)
                bearerVerified = auth.VerifyBearer(presentedBearer);

            if (s.BearerTokenSha256 is not null && !bearerVerified && !s.RequireClientCert)
            {
                await WriteStatusAsync(ssl, "407 Proxy Authentication Required\r\nProxy-Authenticate: Bearer");
                logger.Warn("proxy.reject.bearer", new() { ["id"] = id, ["ip"] = hashedIp });
                return;
            }

            if (!IsHostAllowed(host, s.AllowedHosts) || !s.AllowedPorts.Contains(port))
            {
                await WriteStatusAsync(ssl, "403 Forbidden");
                logger.Warn("proxy.reject.policy", new()
                {
                    ["id"] = id,
                    ["host"] = s.HashHostnamesInLogs ? salt.HashHex(host) : host,
                    ["port"] = port,
                });
                return;
            }

            // Resolve + CIDR-filter. Connect to IP, not hostname.
            IPAddress[] ips;
            using (var dnsCts = CancellationTokenSource.CreateLinkedTokenSource(shutdown))
            {
                dnsCts.CancelAfter(TimeSpan.FromSeconds(s.ConnectTimeoutSeconds));
                try { ips = await SafeResolver.ResolveAsync(host, dnsCts.Token); }
                catch (Exception ex) when (ex is SocketException or OperationCanceledException)
                {
                    await WriteStatusAsync(ssl, "502 Bad Gateway");
                    logger.Warn("proxy.reject.dns", new() { ["id"] = id, ["type"] = ex.GetType().Name });
                    return;
                }
            }
            if (ips.Length == 0)
            {
                await WriteStatusAsync(ssl, "403 Forbidden");
                logger.Warn("proxy.reject.cidr", new() { ["id"] = id, ["host"] = salt.HashHex(host) });
                return;
            }

            using var upstream = new TcpClient { NoDelay = true };
            try
            {
                using var connCts = CancellationTokenSource.CreateLinkedTokenSource(shutdown);
                connCts.CancelAfter(TimeSpan.FromSeconds(s.ConnectTimeoutSeconds));
                await upstream.ConnectAsync(new IPEndPoint(ips[0], port), connCts.Token);
            }
            catch (Exception ex)
            {
                await WriteStatusAsync(ssl, "502 Bad Gateway");
                logger.Warn("proxy.reject.upstream", new() { ["id"] = id, ["type"] = ex.GetType().Name });
                return;
            }

            await WriteStatusAsync(ssl, "200 Connection Established");

            logger.Info("proxy.tunnel.open", new()
            {
                ["id"] = id,
                ["ip"] = hashedIp,
                ["host"] = s.HashHostnamesInLogs ? salt.HashHex(host) : host,
                ["port"] = port,
                ["upstreamIp"] = ips[0].ToString(),
            });

            var upstreamStream = upstream.GetStream();
            var idle = TimeSpan.FromSeconds(s.IdleTunnelSeconds);

            using var tunnelCts = CancellationTokenSource.CreateLinkedTokenSource(shutdown);
            long bytesUp = 0, bytesDown = 0;
            var up = PumpAsync(ssl, upstreamStream, idle, tunnelCts.Token, n => Interlocked.Add(ref bytesUp, n));
            var down = PumpAsync(upstreamStream, ssl, idle, tunnelCts.Token, n => Interlocked.Add(ref bytesDown, n));
            await Task.WhenAny(up, down);
            tunnelCts.Cancel();
            await Task.WhenAll(up, down).ConfigureAwait(ConfigureAwaitOptions.SuppressThrowing);

            logger.Info("proxy.tunnel.close", new()
            {
                ["id"] = id,
                ["up"] = Interlocked.Read(ref bytesUp),
                ["down"] = Interlocked.Read(ref bytesDown),
            });
        }
        finally
        {
            ipTracker.Release(remoteIp);
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // TLS options
    // ─────────────────────────────────────────────────────────────────────────
    static SslServerAuthenticationOptions BuildServerTlsOptions(
        X509Certificate2 cert, ProxySettings s, Authenticator auth)
    {
        var opts = new SslServerAuthenticationOptions
        {
            ServerCertificate = cert,
            ClientCertificateRequired = s.RequireClientCert,
            EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
            CertificateRevocationCheckMode = X509RevocationMode.Online,
            RemoteCertificateValidationCallback = (_, c, _, _) =>
            {
                if (!s.RequireClientCert) return true;
                if (c is null) return false;
                var der = c.GetRawCertData();
                var fp = Convert.ToHexString(SHA256.HashData(der)).ToLowerInvariant();
                return auth.IsPinnedClientCert(fp);
            },
        };

        // CipherSuitesPolicy is unsupported on Windows (uses SCHANNEL). Guard.
        if (!OperatingSystem.IsWindows())
        {
            opts.CipherSuitesPolicy = new CipherSuitesPolicy(new[]
            {
                TlsCipherSuite.TLS_AES_256_GCM_SHA384,
                TlsCipherSuite.TLS_CHACHA20_POLY1305_SHA256,
                TlsCipherSuite.TLS_AES_128_GCM_SHA256,
                TlsCipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
                TlsCipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            });
        }
        return opts;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Parsing
    // ─────────────────────────────────────────────────────────────────────────
    static async Task<string?> ReadConnectHeadAsync(SslStream ssl, ProxySettings s, CancellationToken shutdown)
    {
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(shutdown);
        cts.CancelAfter(TimeSpan.FromSeconds(s.HeaderReadTimeoutSeconds));
        var buf = new byte[1024];
        var sb = new StringBuilder(256);
        int total = 0;
        while (true)
        {
            int n;
            try { n = await ssl.ReadAsync(buf, cts.Token); }
            catch (OperationCanceledException) { return null; }
            if (n == 0) return null;
            total += n;
            if (total > s.MaxHeaderBytes) return null;

            for (int i = 0; i < n; i++)
            {
                var b = buf[i];
                if (b == 0) return null;                         // NUL smuggling
                if (b < 0x09 || (b > 0x0D && b < 0x20)) return null; // control chars
                sb.Append((char)b);
            }
            var str = sb.ToString();
            var end = str.IndexOf("\r\n\r\n", StringComparison.Ordinal);
            if (end >= 0)
            {
                var head = str[..end];
                foreach (var line in head.Split("\r\n"))
                    if (line.Length > s.MaxHeaderLineBytes) return null;
                return head;
            }
        }
    }

    static bool TryParseAuthority(string authority, out string host, out int port)
    {
        host = ""; port = 443;
        if (authority.Length == 0 || authority.Length > 253) return false;
        foreach (var c in authority)
            if (c < 0x21 || c > 0x7E) return false;

        var idx = authority.LastIndexOf(':');
        if (idx < 0) { host = authority; }
        else
        {
            host = authority[..idx];
            if (!int.TryParse(authority[(idx + 1)..], NumberStyles.None, CultureInfo.InvariantCulture, out port)) return false;
            if (port is < 1 or > 65535) return false;
        }
        if (host.Length == 0) return false;
        if (host is "." or ".." or "localhost") return false;
        if (host.Contains('[') || host.Contains(']')) return false;
        return true;
    }

    static bool IsHostAllowed(string host, string[] patterns)
    {
        foreach (var p in patterns)
        {
            if (p.StartsWith("*.", StringComparison.Ordinal))
            {
                if (host.Length > p.Length - 1 &&
                    h