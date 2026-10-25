#:sdk Microsoft.NET.Sdk.Web
#:property TargetFramework=net8.0
#:property Nullable=enable

// ↑ .NET 8 "file-based app" directives. If you're on an older SDK,
//   just paste this into an existing web project's Program.cs.

using System.Buffers;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.Server.Kestrel.Https;

// ============================================================================
//  CONFIGURATION — override via environment variables in production
// ============================================================================
var cfg = new ProxyConfig
{
    ListenPort          = int.Parse(Environment.GetEnvironmentVariable("PROXY_PORT") ?? "8443"),
    ServerCertPath      = Environment.GetEnvironmentVariable("PROXY_CERT")    ?? "/etc/proxy/server.pfx",
    ServerCertPassword  = Environment.GetEnvironmentVariable("PROXY_CERT_PW") ?? "",
    AllowedUpstreams    = (Environment.GetEnvironmentVariable("PROXY_UPSTREAMS") ?? "")
                          .Split(',', StringSplitOptions.RemoveEmptyEntries)
                          .Select(u => new Uri(u))
                          .ToArray(),
    RequestsPerMinute   = int.Parse(Environment.GetEnvironmentVariable("PROXY_RPM") ?? "600"),
    MaxBodyBytes        = long.Parse(Environment.GetEnvironmentVariable("PROXY_MAX_BODY") ?? (10L * 1024 * 1024)),
};

var builder = WebApplication.CreateSlimBuilder(args);

// ---------- 1. Kestrel: TLS 1.3 ONLY, mTLS REQUIRED, tight limits ----------
builder.WebHost.ConfigureKestrel(k =>
{
    k.AddServerHeader = false;                          // no "Server: Kestrel"
    k.Limits.MaxRequestBodySize             = cfg.MaxBodyBytes;
    k.Limits.MaxRequestHeadersTotalSize     = 32 * 1024;
    k.Limits.MaxRequestHeaderCount          = 100;
    k.Limits.RequestHeadersTimeout          = TimeSpan.FromSeconds(15);
    k.Limits.KeepAliveTimeout               = TimeSpan.FromSeconds(60);
    k.Limits.MinRequestBodyDataRate         = new(240, TimeSpan.FromSeconds(5));
    k.Limits.MinResponseDataRate            = new(240, TimeSpan.FromSeconds(5));

    k.ListenAnyIP(cfg.ListenPort, listen =>
    {
        // HTTP/2 only — HTTP/1.1 stays in the proxy path (upstream side),
        // but clients must speak h2 over TLS 1.3.
        listen.Protocols = Microsoft.AspNetCore.Server.Kestrel.Core.HttpProtocols.Http2;
        listen.UseHttps(https =>
        {
            https.ServerCertificate               = LoadServerCert(cfg);
            https.SslProtocols                    = SslProtocols.Tls13;   // ← 1.3 only
            https.ClientCertificateMode           = ClientCertificateMode.RequireCertificate;
            https.ClientCertificateValidation     = ValidateClientCert;
            https.AllowAnyClientCertificate       = false;
            https.CheckCertificateRevocation      = true;
        });
    });
});

// ---------- 2. Rate limiter partitioned by CLIENT CERT THUMBPRINT ----------
builder.Services.AddRateLimiter(o =>
{
    o.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
    o.GlobalLimiter = PartitionedRateLimiter.Create<HttpContext, string>(ctx =>
    {
        var id = ctx.Connection.ClientCertificate?.Thumbprint ?? "anon";
        return RateLimitPartition.GetFixedWindowLimiter(id, _ => new()
        {
            PermitLimit = cfg.RequestsPerMinute,
            Window      = TimeSpan.FromMinutes(1),
            QueueLimit  = 0,
        });
    });
});

// ---------- 3. ONE HttpClient for upstream, pinned TLS 1.3, no redirects ----------
builder.Services.AddSingleton(_ =>
{
    var handler = new SocketsHttpHandler
    {
        SslOptions =
        {
            EnabledSslProtocols       = SslProtocols.Tls13,
            CertificateRevocationCheckMode = X509RevocationMode.Online,
        },
        AllowAutoRedirect             = false,              // never follow redirects
        AutomaticDecompression        = DecompressionMethods.None, // don't decode — pass through
        UseCookies                    = false,              // proxy holds no state
        PooledConnectionLifetime      = TimeSpan.FromMinutes(5),
        ConnectTimeout                = TimeSpan.FromSeconds(10),
        MaxConnectionsPerServer       = 100,
    };
    var client = new HttpClient(handler)
    {
        // Cap upstream response time — prevents slow-loris upstream
        Timeout = TimeSpan.FromSeconds(30),
    };
    client.DefaultRequestHeaders.UserAgent.Clear();         // strip .NET default
    return client;
});

var app = builder.Build();

// ---------- 4. Middleware chain (ORDER MATTERS) ----------
app.UseHsts();

// 4a. Reject methods that enable open-proxy / tunneling attacks
app.Use(async (ctx, next) =>
{
    if (ctx.Request.Method is "TRACE" or "TRACK" or "CONNECT")
    {
        ctx.Response.StatusCode = StatusCodes.Status405MethodNotAllowed;
        return;
    }
    await next();
});

// 4b. Request smuggling + header-injection guard
app.Use(async (ctx, next) =>
{
    var h = ctx.Request.Headers;

    // CL + TE together = request smuggling (RFC 7230 §3.3.3)
    if (h.ContainsKey("Transfer-Encoding") && h.ContainsKey("Content-Length"))
    {
        ctx.Response.StatusCode = StatusCodes.Status400BadRequest;
        return;
    }

    // Duplicate Host = host-header injection
    if (h.Host.Count > 1)
    {
        ctx.Response.StatusCode = StatusCodes.Status400BadRequest;
        return;
    }

    // Forbid absolute-form request target ("GET http://evil/ HTTP/1.1")
    // — classic open-proxy abuse vector.
    var raw = ctx.Features.Get<IHttpRequestFeature>()?.RawTarget ?? "";
    if (raw.StartsWith("http://",  StringComparison.OrdinalIgnoreCase) ||
        raw.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
    {
        ctx.Response.StatusCode = StatusCodes.Status400BadRequest;
        return;
    }

    // Strip hop-by-hop + trust-forged headers
    foreach (var name in HopByHopAndUntrusted)
        ctx.Request.Headers.Remove(name);

    await next();
});

// 4c. Rate limiting
app.UseRateLimiter();

// 4d. The actual proxy — hand-written, no library
app.Run(async ctx =>
{
    if (!TryResolveUpstream(ctx, cfg, out var upstream, out var path))
    {
        ctx.Response.StatusCode = StatusCodes.Status400BadRequest;
        return;
    }

    using var upstreamReq = BuildUpstreamRequest(ctx, upstream, path);

    using var upstreamResp = await app.Services
        .GetRequiredService<HttpClient>()
        .SendAsync(upstreamReq, HttpCompletionOption.ResponseHeadersRead, ctx.RequestAborted);

    ctx.Response.StatusCode = (int)upstreamResp.StatusCode;

    // Copy response headers, filtering hop-by-hop + security-relevant ones
    foreach (var (name, values) in upstreamResp.Headers.Concat(upstreamResp.Content.Headers))
    {
        if (ResponseHeaderBlocklist.Contains(name)) continue;
        foreach (var v in values) ctx.Response.Headers.Append(name, v);
    }
    // Never let upstream set cookies for the proxy's domain
    ctx.Response.Headers.Remove("Set-Cookie");

    await upstreamResp.Content.CopyToAsync(ctx.Response.Body, ctx.RequestAborted);
});

app.Run();

// ============================================================================
//  HELPERS
// ============================================================================

static readonly string[] HopByHopAndUntrusted =
{
    "Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization",
    "TE", "Trailer", "Transfer-Encoding", "Upgrade",
    // Never trust client-supplied forwarding headers — we set our own
    "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto",
    "Forwarded", "X-Real-IP",
};

static readonly HashSet<string> ResponseHeaderBlocklist =
    new(StringComparer.OrdinalIgnoreCase)
    {
        "Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization",
        "TE", "Trailer", "Transfer-Encoding", "Upgrade",
        "Server", "X-Powered-By", "Set-Cookie",          // leak / state vectors
        "Content-Length",                                 // recomputed by Kestrel
        "Strict-Transport-Security",                      // we set our own via HSTS
    };

static bool TryResolveUpstream(HttpContext ctx, ProxyConfig cfg, out Uri upstream, out string path)
{
    upstream = default!;
    path     = default!;

    // Host header must EXACTLY match an allow-listed upstream host.
    // This is the open-proxy kill switch: no dynamic destination = no SSRF.
    var host = ctx.Request.Host.Host;
    var match = cfg.AllowedUpstreams.FirstOrDefault(u =>
        string.Equals(u.Host, host, StringComparison.OrdinalIgnoreCase));

    if (match is null) return false;

    upstream = match;
    path     = ctx.Request.Path + ctx.Request.QueryString;
    return true;
}

static HttpRequestMessage BuildUpstreamRequest(HttpContext ctx, Uri upstream, string path)
{
    var req = ctx.Request;
    var uri = new Uri(upstream, path);

    var msg = new HttpRequestMessage(new HttpMethod(req.Method), uri)
    {
        Version          = HttpVersion.Version20,
        VersionPolicy    = HttpVersionPolicy.RequestVersionExact,
        Content          = req.ContentLength == 0 && !req.Headers.ContainsKey("Transfer-Encoding")
                            ? null
                            : new StreamContent(req.Body),
    };

    // Copy only safe request headers
    foreach (var (name, values) in req.Headers)
    {
        if (HopByHopAndUntrusted.Contains(name, StringComparer.OrdinalIgnoreCase)) continue;
        if (name.Equals("Host", StringComparison.OrdinalIgnoreCase))                continue;

        if (!msg.Headers.TryAddWithoutValidation(name, (IEnumerable<string>)values!))
            msg.Content?.Headers.TryAddWithoutValidation(name, (IEnumerable<string>)values!);
    }

    // Add exactly ONE forwarding identity, derived from the verified client cert
    msg.Headers.TryAddWithoutValidation("X-Forwarded-For", ctx.Connection.RemoteIpAddress?.ToString());
    msg.Headers.TryAddWithoutValidation("X-Forwarded-Proto", "https");
    msg.Headers.TryAddWithoutValidation("X-Client-Cert-Thumbprint",
        ctx.Connection.ClientCertificate?.Thumbprint);

    return msg;
}

static X509Certificate2 LoadServerCert(ProxyConfig cfg)
{
    // In production: fetch from Azure Key Vault / HSM / Windows cert store.
    // NEVER ship a PFX in the container or a password in source.
    if (!File.Exists(cfg.ServerCertPath))
        throw new FileNotFoundException("Server cert not found", cfg.ServerCertPath);

    return X509CertificateLoader.LoadPkcs12FromFile(cfg.ServerCertPath, cfg.ServerCertPassword);
}

static bool ValidateClientCert(X509Certificate2 cert, X509Chain? chain, SslPolicyErrors errors)
{
    if (errors != SslPolicyErrors.None) return false;
    if (chain is null)                  return false;

    chain.ChainPolicy.RevocationMode    = X509RevocationMode.Online;
    chain.ChainPolicy.RevocationFlag    = X509RevocationFlag.EntireChain;
    chain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;
    // Optional pinning: if (cert.Issuer != "CN=My-Client-CA") return false;

    return chain.Build(cert);
}

// ============================================================================
//  CONFIG TYPE
// ============================================================================
sealed class ProxyConfig
{
    public int      ListenPort        { get; init; }
    public string   ServerCertPath    { get; init; } = "";
    public string   ServerCertPassword{ get; init; } = "";
    public Uri[]    AllowedUpstreams  { get; init; } = Array.Empty<Uri>();
    public int      RequestsPerMinute { get; init; }
    public long     MaxBodyBytes      { get; init; }
}