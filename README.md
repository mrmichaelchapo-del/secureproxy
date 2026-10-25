# Secure C# Proxy

A hardened reverse proxy in a single C# file. TLS 1.3 only, mutual TLS required, allow-listed upstreams, request-smuggling defenses, per-client rate limiting. No third-party proxy library — the entire request path is visible and auditable.

---

Features

- TLS 1.3 only — older protocol versions are not negotiated
- Mutual TLS required — no anonymous clients
- Online revocation checking — revoked client certs are rejected
- Allow-listed upstreams — Host header must exactly match a configured upstream Uri; unmatched requests are rejected before any outbound connection
- Request smuggling defenses — Content-Length + Transfer-Encoding conflicts and duplicate Host headers are rejected
- Absolute-form request rejection — GET http://evil/ HTTP/1.1 style requests are blocked
- Hop-by-hop header stripping — inbound and outbound
- Response header blocklist — strips Server, X-Powered-By, Set-Cookie, Content-Length
- Per-client rate limiting — partitioned by client certificate thumbprint
- No redirects, no cookies, no caching — the proxy holds no state
- No Server header — nothing to fingerprint
- HTTP/2 on both legs — client and upstream
- Certificate identity forwarding — client cert thumbprint injected as X-Client-Cert-Thumbprint for upstream authorization

---

Requirements

- .NET 8 SDK or later
- A server certificate (PFX) for TLS termination
- A client CA whose issued certificates will be accepted

---

# Configuration

All configuration is via environment variables.

Variable Required Default Description
PROXY_PORT no 8443 Listen port
PROXY_CERT yes /etc/proxy/server.pfx Path to server PFX
PROXY_CERT_PW no empty PFX password
PROXY_UPSTREAMS yes empty Comma-separated list of allowed upstream Uris
PROXY_RPM no 600 Requests per minute, per client cert
PROXY_MAX_BODY no 10485760 (10 MB) Max request body in bytes

---

Running

```
export PROXY_CERT=/etc/proxy/server.pfx
export PROXY_CERT_PW="$(secret-tool lookup service proxy key pfx)"
export PROXY_UPSTREAMS="https://internal-api.corp:443/,https://internal-svc.corp:443/"
export PROXY_RPM=600

dotnet run Proxy.cs
```

The proxy listens on 0.0.0.0:8443 (or PROXY_PORT) over HTTP/2 + TLS 1.3 and requires a valid client certificate on every connection.

---

Upstream resolution

The Host header of each inbound request is matched against the host component of each entry in PROXY_UPSTREAMS. On a match, the request is forwarded to that upstream at the original path and query. On no match, the request is rejected with 400 Bad Request before any outbound socket is opened.

Example: with PROXY_UPSTREAMS=https://internal-api.corp:443/, a request to https://proxy.example.com/api/users (with Host: internal-api.corp) is forwarded to https://internal-api.corp:443/api/users. A request with any other Host is rejected.

---

Client certificates

Clients must present a certificate chaining to a trusted CA. The default validation:

· Rejects any chain error
· Requires online revocation check (OCSP / CRL)
· Requires the entire chain to build cleanly

To pin a specific client CA, uncomment the issuer check in ValidateClientCert:

```
if (cert.Issuer != "CN=My-Client-CA") return false;
```

---

What gets forwarded upstream

Request headers: all headers except hop-by-hop headers, Host, and client-supplied forwarding headers (X-Forwarded-For, X-Forwarded-Host, X-Forwarded-Proto, Forwarded, X-Real-IP).

Added by the proxy:

- X-Forwarded-For — client IP
- X-Forwarded-Proto: https
- X-Client-Cert-Thumbprint — SHA-1 thumbprint of the verified client certificate

Response headers: all headers except hop-by-hop headers, Server, X-Powered-By, Set-Cookie, Content-Length, Strict-Transport-Security.

---

Rejected requests

The proxy returns one of the following without contacting any upstream:

Condition Status
Method is TRACE, TRACK, or CONNECT 405 Method Not Allowed
Both Content-Length and Transfer-Encoding present 400 Bad Request
Multiple Host headers 400 Bad Request
Absolute-form request target 400 Bad Request
Host does not match any allowed upstream 400 Bad Request
Rate limit exceeded 429 Too Many Requests

---

Deployment notes

- Secrets: load the PFX password from a secrets manager (Key Vault, AWS Secrets Manager, secret-tool, etc.). Do not pass it on the command line or bake it into an image.
- Container: run as non-root, read-only filesystem, no CAP_NET_RAW, egress restricted to the allow-listed upstream IPs.
- Network: place the proxy behind a load balancer only if that LB is itself trusted; ForwardedHeaders is intentionally not configured.
- Logs: Kestrel and ASP.NET Core logs are enabled by default. Ship them to your SIEM; retain per your policy.
- Patching: track .NET and ASP.NET Core security advisories. Run dotnet list package --vulnerable in CI.
- Rotation: rotate the server PFX and client CA certificates on a defined schedule. Restart the proxy after rotation — the server certificate is loaded at startup.

---

Extending

Common additions and where they go:

- Per-cert authorization — inspect ctx.Connection.ClientCertificate in the request middleware before app.Run
- Request body inspection — add a middleware between the header guard and the rate limiter; use ctx.Request.EnableBuffering() and rewind before proxying
- Custom audit log — add ILogger calls in the request middleware; log to structured sinks (Serilog, OpenTelemetry)
- Outbound mTLS to upstream — configure SocketsHttpHandler.SslOptions.ClientCertificates in the AddSingleton<HttpClient> registration
- Upstream health checks — the HttpClient ConnectTimeout will fail fast on dead upstreams; add an out-of-band prober if you need faster failover
- HTTP/3 — change listen.Protocols to include Http3; requires QUIC support in your Kestrel build

---

Testing the proxy

```
# Should succeed (matching Host + valid client cert)
curl --http2 \
     --cert client.pem --key client.key \
     --cacert ca.pem \
     -H "Host: internal-api.corp" \
     https://proxy.example.com:8443/api/users

# Should return 400 (Host not allow-listed)
curl --http2 \
     --cert client.pem --key client.key \
     --cacert ca.pem \
     -H "Host: evil.com" \
     https://proxy.example.com:8443/api/users

# Should return 400 (absolute-form target)
curl --http2 \
     --cert client.pem --key client.key \
     --cacert ca.pem \
     --request-target "http://evil.com/" \
     https://proxy.example.com:8443/

# Should return 405 (CONNECT)
curl --http2 \
     --cert client.pem --key client.key \
     --cacert ca.pem \
     -X CONNECT \
     https://proxy.example.com:8443/
```

---

# License

MIT