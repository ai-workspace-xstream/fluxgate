# Fluxgate

Lightweight, zero-GC, high-performance HTTP/HTTPS reverse proxy built with **Rust + Cloudflare Pingora**, featuring a Caddyfile-inspired declarative DSL.

## Key Features

- **Pingora Core (`pingora 0.9.1`)**: Multi-threaded async Tokio runtime, zero GC stalls, deterministic memory footprint.
- **Native `h2c` over Unix Domain Socket**: Enforces HTTP/2 cleartext prior-knowledge (`set_http_version(2, 2)`) to Unix sockets (e.g. `unix//dev/shm/xray.sock`) without silent HTTP/1.1 downgrade.
- **Streaming-First**: Streams request and response bodies without full-body buffering; disables unsafe automatic retries on streaming failures.
- **Caddy-style DSL & `import`**: Supports site blocks, `import` globs with cycle detection and max-depth protection, named matchers (`@xhttp`), `handle_path`, `handle`, `rewrite`, `uri query -param`, `reverse_proxy`, `tls`, and `respond`.
- **Fail-Fast Validation**: Unknown directives or broken imports are explicitly rejected with file and line numbers.

## CLI Usage

```bash
# Validate configuration
fluxgate validate --config /etc/fluxgate/Fluxgatefile

# Run proxy server
fluxgate run --config /etc/fluxgate/Fluxgatefile

# Print version
fluxgate version
```

## Caddyfile Compatibility Scope

Fluxgate implements a **focused subset** of Caddyfile syntax rather than a full Caddy interpreter:

| Directive / Feature | Status | Notes |
| :--- | :--- | :--- |
| Global `{ grace_period ...; log { level ... } }` | Supported | Maps `grace_period` to Pingora `grace_period_seconds` |
| `import <glob/path>` | Supported | Relative/absolute paths, sorted globs, cycle & depth (`16`) checks |
| Site blocks `<host1> <host2> { ... }` | Supported | Exact and wildcard (`*.domain`) host matching |
| `tls <cert> <key>` | Supported | OpenSSL `intermediate` profile with H2/H1.1 ALPN |
| `handle_path <prefix> { ... }` | Supported | Strips matched prefix before proxying |
| `@name { path ... }` / `@name path ...` | Supported | Exact and `*` suffix path matchers |
| `handle [@matcher] { ... }` | Supported | Mutually-exclusive block evaluation |
| `rewrite [@matcher] <target>` | Supported | Path rewriting |
| `uri query -<param>` | Supported | Removes target query parameter while preserving others |
| `reverse_proxy <tcp\|unix//...> { ... }` | Supported | Supports `flush_interval -1` and `transport http { versions h2c 2 }` |
| `respond "<body>" [status]` | Supported | Static fallback response |
| Unimplemented Caddy directives | Rejected | Fails explicitly during config validation |

## CI Build & Target Host Deployment

Builds are executed in GitHub Actions (`.github/workflows/ci.yml`), producing a stripped Linux `amd64` release binary (`fluxgate-linux-amd64`). Target hosts only download and deploy the binary without running Rust toolchains locally.

### Migration & Rollback (Caddy / HAProxy ↔ Fluxgate)

1. Install binary to `/usr/local/bin/fluxgate` and unit to `/etc/systemd/system/fluxgate.service`.
2. Place `Fluxgatefile` and `conf.d/*.conf` under `/etc/fluxgate/`.
3. Validate before switching:
   ```bash
   fluxgate validate --config /etc/fluxgate/Fluxgatefile
   ```
4. Switch active ingress (preserving existing Caddy/HAProxy configs untouched):
   ```bash
   systemctl disable --now caddy haproxy 2>/dev/null || true
   systemctl enable --now fluxgate
   ```
5. Instant rollback:
   ```bash
   systemctl disable --now fluxgate
   systemctl enable --now haproxy   # or caddy
   ```
