# Changelog

All notable changes to **Fluxgate** are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-11-22

### Added
- **Vault KV v2 Secret Sync (`vault {}`)**:
  - Global `vault` configuration block supporting `addr`, optional `namespace`, `ca_cert`, `auth approle|token`, and periodic `sync <alias> <kv/data/...> <interval>` declarations.
  - Supports AppRole (`VAULT_ROLE_ID`/`VAULT_SECRET_ID`), Token (`VAULT_TOKEN`), and systemd `LoadCredential` (`$CREDENTIALS_DIRECTORY`), with automatic lease renewal and KV v2 metadata version change detection.
  - Memory-protected `SecretStore` using `zeroize::Zeroizing<String>` and redacted `Debug`/`Display` formatting; preserves cached snapshots with exponential backoff when Vault is temporarily unreachable.
  - Inline `{vault.<alias>.<key>}` and `{env.<VAR>}` / `env(<VAR>)` configuration placeholder parsing and runtime injection.
- **GitOps Non-Sensitive Integration & Zero-Downtime Hot Reload**:
  - Lock-free `ArcSwap<CompiledRouter>` routing table replacement on `SIGHUP` or `fluxgate reload`, leaving existing long-lived streaming connections uninterrupted.
  - `fluxgate validate --strict-gitops` and `--offline` flags to catch accidental plaintext private keys or API tokens in GitOps-managed configurations.
  - `fluxgate reload` and `fluxgate doctor` CLI subcommands for operational reload and configuration/Vault/certificate health checks.
- **Ansible Pull Playbook & Systemd Integration**:
  - Enhanced `deploy/fluxgate.service` with `ExecReload=/usr/local/bin/fluxgate reload`, `EnvironmentFile=-/etc/fluxgate/fluxgate.env`, and `StateDirectory=fluxgate` (`0700`).
  - Added reference Ansible Pull convergence playbook and systemd units under `deploy/ansible-pull/` (`pull_fluxgate.yml`, `ansible-pull-fluxgate.service`, `ansible-pull-fluxgate.timer`) with architecture detection and mandatory `SHA256SUMS` verification.
- **ACME DNS-01 Automated TLS & Multi-Node Vault Certificate Sharing**:
  - Caddy-style block `tls { issuer acme { email ...; ca ... }; dns cloudflare|alidns ...; renew_before ...; storage vault ... }` alongside full backward compatibility with static `tls <cert> <key>`.
  - Dynamic SNI certificate lookup and zero-downtime hot swapping via Pingora `TlsAccept` callbacks (`DynamicCertStore`), supporting exact and wildcard hostnames.
  - Pure-Rust ACME v2 client (`instant-acme` + `rcgen` + `x509-parser`) with built-in **Cloudflare** and **AliDNS** (`HMAC-SHA1`) DNS-01 providers.
  - Multi-node certificate coordination via Vault KV v2 CAS optimistic locking (`renew_owner` / `renew_lock_until`) and `0700`/`0600` local fallback storage to prevent ACME rate-limit contention across edge nodes.
- **Prometheus Metrics & Multi-Arch Release Automation**:
  - Added `fluxgate_vault_sync_success`, `fluxgate_vault_last_sync_timestamp_seconds`, `fluxgate_vault_sync_version`, `fluxgate_config_reload_success`, `fluxgate_config_last_reload_timestamp_seconds`, `fluxgate_config_info`, `fluxgate_tls_cert_expiry_timestamp_seconds`, `fluxgate_tls_cert_days_remaining`, and `fluxgate_acme_renew_total`.
  - Updated GitHub Actions release workflow to publish `fluxgate`, `fluxgate-linux-amd64`, `fluxgate-linux-arm64`, and `SHA256SUMS` automatically on `v*` tags.

## [0.1.0] - 2026-11-20

### Added
- Initial release of **Fluxgate** built on Rust + Cloudflare Pingora (`0.9.1`).
- Caddyfile-compatible DSL lexer, parser, validator, and sorted `import` glob loader with cycle/depth checks.
- Dual-stack IPv4/IPv6 HTTP & HTTPS listeners with OpenSSL TLS (H2/H1.1 ALPN) and HTTP-to-HTTPS 308 auto-redirect.
- Native `h2c` over Unix Domain Sockets (`unix//...` with `versions h2c 2` and `unix+h2c//...` shorthand) with streaming zero-buffer forwarding (`flush_interval -1`).
- Downstream HTTP/2 cancellation (`RST_STREAM` / `Client closed H2`) log noise suppression mapped cleanly to HTTP 499.
- Built-in Prometheus `/metrics` endpoint and `/healthz` probe.
- CLI subcommands `validate`, `run`, `version`, and reference `deploy/fluxgate.service`.
