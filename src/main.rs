use arc_swap::ArcSwap;
use async_trait::async_trait;
use clap::Parser as ClapParser;
use fluxgate::acme::storage::{parse_cert_not_after, LocalCertStorage};
use fluxgate::acme::CertRenewalService;
use fluxgate::cli::{Cli, Commands};
use fluxgate::config::{
    compute_config_hash, load_config, load_config_with_options, AcmeTlsConfig, FluxgateConfig,
    TlsConfig, ValidateOptions,
};
use fluxgate::metrics::{MetricsRegistry, MetricsService};
use fluxgate::proxy::{CompiledRouter, FluxgateProxy};
use fluxgate::tls::{build_dynamic_tls_settings, DynamicCertStore};
use fluxgate::vault::{SecretStore, VaultClient, VaultSyncService};
use pingora::listeners::TcpSocketOptions;
use pingora::prelude::*;
use pingora::proxy::http_proxy_service_with_name;
use pingora::server::configuration::ServerConf;
use pingora::server::ShutdownWatch;
use pingora::services::background::{background_service, BackgroundService};
use std::path::PathBuf;
use std::process;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::signal::unix::{signal, SignalKind};
use tracing_subscriber::EnvFilter;

fn init_logging(level: &str) {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(level.to_ascii_lowercase()));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .try_init();
}

fn now_unix_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn describe_tls(tls: Option<&TlsConfig>) -> String {
    match tls {
        None => "none".to_string(),
        Some(TlsConfig::Static { cert_path, .. }) => format!("static:{}", cert_path.display()),
        Some(TlsConfig::Acme(acme)) => format!(
            "acme:{} (dns={})",
            acme.ca_url,
            match &acme.dns_provider {
                fluxgate::config::DnsProviderConfig::Cloudflare { .. } => "cloudflare",
                fluxgate::config::DnsProviderConfig::AliDns { .. } => "alidns",
            }
        ),
    }
}

fn collect_static_tls_entries(cfg: &FluxgateConfig) -> Vec<(Vec<String>, PathBuf, PathBuf)> {
    cfg.sites
        .iter()
        .filter_map(|site| match &site.tls {
            Some(TlsConfig::Static {
                cert_path,
                key_path,
            }) => Some((site.hosts.clone(), cert_path.clone(), key_path.clone())),
            _ => None,
        })
        .collect()
}

fn collect_acme_sites(cfg: &FluxgateConfig) -> Vec<(Vec<String>, AcmeTlsConfig)> {
    cfg.sites
        .iter()
        .filter_map(|site| match &site.tls {
            Some(TlsConfig::Acme(acme)) => Some((site.hosts.clone(), acme.clone())),
            _ => None,
        })
        .collect()
}

fn sync_static_certs_to_store(
    cfg: &FluxgateConfig,
    cert_store: &DynamicCertStore,
    metrics: Option<&MetricsRegistry>,
) -> fluxgate::error::Result<()> {
    let entries = collect_static_tls_entries(cfg);
    cert_store.clear_and_reload_static(entries)?;
    if let Some(m) = metrics {
        for (domains, not_after) in cert_store.list_expiries() {
            if not_after > 0 {
                m.record_tls_cert_expiry(&domains.join(","), not_after);
            }
        }
    }
    Ok(())
}

fn resolve_node_id() -> String {
    if let Ok(id) = std::env::var("AGENT_ID") {
        let trimmed = id.trim();
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }
    if let Ok(host) = std::env::var("HOSTNAME") {
        let trimmed = host.trim();
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }
    std::fs::read_to_string("/etc/hostname")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "fluxgate-node".to_string())
}

struct ConfigReloadService {
    config_path: PathBuf,
    router: Arc<ArcSwap<CompiledRouter>>,
    cert_store: Arc<DynamicCertStore>,
    metrics: Option<Arc<MetricsRegistry>>,
}

#[async_trait]
impl BackgroundService for ConfigReloadService {
    async fn start(&self, mut shutdown: ShutdownWatch) {
        let mut sighup = match signal(SignalKind::hangup()) {
            Ok(sig) => sig,
            Err(e) => {
                tracing::error!("Failed to register SIGHUP handler: {}", e);
                let _ = shutdown.changed().await;
                return;
            }
        };

        loop {
            tokio::select! {
                _ = shutdown.changed() => {
                    tracing::info!("Shutting down SIGHUP reload watcher");
                    break;
                }
                sig = sighup.recv() => {
                    if sig.is_none() {
                        break;
                    }
                    tracing::info!(
                        "Received SIGHUP, reloading configuration from {}",
                        self.config_path.display()
                    );
                    let ts = now_unix_secs();
                    match load_config(&self.config_path) {
                        Ok(new_cfg) => {
                            let hash = compute_config_hash(&new_cfg);
                            if let Err(e) = sync_static_certs_to_store(
                                &new_cfg,
                                &self.cert_store,
                                self.metrics.as_deref(),
                            ) {
                                tracing::error!(
                                    "Hot-reload aborted (TLS load failure), keeping active config: {}",
                                    e
                                );
                                if let Some(m) = &self.metrics {
                                    m.record_config_reload(false, "", ts);
                                }
                                continue;
                            }

                            let new_router = CompiledRouter::compile(&new_cfg);
                            self.router.store(Arc::new(new_router));
                            if let Some(m) = &self.metrics {
                                m.record_config_reload(true, &hash, ts);
                            }
                            tracing::info!(
                                "Hot-reload applied: {} site block(s), sha256={}",
                                new_cfg.sites.len(),
                                &hash[..12.min(hash.len())]
                            );
                        }
                        Err(e) => {
                            tracing::error!(
                                "Hot-reload rejected invalid config, keeping active config: {}",
                                e
                            );
                            if let Some(m) = &self.metrics {
                                m.record_config_reload(false, "", ts);
                            }
                        }
                    }
                }
            }
        }
    }
}

fn run_reload_command(pid_file: &PathBuf) {
    let raw = match std::fs::read_to_string(pid_file) {
        Ok(s) => s,
        Err(e) => {
            eprintln!(
                "Failed to read PID file {}: {}",
                pid_file.display(),
                e
            );
            process::exit(1);
        }
    };
    let pid: libc::pid_t = match raw.trim().parse() {
        Ok(p) if p > 0 => p,
        _ => {
            eprintln!("Invalid PID value in {}", pid_file.display());
            process::exit(1);
        }
    };
    let rc = unsafe { libc::kill(pid, libc::SIGHUP) };
    if rc != 0 {
        eprintln!(
            "Failed to send SIGHUP to fluxgate PID {}: {}",
            pid,
            std::io::Error::last_os_error()
        );
        process::exit(1);
    }
    println!("Sent SIGHUP reload signal to fluxgate PID {}", pid);
}

fn run_doctor_command(config_path: &PathBuf) {
    init_logging("WARN");
    println!("Fluxgate Doctor (v{})", env!("CARGO_PKG_VERSION"));
    println!("Config: {}", config_path.display());

    let cfg = match load_config_with_options(
        config_path,
        ValidateOptions {
            offline: true,
            strict_gitops: false,
        },
    ) {
        Ok(c) => {
            let hash = compute_config_hash(&c);
            println!(
                "[OK]   Config syntax & schema valid ({} site(s), sha256={})",
                c.sites.len(),
                &hash[..12.min(hash.len())]
            );
            c
        }
        Err(e) => {
            eprintln!("[FAIL] Config validation failed: {}", e);
            process::exit(1);
        }
    };

    match load_config_with_options(
        config_path,
        ValidateOptions {
            offline: true,
            strict_gitops: true,
        },
    ) {
        Ok(_) => println!("[OK]   Strict GitOps secret scan passed"),
        Err(e) => println!("[WARN] Strict GitOps scan warning: {}", e),
    }

    if let Some(vault_cfg) = &cfg.global.vault {
        println!(
            "[INFO] Vault configured: addr={}, auth={:?}, syncs={}",
            vault_cfg.addr,
            vault_cfg.auth,
            vault_cfg.syncs.len()
        );
        if let Ok(rt) = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            rt.block_on(async {
                match VaultClient::from_config(vault_cfg).await {
                    Ok(client) => {
                        println!("[OK]   Vault authentication succeeded");
                        for spec in &vault_cfg.syncs {
                            match client.read_kv2(&spec.kv_path).await {
                                Ok(res) => println!(
                                    "[OK]   Vault sync '{}' ({}) v{} ({} key(s))",
                                    spec.alias,
                                    spec.kv_path,
                                    res.version,
                                    res.data.len()
                                ),
                                Err(e) => println!(
                                    "[WARN] Vault sync '{}' ({}) unreachable/failed: {}",
                                    spec.alias, spec.kv_path, e
                                ),
                            }
                        }
                    }
                    Err(e) => {
                        println!("[WARN] Vault connectivity/auth skipped or failed: {}", e);
                    }
                }
            });
        }
    } else {
        println!("[INFO] Vault integration not configured");
    }

    let now = now_unix_secs();
    for site in &cfg.sites {
        let label = site.hosts.join(", ");
        match &site.tls {
            None => println!("[INFO] Site [{}]: HTTP only (no tls block)", label),
            Some(TlsConfig::Static {
                cert_path,
                key_path,
            }) => {
                if cert_path.exists() && key_path.exists() {
                    match std::fs::read_to_string(cert_path)
                        .ok()
                        .and_then(|pem| parse_cert_not_after(&pem).ok())
                    {
                        Some(not_after) => {
                            let days = (not_after - now) as f64 / 86400.0;
                            println!(
                                "[OK]   Site [{}]: static TLS valid ({:.1} days remaining)",
                                label, days
                            );
                        }
                        None => println!(
                            "[WARN] Site [{}]: static TLS files exist but expiry parse failed",
                            label
                        ),
                    }
                } else {
                    println!(
                        "[WARN] Site [{}]: static TLS file missing (cert={}, key={})",
                        label,
                        cert_path.display(),
                        key_path.display()
                    );
                }
            }
            Some(TlsConfig::Acme(acme)) => match LocalCertStorage::new(&acme.storage_dir) {
                Ok(storage) => match storage.load_cert(&site.hosts) {
                    Ok(Some(bundle)) => {
                        let days = (bundle.not_after_unix - now) as f64 / 86400.0;
                        println!(
                            "[OK]   Site [{}]: ACME cached cert valid ({:.1} days remaining, renew_before={}d)",
                            label, days, acme.renew_before_days
                        );
                    }
                    Ok(None) => println!(
                        "[INFO] Site [{}]: ACME configured (no local cached cert yet; storage={})",
                        label,
                        acme.storage_dir.display()
                    ),
                    Err(e) => println!(
                        "[WARN] Site [{}]: failed reading cached ACME cert: {}",
                        label, e
                    ),
                },
                Err(e) => println!(
                    "[WARN] Site [{}]: ACME storage_dir '{}' error: {}",
                    label,
                    acme.storage_dir.display(),
                    e
                ),
            },
        }
    }
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Version => {
            println!("fluxgate v{}", env!("CARGO_PKG_VERSION"));
        }
        Commands::Validate {
            config,
            offline,
            strict_gitops,
        } => {
            init_logging("WARN");
            let opts = ValidateOptions {
                offline,
                strict_gitops,
            };
            match load_config_with_options(&config, opts) {
                Ok(cfg) => {
                    let hash = compute_config_hash(&cfg);
                    println!(
                        "Configuration valid: {} site block(s), grace_period={}s, log_level={}, sha256={}",
                        cfg.sites.len(),
                        cfg.global.grace_period_secs,
                        cfg.global.log_level,
                        &hash[..12.min(hash.len())]
                    );
                    if let Some(v) = &cfg.global.vault {
                        println!(
                            "  vault: addr={}, auth={:?}, syncs={}",
                            v.addr,
                            v.auth,
                            v.syncs.len()
                        );
                    }
                    for (idx, site) in cfg.sites.iter().enumerate() {
                        println!(
                            "  [{}] hosts={} tls={}",
                            idx + 1,
                            site.hosts.join(", "),
                            describe_tls(site.tls.as_ref())
                        );
                    }
                }
                Err(e) => {
                    eprintln!("Validation failed: {}", e);
                    process::exit(1);
                }
            }
        }
        Commands::Reload { pid_file } => {
            run_reload_command(&pid_file);
        }
        Commands::Doctor { config } => {
            run_doctor_command(&config);
        }
        Commands::Run { config } => {
            let cfg = match load_config(&config) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("Failed to load configuration {}: {}", config.display(), e);
                    process::exit(1);
                }
            };

            init_logging(&cfg.global.log_level);
            tracing::info!(
                "Starting fluxgate v{} with {} site block(s)",
                env!("CARGO_PKG_VERSION"),
                cfg.sites.len()
            );

            let initial_hash = compute_config_hash(&cfg);
            let router = Arc::new(ArcSwap::from_pointee(CompiledRouter::compile(&cfg)));
            let cert_store = Arc::new(DynamicCertStore::new());
            let secret_store = Arc::new(SecretStore::new());

            let static_entries = collect_static_tls_entries(&cfg);
            let acme_sites = collect_acme_sites(&cfg);
            let https_enabled = !static_entries.is_empty() || !acme_sites.is_empty();

            let mut server_conf =
                ServerConf::new().expect("Failed to initialize Pingora ServerConf");
            server_conf.threads = std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(2);
            server_conf.grace_period_seconds = Some(cfg.global.grace_period_secs);
            server_conf.graceful_shutdown_timeout_seconds = Some(cfg.global.grace_period_secs);
            server_conf.pid_file = "/tmp/fluxgate.pid".to_string();
            server_conf.upgrade_sock = "/tmp/fluxgate_upgrade.sock".to_string();

            let mut server = Server::new_with_opt_and_conf(None, server_conf);
            server.bootstrap();

            let metrics_registry = cfg
                .global
                .metrics_addr
                .as_ref()
                .map(|_| Arc::new(MetricsRegistry::new()));

            if let Some(m) = &metrics_registry {
                m.record_config_reload(true, &initial_hash, now_unix_secs());
            }

            if let Err(e) =
                sync_static_certs_to_store(&cfg, &cert_store, metrics_registry.as_deref())
            {
                eprintln!("TLS configuration error: {}", e);
                process::exit(1);
            }

            if let (Some(addr), Some(reg)) = (&cfg.global.metrics_addr, &metrics_registry) {
                let svc = background_service(
                    "Fluxgate Metrics",
                    MetricsService {
                        addr: addr.clone(),
                        registry: reg.clone(),
                    },
                );
                server.add_service(svc);
            }

            let vault_client = if let Some(vault_cfg) = &cfg.global.vault {
                match VaultClient::new_unauthenticated(vault_cfg) {
                    Ok(client) => {
                        let client_arc = Arc::new(client);
                        let vault_svc = background_service(
                            "Fluxgate Vault Sync",
                            VaultSyncService {
                                client: client_arc.clone(),
                                syncs: vault_cfg.syncs.clone(),
                                store: secret_store.clone(),
                                metrics: metrics_registry.clone(),
                            },
                        );
                        server.add_service(vault_svc);
                        Some(client_arc)
                    }
                    Err(e) => {
                        eprintln!("Failed to initialize Vault client: {}", e);
                        process::exit(1);
                    }
                }
            } else {
                None
            };

            if !acme_sites.is_empty() {
                let node_id = resolve_node_id();
                let acme_svc = background_service(
                    "Fluxgate ACME Renewal",
                    CertRenewalService::new(
                        acme_sites,
                        secret_store.clone(),
                        vault_client,
                        cert_store.clone(),
                        metrics_registry.clone(),
                        node_id,
                    ),
                );
                server.add_service(acme_svc);
            }

            let reload_svc = background_service(
                "Fluxgate SIGHUP Reloader",
                ConfigReloadService {
                    config_path: config.clone(),
                    router: router.clone(),
                    cert_store: cert_store.clone(),
                    metrics: metrics_registry.clone(),
                },
            );
            server.add_service(reload_svc);

            let proxy = FluxgateProxy::new(router, https_enabled, metrics_registry);
            let mut service =
                http_proxy_service_with_name(&server.configuration, proxy, "Fluxgate HTTP Proxy");

            // Bind HTTP port
            let mut v6_only_opt = TcpSocketOptions::default();
            v6_only_opt.ipv6_only = Some(true);

            let http_v4 = format!("0.0.0.0:{}", cfg.global.http_port);
            let http_v6 = format!("[::]:{}", cfg.global.http_port);
            service.add_tcp(&http_v4);
            service.add_tcp_with_settings(&http_v6, v6_only_opt.clone());
            tracing::info!("Listening HTTP on {} and {}", http_v4, http_v6);

            // Bind HTTPS port if TLS is configured
            if https_enabled {
                let tls_v4 = build_dynamic_tls_settings(cert_store.clone()).unwrap_or_else(|e| {
                    eprintln!("TLS configuration error: {}", e);
                    process::exit(1);
                });
                let tls_v6 = build_dynamic_tls_settings(cert_store).unwrap_or_else(|e| {
                    eprintln!("TLS configuration error: {}", e);
                    process::exit(1);
                });

                let https_v4 = format!("0.0.0.0:{}", cfg.global.https_port);
                let https_v6 = format!("[::]:{}", cfg.global.https_port);
                service.add_tls_with_settings(&https_v4, None, tls_v4);
                service.add_tls_with_settings(&https_v6, Some(v6_only_opt), tls_v6);
                tracing::info!("Listening HTTPS (H2/H1.1) on {} and {}", https_v4, https_v6);
            }

            server.add_service(service);
            server.run_forever();
        }
    }
}
