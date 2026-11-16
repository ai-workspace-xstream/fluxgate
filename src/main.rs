use clap::Parser as ClapParser;
use fluxgate::cli::{Cli, Commands};
use fluxgate::config::load_config;
use fluxgate::metrics::{MetricsRegistry, MetricsService};
use fluxgate::proxy::{CompiledRouter, FluxgateProxy};
use fluxgate::tls::build_tls_settings;
use pingora::listeners::TcpSocketOptions;
use pingora::prelude::*;
use pingora::proxy::http_proxy_service_with_name;
use pingora::server::configuration::ServerConf;
use pingora::services::background::background_service;
use std::process;
use std::sync::Arc;
use tracing_subscriber::EnvFilter;

fn init_logging(level: &str) {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(level.to_ascii_lowercase()));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .try_init();
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Version => {
            println!("fluxgate v{}", env!("CARGO_PKG_VERSION"));
        }
        Commands::Validate { config } => {
            init_logging("WARN");
            match load_config(&config) {
                Ok(cfg) => {
                    println!(
                        "Configuration valid: {} site block(s), grace_period={}s, log_level={}",
                        cfg.sites.len(),
                        cfg.global.grace_period_secs,
                        cfg.global.log_level
                    );
                    for (idx, site) in cfg.sites.iter().enumerate() {
                        println!(
                            "  [{}] hosts={} tls={}",
                            idx + 1,
                            site.hosts.join(", "),
                            site.tls
                                .as_ref()
                                .map(|t| t.cert_path.display().to_string())
                                .unwrap_or_else(|| "none".to_string())
                        );
                    }
                }
                Err(e) => {
                    eprintln!("Validation failed: {}", e);
                    process::exit(1);
                }
            }
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

            let router = Arc::new(CompiledRouter::compile(&cfg));
            let primary_tls = router.primary_tls().cloned();
            let https_enabled = primary_tls.is_some();

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
            if let Some(tls_cfg) = primary_tls {
                let tls_v4 = build_tls_settings(&tls_cfg).unwrap_or_else(|e| {
                    eprintln!("TLS configuration error: {}", e);
                    process::exit(1);
                });
                let tls_v6 = build_tls_settings(&tls_cfg).unwrap_or_else(|e| {
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
