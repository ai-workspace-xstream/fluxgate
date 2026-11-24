use arc_swap::ArcSwap;
use fluxgate::config::{
    compute_config_hash, load_config, load_config_with_options, parse_secret_ref,
    DnsProviderConfig, SecretRef, TlsConfig, UpstreamTarget, ValidateOptions, VaultAuthMode,
    LETSENCRYPT_PROD_DIRECTORY, LETSENCRYPT_STAGING_DIRECTORY,
};
use fluxgate::proxy::route::RouteResolution;
use fluxgate::proxy::CompiledRouter;
use fluxgate::tls::{build_tls_settings, DynamicCertStore};
use pingora::tls::x509::X509;
use rcgen::{generate_simple_self_signed, CertifiedKey};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tempfile::tempdir;

#[test]
fn test_import_glob_and_deterministic_order() {
    let dir = tempdir().unwrap();
    let conf_d = dir.path().join("conf.d");
    fs::create_dir_all(&conf_d).unwrap();

    fs::write(
        conf_d.join("b.conf"),
        r#"
b.svc.plus {
    respond "Node B"
}
"#,
    )
    .unwrap();

    fs::write(
        conf_d.join("a.conf"),
        r#"
a.svc.plus {
    respond "Node A"
}
"#,
    )
    .unwrap();

    let main_file = dir.path().join("Fluxgatefile");
    fs::write(
        &main_file,
        r#"
{
    grace_period 15s
    metrics 127.0.0.1:9102
    log {
        level INFO
    }
}

import conf.d/*.conf
"#,
    )
    .unwrap();

    let cfg = load_config(&main_file).unwrap();
    assert_eq!(cfg.global.grace_period_secs, 15);
    assert_eq!(cfg.global.log_level, "INFO");
    assert_eq!(cfg.global.metrics_addr.as_deref(), Some("127.0.0.1:9102"));
    assert_eq!(cfg.sites.len(), 2);
    // Alphabetical deterministic sort: a.conf before b.conf
    assert_eq!(cfg.sites[0].hosts, vec!["a.svc.plus"]);
    assert_eq!(cfg.sites[1].hosts, vec!["b.svc.plus"]);
}

#[test]
fn test_circular_import_rejected() {
    let dir = tempdir().unwrap();
    let a = dir.path().join("a.conf");
    let b = dir.path().join("b.conf");

    fs::write(&a, format!("import {}\n", b.display())).unwrap();
    fs::write(&b, format!("import {}\n", a.display())).unwrap();

    let err = load_config(&a).unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("Circular") || msg.contains("import"),
        "Unexpected error: {}",
        msg
    );
}

#[test]
fn test_unknown_directive_rejected() {
    let dir = tempdir().unwrap();
    let main_file = dir.path().join("Fluxgatefile");
    fs::write(
        &main_file,
        r#"
jp-xconnect-01.svc.plus {
    unsupported_caddy_directive foo bar
    respond "ok"
}
"#,
    )
    .unwrap();

    let err = load_config(&main_file).unwrap_err();
    assert!(err.to_string().contains("unsupported_caddy_directive"));
}

#[test]
fn test_full_xconnect_equivalence() {
    let dir = tempdir().unwrap();
    let conf_d = dir.path().join("conf.d");
    fs::create_dir_all(&conf_d).unwrap();

    fs::write(
        conf_d.join("jp-xconnect.conf"),
        r#"
jp-xconnect-01.svc.plus jp-xconnect-02.svc.plus jp-xconnect.svc.plus tky-proxy.svc.plus {
    tls /etc/caddy/tls/agent-proxy.crt /etc/caddy/tls/agent-proxy.key

    handle_path /xray-exporter/xhttp/* {
        reverse_proxy 127.0.0.1:8080
    }

    handle_path /xray-exporter/tcp/* {
        reverse_proxy 127.0.0.1:8081
    }

    @xhttp {
        path /split /split/*
    }

    @xhttp_root path /split
    rewrite @xhttp_root /split/

    handle @xhttp {
        uri query -x_padding

        reverse_proxy unix//dev/shm/xray.sock {
            flush_interval -1

            transport http {
                versions h2c 2
            }
        }
    }

    respond "Agent Service Plus Node"
}
"#,
    )
    .unwrap();

    let main_file = dir.path().join("Fluxgatefile");
    fs::write(&main_file, "import conf.d/*.conf\n").unwrap();

    let cfg = load_config(&main_file).unwrap();
    let router = CompiledRouter::compile(&cfg);

    for host in [
        "jp-xconnect-01.svc.plus",
        "jp-xconnect-02.svc.plus",
        "jp-xconnect.svc.plus",
        "tky-proxy.svc.plus",
    ] {
        match router.resolve(host, &"/".parse().unwrap()) {
            RouteResolution::Respond { status, body } => {
                assert_eq!(status, 200);
                assert_eq!(body, "Agent Service Plus Node");
            }
            other => panic!("Expected static respond for {}, got {:?}", host, other),
        }

        match router.resolve(host, &"/split?x_padding=12345".parse().unwrap()) {
            RouteResolution::Proxy {
                upstream,
                flush_immediately,
                transport,
                new_uri,
            } => {
                assert_eq!(
                    upstream,
                    UpstreamTarget::Uds(PathBuf::from("/dev/shm/xray.sock"))
                );
                assert!(transport.h2c);
                assert_eq!(transport.h2_stream_window_size, 4 * 1024 * 1024);
                assert_eq!(transport.h2_connection_window_size, 16 * 1024 * 1024);
                assert_eq!(transport.h2_ping_interval_secs, 15);
                assert_eq!(transport.max_h2_streams, 256);
                assert_eq!(transport.read_timeout_secs, 3600);
                assert_eq!(transport.idle_timeout_secs, 3600);
                assert!(flush_immediately);
                assert_eq!(new_uri.unwrap().to_string(), "/split/");
            }
            other => panic!("Expected UDS h2c proxy for {}, got {:?}", host, other),
        }
    }
}

#[test]
fn test_unix_h2c_shorthand_and_metrics_block() {
    let dir = tempdir().unwrap();
    let main_file = dir.path().join("Fluxgatefile");
    fs::write(
        &main_file,
        r#"
{
    metrics
}

jp-xconnect-01.svc.plus {
    @xhttp {
        path /split /split/*
    }
    handle @xhttp {
        reverse_proxy unix+h2c//dev/shm/xray.sock
    }
    respond "XConnect Edge Agent"
}
"#,
    )
    .unwrap();

    let cfg = load_config(&main_file).unwrap();
    assert_eq!(cfg.global.metrics_addr.as_deref(), Some("127.0.0.1:9102"));
    let router = CompiledRouter::compile(&cfg);
    match router.resolve("jp-xconnect-01.svc.plus", &"/split".parse().unwrap()) {
        RouteResolution::Proxy {
            upstream,
            transport,
            new_uri,
            ..
        } => {
            assert_eq!(
                upstream,
                UpstreamTarget::Uds(PathBuf::from("/dev/shm/xray.sock"))
            );
            assert!(transport.h2c);
            assert_eq!(transport.h2_stream_window_size, 4 * 1024 * 1024);
            assert_eq!(transport.h2_connection_window_size, 16 * 1024 * 1024);
            assert_eq!(transport.h2_ping_interval_secs, 15);
            assert_eq!(transport.max_h2_streams, 256);
            assert!(new_uri.is_none());
        }
        other => panic!("Expected unix+h2c proxy, got {:?}", other),
    }
}

#[test]
fn test_vault_block_and_placeholder_parsing() {
    let dir = tempdir().unwrap();
    let main_file = dir.path().join("Fluxgatefile");
    fs::write(
        &main_file,
        r#"
{
    vault {
        addr env(VAULT_ADDR)
        namespace {env.VAULT_NAMESPACE}
        auth approle
        ca_cert /etc/fluxgate/vault-ca.pem
        sync dns kv/data/prod/fluxgate/dns 5m
        sync certs kv/data/prod/fluxgate/certs 1h
    }
}

*.svc.plus {
    tls {
        issuer acme {
            email ops@svc.plus
            ca letsencrypt-staging
        }
        dns cloudflare {vault.dns.cf_api_token}
        renew_before 30d
        storage vault kv/data/prod/fluxgate/certs
    }
    respond "ok"
}
"#,
    )
    .unwrap();

    let cfg = load_config(&main_file).unwrap();
    let vault = cfg.global.vault.as_ref().expect("expected vault config");
    assert_eq!(vault.addr, SecretRef::Env("VAULT_ADDR".to_string()));
    assert_eq!(
        vault.namespace,
        Some(SecretRef::Env("VAULT_NAMESPACE".to_string()))
    );
    assert_eq!(vault.auth, VaultAuthMode::AppRole);
    assert_eq!(
        vault.ca_cert.as_deref(),
        Some(Path::new("/etc/fluxgate/vault-ca.pem"))
    );
    assert_eq!(vault.syncs.len(), 2);
    assert_eq!(vault.syncs[0].alias, "dns");
    assert_eq!(vault.syncs[0].kv_path, "kv/data/prod/fluxgate/dns");
    assert_eq!(vault.syncs[0].interval_secs, 300);
    assert_eq!(vault.syncs[1].alias, "certs");
    assert_eq!(vault.syncs[1].interval_secs, 3600);

    match cfg.sites[0].tls.as_ref().unwrap() {
        TlsConfig::Acme(acme) => {
            assert_eq!(acme.email, "ops@svc.plus");
            assert_eq!(acme.ca_url, LETSENCRYPT_STAGING_DIRECTORY);
            assert_eq!(acme.renew_before_days, 30);
            assert_eq!(
                acme.vault_storage_path.as_deref(),
                Some("kv/data/prod/fluxgate/certs")
            );
            assert_eq!(
                acme.dns_provider,
                DnsProviderConfig::Cloudflare {
                    api_token: SecretRef::Vault {
                        alias: "dns".to_string(),
                        key: "cf_api_token".to_string(),
                    },
                }
            );
        }
        other => panic!("Expected TlsConfig::Acme, got {:?}", other),
    }

    assert_eq!(
        parse_secret_ref("{vault.dns.nested.key}"),
        SecretRef::Vault {
            alias: "dns".to_string(),
            key: "nested.key".to_string(),
        }
    );
    let redacted = format!("{:?}", SecretRef::Literal("super_secret_token".to_string()));
    assert!(!redacted.contains("super_secret_token"));
    assert!(redacted.contains("REDACTED"));
}

#[test]
fn test_acme_tls_alidns_and_config_hash() {
    let dir = tempdir().unwrap();
    let main_file = dir.path().join("Fluxgatefile");
    fs::write(
        &main_file,
        r#"
{
    vault {
        addr https://vault.svc.plus
        auth token
        sync dns kv/data/prod/fluxgate/alidns 30s
    }
}

cn.svc.plus {
    tls {
        issuer acme {
            email admin@svc.plus
            ca letsencrypt
        }
        dns alidns {vault.dns.ak} {vault.dns.sk}
        renew_before 48h
        storage_dir /tmp/fluxgate-acme-test
    }
    respond "cn-edge"
}
"#,
    )
    .unwrap();

    let cfg = load_config_with_options(
        &main_file,
        ValidateOptions {
            offline: true,
            strict_gitops: true,
        },
    )
    .unwrap();

    let vault = cfg.global.vault.as_ref().unwrap();
    assert_eq!(vault.auth, VaultAuthMode::Token);
    assert_eq!(vault.syncs[0].interval_secs, 30);

    match cfg.sites[0].tls.as_ref().unwrap() {
        TlsConfig::Acme(acme) => {
            assert_eq!(acme.ca_url, LETSENCRYPT_PROD_DIRECTORY);
            assert_eq!(acme.renew_before_days, 2);
            assert_eq!(acme.storage_dir, PathBuf::from("/tmp/fluxgate-acme-test"));
            assert_eq!(
                acme.dns_provider,
                DnsProviderConfig::AliDns {
                    access_key_id: SecretRef::Vault {
                        alias: "dns".to_string(),
                        key: "ak".to_string(),
                    },
                    access_key_secret: SecretRef::Vault {
                        alias: "dns".to_string(),
                        key: "sk".to_string(),
                    },
                }
            );
        }
        other => panic!("Expected TlsConfig::Acme, got {:?}", other),
    }

    let hash_a = compute_config_hash(&cfg);
    let hash_b = compute_config_hash(&cfg);
    assert_eq!(hash_a.len(), 64);
    assert_eq!(hash_a, hash_b);
}

#[test]
fn test_validation_errors_and_strict_gitops() {
    let dir = tempdir().unwrap();

    // 1. Unknown Vault alias
    let unknown_alias_file = dir.path().join("unknown_alias.conf");
    fs::write(
        &unknown_alias_file,
        r#"
{
    vault {
        addr env(VAULT_ADDR)
        sync dns kv/data/prod/fluxgate/dns 5m
    }
}

a.svc.plus {
    tls {
        issuer acme {
            email ops@svc.plus
        }
        dns cloudflare {vault.missing.cf_api_token}
    }
    respond "ok"
}
"#,
    )
    .unwrap();
    let err = load_config(&unknown_alias_file).unwrap_err();
    assert!(err.to_string().contains("missing"), "got: {}", err);

    // 2. Invalid kv/data/... path
    let bad_kv_file = dir.path().join("bad_kv.conf");
    fs::write(
        &bad_kv_file,
        r#"
{
    vault {
        sync dns kv/prod/not_v2 5m
    }
}

a.svc.plus {
    respond "ok"
}
"#,
    )
    .unwrap();
    let err = load_config(&bad_kv_file).unwrap_err();
    assert!(err.to_string().contains("kv/data/"), "got: {}", err);

    // 3. --strict-gitops rejects plaintext token in dns cloudflare
    let raw_token_file = dir.path().join("raw_token.conf");
    fs::write(
        &raw_token_file,
        r#"
a.svc.plus {
    tls {
        issuer acme {
            email ops@svc.plus
            ca letsencrypt-staging
        }
        dns cloudflare raw_token_123
    }
    respond "ok"
}
"#,
    )
    .unwrap();
    assert!(load_config(&raw_token_file).is_ok());
    let err = load_config_with_options(
        &raw_token_file,
        ValidateOptions {
            offline: true,
            strict_gitops: true,
        },
    )
    .unwrap_err();
    assert!(err.to_string().contains("strict-gitops"), "got: {}", err);

    // 4. --strict-gitops allows {vault.dns.cf_api_token}
    let gitops_ok_file = dir.path().join("gitops_ok.conf");
    fs::write(
        &gitops_ok_file,
        r#"
{
    vault {
        addr https://vault.svc.plus
        sync dns kv/data/prod/fluxgate/dns 5m
    }
}

a.svc.plus {
    tls {
        issuer acme {
            email ops@svc.plus
            ca letsencrypt-staging
        }
        dns cloudflare {vault.dns.cf_api_token}
    }
    respond "ok"
}
"#,
    )
    .unwrap();
    assert!(load_config_with_options(
        &gitops_ok_file,
        ValidateOptions {
            offline: true,
            strict_gitops: true,
        },
    )
    .is_ok());

    // 5. Unrecognized sub-directives in vault {} and tls {} return ConfigSyntax errors
    let bad_vault_dir = dir.path().join("bad_vault_dir.conf");
    fs::write(
        &bad_vault_dir,
        r#"
{
    vault {
        unknown_vault_option foo
    }
}
a.svc.plus {
    respond "ok"
}
"#,
    )
    .unwrap();
    let err = load_config(&bad_vault_dir).unwrap_err();
    assert!(
        err.to_string().contains("unknown_vault_option"),
        "got: {}",
        err
    );

    let bad_tls_dir = dir.path().join("bad_tls_dir.conf");
    fs::write(
        &bad_tls_dir,
        r#"
a.svc.plus {
    tls {
        unknown_tls_option bar
    }
    respond "ok"
}
"#,
    )
    .unwrap();
    let err = load_config(&bad_tls_dir).unwrap_err();
    assert!(
        err.to_string().contains("unknown_tls_option"),
        "got: {}",
        err
    );

    // build_tls_settings rejects ACME config and directs caller to dynamic TLS
    let acme_cfg = load_config(&gitops_ok_file).unwrap();
    let tls_err = match build_tls_settings(acme_cfg.sites[0].tls.as_ref().unwrap()) {
        Ok(_) => panic!("Expected ACME TLS config to fail build_tls_settings"),
        Err(e) => e,
    };
    assert!(tls_err.to_string().contains("build_dynamic_tls_settings"));
}

#[test]
fn test_arc_swap_router_hot_reload() {
    let dir = tempdir().unwrap();
    let conf = dir.path().join("Fluxgatefile");

    fs::write(
        &conf,
        r#"
a.svc.plus {
    respond "v1"
}
"#,
    )
    .unwrap();
    let cfg_v1 = load_config(&conf).unwrap();
    let router = Arc::new(ArcSwap::from_pointee(CompiledRouter::compile(&cfg_v1)));

    let old_guard = router.load();
    match old_guard.resolve("a.svc.plus", &"/".parse().unwrap()) {
        RouteResolution::Respond { body, .. } => assert_eq!(body, "v1"),
        other => panic!("Expected v1, got {:?}", other),
    }

    fs::write(
        &conf,
        r#"
a.svc.plus {
    respond "v2"
}
"#,
    )
    .unwrap();
    let cfg_v2 = load_config(&conf).unwrap();
    router.store(Arc::new(CompiledRouter::compile(&cfg_v2)));

    match router.load().resolve("a.svc.plus", &"/".parse().unwrap()) {
        RouteResolution::Respond { body, .. } => assert_eq!(body, "v2"),
        other => panic!("Expected v2, got {:?}", other),
    }
    // Existing guard from before swap continues seeing v1 safely
    match old_guard.resolve("a.svc.plus", &"/".parse().unwrap()) {
        RouteResolution::Respond { body, .. } => assert_eq!(body, "v1"),
        other => panic!("Expected v1 on old guard, got {:?}", other),
    }
}

#[test]
fn test_dynamic_cert_store_sni_and_hot_replacement() {
    let store = DynamicCertStore::new();
    let domains = vec![
        "*.svc.plus".to_string(),
        "jp-xconnect-02.svc.plus".to_string(),
    ];

    let CertifiedKey {
        cert: cert1,
        key_pair: key1,
    } = generate_simple_self_signed(domains.clone()).unwrap();
    let cert1_pem = cert1.pem();
    let key1_pem = key1.serialize_pem();

    store
        .upsert_pem(&domains, &cert1_pem, &key1_pem, 0)
        .unwrap();

    assert_eq!(store.domain_count(), 2);
    assert!(store.has_domain("jp-xconnect-02.svc.plus"));
    assert!(store.has_domain("ph-xconnect-gateway-01.svc.plus"));
    assert!(!store.has_domain("a.b.svc.plus"));
    assert!(!store.has_domain("other.example.com"));
    assert!(!store.has_domain(""));

    assert!(store.lookup_sni("jp-xconnect-02.svc.plus").is_some());
    assert!(store.lookup_sni("JP-XCONNECT-02.SVC.PLUS").is_some());
    assert!(store.lookup_sni("*.svc.plus").is_some());
    assert!(store
        .lookup_sni("ph-xconnect-gateway-01.svc.plus")
        .is_some());
    assert!(store.lookup_sni("a.b.svc.plus").is_none());
    assert!(store.lookup_sni("other.example.com").is_none());
    assert!(store.lookup_sni("").is_some());

    let (before_leaf, _, _) = store.lookup_sni("ph-xconnect-gateway-01.svc.plus").unwrap();
    let before_der = before_leaf.to_der().unwrap();

    // Hot replace with newly issued certificate
    let CertifiedKey {
        cert: cert2,
        key_pair: key2,
    } = generate_simple_self_signed(domains.clone()).unwrap();
    let cert2_pem = cert2.pem();
    let key2_pem = key2.serialize_pem();
    let expected_der = X509::from_pem(cert2_pem.as_bytes())
        .unwrap()
        .to_der()
        .unwrap();

    store
        .upsert_pem(&domains, &cert2_pem, &key2_pem, 1_950_000_000)
        .unwrap();

    let (after_leaf, _, _) = store.lookup_sni("ph-xconnect-gateway-01.svc.plus").unwrap();
    let after_der = after_leaf.to_der().unwrap();
    assert_ne!(before_der, after_der);
    assert_eq!(after_der, expected_der);
    assert_eq!(
        store.get_expiry("ph-xconnect-gateway-01.svc.plus"),
        Some(1_950_000_000)
    );

    // Reloading static certs preserves ACME certs
    let dir = tempdir().unwrap();
    let static_cert_path = dir.path().join("static.crt");
    let static_key_path = dir.path().join("static.key");
    let CertifiedKey {
        cert: static_cert,
        key_pair: static_key,
    } = generate_simple_self_signed(vec!["static.example.org".to_string()]).unwrap();
    fs::write(&static_cert_path, static_cert.pem()).unwrap();
    fs::write(&static_key_path, static_key.serialize_pem()).unwrap();

    store
        .clear_and_reload_static(vec![(
            vec!["static.example.org".to_string()],
            static_cert_path,
            static_key_path,
        )])
        .unwrap();

    assert!(store.has_domain("static.example.org"));
    assert!(store.has_domain("ph-xconnect-gateway-01.svc.plus"));
}

#[test]
fn test_transport_http_custom_tuning_and_validation() {
    let dir = tempdir().unwrap();
    let main_file = dir.path().join("Fluxgatefile");
    fs::write(
        &main_file,
        r#"
jp-xconnect-02.svc.plus {
    @xhttp {
        path /split /split/*
    }
    handle @xhttp {
        reverse_proxy unix//dev/shm/xray.sock {
            flush_interval -1
            transport http {
                versions h2c 2
                h2_stream_window_size 8MiB
                h2_connection_window_size 32m
                h2_ping_interval 10s
                max_h2_streams 512
                read_timeout 7200s
                idle_timeout_secs 1800
            }
        }
    }
}
"#,
    )
    .unwrap();

    let cfg = load_config(&main_file).unwrap();
    let router = CompiledRouter::compile(&cfg);
    match router.resolve("jp-xconnect-02.svc.plus", &"/split/abc".parse().unwrap()) {
        RouteResolution::Proxy {
            transport,
            flush_immediately,
            ..
        } => {
            assert!(transport.h2c);
            assert!(flush_immediately);
            assert_eq!(transport.h2_stream_window_size, 8 * 1024 * 1024);
            assert_eq!(transport.h2_connection_window_size, 32 * 1024 * 1024);
            assert_eq!(transport.h2_ping_interval_secs, 10);
            assert_eq!(transport.max_h2_streams, 512);
            assert_eq!(transport.read_timeout_secs, 7200);
            assert_eq!(transport.idle_timeout_secs, 1800);
        }
        other => panic!("Expected Proxy, got {:?}", other),
    }

    // Invalid bounds (zero stream window / zero max_h2_streams / unknown directive)
    let bad_zero = dir.path().join("BadZeroFluxgatefile");
    fs::write(
        &bad_zero,
        r#"
jp-xconnect-02.svc.plus {
    reverse_proxy unix//dev/shm/xray.sock {
        transport http {
            versions h2c 2
            max_h2_streams 0
        }
    }
}
"#,
    )
    .unwrap();
    assert!(load_config(&bad_zero).is_err());

    let bad_unknown = dir.path().join("BadUnknownFluxgatefile");
    fs::write(
        &bad_unknown,
        r#"
jp-xconnect-02.svc.plus {
    reverse_proxy unix//dev/shm/xray.sock {
        transport http {
            unknown_knob 123
        }
    }
}
"#,
    )
    .unwrap();
    assert!(load_config(&bad_unknown).is_err());
}
