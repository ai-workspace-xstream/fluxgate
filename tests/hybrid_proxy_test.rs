use fluxgate::config::{
    load_config_with_options, HybridUpstreamRole, StickyKeySpec, UpstreamTarget, ValidateOptions,
};
use fluxgate::proxy::route::{CompiledRouter, RouteResolution};
use std::io::Write;
use std::path::Path;
use tempfile::NamedTempFile;

#[test]
fn test_k3s_hybrid_example_validates_strict_gitops() {
    let example_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("examples")
        .join("Fluxgatefile.k3s-hybrid.example");

    let cfg = load_config_with_options(
        &example_path,
        ValidateOptions {
            offline: true,
            strict_gitops: true,
        },
    )
    .expect("k3s hybrid example should pass --strict-gitops validation");

    assert_eq!(cfg.global.http_port, 8080);
    assert_eq!(cfg.global.metrics_addr.as_deref(), Some("0.0.0.0:9102"));
    assert_eq!(cfg.global.vault.as_ref().unwrap().syncs.len(), 1);
    assert_eq!(
        cfg.global.vault.as_ref().unwrap().syncs[0].kv_path,
        "kv/data/prod/serverless/cloudflare"
    );

    let router = CompiledRouter::compile(&cfg);

    // 1. Healthz route
    match router.resolve("accounts.svc.plus", &"/healthz".parse().unwrap()) {
        RouteResolution::Respond { status, body } => {
            assert_eq!(status, 200);
            assert_eq!(body, "ok");
        }
        other => panic!("expected Respond, got {:?}", other),
    }

    // 2. SSE pinned directly to in-cluster Go origin
    match router.resolve(
        "accounts.svc.plus",
        &"/api/agent-server/v1/users/events".parse().unwrap(),
    ) {
        RouteResolution::Proxy {
            upstream,
            rewrite_host,
            ..
        } => {
            assert_eq!(
                upstream,
                UpstreamTarget::Tcp(
                    "web-saas-xconnect-controller.web-saas-prod.svc.cluster.local:80".to_string()
                )
            );
            assert!(rewrite_host.is_none());
        }
        other => panic!("expected direct Go Proxy for SSE, got {:?}", other),
    }

    // 3. Dual-form route resolves to CompiledHybridPool with CF Worker + Go Fallback
    let pool = match router.resolve(
        "accounts.svc.plus",
        &"/api/agent-server/v1/users".parse().unwrap(),
    ) {
        RouteResolution::HybridProxy { pool, new_uri } => {
            assert!(new_uri.is_none());
            pool
        }
        other => panic!("expected HybridProxy, got {:?}", other),
    };

    assert_eq!(
        pool.sticky_key,
        Some(StickyKeySpec::Header("Authorization".to_string()))
    );
    assert_eq!(pool.upstreams.len(), 2);

    let cf = &pool.upstreams[0];
    assert_eq!(cf.name, "cf_worker");
    assert_eq!(cf.weight, 80);
    assert_eq!(cf.role, HybridUpstreamRole::Primary);
    assert_eq!(cf.connect_timeout_ms, 800);
    assert_eq!(cf.read_timeout_ms, 2000);
    assert_eq!(cf.daily_budget, Some(85_000));
    assert_eq!(
        cf.rewrite_host.as_deref(),
        Some("xconnect-controller-edge.manbuzhe2008.workers.dev")
    );
    assert_eq!(
        cf.target,
        UpstreamTarget::Https {
            addr: "xconnect-controller-edge.manbuzhe2008.workers.dev:443".to_string(),
            sni: "xconnect-controller-edge.manbuzhe2008.workers.dev".to_string(),
            rewrite_host: Some("xconnect-controller-edge.manbuzhe2008.workers.dev".to_string()),
        }
    );

    let go = &pool.upstreams[1];
    assert_eq!(go.name, "go_origin");
    assert_eq!(go.weight, 20);
    assert_eq!(go.role, HybridUpstreamRole::Fallback);

    // 4. Verify GitOps weighted round-robin 80/20 distribution
    let mut cf_hits = 0usize;
    let mut go_hits = 0usize;
    for _ in 0..100 {
        let sel = pool.select(None).unwrap();
        if sel.primary.name == "cf_worker" {
            cf_hits += 1;
            assert_eq!(sel.fallback.unwrap().name, "go_origin");
        } else {
            go_hits += 1;
        }
    }
    assert_eq!(cf_hits, 80);
    assert_eq!(go_hits, 20);
}

#[test]
fn test_strict_gitops_rejects_plaintext_auth_header_in_hybrid_proxy() {
    let bad_cfg = r#"
example.svc.plus {
    hybrid_proxy {
        upstream cf https://edge.example.workers.dev {
            weight 100
            header_up Authorization "Bearer secret-literal-token"
        }
    }
}
"#;
    let mut tmp = NamedTempFile::new().unwrap();
    tmp.write_all(bad_cfg.as_bytes()).unwrap();

    let err = load_config_with_options(
        tmp.path(),
        ValidateOptions {
            offline: true,
            strict_gitops: true,
        },
    )
    .expect_err("expected --strict-gitops to reject plaintext Authorization header_up");
    assert!(
        err.to_string().contains("--strict-gitops"),
        "unexpected error: {}",
        err
    );
}

#[test]
fn test_rejects_vault_ref_in_upstream_weight() {
    let bad_cfg = r#"
{
    vault {
        addr env(VAULT_ADDR)
        auth token
        sync cloudflare kv/data/prod/serverless/cloudflare 5m
    }
}

api.svc.plus {
    hybrid_proxy {
        upstream cf https://edge.example.workers.dev {
            weight {vault.cloudflare.cf_weight}
        }
        upstream go http://127.0.0.1:8080 {
            weight 20
            role fallback
        }
    }
}
"#;
    let mut tmp = NamedTempFile::new().unwrap();
    tmp.write_all(bad_cfg.as_bytes()).unwrap();

    let err = load_config_with_options(
        tmp.path(),
        ValidateOptions {
            offline: true,
            strict_gitops: true,
        },
    )
    .expect_err("weights are non-sensitive GitOps config and must not reference Vault KV");
    assert!(
        err.to_string().contains("Vault KV"),
        "unexpected error: {}",
        err
    );
}
