use fluxgate::config::{load_config, UpstreamTarget};
use fluxgate::proxy::route::RouteResolution;
use fluxgate::proxy::CompiledRouter;
use std::fs;
use std::path::PathBuf;
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
                h2c,
                flush_immediately,
                new_uri,
            } => {
                assert_eq!(
                    upstream,
                    UpstreamTarget::Uds(PathBuf::from("/dev/shm/xray.sock"))
                );
                assert!(h2c);
                assert!(flush_immediately);
                assert_eq!(new_uri.unwrap().to_string(), "/split/");
            }
            other => panic!("Expected UDS h2c proxy for {}, got {:?}", host, other),
        }
    }
}
