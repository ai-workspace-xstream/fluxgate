use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine as _;
use fluxgate::acme::{
    parse_cert_not_after, san_group_key, AliDnsProvider, CertBundle, CloudflareDnsProvider,
    DnsProvider, LocalCertStorage, VaultSharedCertStorage,
};
use fluxgate::config::ast::VaultAuthMode;
use fluxgate::tls::DynamicCertStore;
use fluxgate::vault::VaultClient;
use hmac::{Hmac, Mac};
use instant_acme::AccountCredentials;
use rcgen::{generate_simple_self_signed, CertifiedKey};
use serde_json::json;
use sha1::Sha1;
use std::collections::{BTreeMap, HashMap};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
use tempfile::tempdir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Barrier;
use zeroize::Zeroizing;

#[derive(Debug, Clone)]
struct RecordedHttpRequest {
    method: String,
    target: String,
    headers: HashMap<String, String>,
    body: String,
}

async fn read_http_request(stream: &mut TcpStream) -> std::io::Result<RecordedHttpRequest> {
    let mut buf = Vec::with_capacity(4096);
    let mut tmp = [0u8; 2048];

    let header_end = loop {
        let n = stream.read(&mut tmp).await?;
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "EOF before HTTP headers completed",
            ));
        }
        buf.extend_from_slice(&tmp[..n]);
        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break pos;
        }
    };

    let header_bytes = &buf[..header_end];
    let header_str = String::from_utf8_lossy(header_bytes);
    let mut lines = header_str.split("\r\n");
    let request_line = lines.next().unwrap_or("");
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("").to_string();
    let target = parts.next().unwrap_or("/").to_string();

    let mut headers = HashMap::new();
    let mut content_length = 0usize;
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            let key = k.trim().to_ascii_lowercase();
            let val = v.trim().to_string();
            if key == "content-length" {
                content_length = val.parse::<usize>().unwrap_or(0);
            }
            headers.insert(key, val);
        }
    }

    let body_start = header_end + 4;
    while buf.len() < body_start + content_length {
        let n = stream.read(&mut tmp).await?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&tmp[..n]);
    }

    let body_end = (body_start + content_length).min(buf.len());
    let body = String::from_utf8_lossy(&buf[body_start..body_end]).to_string();

    Ok(RecordedHttpRequest {
        method,
        target,
        headers,
        body,
    })
}

async fn write_http_response(
    stream: &mut TcpStream,
    status_code: u16,
    reason: &str,
    body: &str,
) -> std::io::Result<()> {
    let resp = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        status_code,
        reason,
        body.len(),
        body
    );
    stream.write_all(resp.as_bytes()).await?;
    stream.flush().await?;
    let _ = stream.shutdown().await;
    Ok(())
}

#[test]
fn test_cloudflare_extract_apex_candidates() {
    assert_eq!(
        CloudflareDnsProvider::extract_apex_candidates("*.svc.plus"),
        vec!["svc.plus".to_string()]
    );
    assert_eq!(
        CloudflareDnsProvider::extract_apex_candidates("_acme-challenge.sub.svc.plus"),
        vec!["sub.svc.plus".to_string(), "svc.plus".to_string()]
    );
    assert_eq!(
        CloudflareDnsProvider::extract_apex_candidates("a.b.svc.plus."),
        vec![
            "a.b.svc.plus".to_string(),
            "b.svc.plus".to_string(),
            "svc.plus".to_string(),
        ]
    );
}

#[tokio::test]
async fn test_cloudflare_dns_present_and_cleanup() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let recorded = Arc::new(Mutex::new(Vec::<RecordedHttpRequest>::new()));
    let recorded_srv = recorded.clone();

    let server_handle = tokio::spawn(async move {
        for _ in 0..4 {
            let (mut stream, _) = listener.accept().await.unwrap();
            let req = read_http_request(&mut stream).await.unwrap();
            assert_eq!(
                req.headers.get("authorization").map(String::as_str),
                Some("Bearer cf-secret-token")
            );

            let (status, reason, body) = match (req.method.as_str(), req.target.as_str()) {
                ("GET", "/zones?name=sub.svc.plus&status=active") => {
                    (200, "OK", r#"{"success":true,"errors":[],"result":[]}"#)
                }
                ("GET", "/zones?name=svc.plus&status=active") => (
                    200,
                    "OK",
                    r#"{"success":true,"errors":[],"result":[{"id":"zone-cf-001","name":"svc.plus"}]}"#,
                ),
                ("POST", "/zones/zone-cf-001/dns_records") => {
                    let payload: serde_json::Value = serde_json::from_str(&req.body).unwrap();
                    assert_eq!(payload["type"], "TXT");
                    assert_eq!(payload["name"], "_acme-challenge.sub.svc.plus");
                    assert_eq!(payload["content"], "cf-txt-token");
                    assert_eq!(payload["ttl"], 120);
                    (
                        200,
                        "OK",
                        r#"{"success":true,"errors":[],"result":{"id":"rec-cf-999"}}"#,
                    )
                }
                ("DELETE", "/zones/zone-cf-001/dns_records/rec-cf-999") => (
                    200,
                    "OK",
                    r#"{"success":true,"errors":[],"result":{"id":"rec-cf-999"}}"#,
                ),
                other => panic!("Unexpected Cloudflare request: {:?}", other),
            };

            {
                let mut guard = recorded_srv.lock().unwrap();
                guard.push(req);
            }
            write_http_response(&mut stream, status, reason, body)
                .await
                .unwrap();
        }
    });

    let provider = CloudflareDnsProvider::new(Zeroizing::new("cf-secret-token".to_string()))
        .unwrap()
        .with_base_url(format!("http://{}", addr));

    let guard = provider
        .present(
            "sub.svc.plus",
            "_acme-challenge.sub.svc.plus",
            "cf-txt-token",
        )
        .await
        .unwrap();

    assert_eq!(guard.zone_id, "zone-cf-001");
    assert_eq!(guard.record_id, "rec-cf-999");
    assert_eq!(guard.fqdn, "_acme-challenge.sub.svc.plus");
    assert_eq!(guard.value, "cf-txt-token");

    provider.cleanup(&guard).await.unwrap();
    server_handle.await.unwrap();

    let reqs = recorded.lock().unwrap();
    assert_eq!(reqs.len(), 4);
    assert_eq!(reqs[0].method, "GET");
    assert_eq!(reqs[1].method, "GET");
    assert_eq!(reqs[2].method, "POST");
    assert_eq!(reqs[3].method, "DELETE");
}

#[test]
fn test_alidns_canonical_hmac_sha1_signature() {
    let mut params = BTreeMap::new();
    params.insert("Action".to_string(), "AddDomainRecord".to_string());
    params.insert("Format".to_string(), "JSON".to_string());
    params.insert("Version".to_string(), "2015-01-09".to_string());
    params.insert("AccessKeyId".to_string(), "testid".to_string());
    params.insert("SignatureMethod".to_string(), "HMAC-SHA1".to_string());
    params.insert("Timestamp".to_string(), "2026-11-22T08:00:00Z".to_string());
    params.insert("SignatureVersion".to_string(), "1.0".to_string());
    params.insert("SignatureNonce".to_string(), "nonce-123".to_string());
    params.insert("DomainName".to_string(), "svc.plus".to_string());
    // Include special characters to verify RFC 3986 Aliyun POP encoding (%20, %2A, ~).
    params.insert("Value".to_string(), "val with space * ~".to_string());
    // Existing Signature key must be ignored during signing.
    params.insert("Signature".to_string(), "should-be-ignored".to_string());

    let got = AliDnsProvider::sign_rpc_params("GET", &params, "testsecret");

    // Independently compute canonical StringToSign according to Aliyun POP v1.0 spec.
    let expected_canonical_query = [
        "AccessKeyId=testid",
        "Action=AddDomainRecord",
        "DomainName=svc.plus",
        "Format=JSON",
        "SignatureMethod=HMAC-SHA1",
        "SignatureNonce=nonce-123",
        "SignatureVersion=1.0",
        "Timestamp=2026-11-22T08%3A00%3A00Z",
        "Value=val%20with%20space%20%2A%20~",
        "Version=2015-01-09",
    ]
    .join("&");

    let mut encoded_query = String::new();
    for b in expected_canonical_query.as_bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            encoded_query.push(*b as char);
        } else {
            encoded_query.push_str(&format!("%{:02X}", b));
        }
    }
    let string_to_sign = format!("GET&%2F&{}", encoded_query);

    let mut mac = Hmac::<Sha1>::new_from_slice(b"testsecret&").unwrap();
    mac.update(string_to_sign.as_bytes());
    let expected = BASE64_STANDARD.encode(mac.finalize().into_bytes());

    assert_eq!(got, expected);
}

#[tokio::test]
async fn test_alidns_present_and_cleanup_mock_http() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let actions = Arc::new(Mutex::new(Vec::<String>::new()));
    let actions_srv = actions.clone();

    let server_handle = tokio::spawn(async move {
        for _ in 0..3 {
            let (mut stream, _) = listener.accept().await.unwrap();
            let req = read_http_request(&mut stream).await.unwrap();
            assert_eq!(req.method, "GET");

            let query = req.target.split_once('?').map(|(_, q)| q).unwrap_or("");
            let mut params = BTreeMap::new();
            for (k, v) in url::form_urlencoded::parse(query.as_bytes()) {
                params.insert(k.into_owned(), v.into_owned());
            }

            let provided_sig = params
                .remove("Signature")
                .expect("Signature query param must be present");
            let expected_sig = AliDnsProvider::sign_rpc_params("GET", &params, "ali-key-secret");
            assert_eq!(provided_sig, expected_sig, "AliDNS signature mismatch");

            assert_eq!(params.get("Format").map(String::as_str), Some("JSON"));
            assert_eq!(
                params.get("Version").map(String::as_str),
                Some("2015-01-09")
            );
            assert_eq!(
                params.get("SignatureMethod").map(String::as_str),
                Some("HMAC-SHA1")
            );
            assert_eq!(
                params.get("SignatureVersion").map(String::as_str),
                Some("1.0")
            );
            assert_eq!(
                params.get("AccessKeyId").map(String::as_str),
                Some("ali-key-id")
            );

            let action = params.get("Action").cloned().unwrap_or_default();
            {
                let mut guard = actions_srv.lock().unwrap();
                guard.push(action.clone());
            }

            let body = match action.as_str() {
                "DescribeDomains" => {
                    r#"{"RequestId":"req-0","Domains":{"Domain":[{"DomainName":"svc.plus"}]}}"#
                }
                "AddDomainRecord" => {
                    assert_eq!(
                        params.get("DomainName").map(String::as_str),
                        Some("svc.plus")
                    );
                    assert_eq!(
                        params.get("RR").map(String::as_str),
                        Some("_acme-challenge.sub")
                    );
                    assert_eq!(params.get("Type").map(String::as_str), Some("TXT"));
                    assert_eq!(params.get("TTL").map(String::as_str), Some("600"));
                    assert_eq!(
                        params.get("Value").map(String::as_str),
                        Some("ali-txt-token")
                    );
                    r#"{"RequestId":"req-1","RecordId":"ali-rec-777"}"#
                }
                "DeleteDomainRecord" => {
                    assert_eq!(
                        params.get("RecordId").map(String::as_str),
                        Some("ali-rec-777")
                    );
                    r#"{"RequestId":"req-2"}"#
                }
                other => panic!("Unexpected AliDNS action: {}", other),
            };

            write_http_response(&mut stream, 200, "OK", body)
                .await
                .unwrap();
        }
    });

    let provider = AliDnsProvider::new(
        Zeroizing::new("ali-key-id".to_string()),
        Zeroizing::new("ali-key-secret".to_string()),
    )
    .unwrap()
    .with_endpoint(format!("http://{}", addr));

    let guard = provider
        .present(
            "sub.svc.plus",
            "_acme-challenge.sub.svc.plus",
            "ali-txt-token",
        )
        .await
        .unwrap();

    assert_eq!(guard.zone_id, "svc.plus");
    assert_eq!(guard.record_id, "ali-rec-777");
    assert_eq!(guard.fqdn, "_acme-challenge.sub.svc.plus");
    assert_eq!(guard.value, "ali-txt-token");

    provider.cleanup(&guard).await.unwrap();
    server_handle.await.unwrap();

    let recorded_actions = actions.lock().unwrap();
    assert_eq!(
        *recorded_actions,
        vec!["DescribeDomains", "AddDomainRecord", "DeleteDomainRecord"]
    );
}

#[test]
fn test_parse_cert_not_after_and_local_storage_permissions_and_roundtrip() {
    let domains = vec![
        "*.svc.plus".to_string(),
        "jp-xconnect-02.svc.plus".to_string(),
    ];
    let CertifiedKey { cert, key_pair } = generate_simple_self_signed(domains.clone()).unwrap();
    let cert_pem = cert.pem();
    let key_pem = Zeroizing::new(key_pair.serialize_pem());

    let now_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let not_after_unix = parse_cert_not_after(&cert_pem).unwrap();
    assert!(
        not_after_unix > now_unix + 3600,
        "Expected self-signed cert NotAfter ({}) to be well in the future (> {})",
        not_after_unix,
        now_unix + 3600
    );

    // Deterministic SAN group key regardless of input domain ordering.
    let key_a = san_group_key(&domains);
    let key_b = san_group_key(&[
        "jp-xconnect-02.svc.plus".to_string(),
        "*.svc.plus".to_string(),
    ]);
    assert_eq!(key_a, key_b);
    assert_eq!(key_a, "jp-xconnect-02.svc.plus__wildcard.svc.plus");

    let bundle = CertBundle {
        domains: domains.clone(),
        cert_pem: cert_pem.clone(),
        key_pem: key_pem.clone(),
        not_after_unix,
    };

    // Ensure redacted Debug never exposes private key material.
    let dbg = format!("{:?}", bundle);
    assert!(dbg.contains("[REDACTED]"));
    assert!(!dbg.contains("BEGIN PRIVATE KEY"));

    let dir = tempdir().unwrap();
    let certs_dir = dir.path().join("certs");
    let storage = LocalCertStorage::new(&certs_dir).unwrap();

    #[cfg(unix)]
    {
        let dir_mode = std::fs::metadata(&certs_dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(dir_mode, 0o700);
    }

    storage.save_cert(&bundle).unwrap();

    let crt_file = certs_dir.join(format!("{}.crt", key_a));
    let key_file = certs_dir.join(format!("{}.key", key_a));
    assert!(crt_file.exists());
    assert!(key_file.exists());

    #[cfg(unix)]
    {
        let key_mode = std::fs::metadata(&key_file).unwrap().permissions().mode() & 0o777;
        assert_eq!(key_mode, 0o600);
    }

    let reversed_domains = vec![
        "jp-xconnect-02.svc.plus".to_string(),
        "*.svc.plus".to_string(),
    ];
    let loaded = storage.load_cert(&reversed_domains).unwrap().unwrap();
    assert_eq!(loaded.cert_pem, cert_pem);
    assert_eq!(loaded.key_pem.as_str(), key_pem.as_str());
    assert_eq!(loaded.not_after_unix, not_after_unix);

    // Test ACME account credentials roundtrip and 0600 permissions.
    const SAMPLE_CREDS_JSON: &str = r#"{
        "id": "https://acme-staging-v02.api.letsencrypt.org/acme/acct/12345",
        "key_pkcs8": "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgJVWC_QzOTCS5vtsJp2IG-UDc8cdDfeoKtxSZxaznM-mhRANCAAQenCPoGgPFTdPJ7VLLKt56RxPlYT1wNXnHc54PEyBg3LxKaH0-sJkX0mL8LyPEdsfL_Oz4TxHkWLJGrXVtNhfH",
        "directory": "https://acme-staging-v02.api.letsencrypt.org/directory"
    }"#;
    let creds: AccountCredentials = serde_json::from_str(SAMPLE_CREDS_JSON).unwrap();
    storage.save_account_credentials(&creds).unwrap();

    #[cfg(unix)]
    {
        let acct_meta = std::fs::metadata(certs_dir.join("acme-account.json")).unwrap();
        let acct_mode = acct_meta.permissions().mode() & 0o777;
        assert_eq!(acct_mode, 0o600);
    }

    assert!(storage
        .load_account_credentials_for_ca("https://acme-staging-v02.api.letsencrypt.org/directory")
        .unwrap()
        .is_some());
    assert!(storage
        .load_account_credentials_for_ca("https://acme-v02.api.letsencrypt.org/directory")
        .unwrap()
        .is_none());
}

async fn spawn_mock_vault_kv2_server() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let store: Arc<Mutex<HashMap<String, (serde_json::Value, u64)>>> =
        Arc::new(Mutex::new(HashMap::new()));

    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            let store_conn = store.clone();
            tokio::spawn(async move {
                let Ok(req) = read_http_request(&mut stream).await else {
                    return;
                };
                if req.headers.get("x-vault-token").map(String::as_str) != Some("test-token") {
                    let _ = write_http_response(
                        &mut stream,
                        403,
                        "Forbidden",
                        r#"{"errors":["permission denied"]}"#,
                    )
                    .await;
                    return;
                }

                let key = req.target.trim_start_matches("/v1/").to_string();

                let (status, reason, body) = match req.method.as_str() {
                    "GET" => {
                        let guard = store_conn.lock().unwrap();
                        if let Some((val, ver)) = guard.get(&key) {
                            let body = json!({
                                "data": {
                                    "data": val,
                                    "metadata": { "version": ver }
                                }
                            })
                            .to_string();
                            (200, "OK", body)
                        } else {
                            (404, "Not Found", r#"{"errors":[]}"#.to_string())
                        }
                    }
                    "POST" => {
                        let parsed: serde_json::Value =
                            serde_json::from_str(&req.body).unwrap_or_default();
                        let requested_cas = parsed["options"]["cas"].as_u64().unwrap_or(u64::MAX);
                        let new_data = parsed["data"].clone();

                        let mut guard = store_conn.lock().unwrap();
                        let current_ver = guard.get(&key).map(|(_, v)| *v).unwrap_or(0);
                        if requested_cas != current_ver {
                            (
                                400,
                                "Bad Request",
                                r#"{"errors":["check-and-set parameter did not match the current version"]}"#
                                    .to_string(),
                            )
                        } else {
                            let next_ver = current_ver + 1;
                            guard.insert(key, (new_data, next_ver));
                            let body = json!({ "data": { "version": next_ver } }).to_string();
                            (200, "OK", body)
                        }
                    }
                    _ => (405, "Method Not Allowed", r#"{"errors":[]}"#.to_string()),
                };

                let _ = write_http_response(&mut stream, status, reason, &body).await;
            });
        }
    });

    format!("http://{}", addr)
}

#[tokio::test]
async fn test_vault_two_node_concurrent_cas_lock_and_cert_sharing() {
    let vault_addr = spawn_mock_vault_kv2_server().await;

    let client_a = VaultClient::new(&vault_addr, VaultAuthMode::Token, None, None).unwrap();
    client_a.set_static_token("test-token");
    let client_b = VaultClient::new(&vault_addr, VaultAuthMode::Token, None, None).unwrap();
    client_b.set_static_token("test-token");

    let node_a = Arc::new(VaultSharedCertStorage::new(
        Arc::new(client_a),
        "kv/data/prod/fluxgate/certs",
        "node-a",
    ));
    let node_b = Arc::new(VaultSharedCertStorage::new(
        Arc::new(client_b),
        "kv/data/prod/fluxgate/certs",
        "node-b",
    ));

    let domains = vec![
        "*.svc.plus".to_string(),
        "jp-xconnect-02.svc.plus".to_string(),
    ];

    // Test A: Concurrent CAS lock acquisition -> exactly one node wins.
    let barrier = Arc::new(Barrier::new(2));
    let a_task = {
        let storage = node_a.clone();
        let d = domains.clone();
        let b = barrier.clone();
        tokio::spawn(async move {
            b.wait().await;
            storage.try_acquire_renew_lock(&d, 300).await
        })
    };
    let b_task = {
        let storage = node_b.clone();
        let d = domains.clone();
        let b = barrier.clone();
        tokio::spawn(async move {
            b.wait().await;
            storage.try_acquire_renew_lock(&d, 300).await
        })
    };

    let res_a = a_task.await.unwrap().unwrap();
    let res_b = b_task.await.unwrap().unwrap();

    let (winner, winner_ver, loser) = match (res_a, res_b) {
        (Some(ver), None) => (node_a.clone(), ver, node_b.clone()),
        (None, Some(ver)) => (node_b.clone(), ver, node_a.clone()),
        other => panic!(
            "Expected exactly one CAS lock winner and one None, got {:?}",
            other
        ),
    };
    assert_eq!(winner_ver, 1);

    // While lease is active, loser cannot steal the lock.
    assert_eq!(
        loser.try_acquire_renew_lock(&domains, 300).await.unwrap(),
        None
    );

    // Test B: Winner issues & publishes cert bundle, follower loads it into DynamicCertStore.
    let CertifiedKey { cert, key_pair } = generate_simple_self_signed(domains.clone()).unwrap();
    let cert_pem = cert.pem();
    let key_pem = Zeroizing::new(key_pair.serialize_pem());
    let not_after_unix = parse_cert_not_after(&cert_pem).unwrap();

    let bundle = CertBundle {
        domains: domains.clone(),
        cert_pem: cert_pem.clone(),
        key_pem: key_pem.clone(),
        not_after_unix,
    };

    let published_ver = winner
        .publish_cert_and_release_lock(&domains, &bundle, winner_ver)
        .await
        .unwrap();
    assert_eq!(published_ver, 2);

    let (loaded, loaded_ver) = loser
        .load_shared_cert(&domains)
        .await
        .unwrap()
        .expect("follower must observe published cert bundle");
    assert_eq!(loaded_ver, 2);
    assert_eq!(loaded.domains, domains);
    assert_eq!(loaded.cert_pem, cert_pem);
    assert_eq!(loaded.key_pem.as_str(), key_pem.as_str());
    assert_eq!(loaded.not_after_unix, not_after_unix);

    let cert_store = DynamicCertStore::new();
    cert_store
        .upsert_pem(
            &loaded.domains,
            &loaded.cert_pem,
            loaded.key_pem.as_str(),
            loaded.not_after_unix,
        )
        .unwrap();
    assert!(cert_store.has_domain("jp-xconnect-02.svc.plus"));
    assert!(cert_store.has_domain("api.svc.plus"));
    assert_eq!(cert_store.get_expiry("api.svc.plus"), Some(not_after_unix));

    // After winner released lock, another node can acquire a lock on a subsequent renewal cycle.
    let next_lock = loser.try_acquire_renew_lock(&domains, 300).await.unwrap();
    assert_eq!(next_lock, Some(3));
}
