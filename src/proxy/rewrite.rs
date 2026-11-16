use http::Uri;

/// Strip a `handle_path` prefix such as `/xray-exporter/xhttp/*` from `path`.
pub fn strip_path_prefix(path: &str, prefix_pattern: &str) -> String {
    let prefix = prefix_pattern.trim_end_matches('*').trim_end_matches('/');
    if prefix.is_empty() {
        return path.to_string();
    }
    if let Some(rest) = path.strip_prefix(prefix) {
        if rest.is_empty() {
            "/".to_string()
        } else if rest.starts_with('/') {
            rest.to_string()
        } else {
            format!("/{}", rest)
        }
    } else {
        path.to_string()
    }
}

/// Remove a specific query parameter key from a raw query string, preserving all others.
pub fn remove_query_param(query: &str, param_to_remove: &str) -> Option<String> {
    let kept: Vec<&str> = query
        .split('&')
        .filter(|part| {
            if part.is_empty() {
                return false;
            }
            let key = part.split('=').next().unwrap_or("");
            key != param_to_remove
        })
        .collect();

    if kept.is_empty() {
        None
    } else {
        Some(kept.join("&"))
    }
}

/// Build a new `http::Uri` with updated path and optional query string.
pub fn rebuild_uri(original: &Uri, new_path: &str, new_query: Option<&str>) -> Option<Uri> {
    let path_and_query = match new_query {
        Some(q) if !q.is_empty() => format!("{}?{}", new_path, q),
        _ => new_path.to_string(),
    };

    let mut parts = original.clone().into_parts();
    parts.path_and_query = path_and_query.parse().ok();
    Uri::from_parts(parts).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_strip_path_prefix() {
        assert_eq!(
            strip_path_prefix("/xray-exporter/xhttp/metrics", "/xray-exporter/xhttp/*"),
            "/metrics"
        );
        assert_eq!(
            strip_path_prefix("/xray-exporter/xhttp/", "/xray-exporter/xhttp/*"),
            "/"
        );
        assert_eq!(
            strip_path_prefix("/xray-exporter/tcp/healthz", "/xray-exporter/tcp/*"),
            "/healthz"
        );
    }

    #[test]
    fn test_remove_query_param() {
        assert_eq!(remove_query_param("x_padding=", "x_padding"), None);
        assert_eq!(
            remove_query_param("x_padding=123&foo=bar", "x_padding"),
            Some("foo=bar".to_string())
        );
        assert_eq!(
            remove_query_param("a=1&x_padding=abc&b=2", "x_padding"),
            Some("a=1&b=2".to_string())
        );
        assert_eq!(
            remove_query_param("a=1&x_padding=", "x_padding"),
            Some("a=1".to_string())
        );
        assert_eq!(
            remove_query_param("a=1&b=2", "x_padding"),
            Some("a=1&b=2".to_string())
        );
    }

    #[test]
    fn test_rebuild_uri() {
        let uri: Uri = "/split?x_padding=&foo=1".parse().unwrap();
        let cleaned = remove_query_param(uri.query().unwrap(), "x_padding");
        let new_uri = rebuild_uri(&uri, "/split/", cleaned.as_deref()).unwrap();
        assert_eq!(new_uri.path(), "/split/");
        assert_eq!(new_uri.query(), Some("foo=1"));

        let uri_only_padding: Uri = "/split?x_padding=".parse().unwrap();
        let cleaned2 = remove_query_param(uri_only_padding.query().unwrap(), "x_padding");
        let new_uri2 = rebuild_uri(&uri_only_padding, "/split/", cleaned2.as_deref()).unwrap();
        assert_eq!(new_uri2.to_string(), "/split/");
    }
}
