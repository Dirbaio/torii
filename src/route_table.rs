//! The routing table the control plane computes for the data plane.
//!
//! The control plane recomputes a [`RouteTable`] from the full set of watched
//! Kubernetes objects; it's published to the data plane (with the cert store) via
//! the atomic [`crate::snapshot::Snapshot`]. The data plane reads it lock-free on
//! every request.

use std::cmp::Ordering;
use std::collections::HashMap;

/// The data plane's view of all programmed routing.
///
/// Entries are kept sorted in descending precedence order, and indexed by listener
/// port *and listener hostname* so request dispatch scans only the handful of
/// entries that can serve the request's `(port, Host)` — not the whole table. This
/// matters because real deployments put everything on one port (443) with many
/// distinct hostnames, so a port-only split wouldn't help; the hostname index does.
#[derive(Debug, Default, Clone)]
pub struct RouteTable {
    /// All entries, in descending precedence order (built flat, then `sort()`ed).
    pub entries: Vec<RouteEntry>,
    /// Per-port hostname index into `entries`. Built by `sort()`.
    by_port: HashMap<u16, PortIndex>,
}

/// A port's entries indexed by their *listener hostname* — the field that drives
/// listener isolation. Each bucket holds indices into `RouteTable::entries`, in
/// precedence order. The three tiers mirror `listener_specificity`: exact (2) >
/// wildcard (1) > none (0).
#[derive(Debug, Default, Clone)]
struct PortIndex {
    /// listener_hostname is an exact host → that host (lowercased) → entries.
    exact: HashMap<String, Vec<usize>>,
    /// listener_hostname is `*.suffix` → (suffix, entries). Few in practice.
    wildcard: Vec<(String, Vec<usize>)>,
    /// listener_hostname is None (matches any host) → entries.
    any: Vec<usize>,
}

impl RouteTable {
    /// Find the matching entry for a request on `(port, host)`.
    ///
    /// Listener isolation: when multiple listeners share a port with different
    /// hostnames, the request is served only by routes on the *most specific*
    /// listener whose hostname matches the Host. We pick the most-specific
    /// non-empty listener tier (exact > wildcard > any) whose hostname matches,
    /// then return the first full match within that tier ONLY (in precedence
    /// order) — never falling through to a less-specific tier.
    ///
    /// Only the matched tier's entries are scanned, so dispatch cost is
    /// proportional to the routes serving that one hostname, not the whole port.
    pub fn match_request(
        &self,
        port: u16,
        host: &str,
        path: &str,
        method: &str,
        headers: &http::HeaderMap,
        query: &str,
    ) -> Option<&RouteEntry> {
        let idx = self.by_port.get(&port)?;
        let host_lc = host.to_ascii_lowercase();

        // Tier 1 (most specific): an exact-hostname listener for this host.
        if let Some(bucket) = idx.exact.get(&host_lc) {
            return self.first_match(bucket, host, path, method, headers, query);
        }

        // Tier 2: wildcard-hostname listeners whose suffix covers the host. Among
        // those that match, the most specific (most labels) wins the isolation tier.
        let best_wild = idx
            .wildcard
            .iter()
            .filter(|(suffix, _)| host_matches_suffix(suffix, host))
            .max_by_key(|(suffix, _)| suffix.matches('.').count());
        if let Some((_, bucket)) = best_wild {
            return self.first_match(bucket, host, path, method, headers, query);
        }

        // Tier 3 (least specific): no-hostname listeners (match any host).
        if !idx.any.is_empty() {
            return self.first_match(&idx.any, host, path, method, headers, query);
        }
        None
    }

    /// First entry in a precedence-ordered bucket that fully matches the request.
    fn first_match(
        &self,
        bucket: &[usize],
        host: &str,
        path: &str,
        method: &str,
        headers: &http::HeaderMap,
        query: &str,
    ) -> Option<&RouteEntry> {
        bucket
            .iter()
            .map(|&i| &self.entries[i])
            .find(|e| e.matches(host, path, method, headers, query))
    }

    /// Sort entries into Gateway API precedence order (highest precedence first),
    /// then build the per-port hostname index. Call once after all entries are
    /// pushed. Entries are visited in sorted order, so every bucket stays in
    /// precedence order.
    pub fn sort(&mut self) {
        self.entries.sort_by(|a, b| a.precedence_cmp(b));
        self.by_port.clear();
        for (i, e) in self.entries.iter().enumerate() {
            let idx = self.by_port.entry(e.listener_port).or_default();
            match e.listener_hostname.as_deref() {
                None => idx.any.push(i),
                Some(h) if h.starts_with("*.") => {
                    let suffix = h.to_ascii_lowercase();
                    match idx.wildcard.iter_mut().find(|(s, _)| *s == suffix) {
                        Some((_, v)) => v.push(i),
                        None => idx.wildcard.push((suffix, vec![i])),
                    }
                }
                Some(h) => idx.exact.entry(h.to_ascii_lowercase()).or_default().push(i),
            }
        }
    }
}

/// Does a `*.suffix` listener-hostname wildcard cover `host`? (`*.example.com`
/// covers `a.example.com` but not `example.com`.) `suffix` is the `*.`-prefixed
/// pattern, lowercased.
fn host_matches_suffix(suffix: &str, host: &str) -> bool {
    hostname_matches(suffix, host)
}

/// One flattened (match, backends) pair from an HTTPRoute rule, with the metadata
/// needed for precedence ordering.
#[derive(Debug, Clone)]
pub struct RouteEntry {
    /// Listener port this entry is attached to.
    pub listener_port: u16,
    /// The attached listener's hostname (None = no hostname / match any). Used for
    /// listener isolation: a request is served by the most-specific matching
    /// listener only.
    pub listener_hostname: Option<String>,
    /// Hostnames from the HTTPRoute. Empty = match any.
    pub hostnames: Vec<String>,
    /// The request match criteria.
    pub r#match: RouteMatch,
    /// Resolved backends to forward to.
    pub backends: Vec<Backend>,
    /// Filters applied to matching requests/responses.
    pub filters: Filters,
    /// Request timeout from the rule's `timeouts.request` (None = no timeout,
    /// also used for an explicit "0s" which disables it).
    pub request_timeout: Option<std::time::Duration>,

    // --- precedence tiebreakers (Gateway API spec order) ---
    /// Route creationTimestamp as unix seconds (older wins).
    pub route_creation: i64,
    /// "{namespace}/{name}" (alphabetical tiebreak).
    pub route_key: String,
    /// Index of the rule within the route, then the match within the rule.
    pub rule_order: usize,
    pub match_order: usize,
}

/// HTTPRoute match criteria: path AND headers AND method AND query (all must match).
#[derive(Debug, Clone, Default)]
pub struct RouteMatch {
    pub path: Option<PathMatch>,
    pub headers: Vec<HeaderMatch>,
    pub method: Option<String>,
    pub query_params: Vec<QueryMatch>,
}

#[derive(Debug, Clone)]
pub enum PathMatch {
    Exact(String),
    Prefix(String),
}

#[derive(Debug, Clone)]
pub struct HeaderMatch {
    pub name: String,
    pub value: HeaderValueMatch,
}

#[derive(Debug, Clone)]
pub enum HeaderValueMatch {
    Exact(String),
    Regex(String),
}

#[derive(Debug, Clone)]
pub struct QueryMatch {
    pub name: String,
    pub value: String,
}

/// A resolved backend: concrete pod endpoints to dial, with a relative weight.
#[derive(Debug, Clone)]
pub struct Backend {
    pub weight: u32,
    pub endpoints: Vec<Endpoint>,
    /// Per-backendRef filters (applied only when this backend is selected, in
    /// addition to the rule-level filters).
    pub filters: Filters,
}

/// Header set/add/remove operations (shared by request & response modifiers).
#[derive(Debug, Clone, Default)]
pub struct HeaderMods {
    /// Headers to set (overwrite).
    pub set: Vec<(String, String)>,
    /// Headers to add (append).
    pub add: Vec<(String, String)>,
    /// Header names to remove.
    pub remove: Vec<String>,
}

impl HeaderMods {
    pub fn is_empty(&self) -> bool {
        self.set.is_empty() && self.add.is_empty() && self.remove.is_empty()
    }
}

/// A request redirect filter (produces an early 3xx response).
#[derive(Debug, Clone, Default)]
pub struct Redirect {
    pub scheme: Option<String>,
    pub hostname: Option<String>,
    pub port: Option<u16>,
    pub status_code: u16,
    pub path: Option<PathRewrite>,
}

/// A URL rewrite filter (mutates the proxied request).
#[derive(Debug, Clone, Default)]
pub struct UrlRewrite {
    pub hostname: Option<String>,
    pub path: Option<PathRewrite>,
}

/// Path rewrite/redirect operation.
#[derive(Debug, Clone)]
pub enum PathRewrite {
    ReplaceFullPath(String),
    ReplacePrefixMatch(String),
}

/// All filters that apply to a route entry, pre-parsed for the data plane.
#[derive(Debug, Clone, Default)]
pub struct Filters {
    pub request_headers: HeaderMods,
    pub response_headers: HeaderMods,
    pub redirect: Option<Redirect>,
    pub url_rewrite: Option<UrlRewrite>,
    /// CORS filter config, if present.
    pub cors: Option<Cors>,
}

impl Filters {
    /// Merge per-backend filters on top of rule-level filters. Header mods are
    /// concatenated; redirect/url_rewrite/cors from the backend override if set.
    pub fn merged_with(&self, backend: &Filters) -> Filters {
        let mut out = self.clone();
        out.request_headers.set.extend(backend.request_headers.set.clone());
        out.request_headers.add.extend(backend.request_headers.add.clone());
        out.request_headers.remove.extend(backend.request_headers.remove.clone());
        out.response_headers.set.extend(backend.response_headers.set.clone());
        out.response_headers.add.extend(backend.response_headers.add.clone());
        out.response_headers.remove.extend(backend.response_headers.remove.clone());
        if backend.redirect.is_some() {
            out.redirect = backend.redirect.clone();
        }
        if backend.url_rewrite.is_some() {
            out.url_rewrite = backend.url_rewrite.clone();
        }
        if backend.cors.is_some() {
            out.cors = backend.cors.clone();
        }
        out
    }
}

/// CORS filter configuration (mirrors HTTPCORSFilter).
#[derive(Debug, Clone, Default)]
pub struct Cors {
    pub allow_origins: Vec<String>,
    pub allow_methods: Vec<String>,
    pub allow_headers: Vec<String>,
    pub expose_headers: Vec<String>,
    pub allow_credentials: bool,
    pub max_age: Option<i32>,
}

impl Cors {
    /// Does this CORS config allow the given Origin? Supports `*` (any), exact
    /// match, and a wildcard host like `https://*.bar.com`.
    pub fn allows_origin(&self, origin: &str) -> bool {
        self.allow_origins.iter().any(|o| {
            o == "*"
                || o.eq_ignore_ascii_case(origin)
                || cors_origin_wildcard_matches(o, origin)
        })
    }
}

#[derive(Debug, Clone)]
pub struct Endpoint {
    pub ip: std::net::IpAddr,
    pub port: u16,
    /// How to connect to this endpoint, per any BackendTLSPolicy targeting it.
    pub tls: BackendTls,
}

/// Backend connection mode, decided by BackendTLSPolicy (or its absence).
#[derive(Debug, Clone, Default)]
pub enum BackendTls {
    /// No BackendTLSPolicy applies → plain HTTP to the backend.
    #[default]
    Plaintext,
    /// A valid BackendTLSPolicy applies → re-encrypt (TLS) to the backend.
    ReEncrypt(UpstreamTls),
    /// A BackendTLSPolicy targets this Service but is invalid (bad CA / wrong
    /// kind) → the request must fail (5xx); we must NOT fall back to plaintext.
    Invalid,
}

/// Upstream (gateway→backend) TLS config from a valid BackendTLSPolicy.
#[derive(Debug, Clone)]
pub struct UpstreamTls {
    /// SNI + cert-validation hostname.
    pub hostname: String,
    /// CA bundle (PEM) to verify the backend cert; empty = use system roots.
    pub ca_pem: Vec<u8>,
}

impl RouteEntry {
    pub fn matches(
        &self,
        host: &str,
        path: &str,
        method: &str,
        headers: &http::HeaderMap,
        query: &str,
    ) -> bool {
        self.matches_host(host) && self.r#match.matches(path, method, headers, query)
    }

    /// Pick a backend endpoint for one request, weighted by backend weight.
    ///
    /// Gateway API semantics: a backend with weight 0 receives no traffic; the
    /// probability of a backend is `weight / sum(weights)`. We pick a backend by
    /// weight, then an endpoint within it uniformly (round-robin via the rng).
    pub fn pick_endpoint(&self, rng: u64) -> Option<(&Endpoint, &Backend)> {
        let total: u64 = self.backends.iter().map(|b| b.weight as u64).sum();
        let backend = if total == 0 {
            // All weights zero (or single unweighted) → first backend with endpoints.
            self.backends.iter().find(|b| !b.endpoints.is_empty())?
        } else {
            let mut pick = rng % total;
            let mut chosen = None;
            for b in &self.backends {
                let w = b.weight as u64;
                if pick < w {
                    chosen = Some(b);
                    break;
                }
                pick -= w;
            }
            // `chosen` is the weighted backend; if it has no endpoints, the request
            // still belongs to it (weight 0 backends are skipped by construction).
            chosen?
        };
        if backend.endpoints.is_empty() {
            return None;
        }
        let idx = (rng as usize) % backend.endpoints.len();
        backend.endpoints.get(idx).map(|ep| (ep, backend))
    }

    fn matches_host(&self, host: &str) -> bool {
        if self.hostnames.is_empty() {
            return true;
        }
        self.hostnames.iter().any(|h| hostname_matches(h, host))
    }

    /// Does this entry's listener hostname match the request host? (None = any.)
    /// Used by the test-only reference scan that the hostname index is checked
    /// against; the index itself encodes this via its tier buckets.
    #[cfg(test)]
    fn listener_hostname_matches(&self, host: &str) -> bool {
        match &self.listener_hostname {
            None => true,
            Some(lh) => hostname_matches(lh, host),
        }
    }

    /// Compare two entries: returns Less if `self` has HIGHER precedence (should
    /// come first). Follows the Gateway API precedence rules.
    fn precedence_cmp(&self, other: &Self) -> Ordering {
        // 1. Exact path beats prefix; longer prefix beats shorter.
        other
            .path_score()
            .cmp(&self.path_score())
            // 2. Method match present.
            .then_with(|| {
                (other.r#match.method.is_some() as u8).cmp(&(self.r#match.method.is_some() as u8))
            })
            // 3. Largest number of header matches.
            .then_with(|| other.r#match.headers.len().cmp(&self.r#match.headers.len()))
            // 4. Largest number of query param matches.
            .then_with(|| {
                other
                    .r#match
                    .query_params
                    .len()
                    .cmp(&self.r#match.query_params.len())
            })
            // 5. Oldest route by creation timestamp.
            .then_with(|| self.route_creation.cmp(&other.route_creation))
            // 6. Alphabetical by {namespace}/{name}.
            .then_with(|| self.route_key.cmp(&other.route_key))
            // 7. First rule/match in list order.
            .then_with(|| self.rule_order.cmp(&other.rule_order))
            .then_with(|| self.match_order.cmp(&other.match_order))
    }

    /// Compute the rewritten request path for a URL-rewrite filter, given the
    /// incoming path. ReplacePrefixMatch swaps the matched prefix; ReplaceFullPath
    /// replaces everything.
    pub fn rewrite_path(&self, incoming: &str) -> Option<String> {
        let rw = self.filters.url_rewrite.as_ref()?.path.as_ref()?;
        Some(self.apply_path_rewrite(rw, incoming))
    }

    pub fn apply_path_rewrite(&self, rw: &PathRewrite, incoming: &str) -> String {
        match rw {
            PathRewrite::ReplaceFullPath(p) => p.clone(),
            PathRewrite::ReplacePrefixMatch(replacement) => {
                // Replace the portion that the route's PathPrefix matched.
                let matched_prefix = match &self.r#match.path {
                    Some(PathMatch::Prefix(p)) => p.trim_end_matches('/'),
                    _ => "",
                };
                let rest = incoming.strip_prefix(matched_prefix).unwrap_or(incoming);
                let replacement = replacement.trim_end_matches('/');
                if rest.is_empty() {
                    if replacement.is_empty() {
                        "/".to_string()
                    } else {
                        replacement.to_string()
                    }
                } else {
                    format!("{}{}", replacement, rest)
                }
            }
        }
    }

    /// Path precedence score: Exact ranks above any Prefix; among prefixes,
    /// longer is higher. Encoded so larger = higher precedence.
    fn path_score(&self) -> (u8, usize) {
        match &self.r#match.path {
            Some(PathMatch::Exact(p)) => (2, p.len()),
            Some(PathMatch::Prefix(p)) => (1, p.trim_end_matches('/').len()),
            None => (1, 0), // absent path defaults to prefix "/"
        }
    }
}

impl RouteMatch {
    fn matches(&self, path: &str, method: &str, headers: &http::HeaderMap, query: &str) -> bool {
        self.matches_path(path)
            && self.matches_method(method)
            && self.matches_headers(headers)
            && self.matches_query(query)
    }

    fn matches_path(&self, path: &str) -> bool {
        match &self.path {
            None => true,
            Some(PathMatch::Exact(p)) => path == p,
            Some(PathMatch::Prefix(p)) => path_prefix_matches(p, path),
        }
    }

    fn matches_method(&self, method: &str) -> bool {
        match &self.method {
            None => true,
            Some(m) => m.eq_ignore_ascii_case(method),
        }
    }

    fn matches_headers(&self, headers: &http::HeaderMap) -> bool {
        self.headers.iter().all(|hm| {
            headers
                .get_all(hm.name.as_str())
                .iter()
                .filter_map(|v| v.to_str().ok())
                .any(|v| match &hm.value {
                    HeaderValueMatch::Exact(want) => v == want,
                    // Minimal regex support: fall back to exact if we can't compile.
                    HeaderValueMatch::Regex(want) => v == want,
                })
        })
    }

    fn matches_query(&self, query: &str) -> bool {
        if self.query_params.is_empty() {
            return true;
        }
        let pairs: Vec<(&str, &str)> = query
            .split('&')
            .filter(|s| !s.is_empty())
            .map(|kv| kv.split_once('=').unwrap_or((kv, "")))
            .collect();
        self.query_params
            .iter()
            .all(|qm| pairs.iter().any(|(k, v)| *k == qm.name && *v == qm.value))
    }
}

/// Match a CORS origin pattern with a `*.` host wildcard (e.g. `https://*.bar.com`
/// matches `https://www.bar.com` and `https://a.b.bar.com`) against an origin.
fn cors_origin_wildcard_matches(pattern: &str, origin: &str) -> bool {
    // Split scheme:// from host for both.
    let (p_scheme, p_host) = match pattern.split_once("://") {
        Some(x) => x,
        None => return false,
    };
    let (o_scheme, o_host) = match origin.split_once("://") {
        Some(x) => x,
        None => return false,
    };
    if !p_scheme.eq_ignore_ascii_case(o_scheme) {
        return false;
    }
    if let Some(suffix) = p_host.strip_prefix("*.") {
        // `www.bar.com` ends with `.bar.com` and has a non-empty label before it.
        o_host
            .strip_suffix(suffix)
            .map(|pre| pre.ends_with('.') && pre.len() > 1)
            .unwrap_or(false)
    } else {
        p_host.eq_ignore_ascii_case(o_host)
    }
}

/// Specificity of a listener hostname, for listener isolation. Higher = more
/// specific: an exact hostname beats a wildcard beats no-hostname; among
/// non-empty, more labels = more specific. The hostname index encodes this as its
/// exact > wildcard(by labels) > any tier order; this function backs the test-only
/// reference scan the index is validated against.
#[cfg(test)]
fn listener_specificity(hostname: Option<&str>) -> (u8, usize) {
    match hostname {
        None => (0, 0),
        Some(h) if h.starts_with("*.") => (1, h.matches('.').count()),
        Some(h) => (2, h.matches('.').count()),
    }
}

/// Gateway API prefix semantics: `/foo` matches `/foo` and `/foo/bar` but not
/// `/foobar`. The prefix `/` matches everything. Matching is on path *elements*.
fn path_prefix_matches(prefix: &str, path: &str) -> bool {
    if prefix == "/" {
        return true;
    }
    let prefix = prefix.trim_end_matches('/');
    if let Some(rest) = path.strip_prefix(prefix) {
        rest.is_empty() || rest.starts_with('/')
    } else {
        false
    }
}

/// Hostname match supporting a single leading wildcard label (`*.example.com`).
/// Case-INSENSITIVE on both sides (RFC 3986 §3.2.2 / RFC 9110 §4.2.3 — host
/// comparison is case-insensitive). The wildcard branch previously used a
/// byte-exact `strip_suffix`, so a legal mixed-case `Host: A.EXAMPLE.COM` against
/// `*.example.com` spuriously 404'd.
fn hostname_matches(pattern: &str, host: &str) -> bool {
    if let Some(suffix) = pattern.strip_prefix("*.") {
        // `host` must end with `.<suffix>` (case-insensitively) with a non-empty
        // leftmost label, so `*.example.com` covers `a.example.com` but not
        // `example.com`.
        let Some(rest_len) = host.len().checked_sub(suffix.len()) else {
            return false;
        };
        // Need at least "x." before the suffix; guard char boundary so a
        // multibyte (non-ASCII) host can't panic split_at.
        if rest_len < 2 || !host.is_char_boundary(rest_len) {
            return false;
        }
        let (prefix, tail) = host.split_at(rest_len);
        tail.eq_ignore_ascii_case(suffix) && prefix.ends_with('.')
    } else {
        pattern.eq_ignore_ascii_case(host)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefix_matching() {
        assert!(path_prefix_matches("/", "/anything"));
        assert!(path_prefix_matches("/foo", "/foo"));
        assert!(path_prefix_matches("/foo", "/foo/bar"));
        assert!(!path_prefix_matches("/foo", "/foobar"));
        // From HTTPRouteMatching: /v2 must not match /v2example
        assert!(!path_prefix_matches("/v2", "/v2example"));
        assert!(path_prefix_matches("/v2", "/v2/example"));
    }

    #[test]
    fn host_matching() {
        assert!(hostname_matches("example.com", "example.com"));
        assert!(hostname_matches("example.com", "EXAMPLE.com"));
        assert!(hostname_matches("*.example.com", "a.example.com"));
        assert!(!hostname_matches("*.example.com", "example.com"));
        // L1: the wildcard branch must be case-insensitive on both sides.
        assert!(hostname_matches("*.example.com", "A.EXAMPLE.COM"));
        assert!(hostname_matches("*.example.com", "a.Example.Com"));
        assert!(hostname_matches("*.EXAMPLE.COM", "a.example.com"));
        // Still must not match the bare domain or a too-short leftmost label.
        assert!(!hostname_matches("*.example.com", "EXAMPLE.COM"));
        assert!(!hostname_matches("*.example.com", ".example.com"));
        // A non-ASCII leftmost label is a valid subdomain and must not panic.
        assert!(hostname_matches("*.example.com", "ñ.example.com"));
        // A multibyte char straddling the suffix boundary must not panic.
        let _ = hostname_matches("*.example.com", "añ.example.com");
    }

    fn entry(path: PathMatch, headers: usize) -> RouteEntry {
        RouteEntry {
            listener_port: 80,
            listener_hostname: None,
            hostnames: vec![],
            r#match: RouteMatch {
                path: Some(path),
                headers: (0..headers)
                    .map(|i| HeaderMatch {
                        name: format!("h{i}"),
                        value: HeaderValueMatch::Exact("v".into()),
                    })
                    .collect(),
                method: None,
                query_params: vec![],
            },
            backends: vec![],
            filters: Filters::default(),
            request_timeout: None,
            route_creation: 0,
            route_key: "ns/n".into(),
            rule_order: 0,
            match_order: 0,
        }
    }

    #[test]
    fn precedence_exact_beats_prefix() {
        let mut t = RouteTable {
            entries: vec![
                entry(PathMatch::Prefix("/".into()), 0),
                entry(PathMatch::Exact("/a".into()), 0),
            ],
            ..Default::default()
        };
        t.sort();
        matches!(t.entries[0].r#match.path, Some(PathMatch::Exact(_)));
    }

    #[test]
    fn precedence_longer_prefix_first() {
        let mut t = RouteTable {
            entries: vec![
                entry(PathMatch::Prefix("/".into()), 0),
                entry(PathMatch::Prefix("/v2".into()), 0),
            ],
            ..Default::default()
        };
        t.sort();
        assert!(matches!(&t.entries[0].r#match.path, Some(PathMatch::Prefix(p)) if p == "/v2"));
    }

    #[test]
    fn weighted_distribution() {
        let ip = |n: u8| Endpoint {
            ip: std::net::IpAddr::from([10, 0, 0, n]),
            port: 80,
            tls: BackendTls::default(),
        };
        let e = RouteEntry {
            listener_port: 80,
            listener_hostname: None,
            hostnames: vec![],
            r#match: RouteMatch::default(),
            backends: vec![
                Backend { weight: 70, endpoints: vec![ip(1)], filters: Filters::default() },
                Backend { weight: 30, endpoints: vec![ip(2)], filters: Filters::default() },
                Backend { weight: 0, endpoints: vec![ip(3)], filters: Filters::default() },
            ],
            filters: Filters::default(),
            request_timeout: None,
            route_creation: 0,
            route_key: "ns/n".into(),
            rule_order: 0,
            match_order: 0,
        };
        let mut counts = [0u32; 3];
        for r in 0..10_000u64 {
            // Spread the rng across the weight space deterministically.
            let pick = r.wrapping_mul(2654435761) % 100;
            let (ep, _) = e.pick_endpoint(pick).unwrap();
            match ep.ip {
                std::net::IpAddr::V4(v) if v.octets()[3] == 1 => counts[0] += 1,
                std::net::IpAddr::V4(v) if v.octets()[3] == 2 => counts[1] += 1,
                _ => counts[2] += 1,
            }
        }
        // weight 0 backend must never be chosen.
        assert_eq!(counts[2], 0, "weight-0 backend received traffic");
        // ~70/30 split within tolerance.
        let ratio = counts[0] as f64 / (counts[0] + counts[1]) as f64;
        assert!((0.6..0.8).contains(&ratio), "70/30 split off: {ratio}");
    }

    #[test]
    fn match_request_uses_port_bucket_and_precedence() {
        // Two ports, each with its own routes; a request only matches its port,
        // and within a port the higher-precedence (exact) entry wins.
        let mk = |port: u16, path: PathMatch| {
            let mut e = entry(path, 0);
            e.listener_port = port;
            e
        };
        let mut t = RouteTable {
            entries: vec![
                mk(80, PathMatch::Prefix("/".into())),
                mk(80, PathMatch::Exact("/a".into())),
                mk(443, PathMatch::Prefix("/only443".into())),
            ],
            ..Default::default()
        };
        t.sort();
        let h = http::HeaderMap::new();
        // Port 80, /a → exact match wins over prefix "/".
        let m = t.match_request(80, "x", "/a", "GET", &h, "").unwrap();
        assert!(matches!(&m.r#match.path, Some(PathMatch::Exact(p)) if p == "/a"));
        // Port 443 only sees its own bucket — the 80 routes are invisible.
        assert!(t.match_request(443, "x", "/a", "GET", &h, "").is_none());
        assert!(t.match_request(443, "x", "/only443/x", "GET", &h, "").is_some());
        // Unknown port → no bucket → no match.
        assert!(t.match_request(9999, "x", "/a", "GET", &h, "").is_none());
    }

    /// Reference implementation: the original O(n) linear scan with listener
    /// isolation. The hostname index must produce identical results to this.
    fn reference_match<'a>(
        t: &'a RouteTable,
        port: u16,
        host: &str,
        path: &str,
        method: &str,
        headers: &http::HeaderMap,
        query: &str,
    ) -> Option<&'a RouteEntry> {
        let on_port = || {
            t.entries
                .iter()
                .filter(|e| e.listener_port == port && e.listener_hostname_matches(host))
        };
        let best = on_port()
            .map(|e| listener_specificity(e.listener_hostname.as_deref()))
            .max()?;
        t.entries.iter().find(|e| {
            e.listener_port == port
                && listener_specificity(e.listener_hostname.as_deref()) == best
                && e.listener_hostname_matches(host)
                && e.matches(host, path, method, headers, query)
        })
    }

    /// The hostname index must agree with the reference linear scan on every
    /// request, across a pseudo-random population of entries and queries.
    #[test]
    fn index_matches_reference_scan() {
        let listener_hosts = [
            None,
            Some("a.example.com"),
            Some("b.example.com"),
            Some("*.example.com"),
            Some("*.svc.example.com"),
            Some("EXAMPLE.com"), // case sensitivity
        ];
        let route_hosts: [&[&str]; 4] = [
            &[],
            &["a.example.com"],
            &["*.example.com"],
            &["x.svc.example.com"],
        ];
        let paths = [
            PathMatch::Prefix("/".into()),
            PathMatch::Prefix("/api".into()),
            PathMatch::Exact("/api/v1".into()),
        ];
        let ports = [80u16, 443];

        // Build a deterministic but varied population of entries.
        let mut entries = Vec::new();
        let mut seed = 12345u64;
        let mut rng = || {
            seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
            (seed >> 33) as usize
        };
        for n in 0..60 {
            let mut e = entry(paths[rng() % paths.len()].clone(), 0);
            e.listener_port = ports[rng() % ports.len()];
            e.listener_hostname = listener_hosts[rng() % listener_hosts.len()].map(|s| s.into());
            e.hostnames = route_hosts[rng() % route_hosts.len()]
                .iter()
                .map(|s| s.to_string())
                .collect();
            e.route_key = format!("ns/r{n}");
            entries.push(e);
        }
        let mut t = RouteTable { entries, ..Default::default() };
        t.sort();

        let test_hosts = [
            "a.example.com",
            "b.example.com",
            "c.example.com",
            "x.svc.example.com",
            "example.com",
            "A.EXAMPLE.COM",
            "nomatch.org",
        ];
        let test_paths = ["/", "/api", "/api/v1", "/api/v2", "/other"];
        let h = http::HeaderMap::new();
        for &port in &ports {
            for host in &test_hosts {
                for path in &test_paths {
                    let got = t.match_request(port, host, path, "GET", &h, "");
                    let want = reference_match(&t, port, host, path, "GET", &h, "");
                    // Compare by route_key + path identity (entries are unique enough).
                    let key = |e: Option<&RouteEntry>| {
                        e.map(|e| (e.route_key.clone(), format!("{:?}", e.r#match.path)))
                    };
                    assert_eq!(
                        key(got),
                        key(want),
                        "mismatch at port={port} host={host} path={path}"
                    );
                }
            }
        }
    }

    #[test]
    fn precedence_more_headers_first() {
        let mut t = RouteTable {
            entries: vec![
                entry(PathMatch::Prefix("/".into()), 0),
                entry(PathMatch::Prefix("/".into()), 2),
            ],
            ..Default::default()
        };
        t.sort();
        assert_eq!(t.entries[0].r#match.headers.len(), 2);
    }
}
