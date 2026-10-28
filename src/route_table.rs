//! The routing table the control plane computes for the data plane.
//!
//! The control plane recomputes a [`RouteTable`] from the full set of watched
//! Kubernetes objects; it's published to the data plane (with the cert store) via
//! the atomic [`crate::snapshot::Snapshot`]. The data plane reads it lock-free on
//! every request.

use std::cmp::Ordering;
use std::collections::HashMap;
use std::sync::Arc;

/// The data plane's view of all programmed routing.
///
/// Entries are kept sorted in descending precedence order, and indexed by listener
/// port, listener hostname and route hostname, so request dispatch scans only the
/// handful of entries that can serve the request's `(port, Host)` — not the whole
/// table. This matters because real deployments put everything on one port (443)
/// with many distinct hostnames, so a port-only split wouldn't help; the hostname
/// index does.
#[derive(Debug, Default, Clone)]
pub struct RouteTable {
    /// All entries, in descending precedence order (built flat, then `sort()`ed).
    pub entries: Vec<RouteEntry>,
    /// The HTTP and HTTPS listeners, as (port, hostname). A request belongs to the
    /// most specific listener whose hostname matches it also when that listener
    /// has no routes: it then gets a 404, not another listener's routes.
    pub listeners: Vec<(u16, Option<String>)>,
    /// Per-port hostname index into `entries`. Built by `sort()`.
    by_port: HashMap<u16, PortIndex>,
}

/// A port's entries indexed by their *listener hostname* — the field that drives
/// listener isolation. The three tiers mirror `listener_specificity`: exact (2) >
/// wildcard (1) > none (0).
#[derive(Debug, Default, Clone)]
struct PortIndex {
    /// listener_hostname is an exact host → that host (lowercased) → entries.
    exact: HashMap<String, HostIndex>,
    /// listener_hostname is `*.suffix` → (suffix, entries). Few in practice.
    wildcard: Vec<(String, HostIndex)>,
    /// listener_hostname is None (matches any host) → entries.
    any: Option<HostIndex>,
}

impl PortIndex {
    /// The tier of the listeners with hostname `hostname`, created if new.
    fn tier(&mut self, hostname: Option<&str>) -> &mut HostIndex {
        match hostname {
            None => self.any.get_or_insert_default(),
            Some(h) if h.starts_with("*.") => {
                let suffix = h.to_ascii_lowercase();
                match self.wildcard.iter().position(|(s, _)| *s == suffix) {
                    Some(n) => &mut self.wildcard[n].1,
                    None => {
                        self.wildcard.push((suffix, HostIndex::default()));
                        &mut self.wildcard.last_mut().unwrap().1
                    }
                }
            }
            Some(h) => self.exact.entry(h.to_ascii_lowercase()).or_default(),
        }
    }
}

/// One listener tier's entries indexed by the route hostnames they match a host
/// with. Among routes that match a request, the spec gives precedence to the one
/// with the most characters in a matching non-wildcard hostname, then in a matching
/// hostname, before any of the match criteria: so an exact hostname beats every
/// wildcard, a longer wildcard beats a shorter one, and both beat a route with no
/// hostnames. Each bucket holds indices into `RouteTable::entries`, in precedence
/// order.
#[derive(Debug, Default, Clone)]
struct HostIndex {
    /// Entries of routes that name an exact hostname → that host (lowercased).
    exact: HashMap<String, Vec<usize>>,
    /// Entries of routes that name a `*.` wildcard → (wildcard, entries), longest
    /// wildcard first.
    wildcard: Vec<(String, Vec<usize>)>,
    /// Entries of routes that name no hostname.
    any: Vec<usize>,
}

impl HostIndex {
    /// Whether no route is attached to the listener.
    fn is_empty(&self) -> bool {
        self.exact.is_empty() && self.wildcard.is_empty() && self.any.is_empty()
    }

    fn add(&mut self, i: usize, hostnames: &[String]) {
        let push = |bucket: &mut Vec<usize>| {
            // A route may name a host twice (in different case).
            if bucket.last() != Some(&i) {
                bucket.push(i);
            }
        };
        if hostnames.is_empty() {
            push(&mut self.any);
        }
        for h in hostnames {
            let h = h.to_ascii_lowercase();
            if h.starts_with("*.") {
                match self.wildcard.iter_mut().find(|(w, _)| *w == h) {
                    Some((_, bucket)) => push(bucket),
                    None => self.wildcard.push((h, vec![i])),
                }
            } else {
                push(self.exact.entry(h).or_default());
            }
        }
    }

    /// The first entry, by hostname precedence and then by match precedence, that
    /// matches the request.
    fn first_match<'a>(
        &self,
        entries: &'a [RouteEntry],
        host: &str,
        path: &str,
        method: &str,
        headers: &dyn HeaderLookup,
        query: &str,
    ) -> Option<&'a RouteEntry> {
        let exact = self.exact.get(&host.to_ascii_lowercase());
        let wildcards = self
            .wildcard
            .iter()
            .filter(|(w, _)| hostname_matches(w, host))
            .map(|(_, bucket)| bucket);
        exact
            .into_iter()
            .chain(wildcards)
            .chain([&self.any])
            .find_map(|bucket| {
                bucket
                    .iter()
                    .map(|&i| &entries[i])
                    .find(|e| e.r#match.matches(path, method, headers, query))
            })
    }
}

/// A request's header fields, as route matching sees them.
pub trait HeaderLookup {
    /// Whether `f` holds for any value of the field `name` (compared without
    /// case) that is a string of visible ASCII; other values never match.
    fn any_value(&self, name: &str, f: &mut dyn FnMut(&str) -> bool) -> bool;
}

impl HeaderLookup for http::HeaderMap {
    fn any_value(&self, name: &str, f: &mut dyn FnMut(&str) -> bool) -> bool {
        self.get_all(name).iter().filter_map(|v| v.to_str().ok()).any(f)
    }
}

impl RouteTable {
    /// Find the matching entry for a request on `(port, host)`.
    ///
    /// Listener isolation: when multiple listeners share a port with different
    /// hostnames, the request is served only by routes on the *most specific*
    /// listener whose hostname matches the Host. We pick the most-specific
    /// listener tier (exact > wildcard > any) whose hostname matches, with or
    /// without routes,
    /// then return the first full match within that tier ONLY (by route hostname
    /// precedence, then match precedence) — never falling through to a
    /// less-specific tier.
    ///
    /// Only the matched tier's entries are scanned, so dispatch cost is
    /// proportional to the routes serving that one hostname, not the whole port.
    pub fn match_request(
        &self,
        port: u16,
        host: &str,
        path: &str,
        method: &str,
        headers: &dyn HeaderLookup,
        query: &str,
    ) -> Option<&RouteEntry> {
        let idx = self.by_port.get(&port)?;
        let host_lc = host.to_ascii_lowercase();

        // Tier 1 (most specific): an exact-hostname listener for this host.
        // Tier 2: wildcard-hostname listeners whose suffix covers the host. Among
        // those that match, the most specific (most labels) wins the isolation tier.
        // Tier 3 (least specific): no-hostname listeners (match any host).
        let tier = idx.exact.get(&host_lc).or_else(|| {
            idx.wildcard
                .iter()
                .filter(|(suffix, _)| host_matches_suffix(suffix, host))
                .max_by_key(|(suffix, _)| suffix.matches('.').count())
                .map(|(_, tier)| tier)
                .or(idx.any.as_ref())
        })?;
        tier.first_match(&self.entries, host, path, method, headers, query)
    }

    /// Whether a listener on `port` with routes attached serves the hostname
    /// `host` (an exact or wildcard listener hostname covering it, or a listener
    /// with no hostname); with no `host`, whether one with no hostname exists.
    pub fn serves_host(&self, port: u16, host: Option<&str>) -> bool {
        let Some(idx) = self.by_port.get(&port) else {
            return false;
        };
        if idx.any.as_ref().is_some_and(|tier| !tier.is_empty()) {
            return true;
        }
        let Some(host) = host else {
            return false;
        };
        let host_lc = host.to_ascii_lowercase();
        idx.exact.get(&host_lc).is_some_and(|tier| !tier.is_empty())
            || idx
                .wildcard
                .iter()
                .any(|(suffix, tier)| host_matches_suffix(suffix, host) && !tier.is_empty())
    }

    /// Sort entries into Gateway API precedence order (highest precedence first),
    /// then build the per-port hostname index. Call once after all entries are
    /// pushed. Entries are visited in sorted order, so every bucket stays in
    /// precedence order.
    pub fn sort(&mut self) {
        self.entries.sort_by(|a, b| a.precedence_cmp(b));
        self.by_port.clear();
        for (port, hostname) in &self.listeners {
            self.by_port.entry(*port).or_default().tier(hostname.as_deref());
        }
        for (i, e) in self.entries.iter().enumerate() {
            let idx = self.by_port.entry(e.listener_port).or_default();
            idx.tier(e.listener_hostname.as_deref()).add(i, &e.hostnames);
        }
        let tiers = self.by_port.values_mut().flat_map(|idx| {
            idx.exact
                .values_mut()
                .chain(idx.wildcard.iter_mut().map(|(_, tier)| tier))
                .chain(idx.any.as_mut())
        });
        for tier in tiers {
            tier.wildcard.sort_by_key(|(w, _)| std::cmp::Reverse(w.len()));
        }
    }
}

/// Does a `*.suffix` listener-hostname wildcard cover `host`? (`*.example.com`
/// covers `a.example.com` but not `example.com`.) `suffix` is the `*.`-prefixed
/// pattern, lowercased.
fn host_matches_suffix(suffix: &str, host: &str) -> bool {
    hostname_matches(suffix, host)
}

/// One match of an HTTPRoute rule on one attached listener, with the metadata
/// needed for precedence ordering.
///
/// A route has up to 128 matches and attaches to any number of listeners, so
/// whatever an entry holds is multiplied by both. Everything sizeable is shared:
/// the rule by all the entries of the rule, the match by its listeners, and the
/// hostnames by the route's matches on one listener.
#[derive(Debug, Clone)]
pub struct RouteEntry {
    /// Listener port this entry is attached to.
    pub listener_port: u16,
    /// The attached listener's hostname (None = no hostname / match any). Used for
    /// listener isolation: a request is served by the most-specific matching
    /// listener only.
    pub listener_hostname: Option<String>,
    /// The route's hostnames that the listener's hostname covers or overlaps.
    /// Empty when the route names none: it matches any host its listener does.
    pub hostnames: Arc<[String]>,
    /// The request match criteria.
    pub r#match: Arc<RouteMatch>,
    /// What the rule does with the requests it matches.
    pub rule: Arc<Rule>,

    // --- precedence tiebreakers (Gateway API spec order) ---
    /// Route creationTimestamp as unix seconds (older wins).
    pub route_creation: i64,
    /// "{namespace}/{name}" (alphabetical tiebreak).
    pub route_key: Arc<str>,
    /// Index of the rule within the route, then the match within the rule.
    pub rule_order: usize,
    pub match_order: usize,
}

/// What an HTTPRoute rule does with the requests it matches.
#[derive(Debug, Default)]
pub struct Rule {
    /// Resolved backends to forward to.
    pub backends: Vec<Backend>,
    /// Filters applied to matching requests/responses.
    pub filters: Filters,
    /// Request timeout from the rule's `timeouts` (the smaller non-zero one of
    /// `request` and `backendRequest`). None = the rule sets none, so the data
    /// plane's default applies; zero = "0s", which disables it.
    pub request_timeout: Option<std::time::Duration>,
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
    /// A compiled `type: RegularExpression` header-value matcher. Compiled once in
    /// the control plane (an un-compilable pattern produces no match entry, so it
    /// never reaches here); `regex::Regex` is cheap to clone (Arc-shared program).
    Regex(regex::Regex),
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
    /// Shared by every backendRef to the same Service port.
    pub endpoints: Arc<[Endpoint]>,
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
        out.request_headers
            .remove
            .extend(backend.request_headers.remove.clone());
        out.response_headers.set.extend(backend.response_headers.set.clone());
        out.response_headers.add.extend(backend.response_headers.add.clone());
        out.response_headers
            .remove
            .extend(backend.response_headers.remove.clone());
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
        self.allow_origins
            .iter()
            .any(|o| o == "*" || o.eq_ignore_ascii_case(origin) || cors_origin_wildcard_matches(o, origin))
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
    /// A valid BackendTLSPolicy applies → re-encrypt (TLS) to the backend. One
    /// per policy, shared by all its endpoints (the CA bundle can be a MiB).
    ReEncrypt(Arc<UpstreamTls>),
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

/// Why a request has no endpoint to go to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NoEndpoint {
    /// Its rule has no valid backend for it: a 500, as Gateway API requires.
    NoBackend,
    /// Its backend's Service has no ready endpoints: a 503, as Gateway API
    /// recommends.
    NotReady,
}

impl RouteEntry {
    /// Pick a backend endpoint for one request, weighted by backend weight.
    ///
    /// Gateway API semantics: a backend with weight 0 receives no traffic; the
    /// probability of a backend is `weight / sum(weights)`. We pick a backend by
    /// weight, then an endpoint within it uniformly (round-robin via the rng).
    pub fn pick_endpoint(&self, rng: u64) -> Result<(&Endpoint, &Backend), NoEndpoint> {
        let backends = &self.rule.backends;
        let total: u64 = backends.iter().map(|b| b.weight as u64).sum();
        let backend = if total == 0 {
            // All weights zero (or single unweighted) → first backend with endpoints.
            backends
                .iter()
                .find(|b| !b.endpoints.is_empty())
                .ok_or(NoEndpoint::NoBackend)?
        } else {
            let mut pick = rng % total;
            let mut chosen = None;
            for b in backends {
                let w = b.weight as u64;
                if pick < w {
                    chosen = Some(b);
                    break;
                }
                pick -= w;
            }
            // `chosen` is the weighted backend; if it has no endpoints, the request
            // still belongs to it (weight 0 backends are skipped by construction).
            chosen.ok_or(NoEndpoint::NoBackend)?
        };
        // Invalid backendRefs are left out of a rule, so an empty backend is a
        // Service with no ready endpoints.
        if backend.endpoints.is_empty() {
            return Err(NoEndpoint::NotReady);
        }
        let idx = (rng as usize) % backend.endpoints.len();
        Ok((&backend.endpoints[idx], backend))
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
            .then_with(|| (other.r#match.method.is_some() as u8).cmp(&(self.r#match.method.is_some() as u8)))
            // 3. Largest number of header matches.
            .then_with(|| other.r#match.headers.len().cmp(&self.r#match.headers.len()))
            // 4. Largest number of query param matches.
            .then_with(|| other.r#match.query_params.len().cmp(&self.r#match.query_params.len()))
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
        let rw = self.rule.filters.url_rewrite.as_ref()?.path.as_ref()?;
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
    fn matches(&self, path: &str, method: &str, headers: &dyn HeaderLookup, query: &str) -> bool {
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

    fn matches_headers(&self, headers: &dyn HeaderLookup) -> bool {
        self.headers.iter().all(|hm| {
            headers.any_value(hm.name.as_str(), &mut |v| match &hm.value {
                HeaderValueMatch::Exact(want) => v == want,
                HeaderValueMatch::Regex(re) => re.is_match(v),
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

/// The normal form of a request path, which routes match, filters rewrite and the
/// backend gets; None if the request must be refused (400). Backends resolve a path
/// before routing on it, so without this `/%61dmin` or `/x/../admin` skipped the
/// rules for `/admin` and still reached it, and `..` escaped a ReplacePrefixMatch.
///
/// - Escapes of unreserved characters are decoded, other escapes get uppercase hex,
///   and bytes a path may not hold raw (`"`, `|`, non-ASCII, ...) are escaped
///   (RFC 3986 §6.2.2.1-2).
/// - Then `.` and `..` segments are removed (§5.2.4), also when they carry
///   `;params` (`..;x` is `..` to Tomcat and Jetty), and `//` is merged, as nginx
///   and Envoy do.
/// - An encoded `/` or `\` (`%2F`, `%5C`) is refused unless `allow_encoded_slashes`:
///   nginx and Python's http.server decode them before resolving `..`. Allowed ones
///   stay escaped, so they never split segments here. `%00`, a raw `\` or `#`, and
///   a `%` that starts no escape are always refused.
pub fn normalize_path(path: &[u8], allow_encoded_slashes: bool) -> Option<String> {
    use std::fmt::Write;

    let path: &[u8] = match path {
        [] => b"/",
        [b'/', ..] => path,
        _ => return None,
    };
    let unreserved = |b: u8| b.is_ascii_alphanumeric() || b"-._~".contains(&b);
    let mut escaped = String::with_capacity(path.len());
    let mut i = 0;
    while i < path.len() {
        let mut b = path[i];
        i += 1;
        if b == b'%' {
            let hex = |i: usize| path.get(i).and_then(|&h| char::from(h).to_digit(16));
            b = ((hex(i)? << 4) | hex(i + 1)?) as u8;
            i += 2;
            match b {
                0 => return None,
                b'/' | b'\\' if !allow_encoded_slashes => return None,
                _ if unreserved(b) => escaped.push(char::from(b)),
                _ => {
                    let _ = write!(escaped, "%{b:02X}");
                }
            }
        } else if b == b'\\' || b == b'#' {
            return None;
        } else if unreserved(b) || b"/!$&'()*+,;=:@".contains(&b) {
            escaped.push(char::from(b));
        } else {
            let _ = write!(escaped, "%{b:02X}");
        }
    }
    Some(remove_dot_segments(&escaped))
}

/// The normal form of `path` (itself in normal form) without the `;params` of its
/// segments: the path that Tomcat, Jetty and others route on.
pub fn without_path_params(path: &str) -> String {
    let segments: Vec<&str> = path.split('/').map(path_segment_name).collect();
    remove_dot_segments(&segments.join("/"))
}

/// A path segment without its `;params`.
fn path_segment_name(segment: &str) -> &str {
    segment.split_once(';').map_or(segment, |(name, _)| name)
}

/// Remove the `.` and `..` segments of a path that starts with `/` (RFC 3986
/// §5.2.4, judging a segment by its name, see [`path_segment_name`]), and its empty
/// segments. A path that ends in one of them keeps a trailing `/`.
fn remove_dot_segments(path: &str) -> String {
    let mut segments = Vec::new();
    let mut trailing_slash = false;
    for segment in path.strip_prefix('/').unwrap_or(path).split('/') {
        let name = path_segment_name(segment);
        if name == ".." {
            segments.pop();
        }
        trailing_slash = segment.is_empty() || name == "." || name == "..";
        if !trailing_slash {
            segments.push(segment);
        }
    }
    let mut normal = String::with_capacity(path.len());
    for segment in &segments {
        normal.push('/');
        normal.push_str(segment);
    }
    if trailing_slash || segments.is_empty() {
        normal.push('/');
    }
    normal
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

    // Every form of a path that a backend resolves to the same path has the same
    // normal form, so that routes match what the backend will serve.
    #[test]
    fn path_normal_form() {
        let normal = |path: &[u8]| normalize_path(path, false);
        for (path, want) in [
            (&b"/admin/panel"[..], "/admin/panel"),
            (b"/%61dmin/panel", "/admin/panel"),
            (b"/secre%74", "/secret"),
            (b"/x/../admin/panel", "/admin/panel"),
            (b"/./admin/panel", "/admin/panel"),
            (b"/x/%2e%2E/admin/panel", "/admin/panel"),
            (b"//admin//panel", "/admin/panel"),
            (b"/x/..;y/admin", "/admin"),
            (b"/x/.;y/admin", "/x/admin"),
            (b"/public/../../..", "/"),
            (b"/a/b/..", "/a/"),
            (b"/a/.", "/a/"),
            (b"/a/", "/a/"),
            (b"/", "/"),
            (b"", "/"),
            // Escapes of other characters stay, in uppercase; raw bytes a path may
            // not hold get escaped.
            (b"/a%3fb%7e", "/a%3Fb~"),
            (b"/caf%c3%a9", "/caf%C3%A9"),
            ("/café".as_bytes(), "/caf%C3%A9"),
            (b"/caf\xe9", "/caf%E9"),
            (b"/a|b\"{}", "/a%7Cb%22%7B%7D"),
            // `;params` are data, but not on a dot segment.
            (b"/admin;x=1/panel", "/admin;x=1/panel"),
            (b"/app/;jsessionid=1", "/app/;jsessionid=1"),
        ] {
            assert_eq!(normal(path).as_deref(), Some(want), "{}", path.escape_ascii());
        }
        for path in [
            &b"/a%2Fb"[..],
            b"/..%2fadmin",
            b"/a%5cb",
            b"/a\\b",
            b"/a%00",
            b"/a%",
            b"/a%4",
            b"/a%zz",
            b"/a%+1",
            b"/a#b",
            b"*",
        ] {
            assert_eq!(normal(path), None, "{}", path.escape_ascii());
        }
        // Allowed encoded slashes are data: `..%2F` is no `..`.
        assert_eq!(normalize_path(b"/x/..%2fadmin", true).as_deref(), Some("/x/..%2Fadmin"));
        assert_eq!(normalize_path(b"/a%5cb", true).as_deref(), Some("/a%5Cb"));
        assert_eq!(normalize_path(b"/a%00", true), None);

        assert_eq!(without_path_params("/admin;x=1/panel"), "/admin/panel");
        assert_eq!(without_path_params("/;x/admin"), "/admin");
        assert_eq!(without_path_params("/app/;jsessionid=1"), "/app/");
    }

    #[test]
    fn regex_header_match() {
        let h = |name: &str, val: HeaderValueMatch| RouteMatch {
            headers: vec![HeaderMatch {
                name: name.into(),
                value: val,
            }],
            ..Default::default()
        };
        let re = |p: &str| HeaderValueMatch::Regex(regex::Regex::new(p).unwrap());

        let mut hdrs = http::HeaderMap::new();
        hdrs.insert("x-ver", "v123".parse().unwrap());

        // A real regex matches (it used to do plain string equality, so `v123`
        // would only have matched the literal pattern string `^v\d+$`).
        assert!(h("x-ver", re(r"^v\d+$")).matches("", "GET", &hdrs, ""));
        assert!(h("x-ver", re(r"\d{3}")).matches("", "GET", &hdrs, ""));
        // Non-matching pattern doesn't match.
        assert!(!h("x-ver", re(r"^w")).matches("", "GET", &hdrs, ""));
        assert!(!h("x-ver", re(r"^v\d{4}$")).matches("", "GET", &hdrs, ""));
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
            hostnames: Arc::new([]),
            r#match: Arc::new(RouteMatch {
                path: Some(path),
                headers: (0..headers)
                    .map(|i| HeaderMatch {
                        name: format!("h{i}"),
                        value: HeaderValueMatch::Exact("v".into()),
                    })
                    .collect(),
                method: None,
                query_params: vec![],
            }),
            rule: Arc::default(),
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
        let backend = |weight: u32, n: u8| Backend {
            weight,
            endpoints: Arc::new([ip(n)]),
            filters: Filters::default(),
        };
        let e = RouteEntry {
            listener_port: 80,
            listener_hostname: None,
            hostnames: Arc::new([]),
            r#match: Arc::default(),
            rule: Arc::new(Rule {
                backends: vec![backend(70, 1), backend(30, 2), backend(0, 3)],
                ..Default::default()
            }),
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
    fn a_backend_with_no_ready_endpoints_is_not_a_missing_one() {
        let e = |backends| RouteEntry {
            rule: Arc::new(Rule {
                backends,
                ..Default::default()
            }),
            ..entry(PathMatch::Prefix("/".into()), 0)
        };
        let empty = |weight| Backend {
            weight,
            endpoints: Arc::new([]),
            filters: Filters::default(),
        };
        assert_eq!(e(vec![]).pick_endpoint(0).unwrap_err(), NoEndpoint::NoBackend);
        assert_eq!(e(vec![empty(1)]).pick_endpoint(0).unwrap_err(), NoEndpoint::NotReady);
        assert_eq!(e(vec![empty(0)]).pick_endpoint(0).unwrap_err(), NoEndpoint::NoBackend);
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

    /// Reference implementation: an O(n) linear scan with listener isolation and
    /// route hostname precedence, as the spec words them. The hostname index must
    /// produce identical results to this.
    fn reference_match<'a>(
        t: &'a RouteTable,
        port: u16,
        host: &str,
        path: &str,
        method: &str,
        headers: &dyn HeaderLookup,
        query: &str,
    ) -> Option<&'a RouteEntry> {
        let on_port = || {
            t.entries
                .iter()
                .filter(|e| e.listener_port == port && e.listener_hostname_matches(host))
        };
        let listeners = t
            .listeners
            .iter()
            .filter(|(p, h)| *p == port && h.as_deref().is_none_or(|h| hostname_matches(h, host)))
            .map(|(_, h)| listener_specificity(h.as_deref()));
        let best = on_port()
            .map(|e| listener_specificity(e.listener_hostname.as_deref()))
            .chain(listeners)
            .max()?;
        // (characters in the longest matching non-wildcard hostname, characters in
        // the longest matching hostname); a route that names none scores (0, 0).
        let host_score = |e: &RouteEntry| {
            if e.hostnames.is_empty() {
                return Some((0, 0));
            }
            e.hostnames
                .iter()
                .filter(|h| hostname_matches(h, host))
                .map(|h| {
                    if h.starts_with("*.") {
                        (0, h.len())
                    } else {
                        (h.len(), h.len())
                    }
                })
                .max()
        };
        let mut found: Option<((usize, usize), &RouteEntry)> = None;
        for e in on_port().filter(|e| listener_specificity(e.listener_hostname.as_deref()) == best) {
            let Some(score) = host_score(e) else { continue };
            // Entries are in precedence order: an equal score keeps the earlier one.
            if e.r#match.matches(path, method, headers, query) && found.is_none_or(|(s, _)| score > s) {
                found = Some((score, e));
            }
        }
        found.map(|(_, e)| e)
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
        let route_hosts: [&[&str]; 4] = [&[], &["a.example.com"], &["*.example.com"], &["x.svc.example.com"]];
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
            e.route_key = format!("ns/r{n}").into();
            entries.push(e);
        }
        // Listeners with no routes.
        let listeners = vec![
            (80, Some("c.example.com".into())),
            (443, Some("*.svc.example.com".into())),
        ];
        let mut t = RouteTable {
            entries,
            listeners,
            ..Default::default()
        };
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
                    let key =
                        |e: Option<&RouteEntry>| e.map(|e| (e.route_key.clone(), format!("{:?}", e.r#match.path)));
                    assert_eq!(key(got), key(want), "mismatch at port={port} host={host} path={path}");
                }
            }
        }
    }

    // A request belongs to the most specific listener that covers its host, also
    // when that listener has no routes: it must not get another listener's (T056).
    #[test]
    fn a_listener_without_routes_still_isolates_its_host() {
        let mut t = RouteTable {
            entries: vec![entry(PathMatch::Prefix("/".into()), 0)],
            listeners: vec![
                (80, None),
                (80, Some("bank.example".into())),
                (80, Some("*.shop.example".into())),
            ],
            ..Default::default()
        };
        t.sort();
        let h = http::HeaderMap::new();
        assert!(t.match_request(80, "other.example", "/", "GET", &h, "").is_some());
        assert!(t.match_request(80, "bank.example", "/", "GET", &h, "").is_none());
        assert!(t.match_request(80, "a.shop.example", "/", "GET", &h, "").is_none());
        // It does not take TLS connections from TLSRoutes on its port, though.
        assert!(t.serves_host(80, Some("other.example")));
        t.entries.clear();
        t.sort();
        assert!(!t.serves_host(80, Some("other.example")));
    }

    // Among the routes that match a request, the one whose hostname matches it most
    // specifically wins, before any match criteria: a route with no hostnames, or a
    // wildcard one with a longer path, never takes a request from a route that
    // names its exact host, nor does an older route with no hostnames (T018).
    #[test]
    fn route_hostname_precedes_match_precedence() {
        let route = |name: &str, hostnames: &[&str], path: PathMatch, created: i64| {
            let mut e = entry(path, 0);
            e.hostnames = hostnames.iter().map(|h| h.to_string()).collect();
            e.route_key = format!("ns/{name}").into();
            e.route_creation = created;
            e
        };
        let mut t = RouteTable {
            entries: vec![
                route("default", &[], PathMatch::Prefix("/".into()), 0),
                route("shop", &["shop.example"], PathMatch::Prefix("/".into()), 1),
                route("grab", &[], PathMatch::Prefix("/login".into()), 2),
                route("grab-wild", &["*.example"], PathMatch::Exact("/checkout".into()), 3),
                route("wild-longer", &["*.b.example"], PathMatch::Prefix("/".into()), 4),
            ],
            ..Default::default()
        };
        t.sort();
        let h = http::HeaderMap::new();
        let served = |host: &str, path: &str| t.match_request(80, host, path, "GET", &h, "").map(|e| &*e.route_key);
        assert_eq!(served("shop.example", "/login"), Some("ns/shop"));
        assert_eq!(served("SHOP.example", "/checkout"), Some("ns/shop"));
        assert_eq!(served("shop.example", "/"), Some("ns/shop"));
        assert_eq!(served("other.example", "/checkout"), Some("ns/grab-wild"));
        assert_eq!(served("other.example", "/login"), Some("ns/grab"));
        assert_eq!(served("a.b.example", "/checkout"), Some("ns/wild-longer"));
        assert_eq!(served("other.org", "/"), Some("ns/default"));
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
