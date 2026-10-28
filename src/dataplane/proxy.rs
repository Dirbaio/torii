//! What to do with a request, and the heads torii sends on its behalf: routing
//! against the current snapshot, the HTTPRoute filters (redirect, rewrite, header
//! modifiers, CORS), the forwarded headers, and the rewrite of request and response
//! heads between client and backend. Shared by HTTP/1 and HTTP/2.

use std::borrow::Cow;
use std::net::IpAddr;
use std::time::Duration;

use bytes::Bytes;

use super::h1::{Fields, RequestHead, ResponseHead, Version, reason};
use super::{ConnInfo, Ctx};
use crate::conn_limit::ConnPermit;
use crate::route_table::{BackendTls, Cors, Endpoint, Filters, HeaderMods, normalize_path, without_path_params};

/// The page torii answers its own errors with.
const ERROR_PAGE: &str = include_str!("error.html");

/// A response torii answers itself: an error page for an error, else no body.
#[derive(Debug)]
pub struct Local {
    pub status: u16,
    pub headers: Vec<(&'static str, String)>,
    pub body: Bytes,
}

impl Local {
    pub fn status(status: u16) -> Local {
        if status < 400 {
            return Local {
                status,
                headers: Vec::new(),
                body: Bytes::new(),
            };
        }
        let body = ERROR_PAGE
            .replace("{status}", &status.to_string())
            .replace("{reason}", reason(status));
        Local {
            status,
            headers: vec![
                ("cache-control", "private, no-store".to_string()),
                ("content-type", "text/html; charset=utf-8".to_string()),
            ],
            body: Bytes::from(body),
        }
    }
}

/// A request to forward to a backend.
pub struct Plan {
    pub endpoint: Endpoint,
    /// Rule-level filters merged with the chosen backendRef's.
    pub filters: Filters,
    /// The request-target to send: the normal (or rewritten) path and the query.
    pub target: String,
    /// The Host to send (the client's, or the rewrite's).
    pub host: Option<String>,
    /// The deadline for the backend to make progress (`--upstream-timeout`, or the
    /// rule's `timeouts`); None for none.
    pub timeout: Option<Duration>,
    /// The deadline for connecting to the backend.
    pub connect_timeout: Option<Duration>,
    /// The rule's `timeouts`, if any: also a deadline for the response head.
    pub deadline: Option<Duration>,
    /// The request's allowed Origin: add CORS headers to the response.
    pub cors_origin: Option<String>,
    pub forwarded: Forwarded,
    /// The request's slot under the request caps, held until it ends.
    pub _slot: ConnPermit,
}

/// Values for the `X-Forwarded-*` headers. They OVERWRITE any the client sent:
/// torii may face the internet directly, where an inbound X-Forwarded-For is
/// attacker-controlled and must not be honored (it would let a client spoof its
/// source IP past rate limits or geo-blocking).
pub struct Forwarded {
    pub client_ip: Option<IpAddr>,
    /// The client's Host, port stripped (before any rewrite).
    pub host: String,
    pub port: u16,
    pub scheme: &'static str,
}

pub enum Decision {
    Local(Local),
    Proxy(Box<Plan>),
}

/// The parts of a request-target.
struct Target<'a> {
    /// The authority of an absolute-form target.
    authority: Option<&'a [u8]>,
    path: &'a [u8],
    /// The query, `?` included, or empty.
    query: &'a [u8],
}

/// Split an origin-form (`/p?q`) or absolute-form (`http://host/p?q`) target.
/// Asterisk-form and authority-form (CONNECT) targets are refused.
fn split_target(target: &[u8]) -> Option<Target<'_>> {
    let (authority, rest) = if target.first() == Some(&b'/') {
        (None, target)
    } else {
        let lower = |n: usize| target.get(..n).map(<[u8]>::to_ascii_lowercase);
        let skip = if lower(7).as_deref() == Some(b"http://") {
            7
        } else if lower(8).as_deref() == Some(b"https://") {
            8
        } else {
            return None;
        };
        let rest = &target[skip..];
        let end = rest.iter().position(|&b| b == b'/' || b == b'?').unwrap_or(rest.len());
        (Some(&rest[..end]), &rest[end..])
    };
    let q = rest.iter().position(|&b| b == b'?').unwrap_or(rest.len());
    Some(Target {
        authority,
        path: &rest[..q],
        query: &rest[q..],
    })
}

/// Decide what to do with a request: answer it, or forward it.
pub fn decide(ctx: &Ctx, head: &RequestHead, conn: &ConnInfo) -> Decision {
    let Some(target) = split_target(head.target()) else {
        tracing::debug!("unsupported request-target -> 400");
        return Decision::Local(Local::status(400));
    };
    // From here on, routing, filters and the backend all see the path's normal form.
    let Some(path) = normalize_path(target.path, ctx.allow_encoded_slashes) else {
        tracing::debug!("malformed request path -> 400");
        return Decision::Local(Local::status(400));
    };

    // The target host: an absolute-form target's authority, else Host (HTTP/2's
    // `:authority` arrives as Host). Two Hosts are ambiguous.
    let mut hosts = head.fields.get_all("host");
    let host_field = match (hosts.next(), hosts.next()) {
        (_, Some(_)) => return Decision::Local(Local::status(400)),
        (h, None) => h,
    };
    if host_field.is_none() && target.authority.is_none() && head.version == Version::Http11 {
        return Decision::Local(Local::status(400));
    }
    let authority = target.authority.or(host_field).unwrap_or_default();
    let Ok(authority) = std::str::from_utf8(authority) else {
        return Decision::Local(Local::status(400));
    };
    let host = host_from_authority(authority).unwrap_or_default().to_string();
    // A host torii routes on, echoes in X-Forwarded-Host and redirects to is a
    // name or an IP address, nothing else (T117: `@`, `/` or `?` in a Host made a
    // redirect point elsewhere).
    if !host.bytes().all(|b| b.is_ascii_alphanumeric() || b"-._:%".contains(&b)) {
        tracing::debug!(%host, "malformed host -> 400");
        return Decision::Local(Local::status(400));
    }
    let query = std::str::from_utf8(target.query).unwrap_or("");
    let query_params = query.strip_prefix('?').unwrap_or(query);
    let method = head.method();

    let forwarded = Forwarded {
        client_ip: conn.peer,
        host: host.clone(),
        port: conn.port,
        scheme: if conn.tls { "https" } else { "http" },
    };

    let snapshot = ctx.data_plane.load();
    let routes = &snapshot.routes;
    let entry = routes.match_request(conn.port, &host, &path, method, &head.fields, query_params);
    // Tomcat, Jetty and others drop `;params` from path segments before they route
    // (`/admin;x/panel` is their `/admin/panel`), and most backends don't. Where the
    // params decide the rule, one kind of backend gets a path its rule was not meant
    // to let through, so refuse the request.
    if path.contains(';') {
        let bare = without_path_params(&path);
        let bare_entry = routes.match_request(conn.port, &host, &bare, method, &head.fields, query_params);
        if entry.map(std::ptr::from_ref) != bare_entry.map(std::ptr::from_ref) {
            tracing::debug!(%host, %path, "path parameters change the route -> 400");
            return Decision::Local(Local::status(400));
        }
    }
    let Some(entry) = entry else {
        tracing::debug!(%host, %path, %method, "no route matched -> 404");
        return Decision::Local(Local::status(404));
    };

    // CORS: answer a preflight here; for an actual request, add headers to the
    // response later.
    let mut cors_origin = None;
    if let Some(cors) = &entry.rule.filters.cors {
        let origin = head.fields.get_str("origin").unwrap_or("");
        let allowed = !origin.is_empty() && cors.allows_origin(origin);
        if method.eq_ignore_ascii_case("OPTIONS") && head.fields.get("access-control-request-method").is_some() {
            let mut local = Local::status(204);
            if allowed {
                let req_method = head.fields.get_str("access-control-request-method").unwrap_or("");
                let req_headers = head.fields.get_str("access-control-request-headers").unwrap_or("");
                cors_preflight_headers(&mut local.headers, cors, origin, req_method, req_headers);
            }
            return Decision::Local(local);
        }
        if allowed {
            cors_origin = Some(origin.to_string());
        }
    }

    // A RequestRedirect filter produces an early 3xx response — no upstream.
    if let Some(redirect) = &entry.rule.filters.redirect {
        if host.is_empty() && redirect.hostname.is_none() {
            // No host to send the client to (T117: `https:///evil.test/x`).
            return Decision::Local(Local::status(400));
        }
        let location = build_redirect_location(redirect, entry, &host, &path, conn.port, conn.tls);
        tracing::debug!(%host, %path, status = redirect.status_code, "redirect");
        let mut local = Local::status(redirect.status_code);
        local.headers.push(("location", location));
        return Decision::Local(local);
    }

    match entry.pick_endpoint(next_rng()) {
        Some((ep, _)) if matches!(ep.tls, BackendTls::Invalid) => {
            // The backend is targeted by an INVALID BackendTLSPolicy. We must not
            // fall back to plaintext — fail the request (Gateway API: 5xx).
            tracing::debug!(%host, %path, "backend has an invalid BackendTLSPolicy -> 500");
            Decision::Local(Local::status(500))
        }
        Some((ep, backend)) => {
            let Some(slot) = ctx.limiter.admit_request(conn.peer) else {
                tracing::debug!(%host, %path, "over the request caps -> 503");
                return Decision::Local(Local::status(503));
            };
            tracing::debug!(%host, %path, %method, ip = %ep.ip, port = ep.port, "matched route");
            let filters = entry.rule.filters.merged_with(&backend.filters);
            let query = String::from_utf8_lossy(target.query);
            let target = match entry.rewrite_path(&path) {
                Some(rewritten) => format!("{rewritten}{query}"),
                None => format!("{path}{query}"),
            };
            let rewrite_host = filters.url_rewrite.as_ref().and_then(|rw| rw.hostname.clone());
            let host = rewrite_host.or_else(|| (!authority.is_empty()).then(|| authority.to_string()));
            // The rule's `timeouts` replace the default backend timeout ("0s"
            // disables it), and can only shorten the connect deadline.
            let timeout = match entry.rule.request_timeout {
                None => ctx.timeouts.response,
                Some(t) => Some(t).filter(|t| !t.is_zero()),
            };
            let connect_timeout = ctx.timeouts.connect.into_iter().chain(timeout).min();
            let deadline = entry.rule.request_timeout.filter(|t| !t.is_zero());
            Decision::Proxy(Box::new(Plan {
                endpoint: ep.clone(),
                filters,
                target,
                host,
                timeout,
                connect_timeout,
                deadline,
                cors_origin,
                forwarded,
                _slot: slot,
            }))
        }
        None => {
            // A rule matched but its backend is invalid/unresolvable. Gateway API
            // requires HTTP 500 here (not 404).
            tracing::debug!(%host, %path, %method, "matched route with no valid backend -> 500");
            Decision::Local(Local::status(500))
        }
    }
}

/// How the request body goes to the backend.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UpstreamBody {
    None,
    Length(u64),
    Chunked,
}

/// Request fields that are about the connection, or that torii sets itself.
const REQUEST_DROPPED: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-connection",
    "te",
    "transfer-encoding",
    "upgrade",
    "trailer",
    "host",
    "content-length",
    "expect",
    "x-forwarded-for",
    "x-forwarded-host",
    "x-forwarded-port",
    "x-forwarded-proto",
    "x-forwarded-scheme",
    // Other forwarding fields a client could use to claim another address, next
    // to the X-Forwarded-For torii sets (T108).
    "forwarded",
    "x-real-ip",
];

/// Response fields that are about the connection, or that torii sets itself.
const RESPONSE_DROPPED: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-connection",
    "te",
    "transfer-encoding",
    "upgrade",
    "trailer",
    "content-length",
];

/// A field list being rewritten.
type FieldList<'a> = Vec<(Cow<'a, [u8]>, Cow<'a, [u8]>)>;

fn is_named(name: &[u8], set: &[&str]) -> bool {
    set.iter().any(|n| name.eq_ignore_ascii_case(n.as_bytes()))
}

/// The fields of `fields` minus `dropped` and minus any field the `Connection`
/// field names (RFC 9110 §7.6.1).
fn passed_fields<'a>(fields: &'a Fields, dropped: &[&str]) -> FieldList<'a> {
    let listed: Vec<&[u8]> = fields
        .get_all("connection")
        .flat_map(|v| v.split(|&b| b == b','))
        .map(<[u8]>::trim_ascii)
        .filter(|t| !t.is_empty())
        .collect();
    fields
        .iter()
        .filter(|(n, _)| !is_named(n, dropped) && !listed.iter().any(|l| l.eq_ignore_ascii_case(n)))
        .map(|(n, v)| (Cow::Borrowed(n), Cow::Borrowed(v)))
        .collect()
}

/// Apply a [`HeaderMods`] (set/add/remove) to a field list.
fn apply_mods<'a>(list: &mut FieldList<'a>, mods: &'a HeaderMods) {
    // Fields about the message's framing or the connection are torii's: a filter
    // that sets them would make torii and the peer read different message
    // boundaries (T129).
    let allowed = |name: &str| !is_named(name.as_bytes(), MOD_PROTECTED);
    for (name, value) in mods.set.iter().filter(|(n, _)| allowed(n)) {
        set_field(list, name, value.as_bytes().to_vec());
    }
    for (name, value) in mods.add.iter().filter(|(n, _)| allowed(n)) {
        list.push((Cow::Borrowed(name.as_bytes()), Cow::Borrowed(value.as_bytes())));
    }
    for name in mods.remove.iter().filter(|n| allowed(n)) {
        list.retain(|(n, _)| !n.eq_ignore_ascii_case(name.as_bytes()));
    }
}

/// Fields header filters may not touch (see [`apply_mods`]).
const MOD_PROTECTED: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-connection",
    "te",
    "transfer-encoding",
    "upgrade",
    "trailer",
    "content-length",
];

/// Replace every field `name` with one holding `value`.
fn set_field<'a>(list: &mut FieldList<'a>, name: &'a str, value: Vec<u8>) {
    list.retain(|(n, _)| !n.eq_ignore_ascii_case(name.as_bytes()));
    list.push((Cow::Borrowed(name.as_bytes()), Cow::Owned(value)));
}

/// The head of the request to the backend, ready to write.
pub fn upstream_head(head: &RequestHead, plan: &Plan, body: UpstreamBody, upgrade: Option<&[u8]>) -> Vec<u8> {
    let mut list = passed_fields(&head.fields, REQUEST_DROPPED);
    // A field name with `_` is dropped, as nginx does: CGI-style backends read
    // `X_Forwarded_For` as `X-Forwarded-For`, so a client could pass a field that
    // torii manages or strips under another spelling (T103).
    list.retain(|(n, _)| !n.contains(&b'_'));
    if head.version == Version::Http2 {
        // HTTP/2 splits Cookie into one field per pair; an HTTP/1.1 recipient wants
        // them as one (RFC 9113 §8.2.3).
        let cookies: Vec<&[u8]> = head.fields.get_all("cookie").collect();
        if cookies.len() > 1 {
            set_field(&mut list, "cookie", cookies.join(&b"; "[..]));
        }
    }
    // Forwarded headers, set before the filters so that an explicit
    // RequestHeaderModifier still wins.
    let fwd = &plan.forwarded;
    if let Some(ip) = fwd.client_ip {
        list.push((
            Cow::Borrowed(b"X-Forwarded-For"),
            Cow::Owned(ip.to_string().into_bytes()),
        ));
    }
    // In Host syntax: an IPv6 literal in brackets, and none without a host (T120).
    if fwd.host.contains(':') {
        let bracketed = format!("[{}]", fwd.host);
        list.push((Cow::Borrowed(b"X-Forwarded-Host"), Cow::Owned(bracketed.into_bytes())));
    } else if !fwd.host.is_empty() {
        list.push((
            Cow::Borrowed(b"X-Forwarded-Host"),
            Cow::Owned(fwd.host.clone().into_bytes()),
        ));
    }
    list.push((
        Cow::Borrowed(b"X-Forwarded-Port"),
        Cow::Owned(fwd.port.to_string().into_bytes()),
    ));
    list.push((
        Cow::Borrowed(b"X-Forwarded-Proto"),
        Cow::Borrowed(fwd.scheme.as_bytes()),
    ));
    list.push((
        Cow::Borrowed(b"X-Forwarded-Scheme"),
        Cow::Borrowed(fwd.scheme.as_bytes()),
    ));
    apply_mods(&mut list, &plan.filters.request_headers);

    let mut out = Vec::with_capacity(256 + list.iter().map(|(n, v)| n.len() + v.len() + 4).sum::<usize>());
    out.extend_from_slice(head.method().as_bytes());
    out.push(b' ');
    out.extend_from_slice(plan.target.as_bytes());
    out.extend_from_slice(b" HTTP/1.1\r\n");
    if let Some(host) = &plan.host {
        push_field(&mut out, b"Host", host.as_bytes());
    }
    for (name, value) in &list {
        push_field(&mut out, name, value);
    }
    match body {
        UpstreamBody::None => {}
        UpstreamBody::Length(n) => push_field(&mut out, b"Content-Length", n.to_string().as_bytes()),
        UpstreamBody::Chunked => push_field(&mut out, b"Transfer-Encoding", b"chunked"),
    }
    if let Some(protocol) = upgrade {
        push_field(&mut out, b"Connection", b"upgrade");
        push_field(&mut out, b"Upgrade", protocol);
    }
    out.extend_from_slice(b"\r\n");
    out
}

fn push_field(out: &mut Vec<u8>, name: &[u8], value: &[u8]) {
    out.extend_from_slice(name);
    out.extend_from_slice(b": ");
    out.extend_from_slice(value);
    out.extend_from_slice(b"\r\n");
}

/// Response fields a CORS filter owns. The backend's are dropped, so that a
/// client gets only what the filter allows: a backend's own
/// `Access-Control-Allow-Credentials: true` next to an Origin the filter echoes,
/// or its own reflected Origin for one the filter rejects, would grant reads the
/// route's policy does not (GEP-1767 makes the gateway the CORS authority).
const CORS_OWNED: &[&str] = &[
    "access-control-allow-origin",
    "access-control-allow-credentials",
    "access-control-expose-headers",
    "access-control-allow-methods",
    "access-control-allow-headers",
    "access-control-max-age",
];

/// The fields of the response to the client: the backend's, minus the ones about
/// its connection, with CORS and then the response filters applied (so that an
/// explicit ResponseHeaderModifier still wins). Framing fields are the caller's.
pub fn response_fields<'a>(resp: &'a ResponseHead, plan: &'a Plan) -> FieldList<'a> {
    let mut list = passed_fields(&resp.fields, RESPONSE_DROPPED);
    if resp.status == 101 {
        // A switched protocol keeps its Upgrade.
        for v in resp.fields.get_all("upgrade") {
            list.push((Cow::Borrowed(b"upgrade"), Cow::Borrowed(v)));
        }
    }
    if let Some(cors) = &plan.filters.cors {
        list.retain(|(n, _)| !is_named(n, CORS_OWNED));
        if let Some(origin) = &plan.cors_origin {
            let mut extra = Vec::new();
            cors_headers(&mut extra, cors, origin);
            for (name, value) in extra {
                list.push((Cow::Borrowed(name.as_bytes()), Cow::Owned(value.into_bytes())));
            }
        }
    }
    apply_mods(&mut list, &plan.filters.response_headers);
    list
}

/// The fields of an interim (1xx) response to pass on: the backend's, minus the
/// ones about its connection.
pub fn interim_fields(resp: &ResponseHead) -> FieldList<'_> {
    passed_fields(&resp.fields, RESPONSE_DROPPED)
}

/// Write an HTTP/1.1 response head.
pub fn h1_response_head<'a>(
    status: u16,
    reason: &[u8],
    fields: impl IntoIterator<Item = (&'a [u8], &'a [u8])>,
    framing: &[(&[u8], &[u8])],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(512);
    out.extend_from_slice(b"HTTP/1.1 ");
    out.extend_from_slice(status.to_string().as_bytes());
    out.push(b' ');
    out.extend_from_slice(reason);
    out.extend_from_slice(b"\r\n");
    for (name, value) in fields {
        push_field(&mut out, name, value);
    }
    for (name, value) in framing {
        push_field(&mut out, name, value);
    }
    out.extend_from_slice(b"\r\n");
    out
}

/// Write the CORS headers for an allowed *actual* (non-preflight) request.
fn cors_headers(out: &mut Vec<(&'static str, String)>, cors: &Cors, origin: &str) {
    // Echo the specific origin (required when credentials are allowed).
    out.push(("access-control-allow-origin", origin.to_string()));
    if cors.allow_credentials {
        out.push(("access-control-allow-credentials", "true".to_string()));
    }
    if !cors.expose_headers.is_empty() {
        out.push(("access-control-expose-headers", cors.expose_headers.join(", ")));
    }
    // The Allow-Origin value is selected per request Origin, so the response is not
    // safely cacheable across origins. Advertise that with `Vary: Origin` (RFC 9110
    // §12.5.5), appended to any Vary the upstream set.
    out.push(("vary", "Origin".to_string()));
}

/// Write the CORS headers for an allowed preflight request. A `*` in allow-methods
/// or allow-headers is expanded by echoing the request's requested method/headers.
fn cors_preflight_headers(
    out: &mut Vec<(&'static str, String)>,
    cors: &Cors,
    origin: &str,
    req_method: &str,
    req_headers: &str,
) {
    cors_headers(out, cors, origin);
    let methods = expand_wildcard(&cors.allow_methods, req_method);
    if !methods.is_empty() {
        out.push(("access-control-allow-methods", methods));
    }
    let headers = expand_wildcard(&cors.allow_headers, req_headers);
    if !headers.is_empty() {
        out.push(("access-control-allow-headers", headers));
    }
    if let Some(age) = cors.max_age {
        out.push(("access-control-max-age", age.to_string()));
    }
    // A `*` allow-list echoes the request's method/headers, so the preflight
    // response also varies on those request headers.
    out.push(("vary", "Access-Control-Request-Method".to_string()));
    out.push(("vary", "Access-Control-Request-Headers".to_string()));
}

/// Join a CORS allow-list, expanding a sole `*` to the requested value.
fn expand_wildcard(allow: &[String], requested: &str) -> String {
    if allow.iter().any(|v| v == "*") {
        requested.to_string()
    } else {
        allow.join(", ")
    }
}

/// A cheap per-request pseudo-random value for weighted backend selection.
/// splitmix64 over a counter — good enough for traffic distribution (not
/// security-sensitive).
pub fn next_rng() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static STATE: AtomicU64 = AtomicU64::new(0x9E3779B97F4A7C15);
    let mut x = STATE.fetch_add(0x9E3779B97F4A7C15, Ordering::Relaxed);
    x ^= x >> 30;
    x = x.wrapping_mul(0xBF58476D1CE4E5B9);
    x ^= x >> 27;
    x = x.wrapping_mul(0x94D049BB133111EB);
    x ^= x >> 31;
    x
}

/// Build the `Location` header value for a RequestRedirect filter, defaulting
/// each component to the incoming request's value.
///
/// Port inference (Gateway API): use the explicit redirect port if set; otherwise,
/// if the redirect scheme is set, omit the port (the client infers the scheme's
/// default); otherwise reuse the listener port the request arrived on. The port
/// is also omitted when it equals the scheme's default (80/http, 443/https).
fn build_redirect_location(
    redirect: &crate::route_table::Redirect,
    entry: &crate::route_table::RouteEntry,
    req_host: &str,
    req_path: &str,
    listener_port: u16,
    inbound_is_tls: bool,
) -> String {
    // Default scheme to the inbound listener's scheme (https for a TLS listener).
    let default_scheme = if inbound_is_tls { "https" } else { "http" };
    let scheme = redirect.scheme.as_deref().unwrap_or(default_scheme);
    let host = redirect.hostname.as_deref().unwrap_or(req_host);
    // An IPv6 literal goes in brackets.
    let host = if host.contains(':') {
        Cow::Owned(format!("[{host}]"))
    } else {
        Cow::Borrowed(host)
    };
    let path = match &redirect.path {
        Some(rw) => entry.apply_path_rewrite(rw, req_path),
        None => req_path.to_string(),
    };

    let port: Option<u16> = match redirect.port {
        Some(p) => Some(p),
        None if redirect.scheme.is_some() => None, // infer from scheme → omit
        None => Some(listener_port),               // reuse the listener port
    };
    // Omit the port if it's the scheme's default.
    let port = port.filter(|p| !is_default_port(scheme, *p));

    match port {
        Some(p) => format!("{scheme}://{host}:{p}{path}"),
        None => format!("{scheme}://{host}{path}"),
    }
}

fn is_default_port(scheme: &str, port: u16) -> bool {
    matches!((scheme, port), ("http", 80) | ("https", 443))
}

/// Split a `host:port`, `[host]:port`, or `[host%zone]:port` authority into its
/// `(host, port)` parts, unbracketing an IPv6 literal. A faithful port of Go's
/// `net.SplitHostPort` (the stdlib gets the IPv6-bracket and stray-bracket cases
/// right), so it returns an error — rather than silently passing garbage through —
/// for a malformed authority. Like Go, it REQUIRES a port: a bare host with no
/// `:port` is `MissingPort` (the caller decides how to treat that).
fn split_host_port(hostport: &str) -> Result<(&str, &str), HostPortError> {
    let b = hostport.as_bytes();
    // The port starts after the last colon.
    let Some(i) = b.iter().rposition(|&c| c == b':') else {
        return Err(HostPortError::MissingPort);
    };

    let host;
    let (mut j, mut k) = (0usize, 0usize);
    if b[0] == b'[' {
        // Expect the first ']' just before the last ':'.
        let Some(end) = b.iter().position(|&c| c == b']') else {
            return Err(HostPortError::MissingRBracket);
        };
        if end + 1 == hostport.len() {
            // There can't be a ':' behind the ']' now.
            return Err(HostPortError::MissingPort);
        } else if end + 1 == i {
            // The expected result. (fallthrough)
        } else {
            // Either ']' isn't followed by a colon, or it's followed by a colon
            // that is not the last one.
            if b[end + 1] == b':' {
                return Err(HostPortError::TooManyColons);
            }
            return Err(HostPortError::MissingPort);
        }
        host = &hostport[1..end];
        j = 1;
        k = end + 1; // there can't be a '[' resp. ']' before these positions
    } else {
        host = &hostport[..i];
        if host.as_bytes().contains(&b':') {
            return Err(HostPortError::TooManyColons);
        }
    }
    if hostport.as_bytes()[j..].contains(&b'[') {
        return Err(HostPortError::UnexpectedLBracket);
    }
    if hostport.as_bytes()[k..].contains(&b']') {
        return Err(HostPortError::UnexpectedRBracket);
    }

    let port = &hostport[i + 1..];
    Ok((host, port))
}

/// Why an authority string isn't a valid `host:port` (mirrors Go's `AddrError`).
#[derive(Debug, PartialEq, Eq)]
enum HostPortError {
    MissingPort,
    TooManyColons,
    MissingRBracket,
    UnexpectedLBracket,
    UnexpectedRBracket,
}

/// Extract just the host from a Host header / `:authority`, dropping any `:port`
/// and unbracketing an IPv6 literal. Unlike [`split_host_port`], a bare host with
/// no port is valid here (a Host header usually omits the port) — that's the only
/// "error" we tolerate. Any genuinely malformed authority (too many colons,
/// unbalanced brackets) yields `None`, so we route it to a 404 / empty host rather
/// than forwarding garbage as `X-Forwarded-Host`.
pub fn host_from_authority(authority: &str) -> Option<&str> {
    match split_host_port(authority) {
        Ok((host, _)) => Some(host),
        // No port: the whole string is the host. Unbracket a bare IPv6 literal
        // (`[::1]`), but reject an unterminated bracket as malformed.
        Err(HostPortError::MissingPort) => match authority.strip_prefix('[') {
            None => Some(authority),
            Some(rest) => rest.strip_suffix(']'),
        },
        // Too many colons / stray brackets → malformed.
        Err(_) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_target_forms() {
        let t = split_target(b"/a/b?x=1").unwrap();
        assert_eq!((t.authority, t.path, t.query), (None, &b"/a/b"[..], &b"?x=1"[..]));
        let t = split_target(b"HTTP://h.example:8080?q").unwrap();
        assert_eq!(
            (t.authority, t.path, t.query),
            (Some(&b"h.example:8080"[..]), &b""[..], &b"?q"[..])
        );
        let t = split_target(b"https://h/p").unwrap();
        assert_eq!((t.authority, t.path), (Some(&b"h"[..]), &b"/p"[..]));
        assert!(split_target(b"*").is_none());
        assert!(split_target(b"h.example:443").is_none());
    }

    #[test]
    fn split_host_port_ok() {
        assert_eq!(split_host_port("example.com:443"), Ok(("example.com", "443")));
        assert_eq!(split_host_port("10.0.0.1:8080"), Ok(("10.0.0.1", "8080")));
        assert_eq!(split_host_port("[::1]:443"), Ok(("::1", "443")));
        assert_eq!(split_host_port("[2001:db8::1]:8443"), Ok(("2001:db8::1", "8443")));
        assert_eq!(split_host_port("[fe80::1%lo0]:53"), Ok(("fe80::1%lo0", "53")));
        // Empty host or port halves are allowed by Go (it only checks structure).
        assert_eq!(split_host_port(":80"), Ok(("", "80")));
        assert_eq!(split_host_port("example.com:"), Ok(("example.com", "")));
    }

    #[test]
    fn split_host_port_errors() {
        use HostPortError::*;
        // No colon at all → missing port.
        assert_eq!(split_host_port("example.com"), Err(MissingPort));
        // Bare IPv6 (multiple colons, no brackets) → too many colons.
        assert_eq!(split_host_port("::1"), Err(TooManyColons));
        assert_eq!(split_host_port("2001:db8::1"), Err(TooManyColons));
        // Bracketed literal with no port → missing port.
        assert_eq!(split_host_port("[::1]"), Err(MissingPort));
        // Unterminated bracket.
        assert_eq!(split_host_port("[::1:80"), Err(MissingRBracket));
        // ']' not immediately followed by the final ':' → too many / missing port.
        assert_eq!(split_host_port("[::1]extra:80"), Err(MissingPort));
        // Stray brackets in a non-bracketed host.
        assert_eq!(split_host_port("a]b:80"), Err(UnexpectedRBracket));
    }

    // host_from_authority is the caller-side adapter: a bare host (no port) is fine,
    // IPv6 literals are unbracketed, genuine garbage is rejected (None → 404).
    #[test]
    fn host_from_authority_extracts_host() {
        // With a port.
        assert_eq!(host_from_authority("example.com:443"), Some("example.com"));
        assert_eq!(host_from_authority("[::1]:443"), Some("::1"));
        // Without a port (the common Host-header case).
        assert_eq!(host_from_authority("example.com"), Some("example.com"));
        assert_eq!(host_from_authority("10.0.0.1"), Some("10.0.0.1"));
        // Bare bracketed IPv6, no port → unbracketed.
        assert_eq!(host_from_authority("[::1]"), Some("::1"));
        assert_eq!(host_from_authority("[2001:db8::1]"), Some("2001:db8::1"));
    }

    #[test]
    fn host_from_authority_rejects_garbage() {
        // Bare (unbracketed) IPv6 is malformed as an authority.
        assert_eq!(host_from_authority("::1"), None);
        assert_eq!(host_from_authority("2001:db8::1"), None);
        // Unterminated / stray brackets.
        assert_eq!(host_from_authority("[::1"), None);
        assert_eq!(host_from_authority("[::1]extra:80"), None);
    }
}
