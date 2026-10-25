//! The Pingora-based data plane.
//!
//! A `ProxyHttp` implementation that, per request, reads the current
//! [`RouteTable`] snapshot, matches the request, and forwards to a backend pod.
//! Returns 404 when nothing matches.
//!
//! Pingora's `Server::run_forever` is blocking and manages its own tokio
//! runtime, so this runs on a dedicated OS thread, separate from the kube
//! controller's runtime. They share state only through the [`DataPlane`] snapshot.

use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use pingora_core::prelude::*;
use pingora_core::upstreams::peer::HttpPeer;
use pingora_http::ResponseHeader;
use pingora_proxy::{ProxyHttp, Session, http_proxy};

use crate::conn_limit::{ConnLimiter, ConnLimits, ConnPermit};
use crate::route_table::{BackendTls, Endpoint, Filters, HeaderMods, normalize_path, without_path_params};
use crate::snapshot::DataPlane;
use crate::tls_table::TlsDecision;

/// The proxy. Holds the shared snapshot handle.
pub struct GatewayProxy {
    data_plane: DataPlane,
    /// Ports that terminate TLS (HTTPS listeners). Used so redirects from an
    /// HTTPS listener default their scheme to `https`.
    tls_ports: Vec<u16>,
    timeouts: UpstreamTimeouts,
    /// Forward request paths with an encoded `/` or `\` (see [`normalize_path`]).
    allow_encoded_slashes: bool,
}

/// Deadlines for torii's connections and requests to backends (the `--upstream-*`
/// flags; `None` disables one). Pingora sets none by default, so a backend that
/// never answered (an endpoint that drops SYNs, a BackendTLSPolicy endpoint that
/// never finishes the handshake, a server that never sends its response) held the
/// request, its task and its sockets for minutes or forever. A client that gives up
/// does not end a connect either: Pingora only watches the client once it has the
/// backend connection.
#[derive(Clone, Copy, Debug)]
pub struct UpstreamTimeouts {
    /// For connecting to a backend, TLS handshake included.
    pub connect: Option<std::time::Duration>,
    /// How long a backend may go without sending or accepting data during a request,
    /// the wait for its response included, for HTTPRoute rules without `timeouts`.
    pub response: Option<std::time::Duration>,
}

/// Per-request state carried between the proxy phases.
#[derive(Default)]
pub struct RequestCtx {
    upstream: Option<Endpoint>,
    /// Filters to apply to the matched route's request/response.
    filters: Filters,
    /// Rewritten request path (from a URL-rewrite filter), if any.
    rewrite_path: Option<String>,
    /// The matched rule's `timeouts` (see `RouteEntry::request_timeout`).
    request_timeout: Option<std::time::Duration>,
    /// If set, the request's allowed Origin — add CORS headers to the response.
    cors_origin: Option<String>,
    /// Forwarded-header values captured from the inbound connection in
    /// `request_filter` (the only phase with `Session` access), emitted to the
    /// upstream in `upstream_request_filter`. We OVERWRITE any client-supplied
    /// `X-Forwarded-*` rather than appending: torii may sit directly on the
    /// public internet with no trusted proxy in front, so an inbound XFF is
    /// attacker-controlled and must not be honored (it would let a client spoof
    /// its source IP past rate-limits / geo-blocking).
    fwd: Forwarded,
}

/// Values for the `X-Forwarded-*` headers, captured from the inbound request.
#[derive(Default)]
struct Forwarded {
    /// Client IP (no port), for `X-Forwarded-For`.
    client_ip: Option<String>,
    /// Original `Host` header (with any port stripped), for `X-Forwarded-Host`.
    /// Captured before a URLRewrite filter can rewrite `Host`.
    host: String,
    /// Listener port the request arrived on, for `X-Forwarded-Port`.
    port: u16,
    /// `https` for a TLS listener, else `http`; for `X-Forwarded-Proto`/`-Scheme`.
    scheme: &'static str,
}

impl GatewayProxy {
    pub fn new(
        data_plane: DataPlane,
        tls_ports: Vec<u16>,
        timeouts: UpstreamTimeouts,
        allow_encoded_slashes: bool,
    ) -> Self {
        GatewayProxy {
            data_plane,
            tls_ports,
            timeouts,
            allow_encoded_slashes,
        }
    }
}

#[async_trait]
impl ProxyHttp for GatewayProxy {
    type CTX = RequestCtx;

    fn new_ctx(&self) -> Self::CTX {
        RequestCtx::default()
    }

    /// Bound how long an h1 connection may idle before its next request. Pingora's
    /// `read_request()` switches the connection's idle timeout to "infinite" for
    /// HTTP/1.1 (and for `Connection: keep-alive`), and its keep-alive loop carries
    /// that on to every later request: after one request, a client that sends nothing
    /// more (or an unfinished head) held the connection forever. This runs right
    /// after `read_request()` on both h1 paths, before any response.
    async fn early_request_filter(&self, session: &mut Session, _ctx: &mut Self::CTX) -> Result<()> {
        // None: the connection closes after this request. Also None for h2.
        if session.get_keepalive().is_some() {
            session.set_keepalive(Some(H1_IDLE_TIMEOUT.as_secs()));
        }
        Ok(())
    }

    /// Match the request against the route table and stash the chosen backend.
    /// If nothing matches, send a 404 and short-circuit.
    async fn request_filter(&self, session: &mut Session, ctx: &mut Self::CTX) -> Result<bool> {
        // From here on, routing, filters and the backend all see the path's normal form.
        let Some(path) = normalize_request_path(session.req_header_mut(), self.allow_encoded_slashes) else {
            tracing::debug!(uri = %session.req_header().uri, "malformed request path -> 400");
            session.respond_error(400).await?;
            return Ok(true);
        };
        let req = session.req_header();
        let query = req.uri.query().unwrap_or("").to_string();
        let method = req.method.as_str().to_string();
        // Determine the request's target host. HTTP/2 carries it in the `:authority`
        // pseudo-header (surfaced by pingora on the request URI); HTTP/1.1 carries it
        // in the `Host` header. Per RFC 9113 §8.3.1, when `:authority` is present the
        // `Host` header MUST NOT be used — so prefer the URI authority, and only fall
        // back to `Host` for HTTP/1.1 (where the URI has no authority).
        let host = req
            .uri
            .host()
            .or_else(|| req.headers.get("host").and_then(|v| v.to_str().ok()))
            .and_then(host_from_authority)
            .unwrap_or_default()
            .to_string();
        let headers = req.headers.clone();

        // The listener port is the local (server) port the connection landed on,
        // so multi-listener Gateways route correctly per port.
        let port = session
            .server_addr()
            .and_then(|a| a.as_inet())
            .map(|a| a.port())
            .unwrap_or(0);

        // Capture the forwarded-header values now, while we have the Session and
        // the original (pre-rewrite) Host. Emitted to the upstream later.
        ctx.fwd = Forwarded {
            client_ip: session
                .client_addr()
                .and_then(|a| a.as_inet())
                .map(|a| a.ip().to_string()),
            host: host.clone(),
            port,
            scheme: if self.tls_ports.contains(&port) {
                "https"
            } else {
                "http"
            },
        };

        let snapshot = self.data_plane.load();
        let entry = snapshot
            .routes
            .match_request(port, &host, &path, &method, &headers, &query);
        // Tomcat, Jetty and others drop `;params` from path segments before they route
        // (`/admin;x/panel` is their `/admin/panel`), and most backends don't. Where
        // the params decide the rule, one kind of backend gets a path its rule was not
        // meant to let through, so refuse the request.
        if path.contains(';') {
            let bare = without_path_params(&path);
            let bare_entry = snapshot
                .routes
                .match_request(port, &host, &bare, &method, &headers, &query);
            if entry.map(std::ptr::from_ref) != bare_entry.map(std::ptr::from_ref) {
                tracing::debug!(%host, %path, "path parameters change the route -> 400");
                session.respond_error(400).await?;
                return Ok(true);
            }
        }
        let Some(entry) = entry else {
            tracing::debug!(%host, %path, %method, "no route matched -> 404");
            session.respond_error(404).await?;
            return Ok(true);
        };

        // CORS: handle preflight here; for actual requests, stash to add headers
        // to the response later.
        if let Some(cors) = &entry.filters.cors {
            let origin = headers.get("origin").and_then(|v| v.to_str().ok()).unwrap_or("");
            let allowed = !origin.is_empty() && cors.allows_origin(origin);
            if method.eq_ignore_ascii_case("OPTIONS") && headers.contains_key("access-control-request-method") {
                // Preflight: respond directly. Echo the requested method/headers
                // when the filter allows "*".
                let req_method = headers
                    .get("access-control-request-method")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("");
                let req_headers = headers
                    .get("access-control-request-headers")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("");
                let mut resp = ResponseHeader::build(204, None)?;
                if allowed {
                    write_cors_preflight(&mut resp, cors, origin, req_method, req_headers);
                }
                resp.insert_header("Content-Length", "0")?;
                session.write_response_header(Box::new(resp), true).await?;
                return Ok(true);
            }
            if allowed {
                ctx.cors_origin = Some(origin.to_string());
            }
        }

        // A RequestRedirect filter produces an early 3xx response — no upstream.
        if let Some(redirect) = &entry.filters.redirect {
            let is_tls = self.tls_ports.contains(&port);
            let location = build_redirect_location(redirect, entry, &host, &path, port, is_tls);
            let mut resp = ResponseHeader::build(redirect.status_code, None)?;
            resp.insert_header("Location", location)?;
            resp.insert_header("Content-Length", "0")?;
            session.write_response_header(Box::new(resp), true).await?;
            tracing::debug!(%host, %path, status = redirect.status_code, "redirect");
            return Ok(true);
        }

        ctx.request_timeout = entry.request_timeout;

        match entry.pick_endpoint(next_rng()) {
            Some((ep, _)) if matches!(ep.tls, BackendTls::Invalid) => {
                // The backend is targeted by an INVALID BackendTLSPolicy. We must
                // not fall back to plaintext — fail the request (Gateway API: 5xx).
                tracing::debug!(%host, %path, "backend has an invalid BackendTLSPolicy -> 500");
                session.respond_error(500).await?;
                Ok(true)
            }
            Some((ep, backend)) => {
                tracing::debug!(%host, %path, %method, ip = %ep.ip, port = ep.port, "matched route");
                // Rule-level filters plus the chosen backend's per-backendRef filters.
                ctx.filters = entry.filters.merged_with(&backend.filters);
                ctx.rewrite_path = entry.rewrite_path(&path);
                ctx.upstream = Some(ep.clone());
                Ok(false) // continue to upstream_peer
            }
            None => {
                // A rule matched but its backend is invalid/unresolvable.
                // Gateway API requires HTTP 500 here (not 404).
                tracing::debug!(%host, %path, %method, "matched route with no valid backend -> 500");
                session.respond_error(500).await?;
                Ok(true)
            }
        }
    }

    /// Report each chunk of an HTTP/2 request body to the stream's stall watchdog
    /// (see [`H2BodyProgress`]).
    async fn request_body_filter(
        &self,
        session: &mut Session,
        _body: &mut Option<Bytes>,
        end_of_stream: bool,
        _ctx: &mut Self::CTX,
    ) -> Result<()>
    where
        Self::CTX: Send + Sync,
    {
        H2BodyProgress::report(session.req_header(), end_of_stream);
        Ok(())
    }

    /// Apply request header modifiers and URL rewrite to the upstream request.
    async fn upstream_request_filter(
        &self,
        _session: &mut Session,
        upstream: &mut pingora_http::RequestHeader,
        ctx: &mut Self::CTX,
    ) -> Result<()>
    where
        Self::CTX: Send + Sync,
    {
        // Forwarded headers (nginx-ingress parity). OVERWRITE rather than append:
        // an inbound X-Forwarded-* is attacker-controlled when torii faces
        // the internet directly, so we never trust/extend it. Set before
        // apply_header_mods so an explicit user RequestHeaderModifier still wins.
        let fwd = &ctx.fwd;
        match &fwd.client_ip {
            Some(ip) => upstream.set_header("X-Forwarded-For", ip),
            // No known client IP: strip any inbound value so a spoofed one can't
            // leak through. Better to send nothing than an untrusted address.
            None => HeaderTarget::remove_header(upstream, "X-Forwarded-For"),
        }
        upstream.set_header("X-Forwarded-Host", &fwd.host);
        upstream.set_header("X-Forwarded-Port", &fwd.port.to_string());
        upstream.set_header("X-Forwarded-Proto", fwd.scheme);
        upstream.set_header("X-Forwarded-Scheme", fwd.scheme);

        apply_header_mods(&ctx.filters.request_headers, upstream);

        // URL rewrite: path and/or hostname.
        if let Some(rw) = &ctx.filters.url_rewrite {
            if let Some(new_path) = &ctx.rewrite_path {
                let query = upstream.uri.query().map(|q| format!("?{q}")).unwrap_or_default();
                if let Ok(uri) = format!("{new_path}{query}").parse() {
                    upstream.set_uri(uri);
                }
            }
            if let Some(host) = &rw.hostname {
                let _ = upstream.insert_header("Host", host);
            }
        }
        Ok(())
    }

    /// Apply response header modifiers.
    async fn response_filter(
        &self,
        _session: &mut Session,
        upstream_response: &mut ResponseHeader,
        ctx: &mut Self::CTX,
    ) -> Result<()>
    where
        Self::CTX: Send + Sync,
    {
        apply_header_mods(&ctx.filters.response_headers, upstream_response);
        // Add CORS response headers for an allowed cross-origin actual request.
        if let (Some(cors), Some(origin)) = (&ctx.filters.cors, &ctx.cors_origin) {
            write_cors_headers(upstream_response, cors, origin);
        }
        Ok(())
    }

    /// Forward to the backend chosen in `request_filter`.
    async fn upstream_peer(&self, _session: &mut Session, ctx: &mut Self::CTX) -> Result<Box<HttpPeer>> {
        let ep = ctx
            .upstream
            .as_ref()
            .expect("upstream_peer reached without a chosen backend");

        // BackendTLSPolicy: re-encrypt to the backend over TLS, verifying its cert
        // against the policy CA with SNI = the policy hostname. Plain HTTP otherwise.
        let mut peer = match &ep.tls {
            BackendTls::ReEncrypt(tls) => {
                let mut p = HttpPeer::new((ep.ip, ep.port), true, tls.hostname.clone());
                p.options.verify_cert = true;
                p.options.verify_hostname = true;
                if !tls.ca_pem.is_empty()
                    && let Ok(certs) = pingora_core::tls::x509::X509::stack_from_pem(&tls.ca_pem)
                {
                    p.options.ca = Some(std::sync::Arc::new(certs.into_boxed_slice()));
                }
                p
            }
            BackendTls::Plaintext => HttpPeer::new((ep.ip, ep.port), false, String::new()),
            // Invalid endpoints are rejected with a 5xx in request_filter, so the
            // request never reaches here.
            BackendTls::Invalid => unreachable!("invalid-TLS endpoint reached upstream_peer"),
        };
        // The rule's `timeouts` replace the default response timeout ("0s" disables
        // it), and can only shorten the connect deadline.
        let response = match ctx.request_timeout {
            None => self.timeouts.response,
            Some(t) => Some(t).filter(|t| !t.is_zero()),
        };
        peer.options.total_connection_timeout = self.timeouts.connect.into_iter().chain(response).min();
        peer.options.read_timeout = response;
        peer.options.write_timeout = response;
        peer.options.tcp_keepalive = Some(UPSTREAM_TCP_KEEPALIVE);
        Ok(Box::new(peer))
    }

    /// Map upstream timeouts to HTTP 504 (Gateway Timeout) per Gateway API;
    /// otherwise fall back to the default 502/5xx mapping.
    async fn fail_to_proxy(
        &self,
        session: &mut Session,
        e: &pingora_core::Error,
        _ctx: &mut Self::CTX,
    ) -> pingora_proxy::FailToProxy
    where
        Self::CTX: Send + Sync,
    {
        use pingora_core::{ErrorSource, ErrorType};
        let code = match e.etype() {
            ErrorType::ReadTimedout | ErrorType::ConnectTimedout | ErrorType::WriteTimedout => 504,
            ErrorType::HTTPStatus(c) => *c,
            _ => match e.esource() {
                ErrorSource::Upstream => 502,
                ErrorSource::Downstream => 0, // connection already dead
                _ => 500,
            },
        };
        if code > 0 && session.response_written().is_none() {
            let _ = session.respond_error(code).await;
        }
        pingora_proxy::FailToProxy {
            error_code: code,
            can_reuse_downstream: false,
        }
    }
}

/// Put the request path in its normal form ([`normalize_path`]), keeping the query
/// as it is, and return it; None if the request must be refused.
fn normalize_request_path(req: &mut pingora_http::RequestHeader, allow_encoded_slashes: bool) -> Option<String> {
    // Pingora refuses CONNECT, the only request without a path, and request-targets
    // that are not UTF-8, so the URI holds the target that Pingora forwards.
    let target = req.uri.path_and_query()?.as_str();
    let (path, query) = target.split_at(target.find('?').unwrap_or(target.len()));
    let normal = normalize_path(path.as_bytes(), allow_encoded_slashes)?;
    if normal != path {
        let target = format!("{normal}{query}");
        // Keep the scheme and authority of an h2 request: Pingora takes the upstream
        // Host from them.
        let mut uri = req.uri.clone().into_parts();
        uri.path_and_query = Some(target.parse().ok()?);
        req.set_uri(http::Uri::from_parts(uri).ok()?);
    }
    Some(normal)
}

/// Write CORS headers for an allowed *actual* (non-preflight) request.
fn write_cors_headers(resp: &mut ResponseHeader, cors: &crate::route_table::Cors, origin: &str) {
    // Echo the specific origin (required when credentials are allowed).
    let _ = resp.insert_header("Access-Control-Allow-Origin", origin);
    if cors.allow_credentials {
        let _ = resp.insert_header("Access-Control-Allow-Credentials", "true");
    }
    if !cors.expose_headers.is_empty() {
        let _ = resp.insert_header("Access-Control-Expose-Headers", cors.expose_headers.join(", "));
    }
    // The Allow-Origin value is selected per request Origin, so the response is not
    // safely cacheable across origins. Advertise that with `Vary: Origin` (RFC 9110
    // §12.5.5) so a shared cache can't serve one origin's grant to another. Append
    // rather than overwrite, to preserve any Vary the upstream already set.
    let _ = ResponseHeader::append_header(resp, "Vary", "Origin");
}

/// Write CORS headers for an allowed preflight request. A `*` in allow-methods or
/// allow-headers is expanded by echoing the request's requested method/headers.
fn write_cors_preflight(
    resp: &mut ResponseHeader,
    cors: &crate::route_table::Cors,
    origin: &str,
    req_method: &str,
    req_headers: &str,
) {
    write_cors_headers(resp, cors, origin); // adds `Vary: Origin`
    let methods = expand_wildcard(&cors.allow_methods, req_method);
    if !methods.is_empty() {
        let _ = resp.insert_header("Access-Control-Allow-Methods", methods);
    }
    let hdrs = expand_wildcard(&cors.allow_headers, req_headers);
    if !hdrs.is_empty() {
        let _ = resp.insert_header("Access-Control-Allow-Headers", hdrs);
    }
    if let Some(age) = cors.max_age {
        let _ = resp.insert_header("Access-Control-Max-Age", age.to_string());
    }
    // A `*` allow-list echoes the request's method/headers, so the preflight
    // response also varies on those request headers — advertise that for caches.
    let _ = ResponseHeader::append_header(resp, "Vary", "Access-Control-Request-Method");
    let _ = ResponseHeader::append_header(resp, "Vary", "Access-Control-Request-Headers");
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
/// xorshift64* seeded from a monotonic counter — good enough for traffic
/// distribution (not security-sensitive).
fn next_rng() -> u64 {
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

/// Something whose headers can be set/appended/removed — implemented for both
/// Pingora request and response headers.
trait HeaderTarget {
    fn set_header(&mut self, name: &str, value: &str);
    fn append_header(&mut self, name: &str, value: &str);
    fn remove_header(&mut self, name: &str);
}

impl HeaderTarget for pingora_http::RequestHeader {
    fn set_header(&mut self, name: &str, value: &str) {
        let _ = self.insert_header(name.to_string(), value);
    }
    fn append_header(&mut self, name: &str, value: &str) {
        let _ = pingora_http::RequestHeader::append_header(self, name.to_string(), value);
    }
    fn remove_header(&mut self, name: &str) {
        let _ = pingora_http::RequestHeader::remove_header(self, name);
    }
}

impl HeaderTarget for ResponseHeader {
    fn set_header(&mut self, name: &str, value: &str) {
        let _ = self.insert_header(name.to_string(), value);
    }
    fn append_header(&mut self, name: &str, value: &str) {
        let _ = ResponseHeader::append_header(self, name.to_string(), value);
    }
    fn remove_header(&mut self, name: &str) {
        let _ = ResponseHeader::remove_header(self, name);
    }
}

/// Apply a [`HeaderMods`] (set/add/remove) to any header target.
fn apply_header_mods(mods: &HeaderMods, target: &mut impl HeaderTarget) {
    if mods.is_empty() {
        return;
    }
    for (name, value) in &mods.set {
        target.set_header(name, value);
    }
    for (name, value) in &mods.add {
        target.append_header(name, value);
    }
    for name in &mods.remove {
        target.remove_header(name);
    }
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
fn host_from_authority(authority: &str) -> Option<&str> {
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

/// Find `proto` in the client's wire-format ALPN list, returning a sub-slice of
/// `client` (required: the ALPN-select callback's return must borrow from `client`).
fn select_alpn<'a>(client: &'a [u8], proto: &[u8]) -> Option<&'a [u8]> {
    let mut bytes = client;
    while !bytes.is_empty() {
        let len = bytes[0] as usize;
        bytes = &bytes[1..];
        if len > bytes.len() {
            return None;
        }
        if &bytes[..len] == proto {
            return Some(&bytes[..len]);
        }
        bytes = &bytes[len..];
    }
    None
}

/// A Pingora TLS accept callback that selects a server certificate by SNI from
/// the current snapshot's cert store, loading the PEM cert+key in-memory per
/// handshake. This is what makes per-listener / per-SNI HTTPS termination work.
struct SniCertCallback {
    data_plane: DataPlane,
    /// Self-signed last-resort cert, generated once at startup. Served when no
    /// real cert matches so the handshake completes (with a browser warning)
    /// instead of failing — letting a user click through to the upstream.
    fallback: Arc<crate::cert_store::CertKey>,
}

#[async_trait]
impl pingora_core::listeners::TlsAccept for SniCertCallback {
    async fn certificate_callback(&self, ssl: &mut pingora_core::tls::ssl::SslRef) {
        let sni = ssl
            .servername(pingora_core::tls::ssl::NameType::HOST_NAME)
            .map(|s| s.to_ascii_lowercase());

        // ACME TLS-ALPN-01: if the client negotiated `acme-tls/1` and we have a
        // pending challenge cert for this SNI, serve THAT (never a real cert).
        // Gating on the negotiated ALPN ensures real clients never see it.
        if ssl.selected_alpn_protocol() == Some(b"acme-tls/1") {
            let challenges = self.data_plane.load_challenges();
            if let Some(ck) = sni.as_deref().and_then(|h| challenges.get(h)) {
                install_cert(ssl, ck);
            }
            return;
        }

        let snapshot = self.data_plane.load();
        match snapshot.certs.select(sni.as_deref()) {
            Some(ck) => install_cert(ssl, ck),
            // No real cert (no SNI match, Secret missing, ACME not done yet). Serve
            // the self-signed fallback so the handshake completes — the client gets
            // a security warning but can click through and reach the upstream.
            None => {
                tracing::debug!(?sni, "no matching cert; serving self-signed fallback");
                install_cert(ssl, &self.fallback);
            }
        }
    }
}

/// Install a PEM cert+key onto an in-progress TLS handshake.
///
/// `cert_pem` may be a full chain (leaf first, then intermediates): the first
/// certificate is installed as the leaf and the remainder are added to the
/// presented chain. Serving the intermediates is what lets clients build a path
/// to a root they trust — without them, an ACME/CA-issued leaf fails to verify.
fn install_cert(ssl: &mut pingora_core::tls::ssl::SslRef, ck: &crate::cert_store::CertKey) {
    use pingora_core::tls::ext;
    let (Ok(chain), Ok(key)) = (
        pingora_core::tls::x509::X509::stack_from_pem(&ck.cert_pem),
        pingora_core::tls::pkey::PKey::private_key_from_pem(&ck.key_pem),
    ) else {
        return;
    };
    let Some((leaf, intermediates)) = chain.split_first() else {
        return;
    };
    let _ = ext::ssl_use_certificate(ssl, leaf);
    let _ = ext::ssl_use_private_key(ssl, &key);
    for inter in intermediates {
        let _ = ext::ssl_add_chain_cert(ssl, inter);
    }
}

/// A wrapper that re-exposes a boxed [`pingora_core::protocols::Stream`]
/// (`Box<dyn IO>`) as a concrete `S: IO`, and bounds its writes.
///
/// Pingora's `handshake_with_callback<S: IO>` and `ServerSession::new_http1` take
/// a generic `S: IO` / a `Stream`, but `Box<dyn IO>` does not itself implement the
/// `IO` supertraits, so it can't be passed where `S: IO` is required. This wrapper
/// delegates every supertrait method to the inner trait object; the blanket
/// `impl IO for T` in pingora then applies to `BoxedStream` automatically.
///
/// Every downstream connection runs on one, and a write, flush or shutdown that
/// makes no progress for `write_timeout` fails with `TimedOut`, which ends the
/// connection. Pingora writes with no timeout by default, and its per-session
/// `set_write_timeout` leaves h1 response heads and flushes unbounded, so a client
/// that stops reading would hold its task, the response buffers and the upstream
/// connection for as long as it keeps the socket open.
#[derive(Debug)]
struct BoxedStream {
    stream: pingora_core::protocols::Stream,
    write_timeout: std::time::Duration,
    /// Armed when a write first returns `Pending`, cleared when one completes.
    write_stall: Option<std::pin::Pin<Box<tokio::time::Sleep>>>,
}

impl BoxedStream {
    fn new(stream: pingora_core::protocols::Stream, write_timeout: std::time::Duration) -> Self {
        BoxedStream {
            stream,
            write_timeout,
            write_stall: None,
        }
    }

    /// Pass a write's result through, failing it once writes have been pending for
    /// `write_timeout`.
    fn bound_write<T>(
        &mut self,
        cx: &mut std::task::Context<'_>,
        poll: std::task::Poll<std::io::Result<T>>,
    ) -> std::task::Poll<std::io::Result<T>> {
        if poll.is_ready() {
            self.write_stall = None;
            return poll;
        }
        let timeout = self.write_timeout;
        let stall = self
            .write_stall
            .get_or_insert_with(|| Box::pin(tokio::time::sleep(timeout)));
        stall.as_mut().poll(cx).map(|()| {
            Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "write to client stalled",
            ))
        })
    }
}

impl tokio::io::AsyncRead for BoxedStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut *self.stream).poll_read(cx, buf)
    }
}

impl tokio::io::AsyncWrite for BoxedStream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let poll = std::pin::Pin::new(&mut *self.stream).poll_write(cx, buf);
        self.bound_write(cx, poll)
    }
    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let poll = std::pin::Pin::new(&mut *self.stream).poll_flush(cx);
        self.bound_write(cx, poll)
    }
    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let poll = std::pin::Pin::new(&mut *self.stream).poll_shutdown(cx);
        self.bound_write(cx, poll)
    }
}

#[async_trait]
impl pingora_core::protocols::Shutdown for BoxedStream {
    async fn shutdown(&mut self) {
        // Through our own `poll_shutdown`, so that the final flush is bounded too.
        if let Err(e) = tokio::io::AsyncWriteExt::shutdown(self).await {
            tracing::debug!(error = %e, "downstream shutdown failed");
        }
    }
}

impl pingora_core::protocols::UniqueID for BoxedStream {
    fn id(&self) -> pingora_core::protocols::UniqueIDType {
        self.stream.id()
    }
}

impl pingora_core::protocols::Ssl for BoxedStream {
    fn get_ssl(&self) -> Option<&pingora_core::protocols::tls::TlsRef> {
        self.stream.get_ssl()
    }
    fn get_ssl_digest(&self) -> Option<std::sync::Arc<pingora_core::protocols::tls::SslDigest>> {
        self.stream.get_ssl_digest()
    }
    fn selected_alpn_proto(&self) -> Option<pingora_core::protocols::ALPN> {
        self.stream.selected_alpn_proto()
    }
}

impl pingora_core::protocols::GetTimingDigest for BoxedStream {
    fn get_timing_digest(&self) -> Vec<Option<pingora_core::protocols::TimingDigest>> {
        self.stream.get_timing_digest()
    }
    fn get_read_pending_time(&self) -> std::time::Duration {
        self.stream.get_read_pending_time()
    }
    fn get_write_pending_time(&self) -> std::time::Duration {
        self.stream.get_write_pending_time()
    }
}

impl pingora_core::protocols::GetProxyDigest for BoxedStream {
    fn get_proxy_digest(&self) -> Option<std::sync::Arc<pingora_core::protocols::raw_connect::ProxyDigest>> {
        self.stream.get_proxy_digest()
    }
}

impl pingora_core::protocols::GetSocketDigest for BoxedStream {
    fn get_socket_digest(&self) -> Option<std::sync::Arc<pingora_core::protocols::SocketDigest>> {
        self.stream.get_socket_digest()
    }
}

#[async_trait]
impl pingora_core::protocols::Peek for BoxedStream {
    async fn try_peek(&mut self, buf: &mut [u8]) -> std::io::Result<bool> {
        self.stream.try_peek(buf).await
    }
}

/// The stream an HTTP/1.x connection runs on (see [`serve_h1`]): it hands Pingora each
/// request head in a few reads, however many pieces the client splits it into.
///
/// Pingora's `read_request()` runs httparse over the whole buffered head again after
/// every read that leaves it incomplete, so a head of H bytes that arrives in k reads
/// costs about k·H/2 of parsing, up to Pingora's 1 MiB head limit. A client gets
/// 1-byte reads for free over TLS (OpenSSL returns one record per read, and a record
/// may carry one byte), or with one TCP segment per byte: one client sending a long
/// head that way held the TLS ports' only thread for over a minute.
///
/// While it reads a head, this holds back what it reads until the head is complete
/// (see [`HeadScan`]) or it holds as many bytes as Pingora already has, so Pingora
/// parses a head in sizes that double: linear in all. The first bytes go through at
/// once, so Pingora still rejects a malformed head as soon as it arrives, and its
/// 1 MiB limit still applies. After the head, reads pass straight through (the body,
/// an upgraded connection) until [`Self::arm`] is called for the next request.
#[derive(Debug)]
struct H1Stream {
    stream: pingora_core::protocols::Stream,
    /// Bytes read from `stream` that Pingora has not taken yet.
    buf: bytes::BytesMut,
    /// How many of the leading bytes of `buf` Pingora may take.
    released: usize,
    /// While a request head is being read: where its end-of-head scan stands, and
    /// how many of its bytes Pingora has taken.
    head: Option<(HeadScan, usize)>,
}

impl H1Stream {
    fn new(stream: pingora_core::protocols::Stream) -> Self {
        H1Stream {
            stream,
            buf: bytes::BytesMut::new(),
            released: 0,
            head: Some(Default::default()),
        }
    }

    /// Start reading the next request head. What Pingora has not taken yet is its
    /// start, and goes through at once, like the first bytes of any head.
    fn arm(&mut self) {
        let mut scan = HeadScan::default();
        self.head = (!scan.feed(&self.buf)).then_some((scan, 0));
        self.released = self.buf.len();
    }
}

/// How much [`H1Stream`] reads at a time while it holds back a request head; the
/// size of the buffer Pingora starts a head in.
const H1_HEAD_READ_SIZE: usize = 4096;

impl tokio::io::AsyncRead for H1Stream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        out: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        use std::task::{Poll, ready};

        use bytes::Buf;

        let this = &mut *self;
        loop {
            if this.released > 0 {
                let n = this.released.min(out.remaining());
                out.put_slice(&this.buf[..n]);
                this.buf.advance(n);
                this.released -= n;
                match &mut this.head {
                    Some((_, taken)) => *taken += n,
                    // Don't keep the buffer on an idle connection.
                    None if this.buf.is_empty() => this.buf = bytes::BytesMut::new(),
                    None => {}
                }
                return Poll::Ready(Ok(()));
            }
            let Some((scan, taken)) = &mut this.head else {
                return std::pin::Pin::new(&mut *this.stream).poll_read(cx, out);
            };
            // Everything in `buf` is held back. A client can feed one byte per read
            // without end, so take part in Tokio's cooperative scheduling.
            let coop = ready!(tokio::task::coop::poll_proceed(cx));
            let held = this.buf.len();
            this.buf.reserve(H1_HEAD_READ_SIZE);
            let n = ready!(tokio_util::io::poll_read_buf(
                std::pin::Pin::new(&mut *this.stream),
                cx,
                &mut this.buf
            ))?;
            coop.made_progress();
            // At EOF, Pingora gets what there is, then the EOF.
            if n == 0 || scan.feed(&this.buf[held..]) {
                this.head = None;
                if this.buf.is_empty() {
                    return Poll::Ready(Ok(()));
                }
            } else if this.buf.len() < *taken {
                continue;
            }
            this.released = this.buf.len();
        }
    }
}

impl tokio::io::AsyncWrite for H1Stream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut *self.stream).poll_write(cx, buf)
    }
    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut *self.stream).poll_flush(cx)
    }
    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut *self.stream).poll_shutdown(cx)
    }
}

#[async_trait]
impl pingora_core::protocols::Shutdown for H1Stream {
    async fn shutdown(&mut self) {
        pingora_core::protocols::Shutdown::shutdown(&mut *self.stream).await
    }
}

impl pingora_core::protocols::UniqueID for H1Stream {
    fn id(&self) -> pingora_core::protocols::UniqueIDType {
        self.stream.id()
    }
}

impl pingora_core::protocols::Ssl for H1Stream {
    fn get_ssl(&self) -> Option<&pingora_core::protocols::tls::TlsRef> {
        self.stream.get_ssl()
    }
    fn get_ssl_digest(&self) -> Option<std::sync::Arc<pingora_core::protocols::tls::SslDigest>> {
        self.stream.get_ssl_digest()
    }
    fn selected_alpn_proto(&self) -> Option<pingora_core::protocols::ALPN> {
        self.stream.selected_alpn_proto()
    }
}

impl pingora_core::protocols::GetTimingDigest for H1Stream {
    fn get_timing_digest(&self) -> Vec<Option<pingora_core::protocols::TimingDigest>> {
        self.stream.get_timing_digest()
    }
    fn get_read_pending_time(&self) -> std::time::Duration {
        self.stream.get_read_pending_time()
    }
    fn get_write_pending_time(&self) -> std::time::Duration {
        self.stream.get_write_pending_time()
    }
}

impl pingora_core::protocols::GetProxyDigest for H1Stream {
    fn get_proxy_digest(&self) -> Option<std::sync::Arc<pingora_core::protocols::raw_connect::ProxyDigest>> {
        self.stream.get_proxy_digest()
    }
}

impl pingora_core::protocols::GetSocketDigest for H1Stream {
    fn get_socket_digest(&self) -> Option<std::sync::Arc<pingora_core::protocols::SocketDigest>> {
        self.stream.get_socket_digest()
    }
}

/// Peeking is not supported: it would have to see past the held-back bytes.
impl pingora_core::protocols::Peek for H1Stream {}

/// The scan for the end of an HTTP/1.x request head, fed its bytes as they arrive:
/// the first empty line after the request line, as httparse finds it. Lines end in
/// LF or CRLF, and empty lines before the request line are skipped. Bytes httparse
/// would reject (a CR not followed by LF) never end the head here, so a scan never
/// ends early, and Pingora rejects such a head when it gets it.
#[derive(Clone, Copy, Debug, Default)]
enum HeadScan {
    /// No request line yet.
    #[default]
    Start,
    /// Inside a line.
    Line,
    /// At the start of a line after the request line.
    LineStart,
    /// After a CR at the start of a line.
    LineStartCr,
}

impl HeadScan {
    /// Feed the next bytes of the head; true if they complete it.
    fn feed(&mut self, bytes: &[u8]) -> bool {
        for &b in bytes {
            *self = match (*self, b) {
                (Self::Start, b'\r' | b'\n') => Self::Start,
                (Self::Line, b'\n') => Self::LineStart,
                (Self::LineStart, b'\r') => Self::LineStartCr,
                (Self::LineStart | Self::LineStartCr, b'\n') => return true,
                _ => Self::Line,
            };
        }
        false
    }
}

/// Maximum ClientHello we'll peek when extracting the SNI. A real ClientHello is
/// well under this; capping bounds the `read_exact`-based peek so a malicious or
/// broken client can't make us wait for bytes that never arrive.
const MAX_CLIENT_HELLO: usize = 16 * 1024;

/// How long to wait for the ClientHello bytes during the SNI peek. The peek uses
/// `read_exact` (not MSG_PEEK), so without a timeout a stalled/partial handshake
/// would hang the per-connection task.
const PEEK_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Idle timeout for the raw L4 byte pipe (TLSRoute passthrough / terminate-to-TCP).
/// If no bytes flow in EITHER direction for this long, the connection is torn down.
/// Unlike a fixed total cap, an idle bound doesn't kill legitimately long-lived but
/// active connections (large transfers, long-poll). Without it, a client that
/// completes the handshake then stalls would pin a task + its upstream socket
/// indefinitely (no keepalive/read timeout applies on this custom L4 path).
/// It also bounds a write to a client that stops reading but keeps sending, which
/// would otherwise keep the pipe active forever (see [`BoxedStream`]).
const PIPE_IDLE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(300);

/// How long an HTTP client may stall an exchange before torii gives up on it: leave a
/// response write without progress (it stopped reading, or keeps an h2 stream's
/// flow-control window closed), or leave an announced h2 request body without data.
/// Pingora waits forever on all of these, holding the upstream connection and up to
/// ~0.5 MB of buffered response per exchange. 60s is Pingora's h1 read timeout and
/// nginx's `send_timeout` / `client_body_timeout`.
const CLIENT_STALL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

/// Cap on concurrent HTTP/2 streams per connection (SETTINGS_MAX_CONCURRENT_STREAMS,
/// RFC 9113 §6.5.2). Our terminate-then-HTTP h2 accept loop spawns one task per
/// stream; without an advertised cap a single connection could open unboundedly
/// many. 100 is Pingora's own default and the RFC's recommended minimum. It also
/// bounds what one connection can hold: a client that does not read leaves up to
/// ~0.5 MB of upstream response buffered per stream for `CLIENT_STALL_TIMEOUT`, so
/// one connection pins at most ~50 MB and 100 upstream connections.
///
/// The setting alone does not bound the tasks: a stream the client resets stops
/// counting toward it at once, while its task runs on until the proxy notices, which
/// takes as long as the upstream connect. So `GatewayTlsApp::serve_h2_streams` also
/// runs at most this many stream tasks per connection, as Go does since
/// CVE-2023-39325.
const H2_MAX_CONCURRENT_STREAMS: u32 = 100;

/// Cap on the decoded header list of an HTTP/2 request (SETTINGS_MAX_HEADER_LIST_SIZE,
/// RFC 9113 §6.5.2), counted as name + value + 32 bytes per field. Larger requests
/// get a 431 (far larger ones a GOAWAY) before reaching the proxy. Without an
/// explicit cap h2 accepts 16 MiB, and HPACK lets a client repeat a ~4 KB
/// dynamic-table entry for one byte each, so ~8 KB on the wire decodes to a ~16 MB
/// request that the proxy then serializes into one HTTP/1.1 head per stream: a few
/// hundred KB of traffic OOMs the process. 64 KiB is Pingora's own default (Envoy
/// uses 60 KiB), and bounds a connection's request heads to about
/// `H2_MAX_CONCURRENT_STREAMS` × 64 KiB.
const H2_MAX_HEADER_LIST_SIZE: u32 = 64 * 1024;

/// Deadline for completing the downstream TLS handshake, on TLSRoute Terminate and the
/// HTTPS fallback alike (see `GatewayTlsApp::tls_accept`). A client that opens TCP and
/// sends a ClientHello then stalls would otherwise pin a task forever.
const TLS_HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

/// Idle timeout for an HTTP/2 connection on the terminate-then-HTTP path: if no new
/// stream is requested within this window, the connection is closed. Without it, an
/// idle h2 connection (handshake done, no active streams) is held FOREVER — the h2
/// accept loop's `from_h2_conn().await` blocks with no bound. Real browsers prefer
/// h2 (ALPN) and keep connections open, so without this they accumulate one live
/// task + buffers each until the process OOMs (observed in prod: thousands of
/// idle ESTABLISHED :443 connections). [`H1_IDLE_TIMEOUT`] is the h1 equivalent.
/// Matches nginx's ~75s keepalive_timeout.
const H2_IDLE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(75);

/// Idle timeout for an HTTP/1.x connection: how long it may wait for (each read of)
/// the next request head, where [`H1Stream`] ends a read only once the head is
/// complete or has doubled. A whole number of seconds (Pingora's keepalive unit). 60s
/// is what Pingora's own accept loop uses for the first request.
const H1_IDLE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

/// How long `GatewayTlsApp::serve_h2_streams` tries to flush the GOAWAY when it cuts
/// off a client that keeps opening streams over the task cap. Such a client may not
/// be reading.
const H2_GOAWAY_FLUSH_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(1);

/// TCP keepalive on torii's connections to backends: probe after 60s of silence,
/// give up after 3 unanswered probes 10s apart. Without it, a backend that vanished
/// without a FIN or RST (node power loss, a dropped conntrack entry) goes unnoticed
/// by a connection waiting with no timeout: a pooled one, one whose route disables
/// its timeouts, or a TLSRoute pipe until its idle timeout.
const UPSTREAM_TCP_KEEPALIVE: pingora_core::protocols::TcpKeepalive = pingora_core::protocols::TcpKeepalive {
    idle: std::time::Duration::from_secs(60),
    interval: std::time::Duration::from_secs(10),
    count: 3,
    // 0: the system default.
    #[cfg(target_os = "linux")]
    user_timeout: std::time::Duration::ZERO,
};

/// h2 server settings for the terminate-then-HTTP path. Starts from Pingora's bounded
/// defaults (`server::handshake` only applies them when given `None`) and sets the
/// security-relevant limits explicitly, so they can't be dropped by accident.
fn h2_server_options() -> pingora_core::protocols::http::v2::server::H2Options {
    let mut options = pingora_core::protocols::http::v2::server::default_h2_options();
    options.max_header_list_size(H2_MAX_HEADER_LIST_SIZE);
    options.max_concurrent_streams(H2_MAX_CONCURRENT_STREAMS);
    options
}

/// The TLS data-plane application for a port that may carry TLSRoutes.
///
/// On a **plain-TCP** listener (so Pingora does NOT terminate TLS for us), this
/// peeks the SNI out of the ClientHello and dispatches:
///
/// - TLSRoute **passthrough**: pipe the still-encrypted bytes to the backend.
/// - TLSRoute **terminate**: terminate TLS here, pipe the cleartext TCP to the
///   backend (the backend speaks a raw protocol, not HTTP).
/// - **otherwise** (SNI matched no TLSRoute): terminate TLS here and run the HTTP
///   proxy — this is how HTTPS HTTPRoutes keep working on the same port.
///
/// The peek is non-destructive (`Stream::rewind`), so whichever branch we take
/// sees the full original byte stream, ClientHello included.
pub struct GatewayTlsApp {
    data_plane: DataPlane,
    /// The HTTP proxy, driven directly for the terminate-then-HTTP fallback.
    proxy: Arc<pingora_proxy::HttpProxy<GatewayProxy>>,
    /// Server-side TLS acceptor (built once) + its SNI/ACME certificate callback,
    /// used to terminate TLS on a stream we hand it.
    acceptor: Arc<pingora_core::tls::ssl::SslAcceptor>,
    tls_callbacks: Arc<pingora_core::listeners::TlsAcceptCallbacks>,
    /// Deadline for connecting to a TLSRoute backend ([`UpstreamTimeouts::connect`]).
    connect_timeout: Option<std::time::Duration>,
    /// The connection caps, counted together with the plain-HTTP ports' (see [`admit`]).
    limiter: Arc<ConnLimiter>,
}

#[async_trait]
impl pingora_core::apps::ServerApp for GatewayTlsApp {
    async fn process_new(
        self: &Arc<Self>,
        mut stream: pingora_core::protocols::Stream,
        shutdown: &pingora_core::server::ShutdownWatch,
    ) -> Option<pingora_core::protocols::Stream> {
        let _permit = admit(&self.limiter, &stream)?;

        let port = stream
            .get_socket_digest()
            .and_then(|d| d.local_addr().and_then(|a| a.as_inet().map(|i| i.port())))
            .unwrap_or(0);

        // Peek the SNI from the ClientHello without consuming the bytes.
        let sni = peek_sni(&mut stream).await;

        // Decide what to do based on (port, SNI).
        let decision = {
            let snap = self.data_plane.load();
            snap.tls.lookup(port, sni.as_deref(), next_rng())
        };

        match decision {
            TlsDecision::Passthrough(ep) => {
                tracing::debug!(port, ?sni, ip = %ep.ip, ep_port = ep.port, "TLS passthrough");
                let mut upstream = connect_backend(&ep, self.connect_timeout).await?;
                // True bidirectional pipe: the backend may speak first. Bounded by an
                // idle timeout so a stalled connection can't pin the task forever.
                let mut stream = BoxedStream::new(stream, PIPE_IDLE_TIMEOUT);
                let _ = copy_bidirectional_idle(&mut stream, &mut upstream, PIPE_IDLE_TIMEOUT).await;
                None
            }
            TlsDecision::Terminate(ep) => {
                tracing::debug!(port, ?sni, ip = %ep.ip, ep_port = ep.port, "TLS terminate -> TCP");
                // Terminate TLS here (cert chosen by SNI via the callback), then
                // pipe the cleartext to the backend (which expects plaintext TCP).
                let mut tls_stream = self
                    .tls_accept(BoxedStream::new(stream, PIPE_IDLE_TIMEOUT), TLS_HANDSHAKE_TIMEOUT)
                    .await?;
                let mut upstream = connect_backend(&ep, self.connect_timeout).await?;
                let _ = copy_bidirectional_idle(&mut tls_stream, &mut upstream, PIPE_IDLE_TIMEOUT).await;
                None
            }
            TlsDecision::NoBackend => {
                tracing::debug!(port, ?sni, "TLSRoute matched but no backend -> close");
                None
            }
            TlsDecision::NoRoute => {
                // No TLSRoute matched. Terminate TLS and run the HTTP proxy, so
                // HTTPS HTTPRoutes on this same port keep working.
                self.terminate_and_serve_http(stream, shutdown).await
            }
        }
    }
}

impl GatewayTlsApp {
    /// Run the server side of a downstream TLS handshake (cert chosen by SNI via the
    /// callback), giving up after `timeout`. Returns `None` if it fails or times out.
    ///
    /// Both TLS-terminating paths (TLSRoute Terminate and the HTTPS fallback) go
    /// through here, so neither can lose the deadline. A client can send a ClientHello
    /// (so dispatch reaches a handshake) then stall mid-handshake: OpenSSL has no timer
    /// of its own, and Pingora's accept-time handshake deadline does not apply to our
    /// plain-TCP listeners, so without one each such connection would hold its task,
    /// fd and handshake state forever. The SNI peek has its own `PEEK_TIMEOUT`; this
    /// covers the rest of the handshake.
    async fn tls_accept(
        &self,
        stream: BoxedStream,
        timeout: std::time::Duration,
    ) -> Option<pingora_core::protocols::tls::SslStream<BoxedStream>> {
        let handshake =
            pingora_core::protocols::tls::server::handshake_with_callback(&self.acceptor, stream, &self.tls_callbacks);
        match tokio::time::timeout(timeout, handshake).await {
            Ok(Ok(s)) => Some(s),
            Ok(Err(e)) => {
                tracing::debug!(error = %e, "downstream TLS handshake failed");
                None
            }
            Err(_) => {
                tracing::debug!("downstream TLS handshake timed out; closing");
                None
            }
        }
    }

    /// Terminate TLS and feed the resulting stream to the HTTP proxy. Dispatches on
    /// the ALPN-negotiated protocol: HTTP/2 (`h2`) or HTTP/1.1. Mirrors pingora's own
    /// `HttpServerApp` accept loop (`apps/mod.rs`), but inlined because pingora's h2
    /// accept-loop helper (`v2::server::accept_downstream_sessions`) is `pub(crate)`.
    async fn terminate_and_serve_http(
        &self,
        stream: pingora_core::protocols::Stream,
        shutdown: &pingora_core::server::ShutdownWatch,
    ) -> Option<pingora_core::protocols::Stream> {
        use pingora_core::protocols::tls::ALPN;

        let tls_stream = self
            .tls_accept(BoxedStream::new(stream, CLIENT_STALL_TIMEOUT), TLS_HANDSHAKE_TIMEOUT)
            .await?;

        // Box the concrete TLS stream as the `Box<dyn IO>` the HTTP servers take,
        // preserving the trait-object's ALPN accessor for the dispatch below.
        let stream: pingora_core::protocols::Stream = Box::new(tls_stream);
        if matches!(stream.selected_alpn_proto(), Some(ALPN::H2)) {
            self.serve_h2(stream, shutdown).await;
        } else {
            serve_h1(&self.proxy, stream, shutdown).await;
        }
        None
    }

    /// HTTP/2: drive each stream of the connection through the proxy.
    async fn serve_h2(&self, stream: pingora_core::protocols::Stream, shutdown: &pingora_core::server::ShutdownWatch) {
        use pingora_core::apps::HttpServerApp;
        use pingora_core::protocols::http::ServerSession;

        let proxy = self.proxy.clone();
        let shutdown = shutdown.clone();
        Self::serve_h2_streams(stream, CLIENT_STALL_TIMEOUT, move |h2| {
            let proxy = proxy.clone();
            let shutdown = shutdown.clone();
            async move {
                proxy.process_new_http(ServerSession::new_http2(h2), &shutdown).await;
            }
        })
        .await;
    }

    /// HTTP/2 accept loop: handshake the connection, then accept each h2 stream and
    /// run `serve` on it concurrently. Mirrors pingora's `apps/mod.rs` h2 path (which
    /// uses the `pub(crate)` accept_downstream_sessions helper). Takes the per-stream
    /// work as a closure so tests can drive the loop without a proxy.
    ///
    /// A stream's client may stall it for at most `stall_timeout`: a response write
    /// that makes no progress fails, and a request body that goes that long without
    /// data (see [`H2BodyProgress`]) gets the stream reset. The connection's
    /// [`BoxedStream`] cannot see either, as h2 flow control stalls a stream while the
    /// connection itself keeps moving.
    async fn serve_h2_streams<F, Fut>(
        stream: pingora_core::protocols::Stream,
        stall_timeout: std::time::Duration,
        serve: F,
    ) where
        F: Fn(pingora_core::protocols::http::v2::server::HttpSession) -> Fut,
        Fut: Future<Output = ()> + Send + 'static,
    {
        use pingora_core::protocols::Digest;
        use pingora_core::protocols::http::v2::server;

        // Connection digest shared across all streams of this h2 connection.
        let digest = std::sync::Arc::new(Digest {
            ssl_digest: stream.get_ssl_digest(),
            timing_digest: stream.get_timing_digest(),
            proxy_digest: stream.get_proxy_digest(),
            socket_digest: stream.get_socket_digest(),
        });

        // Advertise bounded max_concurrent_streams and max_header_list_size so a
        // single connection can't open unboundedly many streams (each a spawned task)
        // or send huge (HPACK-amplified) request heads.
        let h2_options = h2_server_options();
        // Bound the h2 handshake: a client can negotiate the `h2` ALPN over TLS but then
        // never send the HTTP/2 connection preface, leaving `server::handshake` awaiting
        // forever. Such half-open connections (scanners, abandoned clients) would
        // otherwise pile up unbounded. Reuse the idle window as the handshake deadline.
        let mut conn = match tokio::time::timeout(H2_IDLE_TIMEOUT, server::handshake(stream, Some(h2_options))).await {
            Ok(Ok(c)) => c,
            Ok(Err(e)) => {
                tracing::debug!(error = %e, "HTTPS h2 handshake failed");
                return;
            }
            Err(_) => {
                tracing::debug!("HTTPS h2 handshake timed out (no preface); closing");
                return;
            }
        };

        // Accept h2 streams until the client closes the connection OR goes idle with
        // no active streams. Each stream is an independent request; spawn it so
        // concurrent streams aren't serialized.
        //
        // `from_h2_conn` drives the whole connection codec (so it must keep being
        // polled while streams are in flight) and yields the next NEW stream. We bound
        // the wait with H2_IDLE_TIMEOUT, but only TEAR DOWN the connection when the
        // timeout fires AND no streams are active — otherwise a long-running stream
        // (slow download) would be killed mid-transfer. While streams are active we
        // just re-await (which keeps driving them). The stream tasks live in `tasks`
        // and are reaped as they end (which restarts the idle wait), so its length is
        // the number in flight.
        //
        // A stream the client resets frees its MAX_CONCURRENT_STREAMS slot at once,
        // but its task runs on until the proxy notices, i.e. until the upstream
        // connect ends. Resetting accepted streams would let one connection pile up
        // any number of tasks behind a slow upstream, so a stream that arrives while
        // H2_MAX_CONCURRENT_STREAMS tasks run is refused (REFUSED_STREAM, which the
        // client may retry), and a client that has had that many refused gets
        // GOAWAY(ENHANCE_YOUR_CALM). Leaving the loop drops `tasks`, which aborts the
        // ones still running: their client is gone.
        let mut tasks = tokio::task::JoinSet::new();
        let mut refused = 0;
        loop {
            let next = tokio::select! {
                Some(_) = tasks.join_next() => continue,
                next = tokio::time::timeout(
                    H2_IDLE_TIMEOUT,
                    server::HttpSession::from_h2_conn(&mut conn, digest.clone()),
                ) => next,
            };
            let next = match next {
                Ok(r) => r,
                Err(_) => {
                    // Idle window elapsed. Close only if nothing is in flight;
                    // otherwise keep serving the active stream(s).
                    if tasks.is_empty() {
                        tracing::debug!("HTTPS h2 connection idle; closing");
                        break;
                    }
                    continue;
                }
            };
            match next {
                Ok(Some(mut session)) => {
                    // A task that ended since the last poll is still in `tasks`.
                    while tasks.try_join_next().is_some() {}
                    if tasks.len() >= H2_MAX_CONCURRENT_STREAMS as usize {
                        refused += 1;
                        if refused > H2_MAX_CONCURRENT_STREAMS {
                            tracing::debug!("HTTPS h2 client keeps opening streams over the task cap; closing");
                            conn.abrupt_shutdown(h2::Reason::ENHANCE_YOUR_CALM);
                            let flush = std::future::poll_fn(|cx| conn.poll_closed(cx));
                            let _ = tokio::time::timeout(H2_GOAWAY_FLUSH_TIMEOUT, flush).await;
                            break;
                        }
                        session.shutdown_with_reason(h2::Reason::REFUSED_STREAM);
                        continue;
                    }
                    // Bound how long the client can stall this stream (see above).
                    session.set_write_timeout(Some(stall_timeout));
                    let (progress, body_done) = tokio::sync::watch::channel(session.is_body_done());
                    session
                        .req_header_mut()
                        .extensions
                        .insert(H2BodyProgress(Arc::new(progress)));
                    let stream = serve(session);
                    tasks.spawn(async move {
                        // Dropping the stream's session resets it (CANCEL) and drops its
                        // upstream connection.
                        tokio::select! {
                            () = stream => {}
                            () = h2_body_stalled(body_done, stall_timeout) => {
                                tracing::debug!("HTTPS h2 request body stalled; resetting the stream");
                            }
                        }
                    });
                }
                Ok(None) => break, // client closed the connection cleanly
                Err(e) => {
                    tracing::debug!(error = %e, "HTTPS h2 stream accept failed");
                    break;
                }
            }
        }
    }
}

/// The request-body progress of an HTTP/2 stream, carried in its request's
/// extensions: `true` once the body is complete. Pingora reads an h2 request body
/// with no timeout (`set_read_timeout` does nothing for h2), so a stream that
/// announces a body and never sends it would hold its task and upstream connection
/// forever. The proxy reports each chunk it reads, and
/// [`GatewayTlsApp::serve_h2_streams`] resets a stream whose body stalls.
#[derive(Clone)]
struct H2BodyProgress(Arc<tokio::sync::watch::Sender<bool>>);

impl H2BodyProgress {
    /// Report a chunk of `req`'s body, `end` for the last one. A no-op for requests
    /// without a watchdog (HTTP/1, whose body reads Pingora times out itself).
    fn report(req: &pingora_http::RequestHeader, end: bool) {
        if let Some(progress) = req.extensions.get::<Self>() {
            progress.0.send_replace(end);
        }
    }
}

/// Resolve once an h2 request body has gone `timeout` without a reported chunk.
/// Never resolves once the body is complete.
async fn h2_body_stalled(mut done: tokio::sync::watch::Receiver<bool>, timeout: std::time::Duration) {
    while !*done.borrow_and_update() {
        match tokio::time::timeout(timeout, done.changed()).await {
            Ok(Ok(())) => {}
            // The request is gone, and its stream with it.
            Ok(Err(_)) => break,
            Err(_) => return,
        }
    }
    std::future::pending().await
}

/// HTTP/1.x accept loop with keepalive reuse, for the plain-HTTP ports and the HTTPS
/// fallback. It is Pingora's own (`HttpServerApp::process_new` in `apps/mod.rs`,
/// without the h2c and request-limit options torii does not set), run on an
/// [`H1Stream`] that is armed for each request head.
async fn serve_h1(
    proxy: &Arc<pingora_proxy::HttpProxy<GatewayProxy>>,
    stream: pingora_core::protocols::Stream,
    shutdown: &pingora_core::server::ShutdownWatch,
) {
    use pingora_core::apps::HttpServerApp;
    use pingora_core::protocols::http::ServerSession;

    let mut session = ServerSession::new_http1(Box::new(H1Stream::new(stream)));
    // Idle timeout for the first request, or none while shutting down. The later
    // ones get it from `GatewayProxy::early_request_filter`.
    session.set_keepalive(if *shutdown.borrow() {
        None
    } else {
        Some(H1_IDLE_TIMEOUT.as_secs())
    });

    let mut result = proxy.process_new_http(session, shutdown).await;
    while let Some((stream, persistent_settings)) = result.map(|r| r.consume()) {
        let mut stream = stream
            .into_any()
            .downcast::<H1Stream>()
            .expect("an h1 session hands back the stream it ran on");
        stream.arm();
        let mut session = ServerSession::new_http1(stream);
        if let Some(ps) = persistent_settings {
            ps.apply_to_session(&mut session);
        }
        result = proxy.process_new_http(session, shutdown).await;
    }
}

/// The application for the plain-HTTP ports: [`serve_h1`] on a [`BoxedStream`], so
/// that writes to the client are bounded.
struct GatewayHttpApp {
    proxy: Arc<pingora_proxy::HttpProxy<GatewayProxy>>,
    limiter: Arc<ConnLimiter>,
}

#[async_trait]
impl pingora_core::apps::ServerApp for GatewayHttpApp {
    async fn process_new(
        self: &Arc<Self>,
        stream: pingora_core::protocols::Stream,
        shutdown: &pingora_core::server::ShutdownWatch,
    ) -> Option<pingora_core::protocols::Stream> {
        let _permit = admit(&self.limiter, &stream)?;
        let stream = Box::new(BoxedStream::new(stream, CLIENT_STALL_TIMEOUT));
        serve_h1(&self.proxy, stream, shutdown).await;
        None
    }

    async fn cleanup(&self) {
        pingora_core::apps::ServerApp::cleanup(&*self.proxy).await
    }
}

/// Take a slot under the connection caps for a new downstream connection, by its
/// peer address. Both apps take it before any work for the connection (the SNI
/// peek, the TLS handshake, the HTTP session) and hold it until the connection
/// ends: they never hand the stream back to Pingora for reuse. Pingora accepts and
/// spawns a task for every connection, so `None` (over a cap) means closing it.
fn admit(limiter: &Arc<ConnLimiter>, stream: &pingora_core::protocols::Stream) -> Option<ConnPermit> {
    let peer = stream
        .get_socket_digest()
        .and_then(|d| d.peer_addr().and_then(|a| a.as_inet()).map(|a| a.ip()));
    limiter.admit(peer)
}

/// Connect to a TLSRoute backend the way Pingora connects to an HTTP one: within
/// `timeout`, with TCP keepalive and `TCP_NODELAY`. A bare `connect()` to an endpoint
/// that drops SYNs waits out the kernel's retries (~130s), holding the client's
/// connection and task all along, even after the client has left.
async fn connect_backend(ep: &Endpoint, timeout: Option<std::time::Duration>) -> Option<tokio::net::TcpStream> {
    let connect = tokio::net::TcpStream::connect((ep.ip, ep.port));
    let connected = match timeout {
        Some(t) => tokio::time::timeout(t, connect)
            .await
            .unwrap_or_else(|_| Err(std::io::ErrorKind::TimedOut.into())),
        None => connect.await,
    };
    let stream = match connected {
        Ok(s) => s,
        Err(e) => {
            tracing::debug!(ip = %ep.ip, port = ep.port, error = %e, "TLSRoute backend connect failed");
            return None;
        }
    };
    let _ = pingora_core::protocols::l4::ext::set_tcp_keepalive(&stream, &UPSTREAM_TCP_KEEPALIVE);
    let _ = stream.set_nodelay(true);
    Some(stream)
}

/// Bidirectional byte pipe with an **idle timeout**: if no bytes flow in EITHER
/// direction for `idle`, the connection is torn down. Without it, a client that
/// completes the handshake then stalls would pin a task + its upstream socket
/// indefinitely (no keepalive/read timeout applies on this custom L4 path).
///
/// We keep the proven [`tokio::io::copy_bidirectional`] engine — which gets the
/// half-close / "backend speaks first" semantics right (the conformance TCP backend
/// sends a welcome line before reading) — and wrap each stream in an [`ActivityIo`]
/// that stamps a shared `last_active` instant on every successful read/write. A
/// watchdog races the copy and fires only after a full `idle` window with no
/// activity. Returns the per-direction byte counts, or an idle-timeout error.
async fn copy_bidirectional_idle<A, B>(a: &mut A, b: &mut B, idle: std::time::Duration) -> std::io::Result<(u64, u64)>
where
    A: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + ?Sized,
    B: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + ?Sized,
{
    use std::sync::atomic::{AtomicU64, Ordering};

    // Shared "millis since start of last I/O activity", updated by both wrappers.
    let start = tokio::time::Instant::now();
    let last_active = Arc::new(AtomicU64::new(0));
    let mut wa = ActivityIo {
        inner: a,
        start,
        last_active: last_active.clone(),
    };
    let mut wb = ActivityIo {
        inner: b,
        start,
        last_active: last_active.clone(),
    };

    let copy = tokio::io::copy_bidirectional(&mut wa, &mut wb);
    tokio::pin!(copy);

    loop {
        // Sleep until the deadline implied by the most recent activity, then re-check;
        // if activity advanced in the meantime, sleep again. Only a full idle window
        // with zero progress trips the timeout.
        let deadline = start + std::time::Duration::from_millis(last_active.load(Ordering::Relaxed)) + idle;
        tokio::select! {
            res = &mut copy => return res,
            _ = tokio::time::sleep_until(deadline) => {
                let idle_for = start.elapsed().as_millis() as u64
                    - last_active.load(Ordering::Relaxed);
                if idle_for >= idle.as_millis() as u64 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "idle timeout on L4 pipe",
                    ));
                }
                // Activity happened while we slept; loop and recompute the deadline.
            }
        }
    }
}

/// An `AsyncRead`/`AsyncWrite` wrapper that records the time of the last successful
/// (non-zero, non-pending) I/O into a shared atomic, so [`copy_bidirectional_idle`]
/// can enforce an idle timeout without reimplementing the copy itself.
struct ActivityIo<'a, T: ?Sized> {
    inner: &'a mut T,
    start: tokio::time::Instant,
    last_active: Arc<std::sync::atomic::AtomicU64>,
}

impl<T: ?Sized> ActivityIo<'_, T> {
    fn mark(&self) {
        let ms = self.start.elapsed().as_millis() as u64;
        self.last_active.store(ms, std::sync::atomic::Ordering::Relaxed);
    }
}

impl<T: tokio::io::AsyncRead + Unpin + ?Sized> tokio::io::AsyncRead for ActivityIo<'_, T> {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let r = std::pin::Pin::new(&mut *self.inner).poll_read(cx, buf);
        if let std::task::Poll::Ready(Ok(())) = &r
            && buf.filled().len() != before
        {
            self.mark();
        }
        r
    }
}

impl<T: tokio::io::AsyncWrite + Unpin + ?Sized> tokio::io::AsyncWrite for ActivityIo<'_, T> {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let r = std::pin::Pin::new(&mut *self.inner).poll_write(cx, buf);
        if let std::task::Poll::Ready(Ok(n)) = &r
            && *n > 0
        {
            self.mark();
        }
        r
    }
    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut *self.inner).poll_flush(cx)
    }
    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut *self.inner).poll_shutdown(cx)
    }
}

/// Peek the SNI hostname out of a connection's ClientHello, non-destructively.
///
/// `Stream::try_peek` is `read_exact` + `rewind` (not MSG_PEEK), so we size the
/// peek precisely: first the 5-byte TLS record header (to learn the record
/// length), then exactly the record. The whole thing is timeout-bounded. On any
/// failure (not TLS, truncated, timeout, no SNI) we return `None`, and the bytes
/// remain rewound for the next consumer.
async fn peek_sni(stream: &mut pingora_core::protocols::Stream) -> Option<String> {
    use tokio::time::timeout;

    // 1. Peek the record header.
    let mut header = [0u8; 5];
    match timeout(PEEK_TIMEOUT, stream.try_peek(&mut header)).await {
        Ok(Ok(true)) => {}
        _ => return None,
    }
    if header[0] != 0x16 {
        return None; // not a TLS handshake record
    }
    let record_len = u16::from_be_bytes([header[3], header[4]]) as usize;
    let total = (5 + record_len).min(MAX_CLIENT_HELLO);

    // 2. Peek the full record (header + body). try_peek rewinds it for us.
    let mut buf = vec![0u8; total];
    match timeout(PEEK_TIMEOUT, stream.try_peek(&mut buf)).await {
        Ok(Ok(true)) => {}
        _ => return None,
    }
    crate::tls_sni::parse_client_hello_sni(&buf)
}

/// Build the shared server-side TLS acceptor + its SNI/ACME certificate callback.
/// The acceptor is built the same way pingora's own `TlsSettings` does (Mozilla
/// intermediate v5), with the ACME `acme-tls/1` ALPN handling we already use; the
/// callback selects the per-SNI cert from the live snapshot at handshake time.
fn build_tls_acceptor(
    data_plane: DataPlane,
) -> (
    Arc<pingora_core::tls::ssl::SslAcceptor>,
    Arc<pingora_core::listeners::TlsAcceptCallbacks>,
) {
    use pingora_core::tls::ssl::{SslAcceptor, SslMethod};

    let mut builder =
        SslAcceptor::mozilla_intermediate_v5(SslMethod::tls()).expect("failed to create TLS acceptor builder");
    // Let OpenSSL free a connection's ~17KB record buffers whenever they're
    // empty instead of holding them for the connection's lifetime (nginx sets
    // the same mode). NOTE: on OpenSSL 3.5 (dev host) idle connections measure
    // the same with or without this — but the prod runtime image is bookworm's
    // OpenSSL 3.0, where retained record buffers are the classic idle-conn cost,
    // so keep it: it is free and can only shrink idle memory.
    builder.set_mode(pingora_core::tls::ssl::SslMode::RELEASE_BUFFERS);
    // ALPN: offer, in preference order, the ACME `acme-tls/1` challenge protocol,
    // then HTTP/2 (`h2`), then HTTP/1.1. We pick the first of OUR preferences that
    // the client also offered. NOACK only if the client offered none of them (it
    // then falls back to HTTP/1.1 without an ALPN-negotiated protocol).
    builder.set_alpn_select_callback(|_ssl, client| {
        use pingora_core::tls::ssl::AlpnError;
        for proto in [b"acme-tls/1".as_slice(), b"h2", b"http/1.1"] {
            if let Some(p) = select_alpn(client, proto) {
                return Ok(p);
            }
        }
        Err(AlpnError::NOACK)
    });
    let acceptor = Arc::new(builder.build());
    // Generate the last-resort self-signed cert once, at startup. Always present,
    // independent of ACME — served whenever no real cert matches a handshake.
    let fallback =
        Arc::new(crate::cert_store::CertKey::generate_self_signed().expect("failed to generate fallback TLS cert"));
    let callbacks: pingora_core::listeners::TlsAcceptCallbacks = Box::new(SniCertCallback { data_plane, fallback });
    (acceptor, Arc::new(callbacks))
}

/// Per-connection L4 read buffer size. Pingora's default is 64KB, allocated at
/// accept() and held for the connection's lifetime — the single largest share of
/// an idle downstream connection's memory (measured 2026-07-05: ~85KB total for a
/// plain-HTTP conn, ~64KB of it this buffer). 16KB still fits a full TLS record /
/// typical request headers per read; HTTP header parsing and the SNI peek do not
/// depend on this size (the h1 session has its own header buffer, and
/// `try_peek`'s rewind uses a separate side buffer).
const L4_READ_BUFFER_SIZE: usize = 16 * 1024;

/// Build a TCP listener config with our (smaller) per-connection read buffer.
/// The write buffer keeps pingora's default (1460B, one TCP segment).
fn tcp_listener(addr: &str) -> pingora_core::listeners::ListenerConfig {
    use pingora_core::protocols::l4::stream::L4BufferSettings;
    pingora_core::listeners::ListenerConfig::tcp(addr).l4_buffer(L4BufferSettings::default().read(L4_READ_BUFFER_SIZE))
}

/// Run the Pingora data-plane server.
///
/// `http_ports` get plain-TCP listeners served by the HTTP proxy. `tls_ports` get
/// plain-TCP listeners served by [`GatewayTlsApp`], which peeks the SNI and
/// dispatches per connection: TLSRoute passthrough / terminate-to-TCP, or (no
/// TLSRoute match) TLS-terminate-then-HTTP for HTTPS HTTPRoutes.
///
/// This blocks forever (Pingora calls `std::process::exit` on shutdown), so call
/// it from a dedicated thread.
pub fn run(
    data_plane: DataPlane,
    bind_ip: &str,
    http_ports: &[u16],
    tls_ports: &[u16],
    timeouts: UpstreamTimeouts,
    allow_encoded_slashes: bool,
    limits: ConnLimits,
) -> ! {
    // Pass None so Pingora doesn't parse our process argv as its own options.
    let mut server = Server::new(None).expect("failed to create pingora server");
    server.bootstrap();

    // One count for all ports, so that a source's share is for all of them.
    let limiter = ConnLimiter::new(limits);

    // Plain-HTTP proxy service. The proxy routes per-port via server_addr().
    let http_app = GatewayHttpApp {
        proxy: Arc::new(http_proxy(
            &server.configuration,
            GatewayProxy::new(data_plane.clone(), tls_ports.to_vec(), timeouts, allow_encoded_slashes),
        )),
        limiter: limiter.clone(),
    };
    let mut http_service = pingora_core::services::listening::Service::new("http-proxy".to_string(), http_app);
    for port in http_ports {
        http_service.add_listener(tcp_listener(&format!("{bind_ip}:{port}")));
    }
    server.add_service(http_service);

    // TLS ports: a plain-TCP listener whose ServerApp peeks SNI and dispatches.
    if !tls_ports.is_empty() {
        let (acceptor, tls_callbacks) = build_tls_acceptor(data_plane.clone());
        // A second HttpProxy drives the terminate-then-HTTP fallback. It is built
        // with the same configuration; running it via process_new_http needs an
        // Arc<HttpProxy>, not a Service, so we use the http_proxy() factory.
        let proxy = Arc::new(http_proxy(
            &server.configuration,
            GatewayProxy::new(data_plane.clone(), tls_ports.to_vec(), timeouts, allow_encoded_slashes),
        ));
        let app = GatewayTlsApp {
            data_plane: data_plane.clone(),
            proxy,
            acceptor,
            tls_callbacks,
            connect_timeout: timeouts.connect,
            limiter,
        };
        let mut tls_service = pingora_core::services::listening::Service::new("tls-sni-dispatch".to_string(), app);
        for port in tls_ports {
            tls_service.add_listener(tcp_listener(&format!("{bind_ip}:{port}")));
        }
        server.add_service(tls_service);
    }

    tracing::info!(bind_ip, ?http_ports, ?tls_ports, ?limits, "data plane listening");
    server.run_forever();
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;

    /// Upstream timeouts for the tests whose requests never reach a backend.
    const NO_TIMEOUTS: UpstreamTimeouts = UpstreamTimeouts {
        connect: None,
        response: None,
    };

    const NO_LIMITS: ConnLimits = ConnLimits {
        per_source: None,
        total: None,
    };

    // copy_bidirectional_idle relays bytes both ways and ends cleanly on EOF.
    #[tokio::test]
    async fn idle_copy_relays_both_directions() {
        let (mut a_ext, mut a_int) = tokio::io::duplex(64);
        let (mut b_ext, mut b_int) = tokio::io::duplex(64);

        let pipe =
            tokio::spawn(async move { copy_bidirectional_idle(&mut a_int, &mut b_int, Duration::from_secs(5)).await });

        // a → b
        a_ext.write_all(b"ping").await.unwrap();
        let mut buf = [0u8; 4];
        b_ext.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping");

        // b → a (the backend may speak too)
        b_ext.write_all(b"pong").await.unwrap();
        a_ext.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"pong");

        // Close both external ends → both directions EOF → copy returns counts.
        drop(a_ext);
        drop(b_ext);
        let (a2b, b2a) = pipe.await.unwrap().expect("clean close");
        assert_eq!((a2b, b2a), (4, 4));
    }

    // A stalled connection (no bytes either way) is torn down at the idle deadline.
    #[tokio::test]
    async fn idle_copy_times_out_when_stalled() {
        let (_a_ext, mut a_int) = tokio::io::duplex(64);
        let (_b_ext, mut b_int) = tokio::io::duplex(64);
        // Hold the external ends open but send nothing.
        let err = copy_bidirectional_idle(&mut a_int, &mut b_int, Duration::from_millis(80))
            .await
            .expect_err("must time out");
        assert_eq!(err.kind(), std::io::ErrorKind::TimedOut);
    }

    // A downstream write fails once the client has accepted nothing for the write
    // timeout, so a client that stops reading can't hold the connection. One that
    // reads slowly keeps a write going for longer than that.
    #[tokio::test]
    async fn downstream_write_times_out_when_client_stops_reading() {
        let (mut client, server) = tokio::io::duplex(64);
        let mut stream = BoxedStream::new(Box::new(server), Duration::from_millis(150));

        // 64 bytes every 30 ms: 1 KiB takes ~0.5 s.
        let reader = tokio::spawn(async move {
            let mut buf = [0u8; 64];
            let mut read = 0;
            while read < 1024 {
                tokio::time::sleep(Duration::from_millis(30)).await;
                read += client.read(&mut buf).await.unwrap();
            }
            client
        });
        stream
            .write_all(&[0; 1024])
            .await
            .expect("a slow reader must not time out");
        // The client stops reading but keeps the connection open.
        let _client = reader.await.unwrap();

        let err = tokio::time::timeout(Duration::from_secs(5), stream.write_all(&[0; 1024]))
            .await
            .expect("the write must give up")
            .expect_err("must time out");
        assert_eq!(err.kind(), std::io::ErrorKind::TimedOut);
    }

    // Pingora's read_request() turns the h1 idle timeout into "infinite" for HTTP/1.1
    // and `Connection: keep-alive`, and the keep-alive loop hands the request's value
    // on to the next one on the connection. early_request_filter must put the idle
    // timeout back, and leave a connection that closes after the request closing.
    #[tokio::test]
    async fn h1_idle_timeout_survives_the_request() {
        use pingora_core::apps::HttpPersistentSettings;
        use pingora_core::protocols::http::ServerSession;

        let proxy = GatewayProxy::new(DataPlane::new(), vec![], NO_TIMEOUTS, false);
        let idle = Some(H1_IDLE_TIMEOUT.as_secs());
        for (head, want) in [
            ("GET / HTTP/1.1\r\nHost: a\r\n\r\n", idle),
            ("GET / HTTP/1.1\r\nHost: a\r\nConnection: keep-alive\r\n\r\n", idle),
            ("GET / HTTP/1.0\r\nHost: a\r\nConnection: keep-alive\r\n\r\n", idle),
            ("GET / HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n", None),
            ("GET / HTTP/1.0\r\nHost: a\r\n\r\n", None),
        ] {
            let (mut client, server_io) = tokio::io::duplex(1024);
            client.write_all(head.as_bytes()).await.unwrap();
            let mut session = Session::new_h1(Box::new(server_io));
            session.set_keepalive(idle);
            assert!(session.read_request().await.unwrap());
            proxy
                .early_request_filter(&mut session, &mut proxy.new_ctx())
                .await
                .unwrap();
            assert_eq!(session.get_keepalive(), want, "{head:?}");

            let mut next = ServerSession::new_http1(Box::new(tokio::io::duplex(1).1));
            HttpPersistentSettings::for_session(&session).apply_to_session(&mut next);
            assert_eq!(next.get_keepalive(), want, "next request after {head:?}");
        }
    }

    // The end-of-head scan must end a head exactly where httparse does: earlier would
    // let the rest of the head reach Pingora a byte at a time, later would hold back a
    // complete request.
    #[test]
    fn head_scan_finds_the_end_of_the_head() {
        for (head, complete) in [
            ("GET / HTTP/1.1\r\nHost: a\r\n\r\n", true),
            ("GET / HTTP/1.1\r\n\r\n", true),
            ("GET / HTTP/1.1\nHost: a\n\n", true),
            ("GET / HTTP/1.1\nHost: a\n\r\n", true),
            // httparse skips empty lines before the request line.
            ("\r\n\n\r\nGET / HTTP/1.1\r\n\r\n", true),
            ("GET / HTTP/1.1\r\nHost: a\r\n", false),
            ("\r\n\r\n", false),
            // httparse rejects a CR not followed by LF.
            ("GET / HTTP/1.1\r\nHost: a\r\n\r\r\n", false),
        ] {
            let input = format!("{head}body");
            let mut scan = HeadScan::default();
            let end = input.bytes().position(|b| scan.feed(&[b])).map(|i| i + 1);
            assert_eq!(end, complete.then_some(head.len()), "{head:?}");
            assert_eq!(HeadScan::default().feed(input.as_bytes()), complete, "{head:?} at once");
        }
    }

    // Pingora parses a request head again from its first byte after every read that
    // leaves it incomplete, so a head sent a byte at a time (1-byte TLS records, or one
    // TCP segment per byte) cost it time quadratic in the head's size. An H1Stream
    // hands such a head over in reads that double what Pingora has, then the rest of
    // the head at once, and then passes the body through as it comes. arm() starts
    // over for the next request on the connection.
    #[tokio::test]
    async fn h1_head_reads_double() {
        use futures::FutureExt;

        let head = format!("GET / HTTP/1.1\r\nHost: a\r\nX-Pad: {}\r\n\r\n", "a".repeat(10_000));
        let (mut client, server_io) = tokio::io::duplex(64 * 1024);
        let mut stream = H1Stream::new(Box::new(server_io));
        let mut buf = vec![0; 64 * 1024];
        for _ in 0..2 {
            // The size of each read that returned data.
            let mut reads = vec![];
            let mut got = vec![];
            for b in head.bytes().chain(*b"body") {
                client.write_all(&[b]).await.unwrap();
                // A fresh cooperative-scheduling budget for the read.
                tokio::task::yield_now().await;
                if let Some(n) = stream.read(&mut buf).now_or_never() {
                    let n = n.unwrap();
                    reads.push(n);
                    got.extend_from_slice(&buf[..n]);
                }
            }
            assert_eq!(got, [head.as_bytes(), b"body"].concat());
            let mut want = vec![1];
            want.extend((0..13).map(|i| 1 << i));
            want.push(head.len() - (1 << 13));
            want.extend([1; 4]);
            assert_eq!(reads, want);
            stream.arm();
        }
    }

    // Both h1 accept loops run every request of a connection through an H1Stream armed
    // for its head: heads sent a byte at a time are served, on a keep-alive
    // connection's later requests too.
    #[tokio::test]
    async fn h1_trickled_heads_are_served() {
        use tokio::io::AsyncBufReadExt;

        // A redirect keeps the connection open (an error response would close it).
        let redirect = crate::route_table::Redirect {
            status_code: 302,
            ..Default::default()
        };
        let filters = Filters {
            redirect: Some(redirect),
            ..Default::default()
        };
        let proxy = route_proxy(NO_TIMEOUTS, vec![], filters, None);
        let (client, server_io) = tokio::io::duplex(64 * 1024);
        let (_shutdown_tx, shutdown) = tokio::sync::watch::channel(false);
        let serving = tokio::spawn(async move { serve_h1(&proxy, Box::new(server_io), &shutdown).await });
        let mut client = tokio::io::BufReader::new(client);
        for head in [
            "GET /1 HTTP/1.1\r\nHost: a\r\n\r\n",
            "\r\nGET /2 HTTP/1.1\r\nHost: a\r\nX-Pad: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\r\n\r\n",
            "GET /3 HTTP/1.1\nHost: a\n\n",
        ] {
            for b in head.bytes() {
                client.get_mut().write_all(&[b]).await.unwrap();
                tokio::task::yield_now().await;
            }
            let mut line = String::new();
            tokio::time::timeout(Duration::from_secs(5), client.read_line(&mut line))
                .await
                .expect("the request must be answered")
                .unwrap();
            assert_eq!(line, "HTTP/1.1 302 Found\r\n", "{head:?}");
            while line != "\r\n" {
                line.clear();
                assert!(client.read_line(&mut line).await.unwrap() > 0, "{head:?}");
            }
        }
        serving.abort();
    }

    /// One raw HTTP/2 frame: 9-byte header (length, type, flags, stream id) + payload.
    fn h2_frame(ty: u8, flags: u8, stream: u32, payload: &[u8]) -> Vec<u8> {
        let mut f = (payload.len() as u32).to_be_bytes()[1..].to_vec();
        f.extend([ty, flags]);
        f.extend(stream.to_be_bytes());
        f.extend(payload);
        f
    }

    // RUSTSEC-2026-0258: h2 < 0.4.16 queued every zero-length DATA frame until the
    // body was read, so a client that stalls the proxy's body read could stream 9-byte
    // empty frames (no flow-control cost) until OOM. The h2 server serve_h2 runs must
    // instead cut the connection off with GOAWAY(ENHANCE_YOUR_CALM).
    #[tokio::test]
    async fn h2_empty_data_frame_flood_gets_goaway() {
        use pingora_core::protocols::Digest;
        use pingora_core::protocols::http::v2::server;

        let (mut client, server_io) = tokio::io::duplex(64 * 1024);
        tokio::spawn(async move {
            let mut conn = server::handshake(Box::new(server_io), None).await.unwrap();
            // Accept streams but never read their bodies, like a proxy stuck on a
            // response write.
            let mut held = Vec::new();
            while let Ok(Some(s)) = server::HttpSession::from_h2_conn(&mut conn, Arc::new(Digest::default())).await {
                held.push(s);
            }
        });

        // Preface, SETTINGS, HEADERS(END_HEADERS) for POST https://a/ (HPACK static
        // indices 3, 7, 4 and :authority literal), then 1000 empty DATA frames.
        let mut req = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();
        req.extend(h2_frame(0x4, 0, 0, &[]));
        req.extend(h2_frame(0x1, 0x4, 1, &[0x83, 0x87, 0x84, 0x41, 0x01, b'a']));
        for _ in 0..1000 {
            req.extend(h2_frame(0x0, 0, 1, &[]));
        }
        client.write_all(&req).await.unwrap();

        let goaway = tokio::time::timeout(Duration::from_secs(5), async {
            let mut head = [0u8; 9];
            loop {
                client.read_exact(&mut head).await.ok()?;
                let mut payload = vec![0; u32::from_be_bytes([0, head[0], head[1], head[2]]) as usize];
                client.read_exact(&mut payload).await.ok()?;
                if head[3] == 0x7 {
                    return Some(u32::from_be_bytes(payload[4..8].try_into().unwrap()));
                }
            }
        })
        .await;
        assert_eq!(goaway, Ok(Some(0xb)), "expected GOAWAY(ENHANCE_YOUR_CALM)");
    }

    // HPACK bomb: a header inserted into the dynamic table once, then repeated with
    // 1-byte indexed fields, decodes to far more than its wire size. The h2 options
    // serve_h2 runs must advertise a bounded SETTINGS_MAX_HEADER_LIST_SIZE and refuse
    // such a request before it reaches the proxy, while the connection keeps serving.
    #[tokio::test]
    async fn h2_header_list_bomb_is_refused() {
        use pingora_core::protocols::Digest;
        use pingora_core::protocols::http::v2::server;

        let (mut client, server_io) = tokio::io::duplex(64 * 1024);
        let (accepted_tx, mut accepted) = tokio::sync::mpsc::unbounded_channel();
        tokio::spawn(async move {
            let mut conn = server::handshake(Box::new(server_io), Some(h2_server_options()))
                .await
                .unwrap();
            while let Ok(Some(s)) = server::HttpSession::from_h2_conn(&mut conn, Arc::new(Digest::default())).await {
                let _ = accepted_tx.send(s.req_header().uri.path().to_string());
            }
        });

        // GET https://a<path>: HPACK static indices 2 and 7, then :path and :authority
        // literals without indexing, so the bomb's entry lands at dynamic index 62.
        let request = |path: &str| {
            let mut block = vec![0x82, 0x87, 0x04, path.len() as u8];
            block.extend(path.as_bytes());
            block.extend([0x01, 0x01, b'a']);
            block
        };
        // `x: <100 bytes>` counts 133 bytes toward the list; 600 more references
        // (0xbe = index 62) make ~80 KB decoded from ~700 B on the wire. That is over
        // the 64 KiB cap but under h2's 4x threshold that tears down the connection.
        let mut bomb = request("/bomb");
        bomb.extend([0x40, 0x01, b'x', 100]);
        bomb.extend([b'A'; 100]);
        bomb.extend([0xbe; 600]);

        let mut req = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();
        req.extend(h2_frame(0x4, 0, 0, &[]));
        req.extend(h2_frame(0x1, 0x5, 1, &bomb)); // HEADERS, END_STREAM|END_HEADERS
        req.extend(h2_frame(0x1, 0x5, 3, &request("/ok")));
        client.write_all(&req).await.unwrap();

        // The server's SETTINGS advertise both caps.
        let mut head = [0u8; 9];
        client.read_exact(&mut head).await.unwrap();
        assert_eq!(head[3], 0x4, "server must open with SETTINGS");
        let mut payload = vec![0; u32::from_be_bytes([0, head[0], head[1], head[2]]) as usize];
        client.read_exact(&mut payload).await.unwrap();
        let setting = |id: u16| {
            let s = payload.chunks(6).find(|s| s[..2] == id.to_be_bytes())?;
            Some(u32::from_be_bytes(s[2..6].try_into().unwrap()))
        };
        assert_eq!(setting(0x6), Some(H2_MAX_HEADER_LIST_SIZE), "MAX_HEADER_LIST_SIZE");
        assert_eq!(setting(0x3), Some(H2_MAX_CONCURRENT_STREAMS), "MAX_CONCURRENT_STREAMS");

        // The bomb never reaches the proxy; the next stream on the connection does.
        let first = tokio::time::timeout(Duration::from_secs(5), accepted.recv()).await;
        assert_eq!(first, Ok(Some("/ok".to_string())), "over-size request must be refused");
    }

    // A request whose content-length does not match its DATA is malformed and must not
    // be forwarded (RFC 9113 §8.1.1). h2 < 0.4.20 checked only the first content-length
    // field, so `content-length: 5` + `content-length: 4` with 5 bytes of DATA reached
    // the proxy, which sends both fields to the HTTP/1.1 upstream: a backend that frames
    // the body by the last one reads the rest as a smuggled request. serve_h2 must reset
    // such a stream with PROTOCOL_ERROR before the proxy sees it, and keep serving.
    #[tokio::test]
    async fn h2_conflicting_content_lengths_are_reset() {
        let (mut client, server_io) = tokio::io::duplex(64 * 1024);
        let (accepted_tx, mut accepted) = tokio::sync::mpsc::unbounded_channel();
        tokio::spawn(GatewayTlsApp::serve_h2_streams(
            Box::new(server_io),
            CLIENT_STALL_TIMEOUT,
            move |session| {
                let _ = accepted_tx.send(session.req_header().uri.path().to_string());
                async {}
            },
        ));

        // POST https://a/upload (HPACK static indices 3 and 7, then :path, :authority and
        // two content-length (index 28) literals without indexing), 5 bytes of DATA, then
        // GET https://a/ok on the next stream.
        let mut post = vec![0x83, 0x87, 0x04, 7];
        post.extend(b"/upload");
        post.extend([0x01, 0x01, b'a']);
        post.extend([0x0f, 0x0d, 0x01, b'5']);
        post.extend([0x0f, 0x0d, 0x01, b'4']);
        let mut get = vec![0x82, 0x87, 0x04, 3];
        get.extend(b"/ok");
        get.extend([0x01, 0x01, b'a']);

        let mut req = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();
        req.extend(h2_frame(0x4, 0, 0, &[]));
        req.extend(h2_frame(0x1, 0x4, 1, &post)); // HEADERS, END_HEADERS
        req.extend(h2_frame(0x0, 0x1, 1, b"AAAAA")); // DATA, END_STREAM
        req.extend(h2_frame(0x1, 0x5, 3, &get)); // HEADERS, END_STREAM|END_HEADERS
        client.write_all(&req).await.unwrap();

        // The POST never reaches the proxy; the next stream on the connection does.
        let first = tokio::time::timeout(Duration::from_secs(5), accepted.recv()).await;
        assert_eq!(
            first,
            Ok(Some("/ok".to_string())),
            "request with conflicting content-lengths must be refused"
        );

        // The server's RST_STREAM for the POST: its error code.
        let reset = tokio::time::timeout(Duration::from_secs(5), async {
            let mut head = [0u8; 9];
            loop {
                client.read_exact(&mut head).await.ok()?;
                let mut payload = vec![0; u32::from_be_bytes([0, head[0], head[1], head[2]]) as usize];
                client.read_exact(&mut payload).await.ok()?;
                if head[3] == 0x3 && u32::from_be_bytes(head[5..9].try_into().unwrap()) == 1 {
                    return Some(u32::from_be_bytes(payload[..4].try_into().unwrap()));
                }
            }
        })
        .await;
        assert_eq!(reset, Ok(Some(0x1)), "expected RST_STREAM(PROTOCOL_ERROR)");
    }

    // A client's SETTINGS_HEADER_TABLE_SIZE is a ceiling for the HPACK encoder, not a
    // target (RFC 7541 §4.2). h2 < 0.4.17 sized the response encoder's dynamic table
    // to whatever the client advertised (up to 4 GiB), so nothing was ever evicted and
    // every distinct response field, a slice of its upstream head buffer, stayed
    // pinned for the connection's lifetime. The table must stay capped at 4 KiB.
    #[tokio::test]
    async fn h2_hpack_encoder_table_ignores_client_size() {
        use pingora_core::protocols::Digest;
        use pingora_core::protocols::http::v2::server;

        async fn read_frame(io: &mut tokio::io::DuplexStream) -> (u8, u8, u32, Vec<u8>) {
            let mut head = [0u8; 9];
            io.read_exact(&mut head).await.unwrap();
            let mut payload = vec![0; u32::from_be_bytes([0, head[0], head[1], head[2]]) as usize];
            io.read_exact(&mut payload).await.unwrap();
            let stream = u32::from_be_bytes(head[5..9].try_into().unwrap()) & 0x7fff_ffff;
            (head[3], head[4], stream, payload)
        }

        let (mut client, server_io) = tokio::io::duplex(64 * 1024);
        tokio::spawn(async move {
            let mut conn = server::handshake(Box::new(server_io), Some(h2_server_options()))
                .await
                .unwrap();
            while let Ok(Some(mut s)) = server::HttpSession::from_h2_conn(&mut conn, Arc::new(Digest::default())).await
            {
                let mut resp = ResponseHeader::build(200, None).unwrap();
                resp.insert_header("x-big", "x".repeat(3500)).unwrap();
                s.write_response_header(Box::new(resp), true).unwrap();
            }
        });

        // Preface and SETTINGS_HEADER_TABLE_SIZE = 2^32-1. h2 applies it to the encoder
        // when it ACKs, so wait for the ACK before sending the requests.
        let mut req = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();
        req.extend(h2_frame(0x4, 0, 0, &[0x00, 0x01, 0xff, 0xff, 0xff, 0xff]));
        client.write_all(&req).await.unwrap();
        let blocks = tokio::time::timeout(Duration::from_secs(5), async {
            while !matches!(read_frame(&mut client).await, (0x4, 0x1, ..)) {}
            // Two GET https://a/ (HPACK static indices 2, 7, 4 and :authority literal).
            let mut req = h2_frame(0x1, 0x5, 1, &[0x82, 0x87, 0x84, 0x41, 0x01, b'a']);
            req.extend(h2_frame(0x1, 0x5, 3, &[0x82, 0x87, 0x84, 0x41, 0x01, b'a']));
            client.write_all(&req).await.unwrap();
            let mut blocks = [0, 0];
            while blocks.contains(&0) {
                let (ty, _, stream, payload) = read_frame(&mut client).await;
                if ty == 0x1 {
                    blocks[stream as usize / 2] = payload.len();
                }
            }
            blocks
        })
        .await
        .expect("both responses");

        // `x-big` (3537 bytes in HPACK accounting) is over 3/4 of a 4 KiB table, so h2
        // must not index it: the second response carries the literal again. A table
        // sized by the client would index it and send a 1-byte reference instead.
        assert!(blocks[0] > 2000, "first response must carry x-big: {blocks:?}");
        assert!(
            blocks[1] > 2000,
            "x-big was indexed, the encoder table exceeds 4 KiB: {blocks:?}"
        );
    }

    // MAX_CONCURRENT_STREAMS only counts open streams: one the client resets is freed
    // at once, while its task may still be stuck before the proxy watches the stream
    // (an upstream connect to a black hole). The accept loop must still run at most
    // H2_MAX_CONCURRENT_STREAMS tasks per connection, refuse the streams over that,
    // cut off a client that keeps at it, and abort the stuck tasks once it is gone.
    #[tokio::test]
    async fn h2_reset_streams_keep_their_task_slots() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        // Drops with its stream task: counts the tasks alive.
        struct Running(Arc<AtomicUsize>);
        impl Drop for Running {
            fn drop(&mut self) {
                self.0.fetch_sub(1, Ordering::Relaxed);
            }
        }
        let running = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));

        let (mut client, server_io) = tokio::io::duplex(64 * 1024);
        let serving = tokio::spawn({
            let (running, peak) = (running.clone(), peak.clone());
            GatewayTlsApp::serve_h2_streams(Box::new(server_io), CLIENT_STALL_TIMEOUT, move |session| {
                peak.fetch_max(running.fetch_add(1, Ordering::Relaxed) + 1, Ordering::Relaxed);
                let running = Running(running.clone());
                async move {
                    let _stuck = (session, running);
                    std::future::pending().await
                }
            })
        });
        let wait_running = async |want: usize| {
            while running.load(Ordering::Relaxed) != want {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        };

        // GET https://a/ (HPACK static indices 2, 7, 4 and :authority literal) and
        // RST_STREAM(CANCEL) on stream 2i+1.
        let n = H2_MAX_CONCURRENT_STREAMS;
        let get = |i: u32| h2_frame(0x1, 0x5, 2 * i + 1, &[0x82, 0x87, 0x84, 0x41, 0x01, b'a']);
        let cancel = |i: u32| h2_frame(0x3, 0, 2 * i + 1, &0x8u32.to_be_bytes());
        // The server's next RST_STREAM or GOAWAY: (frame type, error code).
        async fn next_error(io: &mut tokio::io::DuplexStream) -> (u8, u32) {
            let mut head = [0u8; 9];
            loop {
                io.read_exact(&mut head).await.unwrap();
                let mut payload = vec![0; u32::from_be_bytes([0, head[0], head[1], head[2]]) as usize];
                io.read_exact(&mut payload).await.unwrap();
                match head[3] {
                    0x3 => return (0x3, u32::from_be_bytes(payload[..4].try_into().unwrap())),
                    0x7 => return (0x7, u32::from_be_bytes(payload[4..8].try_into().unwrap())),
                    _ => {}
                }
            }
        }

        // A full window of streams, all accepted, then all reset by the client.
        let mut req = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();
        req.extend(h2_frame(0x4, 0, 0, &[]));
        req.extend((0..n).flat_map(get));
        client.write_all(&req).await.unwrap();
        let accepted = tokio::time::timeout(Duration::from_secs(5), wait_running(n as usize)).await;
        assert!(accepted.is_ok(), "the first window must be accepted");
        let resets: Vec<u8> = (0..n).flat_map(cancel).collect();
        client.write_all(&resets).await.unwrap();

        // h2 has room for a whole window again, but the stream tasks are still there:
        // the loop must refuse every stream of it.
        let window: Vec<u8> = (n..2 * n).flat_map(get).collect();
        client.write_all(&window).await.unwrap();
        for _ in 0..n {
            let frame = tokio::time::timeout(Duration::from_secs(5), next_error(&mut client)).await;
            assert_eq!(frame, Ok((0x3, 0x7)), "expected RST_STREAM(REFUSED_STREAM)");
        }
        assert_eq!(peak.load(Ordering::Relaxed), n as usize, "stream tasks over the cap");

        // One more is one refusal too many.
        client.write_all(&get(2 * n)).await.unwrap();
        let frame = tokio::time::timeout(Duration::from_secs(5), next_error(&mut client)).await;
        assert_eq!(frame, Ok((0x7, 0xb)), "expected GOAWAY(ENHANCE_YOUR_CALM)");

        // The loop ends with the connection, and the stuck tasks with it.
        let ended = tokio::time::timeout(Duration::from_secs(5), serving).await;
        assert!(matches!(ended, Ok(Ok(()))), "the accept loop must end");
        let aborted = tokio::time::timeout(Duration::from_secs(5), wait_running(0)).await;
        assert!(aborted.is_ok(), "stuck stream tasks must be aborted");
    }

    // h2 flow control lets a client stall one stream's response (a zero window) while
    // the connection keeps moving, out of the connection write bound's sight. The
    // response write must fail once it has made no progress for the stall timeout.
    #[tokio::test]
    async fn h2_response_write_times_out_on_closed_window() {
        let stall = Duration::from_millis(200);
        let (mut client, server_io) = tokio::io::duplex(64 * 1024);
        let (result_tx, mut result) = tokio::sync::mpsc::unbounded_channel();
        tokio::spawn(GatewayTlsApp::serve_h2_streams(
            Box::new(server_io),
            stall,
            move |mut session| {
                let result_tx = result_tx.clone();
                async move {
                    let resp = ResponseHeader::build(200, None).unwrap();
                    session.write_response_header(Box::new(resp), false).unwrap();
                    let written = session.write_body(Bytes::from_static(b"hello"), true).await;
                    let _ = result_tx.send(written.map_err(|e| e.etype().clone()));
                }
            },
        ));

        // Preface, SETTINGS_INITIAL_WINDOW_SIZE = 0, then GET https://a/ (HPACK static
        // indices 2, 7, 4 and :authority literal).
        let start = tokio::time::Instant::now();
        let mut req = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();
        req.extend(h2_frame(0x4, 0, 0, &[0x00, 0x04, 0, 0, 0, 0]));
        req.extend(h2_frame(0x1, 0x5, 1, &[0x82, 0x87, 0x84, 0x41, 0x01, b'a']));
        client.write_all(&req).await.unwrap();

        let written = tokio::time::timeout(Duration::from_secs(5), result.recv()).await;
        assert_eq!(written, Ok(Some(Err(ErrorType::WriteTimedout))));
        assert!(start.elapsed() >= stall, "timed out early: {:?}", start.elapsed());
    }

    // Pingora reads an h2 request body with no timeout. A stream whose body stops
    // arriving must be reset once it has gone the stall timeout without data, while
    // streams with a slow but steady body, or with no body, keep running.
    #[tokio::test]
    async fn h2_stalled_request_body_is_reset() {
        let stall = Duration::from_millis(300);
        let (client, server_io) = tokio::io::duplex(64 * 1024);
        tokio::spawn(GatewayTlsApp::serve_h2_streams(
            Box::new(server_io),
            stall,
            |mut session| async move {
                // Like the proxy: read the body, reporting each chunk, then keep the
                // stream open as a long response would.
                while let Ok(Some(_)) = session.read_body_bytes().await {
                    H2BodyProgress::report(session.req_header(), false);
                }
                H2BodyProgress::report(session.req_header(), true);
                std::future::pending().await
            },
        ));
        let (mut rd, mut wr) = tokio::io::split(client);

        // HPACK: method (static 2 = GET, 3 = POST), :scheme https (7), :path and
        // :authority literals without indexing, then for a POST content-length: 100
        // (name index 28).
        let request = |method: u8, path: &str| {
            let mut block = vec![method, 0x87, 0x04, path.len() as u8];
            block.extend(path.as_bytes());
            block.extend([0x01, 0x01, b'a']);
            if method == 0x83 {
                block.extend([0x0f, 0x0d, 0x03, b'1', b'0', b'0']);
            }
            block
        };
        // Stream 1 announces a body and never sends it; stream 3 sends its body in 10
        // bytes every 50 ms, for longer than the stall timeout; stream 5 has no body.
        let start = tokio::time::Instant::now();
        let mut req = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();
        req.extend(h2_frame(0x4, 0, 0, &[]));
        req.extend(h2_frame(0x1, 0x4, 1, &request(0x83, "/stalled"))); // HEADERS, END_HEADERS
        req.extend(h2_frame(0x1, 0x4, 3, &request(0x83, "/slow")));
        req.extend(h2_frame(0x1, 0x5, 5, &request(0x82, "/get"))); // END_STREAM|END_HEADERS
        wr.write_all(&req).await.unwrap();
        tokio::spawn(async move {
            for i in 0..10 {
                tokio::time::sleep(Duration::from_millis(50)).await;
                let end_stream = if i == 9 { 0x1 } else { 0 };
                wr.write_all(&h2_frame(0x0, end_stream, 3, &[b'x'; 10])).await.unwrap();
            }
        });

        // The server's RST_STREAMs within 4 stall timeouts: (stream, error code, when).
        let mut resets = Vec::new();
        let _ = tokio::time::timeout(stall * 4, async {
            let mut head = [0u8; 9];
            loop {
                rd.read_exact(&mut head).await.unwrap();
                let mut payload = vec![0; u32::from_be_bytes([0, head[0], head[1], head[2]]) as usize];
                rd.read_exact(&mut payload).await.unwrap();
                if head[3] == 0x3 {
                    let stream = u32::from_be_bytes(head[5..9].try_into().unwrap());
                    let code = u32::from_be_bytes(payload[..4].try_into().unwrap());
                    resets.push((stream, code, start.elapsed()));
                }
            }
        })
        .await;
        assert_eq!(
            resets.iter().map(|&(s, c, _)| (s, c)).collect::<Vec<_>>(),
            [(1, 0x8)],
            "expected only RST_STREAM(CANCEL) for the stalled body"
        );
        assert!(resets[0].2 >= stall, "reset early: {:?}", resets[0].2);
    }

    /// A TLS app on an empty data plane (handshakes get the self-signed fallback cert).
    fn tls_app() -> GatewayTlsApp {
        let data_plane = DataPlane::new();
        let (acceptor, tls_callbacks) = build_tls_acceptor(data_plane.clone());
        let conf = Arc::new(pingora_core::server::configuration::ServerConf::default());
        GatewayTlsApp {
            proxy: Arc::new(http_proxy(
                &conf,
                GatewayProxy::new(data_plane.clone(), vec![], NO_TIMEOUTS, false),
            )),
            data_plane,
            acceptor,
            tls_callbacks,
            connect_timeout: None,
            limiter: ConnLimiter::new(NO_LIMITS),
        }
    }

    /// The ClientHello a TLS client sends to open a connection to `sni`.
    fn client_hello(sni: &str) -> Vec<u8> {
        use pingora_core::tls::ssl::{HandshakeError, SslConnector, SslMethod};

        // Records what the client writes, and has nothing for it to read yet.
        struct Wire(Vec<u8>);
        impl std::io::Read for Wire {
            fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
                Err(std::io::ErrorKind::WouldBlock.into())
            }
        }
        impl std::io::Write for Wire {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.0.extend_from_slice(buf);
                Ok(buf.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        let connector = SslConnector::builder(SslMethod::tls()).unwrap().build();
        match connector.connect(sni, Wire(Vec::new())) {
            Err(HandshakeError::WouldBlock(mid)) => mid.get_ref().0.clone(),
            _ => panic!("the client must wait for the server's flight"),
        }
    }

    // A client that sends its ClientHello and then never finishes the handshake is
    // cut off at the deadline, which TLSRoute Terminate and the HTTPS fallback share.
    // A client that finishes it gets the stream.
    #[tokio::test]
    async fn stalled_tls_handshake_times_out() {
        use pingora_core::tls::ssl::{SslConnector, SslMethod, SslVerifyMode};

        let app = tls_app();
        let deadline = Duration::from_millis(200);

        let (mut client, server_io) = tokio::io::duplex(64 * 1024);
        client.write_all(&client_hello("example.com")).await.unwrap();
        let start = tokio::time::Instant::now();
        let accept = app.tls_accept(BoxedStream::new(Box::new(server_io), PIPE_IDLE_TIMEOUT), deadline);
        let accepted = tokio::time::timeout(Duration::from_secs(5), accept)
            .await
            .expect("the handshake must give up");
        assert!(accepted.is_none());
        assert!(start.elapsed() >= deadline, "gave up early: {:?}", start.elapsed());
        // It got as far as sending its own flight (a handshake record).
        assert_eq!(client.read_u8().await.unwrap(), 0x16);

        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let mut connector = SslConnector::builder(SslMethod::tls()).unwrap();
        connector.set_verify(SslVerifyMode::NONE);
        let config = connector.build().configure().unwrap();
        let client = tokio::spawn(async move {
            pingora_core::protocols::tls::client::handshake(config, "example.com", client_io, None).await
        });
        let accept = app.tls_accept(
            BoxedStream::new(Box::new(server_io), PIPE_IDLE_TIMEOUT),
            TLS_HANDSHAKE_TIMEOUT,
        );
        assert!(accept.await.is_some());
        client.await.unwrap().expect("client handshake");
    }

    /// Accept a TCP connection from 127.0.0.1 the way Pingora's listener does, with
    /// the socket digest that has its peer address. Returns the client side too.
    async fn accept_tcp(
        listener: &tokio::net::TcpListener,
    ) -> (tokio::net::TcpStream, pingora_core::protocols::Stream) {
        use std::os::fd::AsRawFd;

        use pingora_core::protocols::{GetSocketDigest, SocketDigest};

        let client = tokio::net::TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (server, _) = listener.accept().await.unwrap();
        let mut server = pingora_core::protocols::l4::stream::Stream::from(server);
        server.set_socket_digest(SocketDigest::from_raw_fd(server.as_raw_fd()));
        (client, Box::new(server))
    }

    // A connection holds its slot under the connection caps from accept to close, on
    // the plain and the TLS ports alike, which count together. One from a source that
    // already has its share open is closed before any work for it (it would have
    // waited for a request head or a ClientHello), and one that ends frees its slot.
    #[tokio::test]
    async fn connections_over_the_source_cap_are_closed() {
        use pingora_core::apps::ServerApp;

        fn serve<A: ServerApp + Send + Sync + 'static>(
            app: &Arc<A>,
            stream: pingora_core::protocols::Stream,
            shutdown: &pingora_core::server::ShutdownWatch,
        ) -> tokio::task::JoinHandle<()> {
            let (app, shutdown) = (app.clone(), shutdown.clone());
            tokio::spawn(async move {
                app.process_new(stream, &shutdown).await;
            })
        }

        let limiter = ConnLimiter::new(ConnLimits {
            per_source: Some(2),
            total: None,
        });
        let http = Arc::new(GatewayHttpApp {
            proxy: route_proxy(NO_TIMEOUTS, vec![], Filters::default(), None),
            limiter: limiter.clone(),
        });
        let tls = Arc::new(GatewayTlsApp { limiter, ..tls_app() });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let (_shutdown_tx, shutdown) = tokio::sync::watch::channel(false);

        let (plain_client, stream) = accept_tcp(&listener).await;
        let plain = serve(&http, stream, &shutdown);
        let (_tls_client, stream) = accept_tcp(&listener).await;
        let tls_conn = serve(&tls, stream, &shutdown);

        let (mut client, stream) = accept_tcp(&listener).await;
        tokio::time::timeout(Duration::from_secs(1), serve(&http, stream, &shutdown))
            .await
            .expect("the plain port must close it at once")
            .unwrap();
        assert_eq!(client.read(&mut [0; 1]).await.unwrap(), 0);
        let (mut client, stream) = accept_tcp(&listener).await;
        tokio::time::timeout(Duration::from_secs(1), serve(&tls, stream, &shutdown))
            .await
            .expect("the TLS port must close it at once")
            .unwrap();
        assert_eq!(client.read(&mut [0; 1]).await.unwrap(), 0);

        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(
            !plain.is_finished() && !tls_conn.is_finished(),
            "the first two are served"
        );

        drop(plain_client);
        tokio::time::timeout(Duration::from_secs(5), plain)
            .await
            .unwrap()
            .unwrap();
        let (_client, stream) = accept_tcp(&listener).await;
        let admitted = serve(&tls, stream, &shutdown);
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(!admitted.is_finished(), "a closed connection frees its slot");

        tls_conn.abort();
        admitted.abort();
    }

    /// A backend that accepts connections and never sends a byte (so as a TLS backend
    /// it never answers the ClientHello). The receiver yields once for each
    /// connection torii closes.
    async fn silent_backend() -> (Endpoint, tokio::sync::mpsc::UnboundedReceiver<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (closed_tx, closed) = tokio::sync::mpsc::unbounded_channel();
        tokio::spawn(async move {
            while let Ok((mut conn, _)) = listener.accept().await {
                let closed_tx = closed_tx.clone();
                tokio::spawn(async move {
                    let mut buf = [0u8; 4096];
                    while conn.read(&mut buf).await.is_ok_and(|n| n > 0) {}
                    let _ = closed_tx.send(());
                });
            }
        });
        let ep = Endpoint {
            ip: addr.ip(),
            port: addr.port(),
            tls: BackendTls::Plaintext,
        };
        (ep, closed)
    }

    /// A proxy whose one route sends every request to `backends` through `filters`,
    /// with the rule timeout `rule_timeout`.
    fn route_proxy(
        timeouts: UpstreamTimeouts,
        backends: Vec<crate::route_table::Backend>,
        filters: Filters,
        rule_timeout: Option<Duration>,
    ) -> Arc<pingora_proxy::HttpProxy<GatewayProxy>> {
        use crate::route_table::{RouteEntry, RouteMatch, RouteTable};

        // A connection over a duplex has no local address, so its listener port is 0.
        let mut routes = RouteTable::default();
        routes.entries.push(RouteEntry {
            listener_port: 0,
            listener_hostname: None,
            hostnames: vec![],
            r#match: RouteMatch::default(),
            backends,
            filters,
            request_timeout: rule_timeout,
            route_creation: 0,
            route_key: "ns/route".into(),
            rule_order: 0,
            match_order: 0,
        });
        routes.sort();
        let data_plane = DataPlane::new();
        data_plane.store(crate::snapshot::Snapshot {
            routes,
            ..Default::default()
        });
        let conf = Arc::new(pingora_core::server::configuration::ServerConf::default());
        Arc::new(http_proxy(
            &conf,
            GatewayProxy::new(data_plane, vec![], timeouts, false),
        ))
    }

    /// Send `GET /` over HTTP/1.1 through a proxy whose one route forwards to
    /// `backend`, with the rule timeout `rule_timeout`. Returns the response's status
    /// line, or None if there is none after `wait`.
    async fn proxy_get(
        timeouts: UpstreamTimeouts,
        backend: Endpoint,
        rule_timeout: Option<Duration>,
        wait: Duration,
    ) -> Option<String> {
        use pingora_core::apps::HttpServerApp;
        use pingora_core::protocols::http::ServerSession;
        use tokio::io::AsyncBufReadExt;

        use crate::route_table::Backend;

        let backend = Backend {
            weight: 1,
            endpoints: vec![backend],
            filters: Filters::default(),
        };
        let proxy = route_proxy(timeouts, vec![backend], Filters::default(), rule_timeout);

        let (client, server_io) = tokio::io::duplex(64 * 1024);
        let (_shutdown_tx, shutdown) = tokio::sync::watch::channel(false);
        let serving = tokio::spawn(async move {
            proxy
                .process_new_http(ServerSession::new_http1(Box::new(server_io)), &shutdown)
                .await;
        });
        let mut client = tokio::io::BufReader::new(client);
        client.write_all(b"GET / HTTP/1.1\r\nHost: a\r\n\r\n").await.unwrap();
        let mut status = String::new();
        let read = tokio::time::timeout(wait, client.read_line(&mut status)).await;
        serving.abort();
        read.ok()?.ok().filter(|&n| n > 0)?;
        Some(status.trim_end().to_string())
    }

    // A backend that accepts the connection and never answers gets the request 504'd
    // at the response timeout, and its connection closed. Without a default, a
    // request to it waited as long as its client did, which can be forever. A rule's
    // `timeouts` replace the default, and "0s" there disables it.
    #[tokio::test]
    async fn silent_backend_times_out() {
        let (backend, mut closed) = silent_backend().await;
        let default = Duration::from_millis(200);
        let timeouts = UpstreamTimeouts {
            connect: Some(Duration::from_secs(5)),
            response: Some(default),
        };
        for (rule_timeout, deadline) in [
            (None, default),
            (Some(Duration::from_millis(500)), Duration::from_millis(500)),
        ] {
            let start = tokio::time::Instant::now();
            let status = proxy_get(timeouts, backend.clone(), rule_timeout, Duration::from_secs(5)).await;
            assert_eq!(
                status.as_deref(),
                Some("HTTP/1.1 504 Gateway Timeout"),
                "rule timeout {rule_timeout:?}"
            );
            assert!(start.elapsed() >= deadline, "timed out early: {:?}", start.elapsed());
            let closed = tokio::time::timeout(Duration::from_secs(5), closed.recv()).await;
            assert!(closed.is_ok(), "the backend connection must be closed");
        }

        let status = proxy_get(timeouts, backend, Some(Duration::ZERO), default * 3).await;
        assert_eq!(status, None, "\"0s\" must disable the response timeout");
    }

    // The connect deadline covers a BackendTLSPolicy backend's TLS handshake, which
    // had no limit at all: each request to an endpoint that never answers the
    // ClientHello held its task, socket and TLS state forever, even after its client
    // left. A rule's longer timeout, or "0s", must not lengthen it.
    #[tokio::test]
    async fn stalled_backend_tls_handshake_times_out() {
        let (mut backend, mut closed) = silent_backend().await;
        backend.tls = BackendTls::ReEncrypt(crate::route_table::UpstreamTls {
            hostname: "backend.example".into(),
            ca_pem: vec![],
        });
        let deadline = Duration::from_millis(200);
        let timeouts = UpstreamTimeouts {
            connect: Some(deadline),
            response: Some(Duration::from_secs(60)),
        };
        for rule_timeout in [None, Some(Duration::from_secs(3600)), Some(Duration::ZERO)] {
            let start = tokio::time::Instant::now();
            let status = proxy_get(timeouts, backend.clone(), rule_timeout, Duration::from_secs(5)).await;
            assert_eq!(
                status.as_deref(),
                Some("HTTP/1.1 504 Gateway Timeout"),
                "rule timeout {rule_timeout:?}"
            );
            assert!(start.elapsed() >= deadline, "timed out early: {:?}", start.elapsed());
            let closed = tokio::time::timeout(Duration::from_secs(5), closed.recv()).await;
            assert!(closed.is_ok(), "the backend connection must be closed");
        }
    }

    // A TLSRoute backend that drops SYNs must not hold the client's connection for the
    // kernel's ~130s of SYN retries. A listener whose accept queue is full drops them.
    #[tokio::test]
    async fn tlsroute_backend_connect_times_out() {
        let socket = tokio::net::TcpSocket::new_v4().unwrap();
        socket.bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let listener = socket.listen(0).unwrap();
        let addr = listener.local_addr().unwrap();
        let backend = Endpoint {
            ip: addr.ip(),
            port: addr.port(),
            tls: BackendTls::Plaintext,
        };

        // With a backlog of 0, the first connection fills the queue.
        let first = connect_backend(&backend, Some(Duration::from_secs(5)))
            .await
            .expect("the first connection must be queued");
        assert!(first.nodelay().unwrap());

        let deadline = Duration::from_millis(200);
        let start = tokio::time::Instant::now();
        let second = tokio::time::timeout(Duration::from_secs(5), connect_backend(&backend, Some(deadline)))
            .await
            .expect("the connect must give up");
        assert!(second.is_none());
        assert!(start.elapsed() >= deadline, "gave up early: {:?}", start.elapsed());
    }

    /// A backend that answers each request with its request head.
    async fn echo_backend() -> Endpoint {
        use tokio::io::AsyncBufReadExt;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((conn, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut conn = tokio::io::BufReader::new(conn);
                    let mut head = Vec::new();
                    while !head.ends_with(b"\r\n\r\n") {
                        if conn.read_until(b'\n', &mut head).await.unwrap_or(0) == 0 {
                            return;
                        }
                    }
                    let resp = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", head.len());
                    let _ = conn.write_all(&[resp.as_bytes(), &head].concat()).await;
                });
            }
        });
        Endpoint {
            ip: addr.ip(),
            port: addr.port(),
            tls: BackendTls::Plaintext,
        }
    }

    /// A proxy whose routes send `/admin` to a redirect, `/public` to `backend` as
    /// `/static`, and the rest to `backend`.
    fn paths_proxy(backend: Endpoint, allow_encoded_slashes: bool) -> Arc<pingora_proxy::HttpProxy<GatewayProxy>> {
        use crate::route_table::{
            Backend, PathMatch, PathRewrite, Redirect, RouteEntry, RouteMatch, RouteTable, UrlRewrite,
        };

        let backends = vec![Backend {
            weight: 1,
            endpoints: vec![backend],
            filters: Filters::default(),
        }];
        let redirect = Filters {
            redirect: Some(Redirect {
                hostname: Some("login.example".into()),
                status_code: 302,
                ..Default::default()
            }),
            ..Default::default()
        };
        let rewrite = Filters {
            url_rewrite: Some(UrlRewrite {
                hostname: None,
                path: Some(PathRewrite::ReplacePrefixMatch("/static".into())),
            }),
            ..Default::default()
        };
        let mut routes = RouteTable::default();
        for (prefix, filters, backends) in [
            ("/admin", redirect, vec![]),
            ("/public", rewrite, backends.clone()),
            ("/", Filters::default(), backends),
        ] {
            routes.entries.push(RouteEntry {
                listener_port: 0,
                listener_hostname: None,
                hostnames: vec![],
                r#match: RouteMatch {
                    path: Some(PathMatch::Prefix(prefix.into())),
                    ..Default::default()
                },
                backends,
                filters,
                request_timeout: None,
                route_creation: 0,
                route_key: format!("ns{prefix}"),
                rule_order: 0,
                match_order: 0,
            });
        }
        routes.sort();
        let data_plane = DataPlane::new();
        data_plane.store(crate::snapshot::Snapshot {
            routes,
            ..Default::default()
        });
        let conf = Arc::new(pingora_core::server::configuration::ServerConf::default());
        Arc::new(http_proxy(
            &conf,
            GatewayProxy::new(data_plane, vec![], NO_TIMEOUTS, allow_encoded_slashes),
        ))
    }

    /// The request line the backend got for `GET <target>` over HTTP/1.1 through
    /// `proxy`, or the response's status code if it is not 200.
    async fn h1_path(proxy: &Arc<pingora_proxy::HttpProxy<GatewayProxy>>, target: &[u8]) -> Vec<u8> {
        use pingora_core::apps::HttpServerApp;
        use pingora_core::protocols::http::ServerSession;

        let (mut client, server_io) = tokio::io::duplex(64 * 1024);
        let proxy = proxy.clone();
        let serving = tokio::spawn(async move {
            let (_shutdown_tx, shutdown) = tokio::sync::watch::channel(false);
            proxy
                .process_new_http(ServerSession::new_http1(Box::new(server_io)), &shutdown)
                .await;
        });
        let req = [b"GET ", target, b" HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n"].concat();
        client.write_all(&req).await.unwrap();
        let mut resp = Vec::new();
        let read = tokio::time::timeout(Duration::from_secs(5), client.read_to_end(&mut resp)).await;
        serving.abort();
        read.expect("no response").unwrap();
        let line = |b: &[u8]| b.split(|&c| c == b'\r').next().unwrap().to_vec();
        match resp.strip_prefix(b"HTTP/1.1 200 OK\r\n") {
            Some(rest) => line(&rest[rest.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4..]),
            None => resp[9..12].to_vec(),
        }
    }

    // Routes match the normal form of the request path, and the backend gets that same
    // path: no other form of `/admin` may skip its rule (to reach the backend, which
    // would take it for `/admin`), and no `..` may leave a rewritten prefix.
    #[tokio::test]
    async fn request_paths_are_normalized() {
        let proxy = paths_proxy(echo_backend().await, false);
        for (target, want) in [
            (&b"/admin/panel"[..], &b"302"[..]),
            (b"/%61dmin/panel", b"302"),
            (b"/x/../admin/panel", b"302"),
            (b"/./admin/panel", b"302"),
            (b"/x/%2e%2e/admin/panel", b"302"),
            (b"//admin/panel", b"302"),
            (b"/x/..;y/admin", b"302"),
            (b"/public/../admin", b"302"),
            (b"/public/%2e%2e/x", b"GET /x HTTP/1.1"),
            (
                b"/public/a/./b;v=1?q=/../%2e",
                b"GET /static/a/b;v=1?q=/../%2e HTTP/1.1",
            ),
            (b"/caf%c3%a9/%7e", b"GET /caf%C3%A9/~ HTTP/1.1"),
            ("/café/.?q=é".as_bytes(), "GET /caf%C3%A9/?q=é HTTP/1.1".as_bytes()),
            // Pingora refuses a target that is not UTF-8, so the URI is the target.
            (b"/caf\xe9", b"400"),
            // `;params` that do not change the route are forwarded.
            (b"/app;v=1/x", b"GET /app;v=1/x HTTP/1.1"),
            (b"/admin;x=1/panel", b"400"),
            (b"/;x/admin", b"400"),
            (b"/public/..%2fadmin", b"400"),
            (b"/a%5Cb", b"400"),
            (b"/a\\b", b"400"),
            (b"/a%00", b"400"),
            (b"/a%zz", b"400"),
        ] {
            let got = h1_path(&proxy, target).await;
            assert_eq!(
                got.escape_ascii().to_string(),
                want.escape_ascii().to_string(),
                "{}",
                target.escape_ascii()
            );
        }

        // Encoded slashes, when allowed, are data, never separators.
        let proxy = paths_proxy(echo_backend().await, true);
        assert_eq!(
            h1_path(&proxy, b"/public/..%2fadmin").await,
            b"GET /static/..%2Fadmin HTTP/1.1"
        );
        assert_eq!(h1_path(&proxy, b"/a%00").await, b"400");
    }

    // The same over HTTP/2, whose request URI also has the authority that becomes the
    // upstream Host: normalizing the path must keep it.
    #[tokio::test]
    async fn h2_request_paths_are_normalized() {
        use pingora_core::apps::HttpServerApp;
        use pingora_core::protocols::http::ServerSession;

        let proxy = paths_proxy(echo_backend().await, false);
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        tokio::spawn(GatewayTlsApp::serve_h2_streams(
            Box::new(server_io),
            CLIENT_STALL_TIMEOUT,
            move |h2| {
                let proxy = proxy.clone();
                async move {
                    let (_shutdown_tx, shutdown) = tokio::sync::watch::channel(false);
                    proxy.process_new_http(ServerSession::new_http2(h2), &shutdown).await;
                }
            },
        ));
        let (client, conn) = h2::client::handshake(client_io).await.unwrap();
        tokio::spawn(conn);
        for (uri, want) in [
            ("https://a.example/x/%2e%2e/y?q", "200 GET /y?q HTTP/1.1"),
            ("https://a.example/%61dmin", "302 "),
            ("https://a.example/a%2fb", "400 "),
        ] {
            let mut client = client.clone().ready().await.unwrap();
            let (resp, _) = client
                .send_request(http::Request::get(uri).body(()).unwrap(), true)
                .unwrap();
            let resp = tokio::time::timeout(Duration::from_secs(5), resp)
                .await
                .unwrap()
                .unwrap();
            let status = resp.status();
            let mut body = resp.into_body();
            let mut head = Vec::new();
            while let Some(chunk) = body.data().await {
                head.extend(chunk.unwrap());
            }
            let head = String::from_utf8(head).unwrap();
            let got = format!("{} {}", status.as_u16(), head.lines().next().unwrap_or(""));
            assert_eq!(got, want, "{uri}");
            if status == 200 {
                let host = head.to_ascii_lowercase().contains("\r\nhost: a.example\r\n");
                assert!(host, "{uri}: the backend got no Host: {head}");
            }
        }
    }

    // split_host_port matches Go's net.SplitHostPort: it unbrackets IPv6 literals
    // and REQUIRES a port. These cases mirror the stdlib's own test table.
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
