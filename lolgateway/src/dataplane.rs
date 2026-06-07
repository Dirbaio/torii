//! The Pingora-based data plane.
//!
//! A `ProxyHttp` implementation that, per request, reads the current
//! [`RouteTable`] snapshot, matches the request, and forwards to a backend pod.
//! Returns 404 when nothing matches.
//!
//! Pingora's `Server::run_forever` is blocking and manages its own tokio
//! runtime, so this runs on a dedicated OS thread, separate from the kube
//! controller's runtime. They share state only through [`SharedRouteTable`].

use async_trait::async_trait;
use pingora_core::prelude::*;
use pingora_core::upstreams::peer::HttpPeer;
use pingora_http::ResponseHeader;
use pingora_proxy::{http_proxy_service, ProxyHttp, Session};

use crate::route_table::{Endpoint, Filters, HeaderMods, SharedRouteTable};

/// The proxy. Holds the shared routing snapshot handle.
pub struct GatewayProxy {
    routes: SharedRouteTable,
}

/// Per-request state carried between the proxy phases.
#[derive(Default)]
pub struct RequestCtx {
    upstream: Option<Endpoint>,
    /// Filters to apply to the matched route's request/response.
    filters: Filters,
    /// Rewritten request path (from a URL-rewrite filter), if any.
    rewrite_path: Option<String>,
    /// Request timeout for the matched route (applied to the upstream peer).
    request_timeout: Option<std::time::Duration>,
}

impl GatewayProxy {
    pub fn new(routes: SharedRouteTable) -> Self {
        GatewayProxy { routes }
    }
}

#[async_trait]
impl ProxyHttp for GatewayProxy {
    type CTX = RequestCtx;

    fn new_ctx(&self) -> Self::CTX {
        RequestCtx::default()
    }

    /// Match the request against the route table and stash the chosen backend.
    /// If nothing matches, send a 404 and short-circuit.
    async fn request_filter(&self, session: &mut Session, ctx: &mut Self::CTX) -> Result<bool> {
        let req = session.req_header();
        let path = req.uri.path().to_string();
        let query = req.uri.query().unwrap_or("").to_string();
        let method = req.method.as_str().to_string();
        let host = req
            .headers
            .get("host")
            .and_then(|v| v.to_str().ok())
            .map(strip_port)
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

        let table = self.routes.load();
        let Some(entry) = table.match_request(port, &host, &path, &method, &headers, &query) else {
            tracing::debug!(%host, %path, %method, "no route matched -> 404");
            session.respond_error(404).await?;
            return Ok(true);
        };

        // A RequestRedirect filter produces an early 3xx response — no upstream.
        if let Some(redirect) = &entry.filters.redirect {
            let location = build_redirect_location(redirect, entry, &host, &path);
            let mut resp = ResponseHeader::build(redirect.status_code, None)?;
            resp.insert_header("Location", location)?;
            resp.insert_header("Content-Length", "0")?;
            session.write_response_header(Box::new(resp), true).await?;
            tracing::debug!(%host, %path, status = redirect.status_code, "redirect");
            return Ok(true);
        }

        // Stash filters + any path rewrite + timeout for the later phases.
        ctx.filters = entry.filters.clone();
        ctx.rewrite_path = entry.rewrite_path(&path);
        ctx.request_timeout = entry.request_timeout;

        match entry.pick_endpoint(next_rng()) {
            Some(ep) => {
                tracing::debug!(%host, %path, %method, ip = %ep.ip, port = ep.port, "matched route");
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
        Ok(())
    }

    /// Forward to the backend chosen in `request_filter`.
    async fn upstream_peer(
        &self,
        _session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> Result<Box<HttpPeer>> {
        let ep = ctx
            .upstream
            .as_ref()
            .expect("upstream_peer reached without a chosen backend");
        // Plain HTTP upstream: no TLS, empty SNI.
        let mut peer = HttpPeer::new((ep.ip, ep.port), false, String::new());
        // Apply the route's request timeout to the upstream read (response) wait.
        if let Some(t) = ctx.request_timeout {
            peer.options.read_timeout = Some(t);
            peer.options.total_connection_timeout = Some(t);
        }
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
fn build_redirect_location(
    redirect: &crate::route_table::Redirect,
    entry: &crate::route_table::RouteEntry,
    req_host: &str,
    req_path: &str,
) -> String {
    let scheme = redirect.scheme.as_deref().unwrap_or("http");
    let host = redirect.hostname.as_deref().unwrap_or(req_host);
    let path = match &redirect.path {
        Some(rw) => entry.apply_path_rewrite(rw, req_path),
        None => req_path.to_string(),
    };
    match redirect.port {
        Some(p) => format!("{scheme}://{host}:{p}{path}"),
        None => format!("{scheme}://{host}{path}"),
    }
}

fn strip_port(host: &str) -> &str {
    host.rsplit_once(':').map(|(h, _)| h).unwrap_or(host)
}

/// Run the Pingora proxy server, listening on `bind_addr` (e.g. "127.0.0.1:80").
///
/// This blocks forever (Pingora calls `std::process::exit` on shutdown), so call
/// it from a dedicated thread.
pub fn run(routes: SharedRouteTable, bind_ip: &str, ports: &[u16]) -> ! {
    // Pass None so Pingora doesn't parse our process argv as its own options.
    let mut server = Server::new(None).expect("failed to create pingora server");
    server.bootstrap();

    let mut proxy = http_proxy_service(&server.configuration, GatewayProxy::new(routes));
    // Bind every listener port; the proxy routes per-port via server_addr().
    for port in ports {
        proxy.add_tcp(&format!("{bind_ip}:{port}"));
    }
    server.add_service(proxy);

    tracing::info!(bind_ip, ?ports, "data plane listening");
    server.run_forever();
}
