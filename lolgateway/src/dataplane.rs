//! The Pingora-based data plane.
//!
//! A `ProxyHttp` implementation that, per request, reads the current
//! [`RouteTable`] snapshot, matches the request, and forwards to a backend pod.
//! Returns 404 when nothing matches.
//!
//! Pingora's `Server::run_forever` is blocking and manages its own tokio
//! runtime, so this runs on a dedicated OS thread, separate from the kube
//! controller's runtime. They share state only through the [`DataPlane`] snapshot.

use async_trait::async_trait;
use pingora_core::prelude::*;
use pingora_core::upstreams::peer::HttpPeer;
use pingora_http::ResponseHeader;
use pingora_proxy::{http_proxy_service, ProxyHttp, Session};

use crate::route_table::{BackendTls, Endpoint, Filters, HeaderMods};
use crate::snapshot::DataPlane;

/// The proxy. Holds the shared snapshot handle.
pub struct GatewayProxy {
    data_plane: DataPlane,
    /// Ports that terminate TLS (HTTPS listeners). Used so redirects from an
    /// HTTPS listener default their scheme to `https`.
    tls_ports: Vec<u16>,
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
    /// If set, the request's allowed Origin — add CORS headers to the response.
    cors_origin: Option<String>,
}

impl GatewayProxy {
    pub fn new(data_plane: DataPlane, tls_ports: Vec<u16>) -> Self {
        GatewayProxy { data_plane, tls_ports }
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

        let snapshot = self.data_plane.load();
        let Some(entry) = snapshot.routes.match_request(port, &host, &path, &method, &headers, &query) else {
            tracing::debug!(%host, %path, %method, "no route matched -> 404");
            session.respond_error(404).await?;
            return Ok(true);
        };

        // CORS: handle preflight here; for actual requests, stash to add headers
        // to the response later.
        if let Some(cors) = &entry.filters.cors {
            let origin = headers
                .get("origin")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");
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

        // Fire-and-forget RequestMirror: send a copy of the request to each mirror
        // target's endpoint. The response is ignored; the primary request proceeds.
        for mirror in &entry.filters.mirrors {
            if !sample(mirror.percent) {
                continue;
            }
            if let Some(ep) = mirror.endpoints.first() {
                spawn_mirror(ep.ip, ep.port, &method, &path, &host, &headers);
            }
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
        // Add CORS response headers for an allowed cross-origin actual request.
        if let (Some(cors), Some(origin)) = (&ctx.filters.cors, &ctx.cors_origin) {
            write_cors_headers(upstream_response, cors, origin);
        }
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

        // BackendTLSPolicy: re-encrypt to the backend over TLS, verifying its cert
        // against the policy CA with SNI = the policy hostname. Plain HTTP otherwise.
        let mut peer = match &ep.tls {
            BackendTls::ReEncrypt(tls) => {
                let mut p = HttpPeer::new((ep.ip, ep.port), true, tls.hostname.clone());
                p.options.verify_cert = true;
                p.options.verify_hostname = true;
                if !tls.ca_pem.is_empty() {
                    if let Ok(certs) = pingora_core::tls::x509::X509::stack_from_pem(&tls.ca_pem) {
                        p.options.ca = Some(std::sync::Arc::new(certs.into_boxed_slice()));
                    }
                }
                p
            }
            BackendTls::Plaintext => HttpPeer::new((ep.ip, ep.port), false, String::new()),
            // Invalid endpoints are rejected with a 5xx in request_filter, so the
            // request never reaches here.
            BackendTls::Invalid => unreachable!("invalid-TLS endpoint reached upstream_peer"),
        };
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
    write_cors_headers(resp, cors, origin);
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
}

/// Join a CORS allow-list, expanding a sole `*` to the requested value.
fn expand_wildcard(allow: &[String], requested: &str) -> String {
    if allow.iter().any(|v| v == "*") {
        requested.to_string()
    } else {
        allow.join(", ")
    }
}

/// Sample `percent`% of the time (0 = never, 100 = always).
fn sample(percent: u8) -> bool {
    if percent >= 100 {
        return true;
    }
    if percent == 0 {
        return false;
    }
    (next_rng() % 100) < percent as u64
}

/// Send a fire-and-forget copy of a request to a mirror endpoint. Best-effort:
/// any error is ignored (mirroring must never affect the primary request).
fn spawn_mirror(
    ip: std::net::IpAddr,
    port: u16,
    method: &str,
    path: &str,
    host: &str,
    headers: &http::HeaderMap,
) {
    // Build a minimal HTTP/1.1 request. The echo backend logs the path, which is
    // what the conformance test asserts on; we forward method, path, Host, and
    // the original headers, with no body.
    let mut req = format!("{method} {path} HTTP/1.1\r\nHost: {host}\r\n");
    for (name, value) in headers.iter() {
        let n = name.as_str();
        if n.eq_ignore_ascii_case("host") || n.eq_ignore_ascii_case("content-length") {
            continue;
        }
        if let Ok(v) = value.to_str() {
            req.push_str(&format!("{n}: {v}\r\n"));
        }
    }
    req.push_str("Content-Length: 0\r\nConnection: close\r\n\r\n");

    tokio::spawn(async move {
        use tokio::io::AsyncWriteExt;
        if let Ok(mut stream) = tokio::net::TcpStream::connect((ip, port)).await {
            let _ = stream.write_all(req.as_bytes()).await;
            let _ = stream.flush().await;
            // Briefly drain so the backend finishes handling/logging, then drop.
            let mut buf = [0u8; 1024];
            let _ = tokio::time::timeout(
                std::time::Duration::from_secs(2),
                tokio::io::AsyncReadExt::read(&mut stream, &mut buf),
            )
            .await;
        }
    });
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

fn strip_port(host: &str) -> &str {
    host.rsplit_once(':').map(|(h, _)| h).unwrap_or(host)
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
        let Some(ck) = snapshot.certs.select(sni.as_deref()) else {
            // No cert available; leave the default (handshake will fail cleanly).
            return;
        };
        install_cert(ssl, ck);
    }
}

/// Install a PEM cert+key onto an in-progress TLS handshake.
fn install_cert(ssl: &mut pingora_core::tls::ssl::SslRef, ck: &crate::cert_store::CertKey) {
    use pingora_core::tls::ext;
    let (Ok(cert), Ok(key)) = (
        pingora_core::tls::x509::X509::from_pem(&ck.cert_pem),
        pingora_core::tls::pkey::PKey::private_key_from_pem(&ck.key_pem),
    ) else {
        return;
    };
    let _ = ext::ssl_use_certificate(ssl, &cert);
    let _ = ext::ssl_use_private_key(ssl, &key);
}

/// Run the Pingora proxy server: `http_ports` get plain-TCP listeners, `tls_ports`
/// get HTTPS listeners that terminate TLS using SNI-selected certs from the
/// snapshot's cert store.
///
/// This blocks forever (Pingora calls `std::process::exit` on shutdown), so call
/// it from a dedicated thread.
pub fn run(
    data_plane: DataPlane,
    bind_ip: &str,
    http_ports: &[u16],
    tls_ports: &[u16],
) -> ! {
    use pingora_core::listeners::tls::TlsSettings;

    // Pass None so Pingora doesn't parse our process argv as its own options.
    let mut server = Server::new(None).expect("failed to create pingora server");
    server.bootstrap();

    let mut proxy = http_proxy_service(
        &server.configuration,
        GatewayProxy::new(data_plane.clone(), tls_ports.to_vec()),
    );

    // Plain HTTP listeners. The proxy routes per-port via server_addr().
    for port in http_ports {
        proxy.add_tcp(&format!("{bind_ip}:{port}"));
    }
    // HTTPS listeners: terminate TLS, selecting the cert by SNI per handshake.
    for port in tls_ports {
        let cb: pingora_core::listeners::TlsAcceptCallbacks =
            Box::new(SniCertCallback { data_plane: data_plane.clone() });
        let mut settings = TlsSettings::with_callbacks(cb).expect("failed to build TLS settings");
        // ALPN: accept the ACME `acme-tls/1` challenge protocol; for anything else
        // decline (NOACK) — identical to pingora's default (no ALPN → client falls
        // back to HTTP/1.1), so normal traffic is unaffected whether or not --acme.
        settings.set_alpn_select_callback(|_ssl, client| {
            use pingora_core::tls::ssl::AlpnError;
            match select_alpn(client, b"acme-tls/1") {
                Some(p) => Ok(p),
                None => Err(AlpnError::NOACK),
            }
        });
        proxy
            .add_tls_with_settings(&format!("{bind_ip}:{port}"), None, settings);
    }
    server.add_service(proxy);

    tracing::info!(bind_ip, ?http_ports, ?tls_ports, "data plane listening");
    server.run_forever();
}
