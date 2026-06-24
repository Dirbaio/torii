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
use pingora_core::prelude::*;
use pingora_core::upstreams::peer::HttpPeer;
use pingora_http::ResponseHeader;
use pingora_proxy::{http_proxy, http_proxy_service, ProxyHttp, Session};

use crate::route_table::{BackendTls, Endpoint, Filters, HeaderMods};
use crate::snapshot::DataPlane;
use crate::tls_table::TlsDecision;

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
    /// Forwarded-header values captured from the inbound connection in
    /// `request_filter` (the only phase with `Session` access), emitted to the
    /// upstream in `upstream_request_filter`. We OVERWRITE any client-supplied
    /// `X-Forwarded-*` rather than appending: lolgateway may sit directly on the
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

        // Capture the forwarded-header values now, while we have the Session and
        // the original (pre-rewrite) Host. Emitted to the upstream later.
        ctx.fwd = Forwarded {
            client_ip: session
                .client_addr()
                .and_then(|a| a.as_inet())
                .map(|a| a.ip().to_string()),
            host: host.clone(),
            port,
            scheme: if self.tls_ports.contains(&port) { "https" } else { "http" },
        };

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
        // Forwarded headers (nginx-ingress parity). OVERWRITE rather than append:
        // an inbound X-Forwarded-* is attacker-controlled when lolgateway faces
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

/// A newtype that re-exposes a boxed [`pingora_core::protocols::Stream`]
/// (`Box<dyn IO>`) as a concrete `S: IO`.
///
/// Pingora's `handshake_with_callback<S: IO>` and `ServerSession::new_http1` take
/// a generic `S: IO` / a `Stream`, but `Box<dyn IO>` does not itself implement the
/// `IO` supertraits, so it can't be passed where `S: IO` is required. This wrapper
/// delegates every supertrait method to the inner trait object; the blanket
/// `impl IO for T` in pingora then applies to `BoxedStream` automatically.
#[derive(Debug)]
struct BoxedStream(pingora_core::protocols::Stream);

impl tokio::io::AsyncRead for BoxedStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut *self.0).poll_read(cx, buf)
    }
}

impl tokio::io::AsyncWrite for BoxedStream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut *self.0).poll_write(cx, buf)
    }
    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut *self.0).poll_flush(cx)
    }
    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut *self.0).poll_shutdown(cx)
    }
}

#[async_trait]
impl pingora_core::protocols::Shutdown for BoxedStream {
    async fn shutdown(&mut self) {
        self.0.shutdown().await
    }
}

impl pingora_core::protocols::UniqueID for BoxedStream {
    fn id(&self) -> pingora_core::protocols::UniqueIDType {
        self.0.id()
    }
}

impl pingora_core::protocols::Ssl for BoxedStream {
    fn get_ssl(&self) -> Option<&pingora_core::protocols::tls::TlsRef> {
        self.0.get_ssl()
    }
    fn get_ssl_digest(&self) -> Option<std::sync::Arc<pingora_core::protocols::tls::SslDigest>> {
        self.0.get_ssl_digest()
    }
    fn selected_alpn_proto(&self) -> Option<pingora_core::protocols::ALPN> {
        self.0.selected_alpn_proto()
    }
}

impl pingora_core::protocols::GetTimingDigest for BoxedStream {
    fn get_timing_digest(&self) -> Vec<Option<pingora_core::protocols::TimingDigest>> {
        self.0.get_timing_digest()
    }
    fn get_read_pending_time(&self) -> std::time::Duration {
        self.0.get_read_pending_time()
    }
    fn get_write_pending_time(&self) -> std::time::Duration {
        self.0.get_write_pending_time()
    }
}

impl pingora_core::protocols::GetProxyDigest for BoxedStream {
    fn get_proxy_digest(
        &self,
    ) -> Option<std::sync::Arc<pingora_core::protocols::raw_connect::ProxyDigest>> {
        self.0.get_proxy_digest()
    }
}

impl pingora_core::protocols::GetSocketDigest for BoxedStream {
    fn get_socket_digest(
        &self,
    ) -> Option<std::sync::Arc<pingora_core::protocols::SocketDigest>> {
        self.0.get_socket_digest()
    }
}

#[async_trait]
impl pingora_core::protocols::Peek for BoxedStream {
    async fn try_peek(&mut self, buf: &mut [u8]) -> std::io::Result<bool> {
        self.0.try_peek(buf).await
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
}

#[async_trait]
impl pingora_core::apps::ServerApp for GatewayTlsApp {
    async fn process_new(
        self: &Arc<Self>,
        mut stream: pingora_core::protocols::Stream,
        shutdown: &pingora_core::server::ShutdownWatch,
    ) -> Option<pingora_core::protocols::Stream> {
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
                let Ok(mut upstream) = tokio::net::TcpStream::connect((ep.ip, ep.port)).await else {
                    tracing::debug!(ip = %ep.ip, "passthrough backend connect failed");
                    return None;
                };
                // True bidirectional pipe: the backend may speak first.
                let _ = tokio::io::copy_bidirectional(&mut stream, &mut upstream).await;
                None
            }
            TlsDecision::Terminate(ep) => {
                tracing::debug!(port, ?sni, ip = %ep.ip, ep_port = ep.port, "TLS terminate -> TCP");
                // Terminate TLS here (cert chosen by SNI via the callback), then
                // pipe the cleartext to the backend (which expects plaintext TCP).
                let tls_stream = match pingora_core::protocols::tls::server::handshake_with_callback(
                    &self.acceptor,
                    BoxedStream(stream),
                    &self.tls_callbacks,
                )
                .await
                {
                    Ok(s) => s,
                    Err(e) => {
                        tracing::debug!(error = %e, "TLSRoute terminate handshake failed");
                        return None;
                    }
                };
                let Ok(mut upstream) = tokio::net::TcpStream::connect((ep.ip, ep.port)).await else {
                    tracing::debug!(ip = %ep.ip, "terminate backend connect failed");
                    return None;
                };
                let mut tls_stream = tls_stream;
                let _ = tokio::io::copy_bidirectional(&mut tls_stream, &mut upstream).await;
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
    /// Terminate TLS and feed the resulting stream to the HTTP proxy, looping for
    /// HTTP/1.1 keepalive reuse. Mirrors pingora's own `HttpServerApp` accept loop
    /// (`apps/mod.rs`), HTTP/1.1 only — our ALPN never negotiates h2, so h2c is
    /// not a concern here.
    async fn terminate_and_serve_http(
        &self,
        stream: pingora_core::protocols::Stream,
        shutdown: &pingora_core::server::ShutdownWatch,
    ) -> Option<pingora_core::protocols::Stream> {
        use pingora_core::apps::HttpServerApp;
        use pingora_core::protocols::http::ServerSession;

        let tls_stream = match pingora_core::protocols::tls::server::handshake_with_callback(
            &self.acceptor,
            BoxedStream(stream),
            &self.tls_callbacks,
        )
        .await
        {
            Ok(s) => s,
            Err(e) => {
                tracing::debug!(error = %e, "HTTPS terminate handshake failed");
                return None;
            }
        };

        let mut session = ServerSession::new_http1(Box::new(tls_stream));
        // Default keepalive (60s), or none while shutting down.
        session.set_keepalive(if *shutdown.borrow() { None } else { Some(60) });

        let mut result = self.proxy.process_new_http(session, shutdown).await;
        while let Some((stream, persistent_settings)) = result.map(|r| r.consume()) {
            let mut session = ServerSession::new_http1(stream);
            if let Some(ps) = persistent_settings {
                ps.apply_to_session(&mut session);
            }
            result = self.proxy.process_new_http(session, shutdown).await;
        }
        None
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

    let mut builder = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls())
        .expect("failed to create TLS acceptor builder");
    // ALPN: accept the ACME `acme-tls/1` challenge protocol; decline anything else
    // (NOACK → client falls back to HTTP/1.1), identical to the previous listener.
    builder.set_alpn_select_callback(|_ssl, client| {
        use pingora_core::tls::ssl::AlpnError;
        match select_alpn(client, b"acme-tls/1") {
            Some(p) => Ok(p),
            None => Err(AlpnError::NOACK),
        }
    });
    let acceptor = Arc::new(builder.build());
    let callbacks: pingora_core::listeners::TlsAcceptCallbacks =
        Box::new(SniCertCallback { data_plane });
    (acceptor, Arc::new(callbacks))
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
) -> ! {
    // Pass None so Pingora doesn't parse our process argv as its own options.
    let mut server = Server::new(None).expect("failed to create pingora server");
    server.bootstrap();

    // Plain-HTTP proxy service. The proxy routes per-port via server_addr().
    let mut http_service = http_proxy_service(
        &server.configuration,
        GatewayProxy::new(data_plane.clone(), tls_ports.to_vec()),
    );
    for port in http_ports {
        http_service.add_tcp(&format!("{bind_ip}:{port}"));
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
            GatewayProxy::new(data_plane.clone(), tls_ports.to_vec()),
        ));
        let app = GatewayTlsApp {
            data_plane: data_plane.clone(),
            proxy,
            acceptor,
            tls_callbacks,
        };
        let mut tls_service =
            pingora_core::services::listening::Service::new("tls-sni-dispatch".to_string(), app);
        for port in tls_ports {
            tls_service.add_tcp(&format!("{bind_ip}:{port}"));
        }
        server.add_service(tls_service);
    }

    tracing::info!(bind_ip, ?http_ports, ?tls_ports, "data plane listening");
    server.run_forever();
}
