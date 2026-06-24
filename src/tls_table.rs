//! The SNI dispatch table for TLSRoute (the L4 data path).
//!
//! Separate from [`crate::route_table::RouteTable`] (which is HTTP, matched on
//! `(port, Host, path, …)`). A TLSRoute is matched purely on the **SNI** in the
//! TLS ClientHello, and both of its modes end in a raw bidirectional byte pipe —
//! they never parse HTTP:
//!
//! - **Passthrough**: peek the SNI, then pipe the still-encrypted bytes straight
//!   to a backend that terminates TLS itself.
//! - **Terminate**: peek the SNI, terminate TLS here (cert chosen by SNI from the
//!   shared [`crate::cert_store::CertStore`]), then pipe the *cleartext* TCP to the
//!   backend.
//!
//! The control plane builds one [`TlsTable`] per snapshot; the data plane reads it
//! lock-free per connection via [`TlsTable::lookup`].

use std::collections::HashMap;

use crate::route_table::Endpoint;

/// Per-port SNI dispatch, for every Gateway port that carries at least one
/// TLSRoute (i.e. a `protocol: TLS` listener).
#[derive(Debug, Default, Clone)]
pub struct TlsTable {
    by_port: HashMap<u16, TlsPort>,
}

/// One port's SNI → action map, tiered by hostname specificity exactly like the
/// HTTP route table's listener-hostname index: exact beats wildcard beats none.
#[derive(Debug, Default, Clone)]
struct TlsPort {
    /// Exact SNI hostname (lowercased) → action.
    exact: HashMap<String, TlsAction>,
    /// `*.suffix` wildcard SNI → action. The stored key is the `*.`-prefixed
    /// pattern, lowercased. Few in practice; most specific (most labels) wins.
    wildcard: Vec<(String, TlsAction)>,
}

/// What to do with a connection whose SNI matched a TLSRoute on this port.
#[derive(Debug, Clone)]
pub enum TlsAction {
    /// TLS passthrough: pipe the encrypted bytes to one of these backends.
    Passthrough(TlsBackends),
    /// TLS terminate-then-TCP: terminate TLS here, pipe cleartext to a backend.
    Terminate(TlsBackends),
}

/// The decision the data plane acts on for one connection.
#[derive(Debug, Clone)]
pub enum TlsDecision {
    /// Pipe encrypted bytes straight to this endpoint (backend terminates TLS).
    Passthrough(Endpoint),
    /// Terminate TLS, then pipe cleartext to this endpoint.
    Terminate(Endpoint),
    /// SNI matched a rule, but it resolved to no usable backend → close the
    /// connection (Gateway API: reject, do not serve). Distinct from `NoRoute` so
    /// the data plane can log it.
    NoBackend,
    /// No TLSRoute on this port matched the SNI → close the connection.
    NoRoute,
}

/// A weighted set of backends for a TLSRoute rule. Mirrors HTTPRoute weighting:
/// pick a backend by weight, then an endpoint within it.
#[derive(Debug, Clone, Default)]
pub struct TlsBackends {
    pub backends: Vec<TlsBackend>,
}

#[derive(Debug, Clone)]
pub struct TlsBackend {
    pub weight: u32,
    pub endpoints: Vec<Endpoint>,
}

impl TlsBackends {
    /// Pick one endpoint, weighted by backend weight (same semantics as
    /// [`crate::route_table::RouteEntry::pick_endpoint`]). Returns `None` if no
    /// backend has any endpoints.
    pub fn pick_endpoint(&self, rng: u64) -> Option<&Endpoint> {
        let total: u64 = self.backends.iter().map(|b| b.weight as u64).sum();
        let backend = if total == 0 {
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
            chosen?
        };
        if backend.endpoints.is_empty() {
            return None;
        }
        let idx = (rng as usize) % backend.endpoints.len();
        backend.endpoints.get(idx)
    }
}

impl TlsTable {
    /// Add a passthrough or terminate action for an SNI hostname on a port. The
    /// hostname is the *effective* SNI to match (intersection of the TLSRoute
    /// hostname and the listener hostname), lowercased. An empty hostname is
    /// ignored (a TLSRoute that can't be SNI-dispatched; the conformance suite
    /// always sets an SNI hostname, so this only drops genuinely unroutable config).
    pub fn insert(&mut self, port: u16, sni: &str, action: TlsAction) {
        if sni.is_empty() {
            return;
        }
        let sni = sni.to_ascii_lowercase();
        let entry = self.by_port.entry(port).or_default();
        if sni.starts_with("*.") {
            match entry.wildcard.iter_mut().find(|(s, _)| *s == sni) {
                Some((_, a)) => *a = action,
                None => entry.wildcard.push((sni, action)),
            }
        } else {
            entry.exact.insert(sni, action);
        }
    }

    /// Resolve a connection's `(port, SNI)` to a [`TlsDecision`], picking a backend
    /// endpoint by weight with `rng`. Exact SNI match beats the most-specific
    /// wildcard; an unmatched SNI (or absent SNI) is `NoRoute`.
    pub fn lookup(&self, port: u16, sni: Option<&str>, rng: u64) -> TlsDecision {
        let Some(p) = self.by_port.get(&port) else {
            return TlsDecision::NoRoute;
        };
        let Some(sni) = sni else {
            return TlsDecision::NoRoute;
        };
        let sni_lc = sni.to_ascii_lowercase();

        // Tier 1: exact SNI.
        if let Some(action) = p.exact.get(&sni_lc) {
            return Self::act(action, rng);
        }
        // Tier 2: most-specific wildcard whose suffix covers the SNI.
        let best = p
            .wildcard
            .iter()
            .filter(|(suffix, _)| wildcard_covers(suffix, &sni_lc))
            .max_by_key(|(suffix, _)| suffix.matches('.').count());
        if let Some((_, action)) = best {
            return Self::act(action, rng);
        }
        TlsDecision::NoRoute
    }

    fn act(action: &TlsAction, rng: u64) -> TlsDecision {
        match action {
            TlsAction::Passthrough(b) => match b.pick_endpoint(rng) {
                Some(ep) => TlsDecision::Passthrough(ep.clone()),
                None => TlsDecision::NoBackend,
            },
            TlsAction::Terminate(b) => match b.pick_endpoint(rng) {
                Some(ep) => TlsDecision::Terminate(ep.clone()),
                None => TlsDecision::NoBackend,
            },
        }
    }
}

/// Does `*.suffix` wildcard pattern cover `host`? (`*.example.com` covers
/// `a.example.com` but not `example.com`.) `pattern` is the `*.`-prefixed form.
fn wildcard_covers(pattern: &str, host: &str) -> bool {
    if let Some(suffix) = pattern.strip_prefix("*.") {
        host.strip_suffix(suffix)
            .map(|p| p.ends_with('.') && p.len() > 1)
            .unwrap_or(false)
    } else {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::route_table::BackendTls;
    use std::net::IpAddr;

    fn ep(n: u8) -> Endpoint {
        Endpoint {
            ip: IpAddr::from([10, 0, 0, n]),
            port: 443,
            tls: BackendTls::Plaintext,
        }
    }

    fn backends(n: u8) -> TlsBackends {
        TlsBackends {
            backends: vec![TlsBackend { weight: 1, endpoints: vec![ep(n)] }],
        }
    }

    #[test]
    fn exact_sni_passthrough() {
        let mut t = TlsTable::default();
        t.insert(443, "echo.example.com", TlsAction::Passthrough(backends(1)));
        match t.lookup(443, Some("echo.example.com"), 0) {
            TlsDecision::Passthrough(e) => assert_eq!(e.ip, IpAddr::from([10, 0, 0, 1])),
            d => panic!("expected passthrough, got {d:?}"),
        }
    }

    #[test]
    fn terminate_action() {
        let mut t = TlsTable::default();
        t.insert(443, "term.example.com", TlsAction::Terminate(backends(2)));
        assert!(matches!(
            t.lookup(443, Some("term.example.com"), 0),
            TlsDecision::Terminate(_)
        ));
    }

    #[test]
    fn sni_is_case_insensitive() {
        let mut t = TlsTable::default();
        t.insert(443, "Echo.Example.COM", TlsAction::Passthrough(backends(1)));
        assert!(matches!(
            t.lookup(443, Some("echo.example.com"), 0),
            TlsDecision::Passthrough(_)
        ));
        assert!(matches!(
            t.lookup(443, Some("ECHO.EXAMPLE.COM"), 0),
            TlsDecision::Passthrough(_)
        ));
    }

    #[test]
    fn exact_beats_wildcard() {
        let mut t = TlsTable::default();
        t.insert(443, "*.example.com", TlsAction::Passthrough(backends(1)));
        t.insert(443, "a.example.com", TlsAction::Passthrough(backends(2)));
        match t.lookup(443, Some("a.example.com"), 0) {
            TlsDecision::Passthrough(e) => assert_eq!(e.ip, IpAddr::from([10, 0, 0, 2])),
            d => panic!("expected exact match, got {d:?}"),
        }
        // A different subdomain falls to the wildcard.
        match t.lookup(443, Some("b.example.com"), 0) {
            TlsDecision::Passthrough(e) => assert_eq!(e.ip, IpAddr::from([10, 0, 0, 1])),
            d => panic!("expected wildcard match, got {d:?}"),
        }
    }

    #[test]
    fn most_specific_wildcard_wins() {
        let mut t = TlsTable::default();
        t.insert(443, "*.example.com", TlsAction::Passthrough(backends(1)));
        t.insert(443, "*.svc.example.com", TlsAction::Passthrough(backends(2)));
        match t.lookup(443, Some("a.svc.example.com"), 0) {
            TlsDecision::Passthrough(e) => assert_eq!(e.ip, IpAddr::from([10, 0, 0, 2])),
            d => panic!("expected most-specific wildcard, got {d:?}"),
        }
    }

    #[test]
    fn wildcard_does_not_match_bare_domain() {
        let mut t = TlsTable::default();
        t.insert(443, "*.example.com", TlsAction::Passthrough(backends(1)));
        assert!(matches!(
            t.lookup(443, Some("example.com"), 0),
            TlsDecision::NoRoute
        ));
    }

    #[test]
    fn no_sni_is_no_route() {
        let mut t = TlsTable::default();
        t.insert(443, "echo.example.com", TlsAction::Passthrough(backends(1)));
        assert!(matches!(t.lookup(443, None, 0), TlsDecision::NoRoute));
    }

    #[test]
    fn unknown_port_is_no_route() {
        let mut t = TlsTable::default();
        t.insert(443, "echo.example.com", TlsAction::Passthrough(backends(1)));
        assert!(matches!(
            t.lookup(8443, Some("echo.example.com"), 0),
            TlsDecision::NoRoute
        ));
    }

    #[test]
    fn matched_but_no_backend() {
        let mut t = TlsTable::default();
        t.insert(
            443,
            "echo.example.com",
            TlsAction::Passthrough(TlsBackends {
                backends: vec![TlsBackend { weight: 1, endpoints: vec![] }],
            }),
        );
        assert!(matches!(
            t.lookup(443, Some("echo.example.com"), 0),
            TlsDecision::NoBackend
        ));
    }

    #[test]
    fn ports_are_isolated() {
        let mut t = TlsTable::default();
        t.insert(443, "a.example.com", TlsAction::Passthrough(backends(1)));
        t.insert(8443, "a.example.com", TlsAction::Terminate(backends(2)));
        // Same SNI, different port → different action.
        assert!(matches!(
            t.lookup(443, Some("a.example.com"), 0),
            TlsDecision::Passthrough(_)
        ));
        assert!(matches!(
            t.lookup(8443, Some("a.example.com"), 0),
            TlsDecision::Terminate(_)
        ));
    }
}
