//! Connection and request admission control for the data plane.
//!
//! Every connection costs memory for as long as it lives: a task, an fd, the L4
//! read buffer and, on the TLS ports, OpenSSL's state. On a release build an idle
//! plain-HTTP connection costs about 20 KB and an idle TLS one about 60-75 KB. The
//! idle timeouts bound how long each one lives, not how many there are, so a
//! client that opens connections faster than they time out could OOM-kill the
//! whole process, controller included: one address held 16k TLS connections, and
//! killed a 1 GiB pod, in 13 s.
//!
//! A request to a backend costs far more while its client does not read the
//! response: the proxy reads ~0.5-0.7 MB of it ahead from the backend, and the
//! sockets hold some more, ~1 MB in all, for as long as the client stalls it (a
//! minute at a time, see `CLIENT_STALL_TIMEOUT`). So capping connections alone does
//! not bound memory: within its share of connections, one address OOM-killed a 512
//! MiB torii with 7 HTTP/2 connections of 100 stalled streams each, or with 256
//! plain-HTTP connections that each asked for a large response and read none of it.
//!
//! So a connection takes a [`ConnPermit`] before torii does any work for it and
//! holds it until it ends, and a request takes another once it is routed to a
//! backend and holds it until it ends. Each kind has a per-source cap, which keeps
//! one client from taking more than a small share, and a global cap, by default
//! sized from the memory limit, which makes a flood from many sources get refused
//! instead of killing the process. The last quarter of a global cap is kept for the
//! sources that hold little, so that it takes many more sources to lock out the
//! clients that come later.

use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::net::{IpAddr, Ipv6Addr};
use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

/// Memory set aside per connection when the global connection cap comes from the
/// memory limit: about twice the ~70 KB of an idle TLS connection after a request,
/// the costliest idle kind, so that connections can take about half the limit.
const MEMORY_PER_CONNECTION: u64 = 128 * 1024;

/// Memory set aside per request when the global request cap comes from the memory
/// limit: about twice the ~1 MB a request to a backend holds while its client stalls
/// the response (0.75 MB for an HTTP/2 stream, 1.15 MB for an HTTP/1 request on a
/// release build), so that requests can take about half the limit. Both caps full
/// at once would still exhaust it, but with the per-source caps and the reserve
/// that takes ~80 sources at 512 MiB (see [`Caps`]).
const MEMORY_PER_REQUEST: u64 = 2 * 1024 * 1024;

/// The part of a global cap kept for small sources: its last quarter.
const RESERVE_DIVISOR: usize = 4;

/// A source is small while it holds less than this part of its per-source cap: a
/// sixteenth (by default 16 connections, more than a browser opens, and 8 requests
/// in flight).
const SMALL_SOURCE_DIVISOR: usize = 16;

/// How often a refusal may be logged at `warn`. Refusals come at the rate of a
/// flood; each one is logged at `debug`.
const REFUSAL_WARN_INTERVAL: Duration = Duration::from_secs(60);

/// Caps on how many of one kind (connections, requests) may be open at once, across
/// all data-plane ports. `None` is no cap.
///
/// Once three quarters of `total` are taken, only small sources (holding less than a
/// sixteenth of `per_source`) are admitted: with the default caps, sources that hold
/// their whole share fill those three quarters, and then each new one gets only a
/// sixteenth of it. At 512 MiB that takes 12 sources for the connections, then 64
/// more to fill the reserve; 1.5 and then 8 more for the requests.
#[derive(Clone, Copy, Debug)]
pub struct Caps {
    /// From one source: an IPv4 address, or an IPv6 /64.
    pub per_source: Option<usize>,
    /// In all.
    pub total: Option<usize>,
}

/// The data plane's admission caps.
#[derive(Clone, Copy, Debug)]
pub struct ConnLimits {
    /// On connections, from accept to close.
    pub connections: Caps,
    /// On requests to backends, from routing to the end of the response.
    pub requests: Caps,
}

/// Counts the open connections and the requests in flight against [`ConnLimits`].
pub struct ConnLimiter {
    limits: ConnLimits,
    state: Mutex<State>,
}

#[derive(Default)]
struct State {
    connections: Counts,
    requests: Counts,
    /// When a refusal was last logged at `warn`, and the refusals since.
    warned: Option<Instant>,
    refused: Refused,
}

/// The open connections, or the requests in flight.
#[derive(Default)]
struct Counts {
    total: usize,
    /// Per source (see [`source_key`]), for the sources that have any. Only kept with
    /// a per-source cap.
    per_source: HashMap<IpAddr, usize>,
}

/// Refusals since the last `warn`, which counts the one it is about.
#[derive(Debug, Default)]
struct Refused {
    connections: usize,
    requests: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Connection,
    Request,
}

/// The cap a refused connection or request is over.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Over {
    Source,
    /// The reserve of the global cap, which the source is too large for.
    Reserve,
    Total,
}

/// An admitted connection's or request's slot. Dropping it frees the slot.
pub struct ConnPermit {
    limiter: Arc<ConnLimiter>,
    kind: Kind,
    /// The source it counts under, if per source.
    source: Option<IpAddr>,
}

impl ConnLimiter {
    pub fn new(limits: ConnLimits) -> Arc<Self> {
        Arc::new(Self {
            limits,
            state: Mutex::default(),
        })
    }

    /// Admit a connection from `peer` (`None`: it has no IP address, so it only
    /// counts toward the global cap). Returns `None` if it is over a cap, and the
    /// caller must then close it.
    pub fn admit(self: &Arc<Self>, peer: Option<IpAddr>) -> Option<ConnPermit> {
        self.take(Kind::Connection, peer)
    }

    /// Admit a request from `peer` to a backend, as [`Self::admit`] does a
    /// connection. Returns `None` if it is over a cap, and the caller must then
    /// refuse it.
    pub fn admit_request(self: &Arc<Self>, peer: Option<IpAddr>) -> Option<ConnPermit> {
        self.take(Kind::Request, peer)
    }

    fn take(self: &Arc<Self>, kind: Kind, peer: Option<IpAddr>) -> Option<ConnPermit> {
        let caps = self.limits.caps(kind);
        let source = peer.filter(|_| caps.per_source.is_some()).map(source_key);
        let mut state = self.state();
        let counts = state.counts(kind);
        let held = source.map(|source| counts.per_source.get(&source).copied().unwrap_or(0));
        let Some(over) = caps.over(counts.total, held) else {
            counts.total += 1;
            if let Some(source) = source {
                *counts.per_source.entry(source).or_default() += 1;
            }
            return Some(ConnPermit {
                limiter: self.clone(),
                kind,
                source,
            });
        };

        match kind {
            Kind::Connection => state.refused.connections += 1,
            Kind::Request => state.refused.requests += 1,
        }
        let warn = state.warned.is_none_or(|t| t.elapsed() >= REFUSAL_WARN_INTERVAL);
        let refused = if warn {
            state.warned = Some(Instant::now());
            Some(std::mem::take(&mut state.refused))
        } else {
            None
        };
        drop(state);
        let (limit, action, hint) = match (kind, over) {
            (Kind::Connection, Over::Source) => (
                "per-source connection limit reached",
                "closing the connections over it",
                "raise --max-connections-per-source if clients share an address",
            ),
            (Kind::Connection, Over::Reserve) => (
                "connection limit nearly reached",
                "closing new connections from sources that hold many",
                "raise --max-connections if memory allows",
            ),
            (Kind::Connection, Over::Total) => (
                "connection limit reached",
                "closing new connections",
                "raise --max-connections if memory allows",
            ),
            (Kind::Request, Over::Source) => (
                "per-source request limit reached",
                "answering 503 to the requests over it",
                "raise --max-requests-per-source if clients share an address",
            ),
            (Kind::Request, Over::Reserve) => (
                "request limit nearly reached",
                "answering 503 to new requests from sources that have many in flight",
                "raise --max-requests if memory allows",
            ),
            (Kind::Request, Over::Total) => (
                "request limit reached",
                "answering 503 to new requests",
                "raise --max-requests if memory allows",
            ),
        };
        if let Some(refused) = refused {
            tracing::warn!(
                ?peer,
                limits = ?self.limits,
                ?refused,
                "{limit}; {action} ({hint}; logged at most once a minute, with the refusals since the last time)"
            );
        } else {
            tracing::debug!(?peer, "{limit}; refusing");
        }
        None
    }

    fn state(&self) -> MutexGuard<'_, State> {
        // Nothing panics while holding it, but a permit must not panic in drop.
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl ConnLimits {
    fn caps(&self, kind: Kind) -> Caps {
        match kind {
            Kind::Connection => self.connections,
            Kind::Request => self.requests,
        }
    }
}

impl Caps {
    /// The cap that refuses one more where `total` are open and its source holds
    /// `held` (`None`: it is not counted per source), if any.
    fn over(&self, total: usize, held: Option<usize>) -> Option<Over> {
        if let (Some(max), Some(held)) = (self.per_source, held)
            && held >= max
        {
            return Some(Over::Source);
        }
        let max = self.total?;
        if total >= max {
            return Some(Over::Total);
        }
        let small = match (self.per_source, held) {
            (Some(per_source), Some(held)) => held < per_source.div_ceil(SMALL_SOURCE_DIVISOR),
            // Not counted per source, so not told apart.
            _ => true,
        };
        (total >= max - max / RESERVE_DIVISOR && !small).then_some(Over::Reserve)
    }
}

impl State {
    fn counts(&mut self, kind: Kind) -> &mut Counts {
        match kind {
            Kind::Connection => &mut self.connections,
            Kind::Request => &mut self.requests,
        }
    }
}

impl Drop for ConnPermit {
    fn drop(&mut self) {
        let mut state = self.limiter.state();
        let counts = state.counts(self.kind);
        counts.total -= 1;
        if let Some(source) = self.source
            && let Entry::Occupied(mut n) = counts.per_source.entry(source)
        {
            *n.get_mut() -= 1;
            if *n.get() == 0 {
                n.remove();
            }
        }
    }
}

/// The source a per-source cap counts `ip` under: an IPv4 address as is, an IPv6
/// address by its /64, the block a single host or home network gets. An
/// IPv4-mapped IPv6 address, as a dual-stack listener reports an IPv4 peer, counts
/// as that IPv4 address (as a /64 it would lump all IPv4 peers together).
fn source_key(ip: IpAddr) -> IpAddr {
    match ip.to_canonical() {
        IpAddr::V6(ip) => IpAddr::V6(Ipv6Addr::from_bits(ip.to_bits() & (u128::MAX << 64))),
        ip => ip,
    }
}

/// The memory limit of torii's cgroup (a pod's `limits.memory`), or `None` without
/// one, or without cgroup v2.
pub fn memory_limit() -> Option<u64> {
    let proc_cgroup = std::fs::read_to_string("/proc/self/cgroup").ok()?;
    cgroup_memory_limit(&proc_cgroup, |path| std::fs::read_to_string(path).ok())
}

/// The default global connection cap for the memory limit `limit`: one connection
/// per [`MEMORY_PER_CONNECTION`].
pub fn default_max_connections(limit: u64) -> usize {
    (limit / MEMORY_PER_CONNECTION).max(1) as usize
}

/// The default global request cap for the memory limit `limit`: one request per
/// [`MEMORY_PER_REQUEST`].
pub fn default_max_requests(limit: u64) -> usize {
    (limit / MEMORY_PER_REQUEST).max(1) as usize
}

/// The memory limit of a process in cgroup v2 whose `/proc/self/cgroup` reads
/// `proc_cgroup`: the lowest `memory.max` along its cgroup's path, read through
/// `read`. A container with its own cgroup namespace is at `/`, where `memory.max`
/// is the container's limit.
fn cgroup_memory_limit(proc_cgroup: &str, read: impl Fn(&Path) -> Option<String>) -> Option<u64> {
    let path = proc_cgroup.lines().find_map(|line| line.strip_prefix("0::"))?;
    Path::new(path)
        .ancestors()
        .filter_map(|dir| {
            let dir = dir.strip_prefix("/").unwrap_or(dir);
            read(&Path::new("/sys/fs/cgroup").join(dir).join("memory.max"))
        })
        // "max" is no limit.
        .filter_map(|max| max.trim().parse().ok())
        .min()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> Option<IpAddr> {
        Some(s.parse().unwrap())
    }

    /// Limits with `connections` and no caps on requests.
    fn connection_limits(connections: Caps) -> ConnLimits {
        ConnLimits {
            connections,
            requests: Caps {
                per_source: None,
                total: None,
            },
        }
    }

    // One source gets at most its cap, others still get in, and a closed connection
    // frees its slot.
    #[test]
    fn per_source_cap() {
        let limiter = ConnLimiter::new(connection_limits(Caps {
            per_source: Some(2),
            total: None,
        }));
        let a1 = limiter.admit(ip("192.0.2.1")).unwrap();
        let _a2 = limiter.admit(ip("192.0.2.1")).unwrap();
        assert!(limiter.admit(ip("192.0.2.1")).is_none());
        let _b = limiter.admit(ip("192.0.2.2")).unwrap();
        let _no_ip = limiter.admit(None).unwrap();
        drop(a1);
        let _a3 = limiter.admit(ip("192.0.2.1")).unwrap();
        assert!(limiter.admit(ip("192.0.2.1")).is_none());
    }

    // An IPv6 host's addresses share its /64, and an IPv4-mapped address is its IPv4
    // address, not one /64 for every IPv4 peer.
    #[test]
    fn sources_are_ipv4_addresses_and_ipv6_64s() {
        let limiter = ConnLimiter::new(connection_limits(Caps {
            per_source: Some(1),
            total: None,
        }));
        let _v6 = limiter.admit(ip("2001:db8:0:1::1")).unwrap();
        assert!(limiter.admit(ip("2001:db8:0:1:ffff::2")).is_none());
        let _other_64 = limiter.admit(ip("2001:db8:0:2::1")).unwrap();

        let _v4 = limiter.admit(ip("192.0.2.1")).unwrap();
        assert!(limiter.admit(ip("::ffff:192.0.2.1")).is_none());
        let _other_v4 = limiter.admit(ip("::ffff:192.0.2.2")).unwrap();
    }

    // The global cap holds whatever the sources, and frees with them. With no cap
    // nothing is refused.
    #[test]
    fn global_cap() {
        let limiter = ConnLimiter::new(connection_limits(Caps {
            per_source: Some(2),
            total: Some(3),
        }));
        let a = limiter.admit(ip("192.0.2.1")).unwrap();
        let _b = limiter.admit(ip("192.0.2.2")).unwrap();
        let _c = limiter.admit(None).unwrap();
        assert!(limiter.admit(ip("192.0.2.3")).is_none());
        assert!(limiter.admit(None).is_none());
        drop(a);
        let _d = limiter.admit(ip("192.0.2.3")).unwrap();
        assert_eq!(
            limiter.state().connections.per_source.len(),
            2,
            "a source with no connection left is forgotten"
        );

        let unlimited = ConnLimiter::new(connection_limits(Caps {
            per_source: None,
            total: None,
        }));
        let permits: Vec<_> = (0..1000).map(|_| unlimited.admit(ip("192.0.2.1")).unwrap()).collect();
        assert!(unlimited.state().connections.per_source.is_empty());
        drop(permits);
        assert_eq!(unlimited.state().connections.total, 0);
    }

    // Once three quarters of the global cap are taken, a source that holds a
    // sixteenth of its per-source cap or more is refused, and the rest is for the
    // sources that hold less.
    #[test]
    fn last_quarter_is_for_small_sources() {
        let limiter = ConnLimiter::new(connection_limits(Caps {
            per_source: Some(32),
            total: Some(8),
        }));
        let big: Vec<_> = (0..6).map(|_| limiter.admit(ip("192.0.2.1")).unwrap()).collect();
        assert!(limiter.admit(ip("192.0.2.1")).is_none(), "the reserve is not for it");
        let _small = limiter.admit(ip("192.0.2.2")).unwrap();
        let _small2 = limiter.admit(ip("192.0.2.2")).unwrap();
        assert!(limiter.admit(ip("192.0.2.3")).is_none(), "the cap is full");
        drop(big);
        let _again = limiter.admit(ip("192.0.2.1")).unwrap();
    }

    // Requests count apart from connections, under their own caps, and free their
    // slots as connections do.
    #[test]
    fn requests_have_their_own_caps() {
        let limiter = ConnLimiter::new(ConnLimits {
            connections: Caps {
                per_source: Some(1),
                total: None,
            },
            requests: Caps {
                per_source: Some(2),
                total: Some(3),
            },
        });
        let _conn = limiter.admit(ip("192.0.2.1")).unwrap();
        assert!(limiter.admit(ip("192.0.2.1")).is_none());
        let r1 = limiter.admit_request(ip("192.0.2.1")).unwrap();
        let _r2 = limiter.admit_request(ip("192.0.2.1")).unwrap();
        assert!(
            limiter.admit_request(ip("192.0.2.1")).is_none(),
            "over its source's cap"
        );
        let _r3 = limiter.admit_request(ip("192.0.2.2")).unwrap();
        assert!(limiter.admit_request(ip("192.0.2.3")).is_none(), "over the global cap");
        drop(r1);
        let _r4 = limiter.admit_request(ip("192.0.2.1")).unwrap();
        assert_eq!(limiter.state().requests.total, 3);
        assert_eq!(limiter.state().connections.total, 1);
    }

    // The default global caps leave each kind about half of the memory limit.
    #[test]
    fn default_caps_from_the_memory_limit() {
        assert_eq!(default_max_connections(512 << 20), 4096);
        assert_eq!(default_max_requests(512 << 20), 256);
        assert_eq!(default_max_requests(1 << 30), 512);
        assert_eq!(default_max_requests(1 << 20), 1);
    }

    // The limit is the lowest memory.max on the cgroup's path; "max" and missing
    // files are no limit.
    #[test]
    fn cgroup_memory_limit_is_the_lowest_on_the_path() {
        fn fs(files: &[(&str, &str)]) -> impl Fn(&Path) -> Option<String> {
            let files: HashMap<String, String> = files.iter().map(|&(p, s)| (p.into(), s.into())).collect();
            move |path| files.get(path.to_str().unwrap()).cloned()
        }

        // The root cgroup has no memory.max.
        let host = fs(&[
            ("/sys/fs/cgroup/kubepods/memory.max", "max\n"),
            ("/sys/fs/cgroup/kubepods/pod1/memory.max", "1073741824\n"),
            ("/sys/fs/cgroup/kubepods/pod1/ctr/memory.max", "2147483648\n"),
        ]);
        assert_eq!(cgroup_memory_limit("0::/kubepods/pod1/ctr\n", &host), Some(1 << 30));
        assert_eq!(cgroup_memory_limit("0::/kubepods\n", &host), None);
        // cgroup v1 only.
        assert_eq!(cgroup_memory_limit("4:memory:/kubepods/pod1/ctr\n", &host), None);

        // In its own cgroup namespace, a container sees itself at the root.
        let container = fs(&[("/sys/fs/cgroup/memory.max", "536870912\n")]);
        assert_eq!(cgroup_memory_limit("0::/\n", &container), Some(512 << 20));
    }
}
