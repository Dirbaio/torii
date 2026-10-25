//! Connection admission control for the data plane.
//!
//! Every connection costs memory for as long as it lives: a task, an fd, the L4
//! read buffer and, on the TLS ports, OpenSSL's state. On a release build an idle
//! plain-HTTP connection costs about 20 KB and an idle TLS one about 60 KB. The
//! idle timeouts bound how long each one lives, not how many there are, so a
//! client that opens connections faster than they time out could OOM-kill the
//! whole process, controller included: one address held 16k TLS connections, and
//! killed a 1 GiB pod, in 13 s.
//!
//! So a connection takes a [`ConnPermit`] before torii does any work for it, and
//! holds it until it ends. A per-source cap keeps one client from taking more than
//! a small share, and a global cap, by default sized from the memory limit, makes
//! a flood from many sources get refused instead of killing the process.

use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::net::{IpAddr, Ipv6Addr};
use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

/// Memory set aside per connection when the global cap comes from the memory
/// limit: twice the ~64 KB of an idle TLS connection after a request, the costliest
/// idle kind, so idle connections can take about half the limit and the rest stays
/// for the controller and for the requests in flight.
const MEMORY_PER_CONNECTION: u64 = 128 * 1024;

/// How often a refused connection may be logged at `warn`. Refusals come at the
/// rate of a flood; each one is logged at `debug`.
const REFUSAL_WARN_INTERVAL: Duration = Duration::from_secs(60);

/// Caps on concurrent connections, across all data-plane ports. `None` is no cap.
#[derive(Clone, Copy, Debug)]
pub struct ConnLimits {
    /// From one source: an IPv4 address, or an IPv6 /64.
    pub per_source: Option<usize>,
    /// In all.
    pub total: Option<usize>,
}

/// Counts the open connections against [`ConnLimits`].
pub struct ConnLimiter {
    limits: ConnLimits,
    state: Mutex<State>,
}

#[derive(Default)]
struct State {
    total: usize,
    /// Open connections per source (see [`source_key`]), for the sources that have
    /// any. Only kept with a per-source cap.
    per_source: HashMap<IpAddr, usize>,
    /// When a refusal was last logged at `warn`.
    warned: Option<Instant>,
}

/// An admitted connection's slot. Dropping it frees the slot.
pub struct ConnPermit {
    limiter: Arc<ConnLimiter>,
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
        let source = peer.filter(|_| self.limits.per_source.is_some()).map(source_key);
        let mut state = self.state();
        let over_total = self.limits.total.is_some_and(|max| state.total >= max);
        let over_source = match (self.limits.per_source, source) {
            (Some(max), Some(source)) => state.per_source.get(&source).is_some_and(|&n| n >= max),
            _ => false,
        };
        if !over_total && !over_source {
            state.total += 1;
            if let Some(source) = source {
                *state.per_source.entry(source).or_default() += 1;
            }
            return Some(ConnPermit {
                limiter: self.clone(),
                source,
            });
        }

        let warn = state.warned.is_none_or(|t| t.elapsed() >= REFUSAL_WARN_INTERVAL);
        if warn {
            state.warned = Some(Instant::now());
        }
        drop(state);
        let limit = if over_total {
            "connection limit"
        } else {
            "per-source connection limit"
        };
        if warn {
            tracing::warn!(
                ?peer,
                limits = ?self.limits,
                "{limit} reached; closing the connections over it (logged at most once a minute)"
            );
        } else {
            tracing::debug!(?peer, "{limit} reached; closing");
        }
        None
    }

    fn state(&self) -> MutexGuard<'_, State> {
        // Nothing panics while holding it, but a permit must not panic in drop.
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl Drop for ConnPermit {
    fn drop(&mut self) {
        let mut state = self.limiter.state();
        state.total -= 1;
        if let Some(source) = self.source
            && let Entry::Occupied(mut n) = state.per_source.entry(source)
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

/// The default global cap: one connection per [`MEMORY_PER_CONNECTION`] of the
/// memory limit of torii's cgroup (a pod's `limits.memory`), or none without one.
pub fn default_max_connections() -> Option<usize> {
    let proc_cgroup = std::fs::read_to_string("/proc/self/cgroup").ok()?;
    let limit = cgroup_memory_limit(&proc_cgroup, |path| std::fs::read_to_string(path).ok())?;
    Some((limit / MEMORY_PER_CONNECTION).max(1) as usize)
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

    // One source gets at most its cap, others still get in, and a closed connection
    // frees its slot.
    #[test]
    fn per_source_cap() {
        let limiter = ConnLimiter::new(ConnLimits {
            per_source: Some(2),
            total: None,
        });
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
        let limiter = ConnLimiter::new(ConnLimits {
            per_source: Some(1),
            total: None,
        });
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
        let limiter = ConnLimiter::new(ConnLimits {
            per_source: Some(2),
            total: Some(3),
        });
        let a = limiter.admit(ip("192.0.2.1")).unwrap();
        let _b = limiter.admit(ip("192.0.2.2")).unwrap();
        let _c = limiter.admit(None).unwrap();
        assert!(limiter.admit(ip("192.0.2.3")).is_none());
        assert!(limiter.admit(None).is_none());
        drop(a);
        let _d = limiter.admit(ip("192.0.2.3")).unwrap();
        assert_eq!(
            limiter.state().per_source.len(),
            2,
            "a source with no connection left is forgotten"
        );

        let unlimited = ConnLimiter::new(ConnLimits {
            per_source: None,
            total: None,
        });
        let permits: Vec<_> = (0..1000).map(|_| unlimited.admit(ip("192.0.2.1")).unwrap()).collect();
        assert!(unlimited.state().per_source.is_empty());
        drop(permits);
        assert_eq!(unlimited.state().total, 0);
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
