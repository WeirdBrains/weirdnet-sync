//! Hybrid logical clock: `(physical_ms, counter, node_id)`.
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::fmt;

/// A node's id in the log and on the clock (the peer id string).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct NodeId(pub String);

impl NodeId {
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }
}

impl fmt::Display for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<&str> for NodeId {
    fn from(s: &str) -> Self {
        Self(s.to_string())
    }
}

/// Hybrid logical clock. `physical_ms` is the caller's Unix-ms (`now_ms` in tests).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Hlc {
    pub physical_ms: u64,
    pub counter: u32,
    pub node_id: NodeId,
}

impl Hlc {
    pub fn new(physical_ms: u64, counter: u32, node_id: NodeId) -> Self {
        Self { physical_ms, counter, node_id }
    }

    /// Total order: physical, then counter, then node id. Used for LWW of a single field.
    pub fn cmp_total(&self, other: &Self) -> Ordering {
        self.physical_ms.cmp(&other.physical_ms).then(self.counter.cmp(&other.counter)).then(self.node_id.cmp(&other.node_id))
    }

    /// Causal / "strictly later" order: physical, then counter, ignoring node id.
    /// Two events with the same `(physical_ms, counter)` on different nodes are concurrent.
    pub fn cmp_causal(&self, other: &Self) -> Ordering {
        self.physical_ms.cmp(&other.physical_ms).then(self.counter.cmp(&other.counter))
    }

    pub fn strictly_later_than(&self, other: &Self) -> bool {
        self.cmp_causal(other) == Ordering::Greater
    }

    pub fn concurrent_with(&self, other: &Self) -> bool {
        self.cmp_causal(other) == Ordering::Equal && self.node_id != other.node_id
    }

    /// A local write at `wall_ms` after `last` (or the first write, if `last` is `None`).
    pub fn tick(last: Option<&Self>, wall_ms: u64, node_id: NodeId) -> Self {
        match last {
            None => Self { physical_ms: wall_ms, counter: 0, node_id },
            Some(last) if wall_ms > last.physical_ms => Self { physical_ms: wall_ms, counter: 0, node_id },
            Some(last) => Self { physical_ms: last.physical_ms, counter: last.counter.saturating_add(1), node_id },
        }
    }

    /// Advance after seeing `other`, then issuing a local event at `wall_ms`.
    pub fn receive(last: Option<&Self>, other: &Self, wall_ms: u64, node_id: NodeId) -> Self {
        let last_phys = last.map(|l| l.physical_ms).unwrap_or(0);
        let last_ctr = last.map(|l| l.counter).unwrap_or(0);
        let physical_ms = wall_ms.max(last_phys).max(other.physical_ms);
        let counter = if physical_ms == last_phys && physical_ms == other.physical_ms {
            last_ctr.max(other.counter).saturating_add(1)
        } else if physical_ms == last_phys {
            last_ctr.saturating_add(1)
        } else if physical_ms == other.physical_ms {
            other.counter.saturating_add(1)
        } else {
            0
        };
        Self { physical_ms, counter, node_id }
    }
}

impl PartialOrd for Hlc {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(Ord::cmp(self, other))
    }
}

impl Ord for Hlc {
    fn cmp(&self, other: &Self) -> Ordering {
        self.cmp_total(other)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn n(s: &str) -> NodeId {
        NodeId::new(s)
    }

    #[test]
    fn tick_advances_physical_or_bumps_the_counter() {
        let a = Hlc::tick(None, 1000, n("a"));
        assert_eq!(a, Hlc::new(1000, 0, n("a")));
        let b = Hlc::tick(Some(&a), 2000, n("a"));
        assert_eq!(b, Hlc::new(2000, 0, n("a")));
        let c = Hlc::tick(Some(&b), 2000, n("a"));
        assert_eq!(c, Hlc::new(2000, 1, n("a")));
        let d = Hlc::tick(Some(&c), 1500, n("a"));
        assert_eq!(d, Hlc::new(2000, 2, n("a")));
    }

    #[test]
    fn receive_tracks_the_other_clock() {
        let last = Hlc::new(1000, 0, n("a"));
        let other = Hlc::new(3000, 4, n("b"));
        let r = Hlc::receive(Some(&last), &other, 2000, n("a"));
        assert_eq!(r, Hlc::new(3000, 5, n("a")));
        let same = Hlc::receive(Some(&last), &Hlc::new(1000, 2, n("b")), 1000, n("a"));
        assert_eq!(same, Hlc::new(1000, 3, n("a")));
    }

    #[test]
    fn concurrent_is_same_physical_and_counter_on_different_nodes() {
        let a = Hlc::new(5, 1, n("a"));
        let b = Hlc::new(5, 1, n("b"));
        assert!(a.concurrent_with(&b));
        assert!(!a.strictly_later_than(&b));
        assert!(!b.strictly_later_than(&a));
        let later = Hlc::new(5, 2, n("b"));
        assert!(later.strictly_later_than(&a));
        assert!(!later.concurrent_with(&a));
    }

    #[test]
    fn total_order_breaks_ties_on_node_id() {
        let a = Hlc::new(5, 1, n("a"));
        let b = Hlc::new(5, 1, n("b"));
        assert!(a < b);
    }
}
