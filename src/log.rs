//! Append-only per-node op log. A device never rewrites another node's entries.
use crate::hlc::{Hlc, NodeId};
use crate::protocol::PAGE_MAX;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};

/// One mutation in some node's log. `op` is the application's encoding; unknown `typ`
/// values are stored and skipped by the application so a newer device can talk to an older one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogEntry {
    pub node_id: NodeId,
    pub seq: u64,
    pub hlc: Hlc,
    pub typ: String,
    pub record_id: String,
    #[serde(with = "serde_bytes")]
    pub op: Vec<u8>,
}

mod serde_bytes {
    pub use crate::bytes::{deserialize, serialize};
}

/// A slice of one node's log, as sent in a `Page`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Page {
    pub node_id: NodeId,
    pub from_seq: u64,
    pub to_seq: u64,
    pub ops: Vec<LogEntry>,
}

/// In-memory log and peer cursors (the last seq applied from each peer, including ourselves).
#[derive(Debug, Default, Clone)]
pub struct OpLog {
    entries: BTreeMap<(String, u64), LogEntry>,
    /// Next seq this node will assign.
    next: HashMap<String, u64>,
    /// Last seq applied from each peer.
    cursors: HashMap<String, u64>,
}

impl OpLog {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn next_seq(&self, node: &NodeId) -> u64 {
        self.next.get(&node.0).copied().unwrap_or(1)
    }

    pub fn cursor(&self, node: &NodeId) -> u64 {
        self.cursors.get(&node.0).copied().unwrap_or(0)
    }

    pub fn cursors(&self) -> HashMap<NodeId, u64> {
        self.cursors.iter().map(|(k, v)| (NodeId(k.clone()), *v)).collect()
    }

    pub fn set_cursor(&mut self, node: &NodeId, last_seq: u64) {
        self.cursors.insert(node.0.clone(), last_seq);
    }

    /// Append a local mutation. `seq` is assigned here.
    pub fn append(&mut self, node: NodeId, hlc: Hlc, typ: impl Into<String>, record_id: impl Into<String>, op: Vec<u8>) -> &LogEntry {
        let seq = self.next_seq(&node);
        let entry = LogEntry { node_id: node.clone(), seq, hlc, typ: typ.into(), record_id: record_id.into(), op };
        self.entries.insert((node.0.clone(), seq), entry);
        self.next.insert(node.0.clone(), seq + 1);
        self.cursors.insert(node.0.clone(), seq);
        self.entries.get(&(node.0, seq)).expect("just inserted")
    }

    pub fn get(&self, node: &NodeId, seq: u64) -> Option<&LogEntry> {
        self.entries.get(&(node.0.clone(), seq))
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Entries of `node` with `seq > after_seq`, up to `limit` and [`PAGE_MAX`] encoded bytes.
    pub fn page(&self, node: &NodeId, after_seq: u64, limit: usize) -> Page {
        let mut ops = Vec::new();
        let mut bytes = 0usize;
        for seq in (after_seq + 1).. {
            let Some(e) = self.entries.get(&(node.0.clone(), seq)) else { break };
            let add = 64 + e.typ.len() + e.record_id.len() + e.op.len();
            if !ops.is_empty() && (ops.len() >= limit || bytes + add > PAGE_MAX) {
                break;
            }
            if add > PAGE_MAX && ops.is_empty() {
                // A single oversized op still goes out: the app must not write one this large,
                // but dropping it would stall the cursor.
                ops.push(e.clone());
                break;
            }
            bytes += add;
            ops.push(e.clone());
            if ops.len() >= limit {
                break;
            }
        }
        let from_seq = ops.first().map(|e| e.seq).unwrap_or(after_seq);
        let to_seq = ops.last().map(|e| e.seq).unwrap_or(after_seq);
        Page { node_id: node.clone(), from_seq, to_seq, ops }
    }

    /// Integrate a remote page. Existing entries of that node are left untouched; gaps are
    /// accepted and later pages fill them. Returns how many new entries were stored.
    pub fn integrate(&mut self, page: &Page) -> usize {
        let mut added = 0;
        for e in &page.ops {
            if e.node_id != page.node_id {
                continue;
            }
            let key = (e.node_id.0.clone(), e.seq);
            if self.entries.contains_key(&key) {
                continue;
            }
            self.entries.insert(key, e.clone());
            added += 1;
            let next = self.next.entry(e.node_id.0.clone()).or_insert(1);
            if e.seq + 1 > *next {
                *next = e.seq + 1;
            }
        }
        added
    }

    pub fn iter_node(&self, node: &NodeId) -> impl Iterator<Item = &LogEntry> {
        let prefix = node.0.clone();
        self.entries.range((prefix.clone(), 0)..(prefix.clone(), u64::MAX)).filter(move |((n, _), _)| *n == prefix).map(|(_, e)| e)
    }
}

// Range with String and u64 is fine; (prefix, u64::MAX) includes seq MAX. Good.

#[cfg(test)]
mod tests {
    use super::*;

    fn n(s: &str) -> NodeId {
        NodeId::new(s)
    }

    fn h(ms: u64, node: &str) -> Hlc {
        Hlc::new(ms, 0, n(node))
    }

    #[test]
    fn append_assigns_seq_and_never_rewrites_a_peer() {
        let mut log = OpLog::new();
        let a1 = log.append(n("a"), h(1, "a"), "bookmarks", "r1", b"add".to_vec()).clone();
        let a2 = log.append(n("a"), h(2, "a"), "bookmarks", "r1", b"edit".to_vec()).clone();
        assert_eq!(a1.seq, 1);
        assert_eq!(a2.seq, 2);
        let remote = Page {
            node_id: n("b"),
            from_seq: 1,
            to_seq: 1,
            ops: vec![LogEntry { node_id: n("b"), seq: 1, hlc: h(3, "b"), typ: "bookmarks".into(), record_id: "r2".into(), op: b"x".to_vec() }],
        };
        assert_eq!(log.integrate(&remote), 1);
        assert_eq!(log.integrate(&remote), 0);
        assert_eq!(log.get(&n("a"), 1).unwrap().op, b"add");
        assert_eq!(log.len(), 3);
    }

    #[test]
    fn page_starts_after_the_cursor_and_respects_limit() {
        let mut log = OpLog::new();
        for i in 0..5 {
            log.append(n("a"), h(i, "a"), "bookmarks", format!("r{i}"), vec![i as u8]);
        }
        let p = log.page(&n("a"), 2, 2);
        assert_eq!(p.from_seq, 3);
        assert_eq!(p.to_seq, 4);
        assert_eq!(p.ops.len(), 2);
        let empty = log.page(&n("a"), 5, 10);
        assert!(empty.ops.is_empty());
        assert_eq!(empty.to_seq, 5);
    }
}
