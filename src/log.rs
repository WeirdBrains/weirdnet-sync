//! Append-only per-node op log. A device never rewrites another node's entries.
use crate::hlc::{Hlc, NodeId};
use crate::protocol::PAGE_BUDGET;
use crate::record::{Value, is_chunk_type};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap};

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
    /// The full value when `op` is only a fallback (chunked or sealed; see
    /// [`crate::record`]). Absent before 0.4, and dropped by older peers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<Value>,
}

impl LogEntry {
    /// Rough encoded size, for page budgeting.
    pub fn wire_size(&self) -> usize {
        64 + self.typ.len() + self.record_id.len() + self.op.len() + self.value.as_ref().map_or(0, Value::wire_size)
    }
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
    /// Per (node, type): every op of that type with `seq <=` this is applied.
    type_cursors: HashMap<(String, String), u64>,
    /// Chunk entries by (chunk type, hex hash).
    chunk_index: HashMap<(String, String), Vec<(String, u64)>>,
    /// Entries whose value is chunked, by type.
    blobs: HashMap<String, BTreeSet<(String, u64)>>,
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

    /// How far this log holds every op of `typ` from `node`: the explicit
    /// per-type cursor, or the contiguous prefix of `node`'s entries (all
    /// types), whichever is further. A pull of one type resumes from here.
    pub fn cursor_for(&self, node: &NodeId, typ: &str) -> u64 {
        let explicit = self.type_cursors.get(&(node.0.clone(), typ.to_string())).copied().unwrap_or(0);
        explicit.max(self.contiguous(node))
    }

    pub fn set_cursor_for(&mut self, node: &NodeId, typ: &str, last_seq: u64) {
        self.type_cursors.insert((node.0.clone(), typ.to_string()), last_seq);
    }

    /// Per-type cursors, for an application to persist next to [`OpLog::cursors`].
    pub fn type_cursors(&self) -> HashMap<(NodeId, String), u64> {
        self.type_cursors.iter().map(|((n, t), v)| ((NodeId(n.clone()), t.clone()), *v)).collect()
    }

    /// Highest `k` such that every seq `1..=k` of `node` is held.
    pub fn contiguous(&self, node: &NodeId) -> u64 {
        let mut k = 0;
        for e in self.iter_node(node) {
            if e.seq != k + 1 {
                break;
            }
            k = e.seq;
        }
        k
    }

    /// The newest HLC held from any node.
    pub fn newest_hlc(&self) -> Option<&Hlc> {
        self.entries.values().map(|e| &e.hlc).max_by(|a, b| a.cmp_total(b))
    }

    /// Ops of `typ` from `node` with `after_seq < seq <= known_to`, up to `limit` ops and
    /// [`PAGE_BUDGET`] bytes. Missing seqs in that range are other types and are skipped, so
    /// `known_to` must be [`OpLog::cursor_for`] (or less). `to_seq` is the last seq walked,
    /// which may be past the last op returned; a puller resumes after it.
    pub fn page_of_type(&self, node: &NodeId, typ: &str, after_seq: u64, known_to: u64, limit: usize) -> Page {
        let mut ops = Vec::new();
        let mut bytes = 0usize;
        let mut to_seq = after_seq;
        if known_to > after_seq {
            let mut full = false;
            for (_, e) in self.entries.range((node.0.clone(), after_seq + 1)..=(node.0.clone(), known_to)) {
                if e.typ == typ {
                    let add = e.wire_size();
                    if !ops.is_empty() && (ops.len() >= limit || bytes + add > PAGE_BUDGET) {
                        full = true;
                        break;
                    }
                    bytes += add;
                    ops.push(e.clone());
                }
                to_seq = e.seq;
            }
            if !full {
                to_seq = known_to;
            }
        }
        let from_seq = ops.first().map(|e| e.seq).unwrap_or(after_seq);
        Page { node_id: node.clone(), from_seq, to_seq, ops }
    }

    /// Append a local mutation. `seq` is assigned here.
    pub fn append(&mut self, node: NodeId, hlc: Hlc, typ: impl Into<String>, record_id: impl Into<String>, op: Vec<u8>) -> &LogEntry {
        let seq = self.next_seq(&node);
        let entry = LogEntry { node_id: node.clone(), seq, hlc, typ: typ.into(), record_id: record_id.into(), op, value: None };
        self.index(&entry);
        self.entries.insert((node.0.clone(), seq), entry);
        self.next.insert(node.0.clone(), seq + 1);
        self.cursors.insert(node.0.clone(), seq);
        self.entries.get(&(node.0, seq)).expect("just inserted")
    }

    /// Append a local entry with a [`Value`] (see [`crate::SyncState::write`]).
    pub fn append_value(
        &mut self,
        node: NodeId,
        hlc: Hlc,
        typ: impl Into<String>,
        record_id: impl Into<String>,
        op: Vec<u8>,
        value: Value,
    ) -> &LogEntry {
        let seq = self.next_seq(&node);
        let entry = LogEntry { node_id: node.clone(), seq, hlc, typ: typ.into(), record_id: record_id.into(), op, value: Some(value) };
        self.index(&entry);
        self.entries.insert((node.0.clone(), seq), entry);
        self.next.insert(node.0.clone(), seq + 1);
        self.cursors.insert(node.0.clone(), seq);
        self.entries.get(&(node.0, seq)).expect("just inserted")
    }

    fn index(&mut self, e: &LogEntry) {
        if is_chunk_type(&e.typ) {
            self.chunk_index.entry((e.typ.clone(), e.record_id.clone())).or_default().push((e.node_id.0.clone(), e.seq));
        }
        if e.value.as_ref().is_some_and(|v| v.blob.is_some()) {
            self.blobs.entry(e.typ.clone()).or_default().insert((e.node_id.0.clone(), e.seq));
        }
    }

    /// The bytes of chunk `hash` of chunk type `ctyp`, from any entry whose bytes hash to it.
    pub fn chunk(&self, ctyp: &str, hash: &[u8]) -> Option<&[u8]> {
        let at = self.chunk_index.get(&(ctyp.to_string(), hex::encode(hash)))?;
        at.iter()
            .filter_map(|(n, s)| self.entries.get(&(n.clone(), *s)))
            .map(|e| e.op.as_slice())
            .find(|b| blake3::hash(b).as_bytes()[..] == hash[..])
    }

    /// Whether `node` already wrote chunk `hash` of `ctyp` (local writes reuse it).
    pub fn has_own_chunk(&self, node: &NodeId, ctyp: &str, hash: &[u8]) -> bool {
        self.chunk_index.get(&(ctyp.to_string(), hex::encode(hash))).is_some_and(|at| {
            at.iter().any(|(n, s)| *n == node.0 && self.entries.get(&(n.clone(), *s)).is_some_and(|e| blake3::hash(&e.op).as_bytes()[..] == hash[..]))
        })
    }

    /// Entries of `typ` whose chunked value is not complete yet.
    pub fn pending_blobs(&self, typ: &str) -> Vec<&LogEntry> {
        let ctyp = crate::record::chunk_type(typ);
        let Some(set) = self.blobs.get(typ) else { return Vec::new() };
        set.iter()
            .filter_map(|(n, s)| self.entries.get(&(n.clone(), *s)))
            .filter(|e| e.value.as_ref().and_then(|v| v.blob.as_ref()).is_some_and(|b| b.chunk_hashes().any(|h| self.chunk(&ctyp, h).is_none())))
            .collect()
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

    /// Entries of `node` with `seq > after_seq`, up to `limit` and [`PAGE_BUDGET`] plaintext bytes.
    pub fn page(&self, node: &NodeId, after_seq: u64, limit: usize) -> Page {
        let mut ops = Vec::new();
        let mut bytes = 0usize;
        for seq in (after_seq + 1).. {
            let Some(e) = self.entries.get(&(node.0.clone(), seq)) else { break };
            let add = e.wire_size();
            if !ops.is_empty() && (ops.len() >= limit || bytes + add > PAGE_BUDGET) {
                break;
            }
            if add > PAGE_BUDGET && ops.is_empty() {
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
            self.index(e);
            self.entries.insert(key, e.clone());
            added += 1;
            let next = self.next.entry(e.node_id.0.clone()).or_insert(1);
            if e.seq + 1 > *next {
                *next = e.seq + 1;
            }
        }
        added
    }

    /// Every entry held, by node then seq.
    pub fn iter(&self) -> impl Iterator<Item = &LogEntry> {
        self.entries.values()
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
            ops: vec![LogEntry {
                node_id: n("b"),
                seq: 1,
                hlc: h(3, "b"),
                typ: "bookmarks".into(),
                record_id: "r2".into(),
                op: b"x".to_vec(),
                value: None,
            }],
        };
        assert_eq!(log.integrate(&remote), 1);
        assert_eq!(log.integrate(&remote), 0);
        assert_eq!(log.get(&n("a"), 1).unwrap().op, b"add");
        assert_eq!(log.len(), 3);
    }

    #[test]
    fn typed_pages_skip_other_types_and_resume_past_them() {
        let mut log = OpLog::new();
        log.append(n("a"), h(1, "a"), "bookmarks", "b1", vec![1]);
        log.append(n("a"), h(2, "a"), "history", "v1", vec![2]);
        log.append(n("a"), h(3, "a"), "bookmarks", "b2", vec![3]);
        log.append(n("a"), h(4, "a"), "history", "v2", vec![4]);
        log.append(n("a"), h(5, "a"), "bookmarks", "b3", vec![5]);
        let known = log.cursor_for(&n("a"), "history");
        assert_eq!(known, 5, "an authored stream is contiguous");
        let p = log.page_of_type(&n("a"), "history", 0, known, 1);
        assert_eq!(p.ops.iter().map(|e| e.seq).collect::<Vec<_>>(), [2]);
        assert_eq!(p.to_seq, 3, "stops before the next op of the type that did not fit");
        let p = log.page_of_type(&n("a"), "history", p.to_seq, known, 10);
        assert_eq!(p.ops.iter().map(|e| e.seq).collect::<Vec<_>>(), [4]);
        assert_eq!(p.to_seq, 5, "walks past trailing ops of other types");
        let p = log.page_of_type(&n("a"), "history", 5, known, 10);
        assert!(p.ops.is_empty());
        assert_eq!(p.to_seq, 5);
    }

    #[test]
    fn a_relayed_stream_is_served_only_as_far_as_it_is_known() {
        let mut log = OpLog::new();
        // We hold a's bookmarks 1 and 3 but not history 2 (never pulled).
        let e = |seq, typ: &str| LogEntry {
            node_id: n("a"),
            seq,
            hlc: h(seq, "a"),
            typ: typ.into(),
            record_id: format!("r{seq}"),
            op: vec![],
            value: None,
        };
        log.integrate(&Page { node_id: n("a"), from_seq: 1, to_seq: 3, ops: vec![e(1, "bookmarks"), e(3, "bookmarks")] });
        assert_eq!(log.contiguous(&n("a")), 1);
        assert_eq!(log.cursor_for(&n("a"), "history"), 1, "history 2 is unknown, not absent");
        log.set_cursor_for(&n("a"), "bookmarks", 3);
        assert_eq!(log.cursor_for(&n("a"), "bookmarks"), 3);
        let p = log.page_of_type(&n("a"), "bookmarks", 0, 3, 10);
        assert_eq!(p.ops.len(), 2);
        assert_eq!(p.to_seq, 3);
        assert!(log.page_of_type(&n("a"), "history", 0, log.cursor_for(&n("a"), "history"), 10).ops.is_empty());
        assert_eq!(log.type_cursors().len(), 1);
        assert_eq!(log.newest_hlc().unwrap().physical_ms, 3);
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
