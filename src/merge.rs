//! Last-writer-wins registers, OR-sets, edit-vs-delete, tombstone GC and a folder-cycle check.
use crate::hlc::Hlc;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::hash::Hash;

/// Tombstones may be dropped after 90 days, and only once every known peer cursor is past that delete.
pub const TOMBSTONE_GC_MS: u64 = 90 * 24 * 60 * 60 * 1000;
/// Losing versions of a conflict may be kept this long for the application's UI.
pub const CONFLICT_KEEP_MS: u64 = 30 * 24 * 60 * 60 * 1000;

/// Outcome of a last-writer-wins comparison by total HLC order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lww {
    KeepLocal,
    TakeRemote,
    Equal,
}

/// Higher HLC (physical, counter, node id) wins. Equal clocks are [`Lww::Equal`].
pub fn lww(local: &Hlc, remote: &Hlc) -> Lww {
    match local.cmp_total(remote) {
        std::cmp::Ordering::Greater => Lww::KeepLocal,
        std::cmp::Ordering::Less => Lww::TakeRemote,
        std::cmp::Ordering::Equal => Lww::Equal,
    }
}

/// Concurrent edit vs delete: the edit wins. A delete whose HLC is strictly later than
/// the edit wins (the tombstone stands). "Strictly later" is causal: `(physical, counter)`
/// only, so a tie on those two is concurrent even if the node ids differ.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EditOrDelete {
    KeepEdit,
    TakeDelete,
}

pub fn edit_vs_delete(edit: &Hlc, delete: &Hlc) -> EditOrDelete {
    if delete.strictly_later_than(edit) { EditOrDelete::TakeDelete } else { EditOrDelete::KeepEdit }
}

/// True when this tombstone may be dropped: it is at least 90 days old *and* every known
/// peer has already applied the delete (otherwise a late catch-up would resurrect the row).
pub fn can_gc_tombstone(deleted: &Hlc, now_ms: u64, every_peer_cursor_past_delete: bool) -> bool {
    every_peer_cursor_past_delete && now_ms.saturating_sub(deleted.physical_ms) >= TOMBSTONE_GC_MS
}

/// An observed-remove set. Concurrent adds of different elements keep both. A remove is a
/// per-element tombstone and LWW against adds of that element (concurrent add vs remove:
/// the add wins; a strictly later remove wins).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrSet<T: Eq + Hash> {
    adds: HashMap<T, Vec<Hlc>>,
    tombs: HashMap<T, Hlc>,
}

impl<T: Eq + Hash + Clone> Default for OrSet<T> {
    fn default() -> Self {
        Self { adds: HashMap::new(), tombs: HashMap::new() }
    }
}

impl<T: Eq + Hash + Clone> OrSet<T> {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add(&mut self, elem: T, hlc: Hlc) {
        self.adds.entry(elem).or_default().push(hlc);
    }

    pub fn remove(&mut self, elem: T, hlc: Hlc) {
        match self.tombs.get(&elem) {
            Some(prev) if lww(prev, &hlc) != Lww::TakeRemote => {}
            _ => {
                self.tombs.insert(elem, hlc);
            }
        }
    }

    fn present(&self, elem: &T) -> bool {
        let Some(adds) = self.adds.get(elem) else { return false };
        let tomb = self.tombs.get(elem);
        adds.iter().any(|a| match tomb {
            None => true,
            Some(d) => edit_vs_delete(a, d) == EditOrDelete::KeepEdit,
        })
    }

    pub fn contains(&self, elem: &T) -> bool {
        self.present(elem)
    }

    pub fn iter(&self) -> impl Iterator<Item = &T> {
        self.adds.keys().filter(move |e| self.present(e))
    }

    pub fn values(&self) -> HashSet<T> {
        self.iter().cloned().collect()
    }

    /// Merge another replica's add and remove sets into this one.
    pub fn merge(&mut self, other: &Self) {
        for (e, clocks) in &other.adds {
            let slot = self.adds.entry(e.clone()).or_default();
            for c in clocks {
                if !slot.contains(c) {
                    slot.push(c.clone());
                }
            }
        }
        for (e, h) in &other.tombs {
            self.remove(e.clone(), h.clone());
        }
    }
}

/// If assigning `child`'s parent to `new_parent` would cycle, the application should move
/// the later-HLC folder to the root instead.
pub fn folder_cycle<I, F>(child: &I, new_parent: Option<&I>, mut parent_of: F) -> bool
where
    I: Eq + Hash + Clone,
    F: FnMut(&I) -> Option<I>,
{
    let Some(start) = new_parent else { return false };
    let mut seen = HashSet::new();
    let mut cur = start.clone();
    loop {
        if &cur == child {
            return true;
        }
        if !seen.insert(cur.clone()) {
            return true;
        }
        match parent_of(&cur) {
            Some(p) => cur = p,
            None => return false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hlc::NodeId;

    fn n(s: &str) -> NodeId {
        NodeId::new(s)
    }
    fn h(ms: u64, c: u32, node: &str) -> Hlc {
        Hlc::new(ms, c, n(node))
    }

    #[test]
    fn lww_takes_the_later_clock() {
        let a = h(10, 0, "a");
        let b = h(20, 0, "b");
        assert_eq!(lww(&a, &b), Lww::TakeRemote);
        assert_eq!(lww(&b, &a), Lww::KeepLocal);
        assert_eq!(lww(&a, &a), Lww::Equal);
        // Independent fields: a rename and a move at different clocks both survive
        // because the caller LWWs each field separately.
        let title = lww(&h(10, 0, "a"), &h(11, 0, "b"));
        let parent = lww(&h(12, 0, "a"), &h(11, 0, "b"));
        assert_eq!(title, Lww::TakeRemote);
        assert_eq!(parent, Lww::KeepLocal);
    }

    #[test]
    fn concurrent_edit_beats_delete_later_delete_wins() {
        let edit = h(100, 1, "a");
        let concurrent = h(100, 1, "b");
        let later = h(100, 2, "b");
        assert_eq!(edit_vs_delete(&edit, &concurrent), EditOrDelete::KeepEdit);
        assert_eq!(edit_vs_delete(&edit, &later), EditOrDelete::TakeDelete);
        assert_eq!(edit_vs_delete(&later, &edit), EditOrDelete::KeepEdit);
    }

    #[test]
    fn or_set_keeps_concurrent_adds_and_lww_a_tag_remove() {
        let mut a = OrSet::new();
        let mut b = OrSet::new();
        a.add("work", h(10, 0, "a"));
        b.add("home", h(10, 0, "b"));
        a.merge(&b);
        assert_eq!(a.values(), HashSet::from(["work", "home"]));

        a.remove("work", h(10, 0, "c")); // concurrent with the add: add wins
        assert!(a.contains(&"work"));
        a.remove("work", h(11, 0, "c"));
        assert!(!a.contains(&"work"));
        assert!(a.contains(&"home"));
    }

    #[test]
    fn tombstone_gc_waits_for_age_and_cursors() {
        let t = h(1000, 0, "a");
        assert!(!can_gc_tombstone(&t, 1000 + TOMBSTONE_GC_MS - 1, true));
        assert!(!can_gc_tombstone(&t, 1000 + TOMBSTONE_GC_MS, false));
        assert!(can_gc_tombstone(&t, 1000 + TOMBSTONE_GC_MS, true));
        assert_eq!(CONFLICT_KEEP_MS, 30 * 24 * 60 * 60 * 1000);
    }

    #[test]
    fn folder_cycle_is_detected_and_a_root_move_is_not() {
        let parents = HashMap::from([("b", "a"), ("c", "b")]);
        let parent_of = |id: &&str| parents.get(*id).copied();
        assert!(folder_cycle(&"a", Some(&"c"), parent_of));
        assert!(!folder_cycle(&"a", Some(&"d"), parent_of));
        assert!(!folder_cycle(&"a", None, parent_of));
    }
}
