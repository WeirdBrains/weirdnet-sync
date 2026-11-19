//! Record values larger than one page, and values sealed per record.
//!
//! A [`LogEntry`]'s `op` is what every version of this crate reads. Since 0.4 an entry
//! may also carry a [`Value`]: then `op` is only a fallback (empty, or a preview the
//! application chose) and the full value is in the `Value`, either inline (`body`) or
//! split into content-addressed chunks ([`Blob`]). Older peers ignore the field, keep
//! the fallback and never see a chunk, so nothing they hold changes meaning.
//!
//! Chunks are ordinary log entries of the companion type [`chunk_type`]`(typ)`
//! (`<typ>#chunks`), keyed by the BLAKE3 hash of their bytes. They are pulled right after
//! their type ([`Limits::eager_chunks`]) or on demand ([`crate::pull_chunks`]), and
//! reassembled only when every chunk and the whole value match their hashes.
//!
//! A type configured [`RecordOptions::sealed`] has every value sealed under a key derived
//! for that record from the head epoch key ([`record_key`]). Only members of the head
//! rotation hold that key, so a device revoked before the write cannot open it, even
//! with the seed and every older key. Members keep older epoch keys and admitted devices
//! receive them, so values sealed before a rotation stay readable;
//! [`crate::SyncState::reseal_stale`] moves them to the head key. Sealing happens before
//! chunking, so chunks of a sealed value are ciphertext.
use crate::error::{Result, SyncError};
use crate::log::{LogEntry, OpLog};
use crate::protocol::{KeyRef, PAGE_BUDGET};
use crate::rotation::KeyStatus;
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::collections::BTreeMap;
use weirdnet_keys::{Key32, Sealed, kdf};
use zeroize::Zeroizing;

/// Suffix of the companion type that carries a type's chunks.
pub const CHUNK_SUFFIX: &str = "#chunks";

/// Newest [`Value`] format this crate reads.
pub const VALUE_VERSION: u32 = 1;

/// Largest chunk (and inline value) that still fits a page with room to spare.
pub const CHUNK_MAX: usize = PAGE_BUDGET - 4 * 1024;

/// The companion type holding `typ`'s chunks.
pub fn chunk_type(typ: &str) -> String {
    format!("{typ}{CHUNK_SUFFIX}")
}

pub fn is_chunk_type(typ: &str) -> bool {
    typ.ends_with(CHUNK_SUFFIX)
}

/// The type a companion chunk type belongs to.
pub fn base_type(typ: &str) -> Option<&str> {
    typ.strip_suffix(CHUNK_SUFFIX)
}

/// Per-type size limits for [`crate::SyncState::write`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Limits {
    /// Values (after sealing) up to this size go inline in one entry; larger ones are chunked.
    pub inline_max: usize,
    /// Chunk size for larger values.
    pub chunk_size: usize,
    /// Largest value accepted at all.
    pub record_max: usize,
    /// `pull_from` also pulls this type's chunks when an entry is still missing some.
    /// Off: the application calls [`crate::pull_chunks`] when it needs the value.
    pub eager_chunks: bool,
}

impl Default for Limits {
    fn default() -> Self {
        Self { inline_max: 32 * 1024, chunk_size: 48 * 1024, record_max: 16 * 1024 * 1024, eager_chunks: true }
    }
}

impl Limits {
    pub fn check(&self) -> Result<()> {
        let max_chunks = self.record_max.div_ceil(self.chunk_size.max(1));
        if self.chunk_size < 1024 || self.chunk_size > CHUNK_MAX || self.inline_max > CHUNK_MAX || max_chunks * 32 > CHUNK_MAX {
            return Err(SyncError::Protocol(format!(
                "limits out of range: chunk_size 1 KiB..={CHUNK_MAX}, inline_max <= {CHUNK_MAX}, record_max / chunk_size * 32 <= {CHUNK_MAX}"
            )));
        }
        Ok(())
    }
}

/// How a record type is written: sealed or not, and its limits.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RecordOptions {
    /// Seal every value under a per-record key from the head epoch key.
    pub sealed: bool,
    pub limits: Limits,
}

/// The full value of an entry whose `op` is only a fallback.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Value {
    /// Format version; a reader refuses one newer than [`VALUE_VERSION`].
    pub v: u32,
    /// Set when the payload is sealed (see [`SealInfo`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seal: Option<SealInfo>,
    /// The payload, when it is inline.
    #[serde(default, skip_serializing_if = "Vec::is_empty", with = "crate::bytes")]
    pub body: Vec<u8>,
    /// The payload, when it is chunked.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blob: Option<Blob>,
}

/// Which key a sealed payload is under: the rotation `key` at `epoch`, and the nonce.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealInfo {
    pub epoch: u32,
    pub key: String,
    #[serde(with = "crate::bytes")]
    pub nonce: Vec<u8>,
}

/// A chunked payload: its length, BLAKE3 hash, and the chunk hashes in order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Blob {
    pub len: u64,
    #[serde(with = "crate::bytes")]
    pub hash: Vec<u8>,
    /// Concatenated 32-byte chunk hashes.
    #[serde(with = "crate::bytes")]
    pub chunks: Vec<u8>,
}

impl Blob {
    pub fn chunk_hashes(&self) -> impl Iterator<Item = &[u8]> {
        self.chunks.chunks(32)
    }

    pub fn chunk_ids(&self) -> Vec<String> {
        self.chunk_hashes().map(hex::encode).collect()
    }
}

impl Value {
    /// Rough encoded size, for page budgeting.
    pub fn wire_size(&self) -> usize {
        96 + self.body.len() + self.blob.as_ref().map_or(0, |b| 64 + b.chunks.len()) + self.seal.as_ref().map_or(0, |s| 64 + s.key.len())
    }
}

/// What [`crate::SyncState::read`] found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecordValue {
    /// The full value.
    Ready(zeroize::Zeroizing<Vec<u8>>),
    /// Chunks not held yet (hex hashes); pull them and read again.
    Pending { missing: Vec<String> },
}

impl RecordValue {
    pub fn ready(self) -> Option<zeroize::Zeroizing<Vec<u8>>> {
        match self {
            RecordValue::Ready(v) => Some(v),
            RecordValue::Pending { .. } => None,
        }
    }
}

/// One chunk of a payload: its BLAKE3 hash and bytes.
pub type Chunk<'a> = ([u8; 32], &'a [u8]);

/// Split a payload into chunks of `chunk_size`; returns the blob and the chunks.
pub fn split(payload: &[u8], chunk_size: usize) -> (Blob, Vec<Chunk<'_>>) {
    let parts: Vec<Chunk<'_>> = payload.chunks(chunk_size.max(1)).map(|c| (*blake3::hash(c).as_bytes(), c)).collect();
    let chunks = parts.iter().flat_map(|(h, _)| h.iter().copied()).collect();
    (Blob { len: payload.len() as u64, hash: blake3::hash(payload).as_bytes().to_vec(), chunks }, parts)
}

/// Reassemble a blob from `log`'s chunks of `typ`, checking every chunk hash, the length
/// and the whole hash.
pub fn assemble(log: &OpLog, typ: &str, blob: &Blob) -> Result<RecordValue> {
    if !blob.chunks.len().is_multiple_of(32) || blob.hash.len() != 32 {
        return Err(SyncError::Protocol("malformed blob".into()));
    }
    let ctyp = chunk_type(typ);
    let mut missing = Vec::new();
    let mut out = zeroize::Zeroizing::new(Vec::with_capacity(blob.len.min(64 * 1024 * 1024) as usize));
    for h in blob.chunk_hashes() {
        match log.chunk(&ctyp, h) {
            Some(bytes) if missing.is_empty() => out.extend_from_slice(bytes),
            Some(_) => {}
            None => missing.push(hex::encode(h)),
        }
    }
    if !missing.is_empty() {
        missing.dedup();
        return Ok(RecordValue::Pending { missing });
    }
    if out.len() as u64 != blob.len || blake3::hash(&out).as_bytes()[..] != blob.hash[..] {
        return Err(SyncError::Protocol("blob does not match its hash".into()));
    }
    Ok(RecordValue::Ready(out))
}

/// The payload of an entry's value: inline body, or the reassembled blob.
pub(crate) fn payload(log: &OpLog, e: &LogEntry, v: &Value) -> Result<RecordValue> {
    if v.v > VALUE_VERSION {
        return Err(SyncError::Protocol(format!("value format {} is newer than {VALUE_VERSION}", v.v)));
    }
    match &v.blob {
        Some(b) => assemble(log, &e.typ, b),
        None => Ok(RecordValue::Ready(zeroize::Zeroizing::new(v.body.clone()))),
    }
}

impl crate::net::SyncState {
    /// Set how `typ` is written. Adds `typ` to [`crate::SyncState::types`] if missing.
    pub fn configure(&mut self, typ: &str, opts: RecordOptions) -> Result<()> {
        opts.limits.check()?;
        if is_chunk_type(typ) {
            return Err(SyncError::Protocol("chunk types are not configured directly".into()));
        }
        if !self.types.iter().any(|t| t == typ) {
            self.types.push(typ.to_string());
        }
        self.records.insert(typ.to_string(), opts);
        Ok(())
    }

    /// The options for `typ` ([`RecordOptions::default`] when not configured).
    pub fn options(&self, typ: &str) -> RecordOptions {
        self.records.get(typ).cloned().unwrap_or_default()
    }

    /// A local write of a whole value: sealed when the type is sealed, chunked when it
    /// is larger than [`Limits::inline_max`]. Older peers see an empty `op` for a
    /// sealed or chunked value; use [`crate::SyncState::write_with_fallback`] to give
    /// them something. Returns the entry's seq.
    pub fn write(&mut self, now_ms: u64, typ: &str, record_id: &str, value: &[u8]) -> Result<u64> {
        self.write_with_fallback(now_ms, typ, record_id, value, Vec::new())
    }

    /// Like [`crate::SyncState::write`], with the `op` older peers (and apps that
    /// do not call [`crate::SyncState::read`]) see when the value is sealed or chunked,
    /// for example a clipped preview. A value written plain ignores `fallback`. The
    /// fallback itself is never sealed: for a sealed type, leave it empty or make it
    /// something safe to show.
    pub fn write_with_fallback(&mut self, now_ms: u64, typ: &str, record_id: &str, value: &[u8], fallback: Vec<u8>) -> Result<u64> {
        if is_chunk_type(typ) {
            return Err(SyncError::Protocol("chunk types are written by the crate".into()));
        }
        let opts = self.options(typ);
        let limits = &opts.limits;
        if value.len() > limits.record_max {
            return Err(SyncError::Protocol(format!("value of {} bytes is over record_max {}", value.len(), limits.record_max)));
        }
        if fallback.len() > limits.inline_max {
            return Err(SyncError::Protocol("fallback is over inline_max".into()));
        }
        let (seal, payload) = self.seal_payload(&opts, typ, record_id, value)?;
        if seal.is_none() && payload.len() <= limits.inline_max {
            return Ok(self.local_op(now_ms, typ, record_id, payload.to_vec()));
        }
        let mut v = Value { v: VALUE_VERSION, seal, body: Vec::new(), blob: None };
        if payload.len() <= limits.inline_max {
            v.body = payload.to_vec();
        } else {
            let ctyp = chunk_type(typ);
            let (blob, parts) = split(&payload, limits.chunk_size);
            for (h, bytes) in parts {
                if !self.log.has_own_chunk(&self.our_node, &ctyp, &h) {
                    self.local_op(now_ms, &ctyp, &hex::encode(h), bytes.to_vec());
                }
            }
            v.blob = Some(blob);
        }
        let hlc = self.tick(now_ms);
        Ok(self.log.append_value(self.our_node.clone(), hlc, typ, record_id, fallback, v).seq)
    }

    /// The full value of `e`: its `op`, its inline value, or its reassembled chunks,
    /// opened when sealed. `Pending` lists chunks still to pull. An entry of a sealed
    /// type that is not sealed is refused.
    pub fn read(&self, e: &LogEntry) -> Result<RecordValue> {
        let sealed_type = self.options(&e.typ).sealed;
        let Some(v) = &e.value else {
            if sealed_type {
                return Err(SyncError::Protocol("unsealed entry in a sealed type".into()));
            }
            return Ok(RecordValue::Ready(zeroize::Zeroizing::new(e.op.clone())));
        };
        if sealed_type && v.seal.is_none() {
            return Err(SyncError::Protocol("unsealed entry in a sealed type".into()));
        }
        match payload(&self.log, e, v)? {
            RecordValue::Ready(p) => match &v.seal {
                Some(s) => Ok(RecordValue::Ready(self.open_payload(s, e, &p)?)),
                None => Ok(RecordValue::Ready(p)),
            },
            pending => Ok(pending),
        }
    }
}

/// Per-record key: `HKDF-SHA256(epoch key, salt = user id,
/// info = weirdnet-sync/v1/record/<type>/e<n>/k<rotation id>/<record id>)`.
pub fn record_key(epoch_key: &Key32, user_id: &str, typ: &str, record_id: &str, epoch: u32, id: &str) -> Result<Key32> {
    let info = format!("weirdnet-sync/v1/record/{typ}/e{epoch}/k{id}/{record_id}");
    Ok(kdf::hkdf(&epoch_key.0, Some(user_id.as_bytes()), info.as_bytes())?)
}

/// Which record a sealed value belongs to: its type, record id and writer node.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecordRef<'a> {
    pub typ: &'a str,
    pub record_id: &'a str,
    pub node: &'a str,
}

impl<'a> RecordRef<'a> {
    pub fn of(e: &'a LogEntry) -> Self {
        Self { typ: &e.typ, record_id: &e.record_id, node: &e.node_id.0 }
    }
}

/// Associated data of a sealed record: type, epoch, rotation, writer node and record id,
/// so a sealed value cannot be moved to another record, type, key or writer.
pub fn record_aad(r: &RecordRef<'_>, epoch: u32, id: &str) -> Vec<u8> {
    format!("weirdnet-sync/v1/record|v{VALUE_VERSION}|{}|e{epoch}|k{id}|{}|{}", r.typ, r.node, r.record_id).into_bytes()
}

/// Seal `plain` for record `r` under rotation `id`'s epoch key.
pub fn seal_record(epoch_key: &Key32, user_id: &str, r: &RecordRef<'_>, epoch: u32, id: &str, plain: &[u8]) -> Result<(SealInfo, Vec<u8>)> {
    let key = record_key(epoch_key, user_id, r.typ, r.record_id, epoch, id)?;
    let s = weirdnet_keys::seal(&key, plain, &record_aad(r, epoch, id))?;
    let nonce = hex::decode(&s.nonce).map_err(|_| SyncError::Crypto("bad nonce".into()))?;
    let ct = hex::decode(&s.ct).map_err(|_| SyncError::Crypto("bad ciphertext".into()))?;
    Ok((SealInfo { epoch, key: id.to_string(), nonce }, ct))
}

/// Open a value sealed for record `r`.
pub fn open_record(epoch_key: &Key32, user_id: &str, r: &RecordRef<'_>, seal: &SealInfo, ct: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let key = record_key(epoch_key, user_id, r.typ, r.record_id, seal.epoch, &seal.key)?;
    let sealed = Sealed { nonce: hex::encode(&seal.nonce), ct: hex::encode(ct) };
    Ok(weirdnet_keys::open(&key, &sealed, &record_aad(r, seal.epoch, &seal.key))?)
}

impl crate::net::SyncState {
    fn seal_payload<'a>(&self, opts: &RecordOptions, typ: &str, record_id: &str, value: &'a [u8]) -> Result<(Option<SealInfo>, Cow<'a, [u8]>)> {
        if !opts.sealed {
            return Ok((None, Cow::Borrowed(value)));
        }
        if self.key_status() == KeyStatus::Revoked {
            return Err(SyncError::Refused("revoked".into()));
        }
        let KeyRef { epoch, id: Some(id) } = self.current_key() else {
            // Seed-derived keys are held by every seed holder, revoked or not: never seal under them.
            return Err(SyncError::Refused("no-epoch-key".into()));
        };
        let key = self.keys.get(&id).ok_or_else(|| SyncError::Refused("no-epoch-key".into()))?;
        let (seal, ct) = seal_record(key, &self.user_id, &RecordRef { typ, record_id, node: &self.our_node.0 }, epoch, &id, value)?;
        Ok((Some(seal), Cow::Owned(ct)))
    }

    fn open_payload(&self, s: &SealInfo, e: &LogEntry, ct: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        let key = self.keys.get(&s.key).ok_or_else(|| SyncError::Crypto("sealed under an epoch key this device does not hold".into()))?;
        open_record(key, &self.user_id, &RecordRef::of(e), s, ct)
    }

    /// The latest entry of every record of `typ` (by HLC).
    pub fn latest_entries(&self, typ: &str) -> Vec<&LogEntry> {
        let mut latest: BTreeMap<&str, &LogEntry> = BTreeMap::new();
        for e in self.log.iter().filter(|e| e.typ == typ) {
            let slot = latest.entry(e.record_id.as_str()).or_insert(e);
            if e.hlc.cmp_total(&slot.hlc).is_gt() {
                *slot = e;
            }
        }
        latest.into_values().collect()
    }

    /// Re-seal, under the head epoch key, every record of sealed `typ` whose latest
    /// entry is sealed under an older key and readable here. Optional: members keep
    /// older epoch keys (and admitted devices receive them), so old entries stay
    /// readable without it. The new entry is a later write of the same value, so run
    /// it after syncing. A device revoked earlier keeps whatever it could already read;
    /// change the secret itself when that matters. Returns the re-sealed record ids.
    pub fn reseal_stale(&mut self, now_ms: u64, typ: &str) -> Result<Vec<String>> {
        if !self.options(typ).sealed {
            return Ok(Vec::new());
        }
        let Some(head) = self.current_key().id else { return Err(SyncError::Refused("no-epoch-key".into())) };
        let mut todo = Vec::new();
        for e in self.latest_entries(typ) {
            let Some(s) = e.value.as_ref().and_then(|v| v.seal.as_ref()) else { continue };
            if s.key == head {
                continue;
            }
            if let Ok(RecordValue::Ready(plain)) = self.read(e) {
                todo.push((e.record_id.clone(), plain, e.op.clone()));
            }
        }
        let mut done = Vec::new();
        for (rid, plain, fallback) in todo {
            self.write_with_fallback(now_ms, typ, &rid, &plain, fallback)?;
            done.push(rid);
        }
        Ok(done)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hlc::{Hlc, NodeId};
    use crate::log::Page;
    use crate::protocol::{decode, encode};

    fn n(s: &str) -> NodeId {
        NodeId::new(s)
    }

    fn entry(node: &str, seq: u64, typ: &str, rid: &str, op: Vec<u8>, value: Option<Value>) -> LogEntry {
        LogEntry { node_id: n(node), seq, hlc: Hlc::new(seq, 0, n(node)), typ: typ.into(), record_id: rid.into(), op, value }
    }

    fn big(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i * 31 % 251) as u8).collect()
    }

    #[test]
    fn a_split_value_reassembles_only_from_matching_chunks() {
        let data = big(200_000);
        let (blob, parts) = split(&data, 64 * 1024);
        assert_eq!(blob.len, 200_000);
        assert_eq!(parts.len(), 4);
        assert_eq!(blob.chunk_ids().len(), 4);
        let ctyp = chunk_type("notes");
        let mut log = OpLog::new();
        // Nothing yet: every chunk is pending.
        assert_eq!(assemble(&log, "notes", &blob).unwrap(), RecordValue::Pending { missing: blob.chunk_ids() });
        // A chunk entry under the right id but with other bytes is not that chunk.
        let (h0, _) = parts[0];
        let forged = entry("x", 1, &ctyp, &hex::encode(h0), vec![0u8; 10], None);
        log.integrate(&Page { node_id: n("x"), from_seq: 1, to_seq: 1, ops: vec![forged] });
        assert!(log.chunk(&ctyp, &h0).is_none());
        let page: Vec<LogEntry> =
            parts.iter().enumerate().map(|(i, (h, b))| entry("a", i as u64 + 1, &ctyp, &hex::encode(h), b.to_vec(), None)).collect();
        log.integrate(&Page { node_id: n("a"), from_seq: 1, to_seq: 3, ops: page[..3].to_vec() });
        assert_eq!(assemble(&log, "notes", &blob).unwrap(), RecordValue::Pending { missing: vec![hex::encode(parts[3].0)] });
        log.integrate(&Page { node_id: n("a"), from_seq: 4, to_seq: 4, ops: page[3..].to_vec() });
        assert_eq!(&assemble(&log, "notes", &blob).unwrap().ready().unwrap()[..], &data[..]);
        // A manifest whose whole hash or length disagrees with its chunks is refused.
        let bad = Blob { hash: blake3::hash(b"other").as_bytes().to_vec(), ..blob.clone() };
        assert!(assemble(&log, "notes", &bad).is_err());
        let bad = Blob { len: 5, ..blob.clone() };
        assert!(assemble(&log, "notes", &bad).is_err());
        let bad = Blob { chunks: blob.chunks[..40].to_vec(), ..blob };
        assert!(assemble(&log, "notes", &bad).is_err());
    }

    #[test]
    fn entries_keep_the_0_3_wire_shape_and_old_peers_drop_the_value() {
        #[derive(Serialize, Deserialize, PartialEq, Debug)]
        struct EntryV03 {
            node_id: NodeId,
            seq: u64,
            hlc: Hlc,
            typ: String,
            record_id: String,
            #[serde(with = "crate::bytes")]
            op: Vec<u8>,
        }
        let plain = entry("a", 1, "notes", "r", b"hi".to_vec(), None);
        let old: EntryV03 = decode(&encode(&plain).unwrap()).unwrap();
        assert_eq!(encode(&old).unwrap(), encode(&plain).unwrap(), "no value field on a plain entry");
        let back: LogEntry = decode(&encode(&old).unwrap()).unwrap();
        assert_eq!(back, plain);
        // A chunked entry reaches an old peer as its fallback, in a page it can decode.
        let (blob, _) = split(&big(100_000), 32 * 1024);
        let v = Value { v: VALUE_VERSION, seal: None, body: Vec::new(), blob: Some(blob) };
        let rich = entry("a", 2, "notes", "r", b"preview".to_vec(), Some(v));
        #[derive(Deserialize)]
        struct PageV03 {
            ops: Vec<EntryV03>,
        }
        let page = Page { node_id: n("a"), from_seq: 1, to_seq: 2, ops: vec![plain, rich] };
        let old: PageV03 = decode(&encode(&page).unwrap()).unwrap();
        assert_eq!(old.ops[1].op, b"preview");
        assert_eq!(old.ops.len(), 2);
    }

    #[test]
    fn a_newer_value_format_is_refused_not_misread() {
        #[derive(Serialize)]
        struct Future {
            v: u32,
            body: serde_bytes_like::B,
            zstd: bool,
        }
        mod serde_bytes_like {
            pub struct B(pub Vec<u8>);
            impl serde::Serialize for B {
                fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                    s.serialize_bytes(&self.0)
                }
            }
        }
        let v: Value = decode(&encode(&Future { v: 2, body: serde_bytes_like::B(b"x".to_vec()), zstd: true }).unwrap()).unwrap();
        assert_eq!(v.v, 2, "unknown fields are skipped, the version is kept");
        let e = entry("a", 1, "notes", "r", vec![], Some(v));
        assert!(payload(&OpLog::new(), &e, e.value.as_ref().unwrap()).is_err());
    }

    #[test]
    fn limits_stay_inside_a_page() {
        assert!(Limits::default().check().is_ok());
        assert!(Limits { chunk_size: CHUNK_MAX + 1, ..Default::default() }.check().is_err());
        assert!(Limits { chunk_size: 512, ..Default::default() }.check().is_err());
        assert!(Limits { inline_max: CHUNK_MAX + 1, ..Default::default() }.check().is_err());
        assert!(Limits { record_max: usize::MAX / 2, ..Default::default() }.check().is_err());
        assert!(Limits { chunk_size: 8 * 1024, record_max: 1024 * 1024, ..Default::default() }.check().is_ok());
    }

    #[test]
    fn a_sealed_value_opens_only_for_its_record_writer_and_key() {
        let k = Key32::random().unwrap();
        let r = RecordRef { typ: "secrets", record_id: "mcp/github", node: "peer-a" };
        let (seal, ct) = seal_record(&k, "user-1", &r, 2, "rot1", b"token").unwrap();
        assert_eq!(&open_record(&k, "user-1", &r, &seal, &ct).unwrap()[..], b"token");
        for other in [RecordRef { record_id: "mcp/other", ..r }, RecordRef { node: "peer-b", ..r }, RecordRef { typ: "notes", ..r }] {
            assert!(open_record(&k, "user-1", &other, &seal, &ct).is_err(), "{other:?}");
        }
        assert!(open_record(&k, "user-2", &r, &seal, &ct).is_err());
        assert!(open_record(&k, "user-1", &r, &SealInfo { key: "rot2".into(), ..seal.clone() }, &ct).is_err());
        assert!(open_record(&k, "user-1", &r, &SealInfo { epoch: 3, ..seal.clone() }, &ct).is_err());
        assert!(open_record(&Key32::random().unwrap(), "user-1", &r, &seal, &ct).is_err());
        let mut bad = ct.clone();
        bad[0] ^= 1;
        assert!(open_record(&k, "user-1", &r, &seal, &bad).is_err());
    }
}
