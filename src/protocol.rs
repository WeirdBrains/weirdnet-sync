//! `weirdnet-sync/v1` messages and length-prefixed CBOR framing.
//!
//! After the authenticated channel is up, payloads that carry records, cursors or
//! certificates are sealed under [`crate::sync_key`]. An [`Envelope`] carries the type and
//! epoch in the clear so the receiver can pick the key; the body is sealed.
use crate::error::{Result, SyncError};
use crate::hlc::{Hlc, NodeId};
use crate::log::{LogEntry, Page as LogPage};
use crate::roster::DeviceGrant;
use crate::rotation::KeyChain;
use crate::seal::{SyncKey, open_page, page_aad_keyed, rotated_sync_key, seal_page, sync_key};
use serde::{Deserialize, Serialize};
use weirdnet_keys::{Key32, Sealed};
use weirdnet_net::profile::{Profile, WEIRDNET};
use weirdnet_net::user::NodeCert;
use zeroize::Zeroizing;

/// Request-response protocol id. `/2` since weirdnet-net 0.8 sends byte fields as CBOR byte
/// strings; a 0.4 (`/1`) node fails to negotiate instead of failing to decode.
pub const PROTOCOL: &str = "/weirdnet/sync/2";

/// Largest sealed page on the wire (and the request and reply cap to set on a sync node).
pub const PAGE_MAX: usize = 256 * 1024;

/// Plaintext budget for the ops in one page. The sealed body is hex in the envelope (two
/// bytes per plaintext byte), and weirdnet-net 0.8 sends the encoded envelope as one CBOR
/// byte string (one byte per byte, a few bytes of header). So a page is about twice its
/// plaintext on the wire, plus the envelope fields. This reserves 16 KiB for those and for
/// the gap between [`LogEntry::wire_size`](crate::log::LogEntry::wire_size) and the real
/// encoding (which is an estimate), then halves the rest: a full page is about 120 KiB
/// plus slack under [`PAGE_MAX`]. (Through 0.4 this was a quarter, because 0.7 sent the
/// bytes as integer arrays.)
pub const PAGE_BUDGET: usize = (PAGE_MAX - 16 * 1024) / 2 - 8 * 1024;

/// Identifier profile: `/weirdnet/sync/2` for request-response, otherwise [`WEIRDNET`].
pub static SYNC_PROFILE: Profile = Profile { protocol: PROTOCOL, thread: "weirdnet-sync", ..WEIRDNET };

/// Last seq applied from each node, as sent in Hello.
pub type Cursors = Vec<(NodeId, u64)>;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Hello {
    pub cert: NodeCert,
    pub user_id: String,
    pub epoch: u32,
    pub types: Vec<String>,
    pub our_cursors: Cursors,
    pub our_hlc: Hlc,
    /// The sender's key chain, so device keys and rotations spread. Absent from 0.2.
    #[serde(default)]
    pub chain: KeyChain,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HelloOk {
    pub cert: NodeCert,
    pub epoch: u32,
    pub cursors: Cursors,
    /// The answering node's certs. Since 0.5.2 every cert, active and revoked (the name
    /// is kept for the wire); before that only the revoked ones.
    pub revocations: Vec<NodeCert>,
    #[serde(default)]
    pub chain: KeyChain,
    /// The answering node's device grants (roles, service class). Absent before 0.7.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub grants: Vec<DeviceGrant>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Refuse {
    pub reason: String,
}

impl Refuse {
    pub fn new(reason: &'static str) -> Self {
        Self { reason: reason.into() }
    }
}

pub type RefuseReason = Refuse;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Pull {
    pub node_id: NodeId,
    pub after_seq: u64,
    pub typ: String,
    pub limit: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Page {
    pub typ: String,
    pub page: LogPage,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ack {
    pub node_id: NodeId,
    pub last_seq: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RosterMsg {
    pub certs: Vec<NodeCert>,
    pub epoch: u32,
    /// Device keys, rotations (with the sealed epoch keys) and admissions.
    #[serde(default)]
    pub chain: KeyChain,
    /// Device grants (roles, service class). Absent before 0.7.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub grants: Vec<DeviceGrant>,
}

/// Application-level message, before sealing.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum Message {
    Hello(Hello),
    HelloOk(HelloOk),
    Refuse(Refuse),
    Pull(Pull),
    Page(Page),
    Ack(Ack),
    Roster(RosterMsg),
    /// Leases (0.8): a candidate's ask, a voter's grant or denial, a release.
    LeaseAsk(crate::lease::LeaseAsk),
    LeaseGrant(crate::lease::LeaseGrant),
    LeaseDeny(crate::lease::LeaseDeny),
    LeaseFree(crate::lease::LeaseFree),
}

/// What goes on the request-response wire: type, epoch and (after a rotation) the
/// rotation id in the clear, body sealed.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Envelope {
    pub typ: String,
    pub epoch: u32,
    /// Rotation id of the epoch key; `None` for the seed-derived key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    pub sealed: Sealed,
    /// Since 0.7: the body is not sealed (`sealed.ct` is the hex CBOR message). Only a
    /// [`Message::Roster`] or a [`Message::Refuse`] travels this way: the roster is public
    /// (every part verifies under the user key) and a refusal is a reason code, over a
    /// stream Noise already authenticated. Service devices, which hold no seed, use it to
    /// refuse and to fetch the roster. A 0.6 peer cannot open it.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub clear: bool,
}

/// Which key an envelope is sealed under: the seed-derived one at `epoch`, or the
/// rotated one with this id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyRef {
    pub epoch: u32,
    pub id: Option<String>,
}

impl KeyRef {
    pub fn seed(epoch: u32) -> Self {
        Self { epoch, id: None }
    }
}

impl Envelope {
    /// An unsealed envelope (see [`Envelope::clear`]). Only a roster or a refusal may be sent so.
    pub fn clear(typ: &str, epoch: u32, msg: &Message) -> Result<Self> {
        if !matches!(msg, Message::Roster(_) | Message::Refuse(_)) {
            return Err(SyncError::Protocol("only a roster or a refusal travels unsealed".into()));
        }
        let plain = encode(msg)?;
        Ok(Self { typ: typ.into(), epoch, key: None, sealed: Sealed { nonce: String::new(), ct: hex::encode(plain) }, clear: true })
    }

    /// The message of an unsealed envelope. Anything but a roster or a refusal is refused.
    pub fn open_clear(&self) -> Result<Message> {
        if !self.clear {
            return Err(SyncError::Crypto("sealed envelope".into()));
        }
        let plain = hex::decode(&self.sealed.ct).map_err(|e| SyncError::Codec(e.to_string()))?;
        let msg: Message = decode(&plain)?;
        if !matches!(msg, Message::Roster(_) | Message::Refuse(_)) {
            return Err(SyncError::Protocol("only a roster or a refusal travels unsealed".into()));
        }
        Ok(msg)
    }

    /// Seal under a rotated epoch key (rotation `id`).
    pub fn seal_keyed(epoch_key: &Key32, id: &str, user_id: &str, typ: &str, epoch: u32, asking_peer: &str, msg: &Message) -> Result<Self> {
        let key = rotated_sync_key(epoch_key, user_id, typ, epoch, id)?;
        Self::seal_scoped(&key, id, typ, epoch, asking_peer, msg)
    }

    pub fn open_keyed(&self, epoch_key: &Key32, user_id: &str, asking_peer: &str) -> Result<Message> {
        let id = self.key.as_deref().ok_or_else(|| SyncError::Crypto("not sealed under a rotated key".into()))?;
        let key = rotated_sync_key(epoch_key, user_id, &self.typ, self.epoch, id)?;
        self.open_scoped(&key, asking_peer)
    }

    /// Seal under a type-scoped key (since 0.8.3): `typ`'s [`SyncKey`] under rotation `id`,
    /// as [`rotated_sync_key`] derives it from the epoch key and as a service device holds
    /// it ([`crate::EpochKeys::get_scoped`]). The envelope is byte-for-byte the shape
    /// [`Envelope::seal_keyed`] makes, so either side may hold the epoch key or the scoped key.
    pub fn seal_scoped(key: &SyncKey, id: &str, typ: &str, epoch: u32, asking_peer: &str, msg: &Message) -> Result<Self> {
        let plain = Zeroizing::new(encode(msg)?);
        let sealed = weirdnet_keys::seal(key, &plain, &page_aad_keyed(typ, epoch, id, asking_peer))?;
        Ok(Self { typ: typ.into(), epoch, key: Some(id.into()), sealed, clear: false })
    }

    /// Open an envelope sealed under a rotated key with its type-scoped key (since 0.8.3).
    pub fn open_scoped(&self, key: &SyncKey, asking_peer: &str) -> Result<Message> {
        let id = self.key.as_deref().ok_or_else(|| SyncError::Crypto("not sealed under a rotated key".into()))?;
        let plain: Zeroizing<Vec<u8>> = weirdnet_keys::open(key, &self.sealed, &page_aad_keyed(&self.typ, self.epoch, id, asking_peer))?;
        decode(&plain)
    }

    pub fn seal(seed: &[u8], user_id: &str, typ: &str, epoch: u32, asking_peer: &str, msg: &Message) -> Result<Self> {
        let key = sync_key(seed, user_id, typ, epoch)?;
        let plain = encode(msg)?;
        let sealed = seal_page(&key, typ, epoch, asking_peer, &plain)?;
        Ok(Self { typ: typ.into(), epoch, key: None, sealed, clear: false })
    }

    /// Open a seed-sealed envelope. One sealed under a rotated key fails here.
    pub fn open(&self, seed: &[u8], user_id: &str, asking_peer: &str) -> Result<Message> {
        if self.key.is_some() || self.clear {
            return Err(SyncError::Crypto("sealed under a rotated key".into()));
        }
        let key = sync_key(seed, user_id, &self.typ, self.epoch)?;
        let plain: Zeroizing<Vec<u8>> = open_page(&key, &self.typ, self.epoch, asking_peer, &self.sealed)?;
        decode(&plain)
    }
}

/// Length-prefixed CBOR (u32 big-endian length, then the item). For a raw stream;
/// `Node::request` already frames [`Envelope`] as CBOR through libp2p.
pub fn encode<T: Serialize>(v: &T) -> Result<Vec<u8>> {
    cbor4ii::serde::to_vec(Vec::new(), v).map_err(|e| SyncError::Codec(e.to_string()))
}

pub fn decode<'a, T: Deserialize<'a>>(bytes: &'a [u8]) -> Result<T> {
    cbor4ii::serde::from_slice(bytes).map_err(|e| SyncError::Codec(e.to_string()))
}

pub fn encode_framed<T: Serialize>(v: &T) -> Result<Vec<u8>> {
    let body = encode(v)?;
    if body.len() > u32::MAX as usize {
        return Err(SyncError::Codec("frame too large".into()));
    }
    let mut out = Vec::with_capacity(4 + body.len());
    out.extend_from_slice(&(body.len() as u32).to_be_bytes());
    out.extend_from_slice(&body);
    Ok(out)
}

pub fn decode_framed<'a, T: Deserialize<'a>>(bytes: &'a [u8]) -> Result<T> {
    if bytes.len() < 4 {
        return Err(SyncError::Codec("short frame".into()));
    }
    let n = u32::from_be_bytes(bytes[..4].try_into().unwrap()) as usize;
    if bytes.len() != 4 + n {
        return Err(SyncError::Codec(format!("frame length {n} does not match {}", bytes.len().saturating_sub(4))));
    }
    decode(&bytes[4..])
}

/// Build a `Page` message from a log page, dropping ops whose typ does not match (they
/// stay in the log for a later pull of that type).
pub fn page_for_type(typ: &str, page: LogPage) -> Page {
    let ops: Vec<LogEntry> = page.ops.into_iter().filter(|e| e.typ == typ).collect();
    let from_seq = ops.first().map(|e| e.seq).unwrap_or(page.from_seq);
    let to_seq = ops.last().map(|e| e.seq).unwrap_or(page.to_seq);
    Page { typ: typ.into(), page: LogPage { node_id: page.node_id, from_seq, to_seq, ops } }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hlc::Hlc;
    use crate::roster::Roster;
    use weirdnet_net::Keypair;
    use weirdnet_net::user;

    const SEED: [u8; 32] = *b"CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC";

    fn hello() -> (Message, String, Keypair) {
        let u = Keypair::generate_ed25519();
        let uid = user::user_id(&u.public());
        let cert = Roster::self_certify(&WEIRDNET, &u, "peer-a", "a", 1).unwrap();
        let msg = Message::Hello(Hello {
            cert,
            user_id: uid.clone(),
            epoch: 0,
            types: vec!["bookmarks".into()],
            our_cursors: vec![(NodeId::new("peer-a"), 3)],
            our_hlc: Hlc::new(10, 0, NodeId::new("peer-a")),
            chain: Default::default(),
        });
        (msg, uid, u)
    }

    #[test]
    fn a_full_page_fits_the_reply_cap_once_sealed() {
        use crate::log::OpLog;
        let (_, uid, _) = hello();
        let mut log = OpLog::new();
        let node = NodeId::new("peer-a");
        for i in 0..400u64 {
            log.append(node.clone(), Hlc::new(i, 0, node.clone()), "bookmarks", format!("r{i}"), vec![7u8; 1500]);
        }
        let known = log.cursor_for(&node, "bookmarks");
        let page = log.page_of_type(&node, "bookmarks", 0, known, 4096);
        assert!(page.ops.len() > 10 && page.to_seq < 400, "the budget split the stream");
        let msg = Message::Page(Page { typ: "bookmarks".into(), page });
        let env = Envelope::seal(&SEED, &uid, "bookmarks", 0, "peer-b", &msg).unwrap();
        // What weirdnet-net 0.8 sends: the envelope bytes as one CBOR byte string.
        let wire = |env: &Envelope| weirdnet_net::wire::to_vec(&encode(env).unwrap()).unwrap().len();
        assert!(wire(&env) <= PAGE_MAX, "sealed page is {} bytes on the wire, cap {PAGE_MAX}", wire(&env));
        assert!(wire(&env) > PAGE_MAX / 2, "the budget is not far too small ({})", wire(&env));
        assert!(wire(&env) <= PAGE_MAX - 16 * 1024, "keeps a 16 KiB safety margin ({})", wire(&env));
        let page = log.page(&node, 0, 4096);
        let env = Envelope::seal(&SEED, &uid, "bookmarks", 0, "peer-b", &Message::Page(Page { typ: "bookmarks".into(), page })).unwrap();
        assert!(wire(&env) <= PAGE_MAX);
    }

    #[test]
    fn framed_cbor_round_trips_and_rejects_a_truncated_frame() {
        let (msg, _, _) = hello();
        let bytes = encode_framed(&msg).unwrap();
        assert_eq!(u32::from_be_bytes(bytes[..4].try_into().unwrap()) as usize, bytes.len() - 4);
        let back: Message = decode_framed(&bytes).unwrap();
        assert_eq!(back, msg);
        assert!(decode_framed::<Message>(&bytes[..3]).is_err());
        assert!(decode_framed::<Message>(&bytes[..bytes.len() - 1]).is_err());
    }

    #[test]
    fn a_sealed_hello_opens_for_the_same_seed_and_user_only() {
        let (msg, uid, _) = hello();
        let env = Envelope::seal(&SEED, &uid, "bookmarks", 0, "peer-b", &msg).unwrap();
        let opened = env.open(&SEED, &uid, "peer-b").unwrap();
        assert_eq!(opened, msg);
        assert!(env.open(&SEED, "other-user", "peer-b").is_err());
        assert!(env.open(&SEED, &uid, "peer-c").is_err());
        assert!(Envelope { typ: "history".into(), ..env.clone() }.open(&SEED, &uid, "peer-b").is_err());
    }

    #[test]
    fn seed_envelopes_and_rosters_keep_the_0_2_wire_shape() {
        #[derive(Serialize, Deserialize, PartialEq, Debug)]
        struct EnvelopeV02 {
            typ: String,
            epoch: u32,
            sealed: Sealed,
        }
        let (msg, uid, _) = hello();
        let env = Envelope::seal(&SEED, &uid, "bookmarks", 0, "peer-b", &msg).unwrap();
        let old: EnvelopeV02 = decode(&encode(&env).unwrap()).unwrap();
        assert_eq!(encode(&old).unwrap(), encode(&env).unwrap(), "no key field on a seed envelope");
        let back: Envelope = decode(&encode(&old).unwrap()).unwrap();
        assert_eq!(back.key, None);
        #[derive(Serialize)]
        #[serde(tag = "kind", rename_all = "kebab-case")]
        enum OldMessage {
            Roster { certs: Vec<NodeCert>, epoch: u32 },
        }
        let old = encode(&OldMessage::Roster { certs: vec![], epoch: 3 }).unwrap();
        assert_eq!(
            decode::<Message>(&old).unwrap(),
            Message::Roster(RosterMsg { certs: vec![], epoch: 3, chain: KeyChain::default(), grants: vec![] })
        );
        // A keyed envelope never opens as a seed one.
        let k = Key32::random().unwrap();
        let keyed = Envelope::seal_keyed(&k, "r1", &uid, "bookmarks", 1, "peer-b", &msg).unwrap();
        assert!(keyed.open(&SEED, &uid, "peer-b").is_err());
        assert_eq!(keyed.open_keyed(&k, &uid, "peer-b").unwrap(), msg);
        assert!(keyed.open_keyed(&k, &uid, "peer-c").is_err());
        assert!(Envelope { key: Some("r2".into()), ..keyed.clone() }.open_keyed(&k, &uid, "peer-b").is_err());
    }
}
