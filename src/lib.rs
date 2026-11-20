//! Linked-device sync: clocks, an op log, merge primitives, sealed pages, a roster and
//! the `weirdnet-sync/v1` protocol over [`weirdnet-net`](weirdnet_net).
//!
//! Record types (bookmarks, notes, and so on) stay in the application. Persistence stays
//! in the application too; [`OpLog`] is the in-memory log the app can snapshot.
#![forbid(unsafe_code)]

pub mod hlc;
pub mod identity;
pub mod log;
pub mod merge;
pub mod net;
pub mod protocol;
pub mod record;
pub mod roster;
pub mod rotation;
pub mod seal;

mod bytes;
mod error;

pub use error::{Result, SyncError};
pub use hlc::{Hlc, NodeId};
pub use identity::{FileSecrets, Identity, LinkSettings, SecretStore, Tick};
pub use log::{LogEntry, OpLog, Page as LogPage};
pub use merge::{CONFLICT_KEEP_MS, Lww, OrSet, TOMBSTONE_GC_MS, can_gc_tombstone, edit_vs_delete, folder_cycle, lww};
pub use net::{
    LinkBundle, MergeOutcome, PullOutcome, SyncHandler, SyncState, node_config, pull_chunks, pull_from, pull_from_outcome, pull_from_shared,
    start_node,
};
pub use protocol::{
    Ack, Cursors, Envelope, Hello, HelloOk, KeyRef, Message, PAGE_BUDGET, PAGE_MAX, PROTOCOL, Page, Pull, Refuse, RefuseReason, RosterMsg,
    SYNC_PROFILE, decode, decode_framed, encode, encode_framed,
};
pub use record::{Blob, Limits, RecordOptions, RecordRef, RecordValue, SealInfo, Value, chunk_type};
pub use roster::{CallerCheck, DeviceClass, DeviceGrant, MAX_GRANT_ROLES, MAX_GRANT_TYPES, Roster, SessionCheck, SessionOffer};
pub use rotation::{Admission, ChainView, Device, DeviceKey, EpochKeys, KeyChain, KeyStatus, Rotation, SealedKey, ValidRotation};
pub use seal::{SyncKey, SyncType, open_page, page_aad, page_aad_keyed, rotated_sync_key, seal_page, sync_key, sync_key_info};
