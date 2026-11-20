use thiserror::Error;

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum SyncError {
    #[error("{0}")]
    Crypto(String),
    #[error("refused: {0}")]
    Refused(String),
    #[error("codec: {0}")]
    Codec(String),
    #[error("{0}")]
    Protocol(String),
    /// Reading or writing an [`crate::identity::Identity`]'s files.
    #[error("{0}")]
    Io(String),
    /// An [`crate::identity::Identity`] that can't be created, adopted or opened as asked.
    #[error("{0}")]
    Identity(String),
}

impl From<weirdnet_keys::KeysError> for SyncError {
    fn from(e: weirdnet_keys::KeysError) -> Self {
        SyncError::Crypto(e.to_string())
    }
}

impl From<weirdnet_net::NetError> for SyncError {
    fn from(e: weirdnet_net::NetError) -> Self {
        SyncError::Crypto(e.to_string())
    }
}

pub type Result<T> = std::result::Result<T, SyncError>;
