use http::header::{InvalidHeaderValue, ToStrError};
use std::error::Error as StdError;

/// Boxed error
pub type BoxError = Box<dyn StdError + Send + Sync + 'static>;

/// Error type
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// Body operation returned an error
    #[error(transparent)]
    BodyOperation(BoxError),

    /// Hash mismatched
    #[error("Hash mismatched. Expected: {expected}, Got: {got}")]
    HashMismatch {
        /// Hash we expected
        expected: String,

        /// Hash we calculated
        got: String,
    },

    /// Inner service returned an error
    #[error(transparent)]
    InnerService(BoxError),

    /// Invalid digest
    #[error("Invalid digest value")]
    InvalidDigest,

    /// Invalid digest header
    #[error("Invalid digest header")]
    InvalidDigestHeader,

    /// Invalid header value
    #[error(transparent)]
    InvalidHeaderValue(#[from] InvalidHeaderValue),

    /// Missing digest header
    #[error("Missing digest header")]
    MissingHeader,

    /// `ToStrError` from the HTTP crate
    #[error(transparent)]
    ToStr(#[from] ToStrError),

    /// Unsupported digest
    #[error("Unsupported digest")]
    UnsupportedDigest,
}
