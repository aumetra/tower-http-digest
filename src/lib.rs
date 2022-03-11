//!
//! Tower middleware for verifying and calculating the HTTP digest header
//!
//! [MDN page](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Digest)
//!
//! The deprecated digests mentioned on the MDN page are also supported but have to be activated via the `deprecated` feature
//!

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![warn(clippy::all, clippy::pedantic)]
#![allow(clippy::module_name_repetitions, clippy::must_use_candidate)]

use std::{future::Future, pin::Pin};

pub use self::{
    digest::Digest,
    error::Error,
    sign::{Signer, SignerLayer},
    verify::{Verifier, VerifierLayer},
};

mod digest;
mod error;
mod sign;
mod verify;

/// Default size of the buffer
const BUFFER_SIZE: usize = 25;

/// Boxed future
pub type BoxFuture<'a, O> = Pin<Box<dyn Future<Output = O> + Send + 'a>>;
