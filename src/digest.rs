use crate::error::Error;
use digest::Digest as _;
use sha2::{Sha256, Sha512};

/// Representation of a hash produced by a digest
pub enum Hash {
    /// Digest produced a bunch of bytes
    Bytes(Vec<u8>),

    /// Digest produced an unsigned 32-bit integer
    Number(u32),
}

impl Hash {
    /// Encode the hash into its digest header representation
    pub fn encode(self) -> String {
        match self {
            Self::Bytes(bytes) => base64::encode(bytes),
            Self::Number(num) => num.to_string(),
        }
    }
}

impl From<Vec<u8>> for Hash {
    fn from(bytes: Vec<u8>) -> Self {
        Self::Bytes(bytes)
    }
}

impl From<u32> for Hash {
    fn from(number: u32) -> Self {
        Self::Number(number)
    }
}

// Allow unused variants
#[allow(dead_code)]
/// Digests
#[derive(Clone, Debug, PartialEq, PartialOrd)]
pub enum Digest {
    /// CRC-32-C
    Crc32c,

    /// SHA-256
    Sha256,

    /// SHA-512
    Sha512,

    /// Unixcksum
    Unixcksum,

    /// Unixsum
    Unixsum,

    // --- Deprecated algorithms ---
    /// Adler32 (deprecated)
    #[cfg(feature = "deprecated")]
    Adler32,

    /// MD5 (deprecated)
    #[cfg(feature = "deprecated")]
    Md5,

    /// SHA-1 (deprecated)
    #[cfg(feature = "deprecated")]
    Sha1,
}

impl Digest {
    // I know that there's the `FromStr` trait. I just don't want to return an error, just an `Option`
    #[allow(clippy::should_implement_trait)]
    /// Attempt to find a digest variant that matches the specified identifier
    pub(crate) fn from_str(ident: &str) -> Option<Self> {
        let ident = ident.to_lowercase();
        match ident.as_str() {
            "crc32c" => Some(Self::Crc32c),
            "id-sha-256" | "sha-256" => Some(Self::Sha256),
            "id-sha-512" | "sha-512" => Some(Self::Sha512),
            "unixcksum" => Some(Self::Unixcksum),
            "unixsum" => Some(Self::Unixsum),

            #[cfg(feature = "deprecated")]
            "adler32" => Some(Self::Adler32),

            #[cfg(feature = "deprecated")]
            "md5" => Some(Self::Md5),

            #[cfg(feature = "deprecated")]
            "sha" => Some(Self::Sha1),

            _ => None,
        }
    }

    /// Hash the data with the digest
    pub(crate) fn hash<D>(&self, data: D) -> Result<Hash, Error>
    where
        D: AsRef<[u8]>,
    {
        match self {
            Self::Crc32c => Ok(crc32fast::hash(data.as_ref()).into()),
            Self::Sha256 => Ok(Sha256::digest(data).to_vec().into()),
            Self::Sha512 => Ok(Sha512::digest(data).to_vec().into()),

            #[cfg(feature = "deprecated")]
            Self::Adler32 => Ok(adler32::adler32(std::io::Cursor::new(data.as_ref()))
                .unwrap()
                .into()),

            #[cfg(feature = "deprecated")]
            Self::Md5 => Ok(md5::Md5::digest(data).to_vec().into()),

            #[cfg(feature = "deprecated")]
            Self::Sha1 => Ok(sha1::Sha1::digest(data).to_vec().into()),

            _ => Err(Error::UnsupportedDigest),
        }
    }

    /// Get the name of the digest
    pub(crate) fn name(&self) -> &'static str {
        match self {
            Self::Crc32c => "crc32c",
            Self::Sha256 => "sha-256",
            Self::Sha512 => "sha-512",
            Self::Unixcksum => "unixcksum",
            Self::Unixsum => "unixsum",

            #[cfg(feature = "deprecated")]
            Self::Adler32 => "adler32",

            #[cfg(feature = "deprecated")]
            Self::Md5 => "md5",

            #[cfg(feature = "deprecated")]
            Self::Sha1 => "sha",
        }
    }
}
