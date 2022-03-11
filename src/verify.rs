use crate::{digest::Digest, error::BoxError, BoxFuture, Error, BUFFER_SIZE};
use bytes::{BufMut, Bytes, BytesMut};
use http::Request;
use http_body::{Body, Full};
use std::{
    error::Error as StdError,
    task::{Context, Poll},
};
use tower::{buffer::Buffer, Layer, Service};

/// Verify the request
async fn verify_request<B>(req: Request<B>) -> Result<Request<Full<Bytes>>, Error>
where
    B: Body + Unpin,
    B::Error: Into<BoxError>,
{
    let (parts, mut req_body) = req.into_parts();

    let digest_header = parts.headers.get("digest").ok_or(Error::MissingHeader)?;
    let digest_header = digest_header.to_str()?;

    // There's most likely only a single digest specified
    let mut digests = Vec::with_capacity(1);
    for digest in digest_header.split(',') {
        let (name, value) = digest.split_at(digest.find('=').ok_or(Error::InvalidDigestHeader)?);
        let value = &value[1..];

        let digest = Digest::from_str(name).ok_or(Error::UnsupportedDigest)?;
        digests.push((digest, value));
    }

    // Read the whole body into memory (we have to do it at some point anyway)
    let mut body = BytesMut::new();
    while let Some(chunk) = req_body
        .data()
        .await
        .transpose()
        .map_err(|err| Error::BodyOperation(err.into()))?
    {
        body.put(chunk);
    }
    // We're done reading. Body can be frozen
    let body = body.freeze();

    // Hash with every digest and compare the value
    for (digest, value) in digests {
        let hash = digest.hash(&body)?;
        let encoded_hash = hash.encode();
        if encoded_hash != value {
            return Err(Error::HashMismatch {
                expected: value.to_string(),
                got: encoded_hash,
            });
        }
    }

    Ok(Request::from_parts(parts, Full::new(body)))
}

/// Tower layer for verifying the HTTP digest header
#[derive(Clone, Debug)]
pub struct VerifierLayer {
    buffer_size: usize,
}

impl VerifierLayer {
    /// Create a new verifier layer with the default buffer size
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a new verifier layer with a custom buffer size
    pub fn new_with_buffer_size(buffer_size: usize) -> Self {
        Self { buffer_size }
    }
}

impl Default for VerifierLayer {
    fn default() -> Self {
        Self::new_with_buffer_size(BUFFER_SIZE)
    }
}

impl<S> Layer<S> for VerifierLayer
where
    S: Service<Request<Full<Bytes>>> + Send + 'static,
    S::Error: StdError + Send + Sync,
    S::Future: Send,
{
    type Service = Verifier<S>;

    fn layer(&self, service: S) -> Self::Service {
        Verifier::new_with_buffer_size(service, self.buffer_size)
    }
}

/// Verification service
#[derive(Clone)]
pub struct Verifier<S>
where
    S: Service<Request<Full<Bytes>>>,
{
    inner: Buffer<S, Request<Full<Bytes>>>,
}

impl<S> Verifier<S>
where
    S: Service<Request<Full<Bytes>>> + Send + 'static,
    S::Error: StdError + Send + Sync,
    S::Future: Send,
{
    /// Create a new verifier service with the default buffer size
    pub fn new(inner: S) -> Self {
        Self::new_with_buffer_size(inner, BUFFER_SIZE)
    }

    /// Create a new verifier service with a custom buffer size
    pub fn new_with_buffer_size(inner: S, buffer_size: usize) -> Self {
        let buffer = Buffer::new(inner, buffer_size);

        Self { inner: buffer }
    }
}

// Not entirely sure which type bounds clippy thinks can be combined??
#[allow(clippy::type_repetition_in_bounds)]
impl<S, B> Service<Request<B>> for Verifier<S>
where
    S: Service<Request<Full<Bytes>>> + Send + 'static,
    S::Error: Into<BoxError>,
    S::Future: Send,
    B: Body + Send + Unpin + 'static,
    B::Error: Into<BoxError>,
{
    type Response = S::Response;
    type Error = Error;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    #[inline]
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx).map_err(Error::InnerService)
    }

    fn call(&mut self, req: Request<B>) -> Self::Future {
        let mut handle = self.inner.clone();
        Box::pin(async move {
            let req = verify_request(req).await?;
            handle.call(req).await.map_err(Error::InnerService)
        })
    }
}
