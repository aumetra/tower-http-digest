use crate::{error::BoxError, BoxFuture, Digest, Error, BUFFER_SIZE};
use bytes::{BufMut, Bytes, BytesMut};
use http::{header::HeaderName, HeaderValue, Request};
use http_body::{Body, Full};
use std::{
    error::Error as StdError,
    task::{Context, Poll},
};
use tower::{buffer::Buffer, Layer, Service};

/// Generate the digest header for this request
async fn sign_request<B>(
    digests: Vec<Digest>,
    overwrite: bool,
    req: Request<B>,
) -> Result<Request<Full<Bytes>>, Error>
where
    B: Body + Unpin,
    B::Error: Into<BoxError>,
{
    let (mut parts, mut req_body) = req.into_parts();

    // Read the whole body into memory (we have to do it at some point anyway)
    //
    // We could either enum dispatch or box the body to avoid having to read the body into memory if the value should not be overwritten and there's already a header present.
    // But alas, I can't be bothered right now.
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

    let digest_header_name = HeaderName::from_static("digest");
    let digest_header_value = if overwrite || !parts.headers.contains_key(&digest_header_name) {
        // Generate hashes for all digests and construct the digest header value
        let mut digest_parts = Vec::new();
        for digest in digests {
            let name = digest.name();
            let value = digest.hash(&body)?.encode();

            digest_parts.push(format!("{name}={value}"));
        }

        HeaderValue::from_str(&digest_parts.join(","))?
    } else {
        parts.headers.get(&digest_header_name).cloned().unwrap()
    };

    parts
        .headers
        .insert(digest_header_name, digest_header_value);

    Ok(Request::from_parts(parts, Full::new(body)))
}

/// Tower layer for verifying the HTTP digest header
#[derive(Clone, Debug)]
pub struct SignerLayer {
    buffer_size: usize,
    digests: Vec<Digest>,
    overwrite: bool,
}

impl SignerLayer {
    /// Create a new signer layer with the default buffer size
    pub fn new(digests: Vec<Digest>, overwrite: bool) -> Self {
        Self::new_with_buffer_size(digests, BUFFER_SIZE, overwrite)
    }

    /// Create a new signer layer with a custom buffer size
    pub fn new_with_buffer_size(digests: Vec<Digest>, buffer_size: usize, overwrite: bool) -> Self {
        Self {
            buffer_size,
            digests,
            overwrite,
        }
    }
}

impl<S> Layer<S> for SignerLayer
where
    S: Service<Request<Full<Bytes>>> + Send + 'static,
    S::Error: StdError + Send + Sync,
    S::Future: Send,
{
    type Service = Signer<S>;

    fn layer(&self, service: S) -> Self::Service {
        Signer::new_with_buffer_size(
            service,
            self.buffer_size,
            self.digests.clone(),
            self.overwrite,
        )
    }
}

/// Service to generate the digest header for an HTTP request
#[derive(Clone)]
pub struct Signer<S>
where
    S: Service<Request<Full<Bytes>>>,
{
    inner: Buffer<S, Request<Full<Bytes>>>,
    digests: Vec<Digest>,
    overwrite: bool,
}

impl<S> Signer<S>
where
    S: Service<Request<Full<Bytes>>> + Send + 'static,
    S::Error: StdError + Send + Sync,
    S::Future: Send,
{
    /// Create a new signer service with the default buffer size
    pub fn new(inner: S, digests: Vec<Digest>, overwrite: bool) -> Self {
        Self::new_with_buffer_size(inner, BUFFER_SIZE, digests, overwrite)
    }

    /// Create a new signer service with a custom buffer size
    pub fn new_with_buffer_size(
        inner: S,
        buffer_size: usize,
        digests: Vec<Digest>,
        overwrite: bool,
    ) -> Self {
        let buffer = Buffer::new(inner, buffer_size);

        Self {
            inner: buffer,
            digests,
            overwrite,
        }
    }
}

// Not entirely sure which type bounds clippy thinks can be combined??
#[allow(clippy::type_repetition_in_bounds)]
impl<S, B> Service<Request<B>> for Signer<S>
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
        let (mut handle, digests, overwrite) =
            (self.inner.clone(), self.digests.clone(), self.overwrite);

        Box::pin(async move {
            let req = sign_request(digests, overwrite, req).await?;
            handle.call(req).await.map_err(Error::InnerService)
        })
    }
}
