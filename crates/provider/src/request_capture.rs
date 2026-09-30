//! Exact serialized physical-request observation. The observer is minted by the host for one
//! admitted effect; it has no transport, authorization, retry or model mutation authority.
use crate::{AdapterKind, ProviderError};
use std::io::Write;

#[cfg(test)]
#[path = "request_capture_tests.rs"]
mod tests;

const MAX_WIRE_BODY_BYTES: usize = 32 * 1024 * 1024;

/// Borrowed bytes are the same buffer subsequently passed to the HTTP request. Authentication
/// headers are deliberately absent. The endpoint may contain private query values: consumers
/// commit its digest and must not render or retain its raw value.
pub struct ProviderWireRequest<'a> {
    pub adapter: AdapterKind,
    pub method: &'static str,
    pub endpoint: &'a str,
    pub content_type: &'static str,
    pub body: &'a [u8],
    /// The actual immutable request after per-route transport/control adaptation.
    pub request: &'a crate::TurnRequest,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum RequestCaptureError {
    #[error("request observation unavailable")]
    Unavailable,
    #[error("request observation exceeds admitted bounds")]
    Bounds,
    #[error("request observation publication needs reconciliation")]
    ReconciliationNeeded,
}

pub trait ProviderRequestObserver: Send + Sync {
    fn enabled(&self) -> bool {
        true
    }
    fn prepared(&self, request: ProviderWireRequest<'_>) -> Result<(), RequestCaptureError>;
    /// This proves only durable local dispatch intent. It is not a socket write or remote ack.
    fn dispatching(&self) -> Result<(), RequestCaptureError>;
    fn unavailable(&self, reason: &'static str) -> Result<(), RequestCaptureError>;
}

pub struct DisabledRequestObserver;
impl ProviderRequestObserver for DisabledRequestObserver {
    fn enabled(&self) -> bool {
        false
    }
    fn prepared(&self, _: ProviderWireRequest<'_>) -> Result<(), RequestCaptureError> {
        Ok(())
    }
    fn dispatching(&self) -> Result<(), RequestCaptureError> {
        Ok(())
    }
    fn unavailable(&self, _: &'static str) -> Result<(), RequestCaptureError> {
        Ok(())
    }
}

struct BoundedJson(Vec<u8>);
impl Write for BoundedJson {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.len() > MAX_WIRE_BODY_BYTES.saturating_sub(self.0.len()) {
            return Err(std::io::Error::other(
                "physical request body exceeds its bound",
            ));
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

pub(crate) fn prepare_json(
    adapter: AdapterKind,
    endpoint: &str,
    body: &serde_json::Value,
    request: &crate::TurnRequest,
    observer: &dyn ProviderRequestObserver,
) -> Result<Vec<u8>, ProviderError> {
    let mut bytes = BoundedJson(Vec::new());
    serde_json::to_writer(&mut bytes, body)
        .map_err(|_| ProviderError::RequestCaptureRefusedBeforeDispatch)?;
    if observer.enabled() {
        observer
            .prepared(ProviderWireRequest {
                adapter,
                method: "POST",
                endpoint,
                content_type: "application/json",
                body: &bytes.0,
                request,
            })
            .map_err(|_| ProviderError::RequestCaptureRefusedBeforeDispatch)?;
    }
    Ok(bytes.0)
}

pub(crate) fn dispatching(observer: &dyn ProviderRequestObserver) -> Result<(), ProviderError> {
    if observer.enabled() {
        observer
            .dispatching()
            .map_err(|_| ProviderError::RequestCaptureRefusedBeforeDispatch)?;
    }
    Ok(())
}

pub(crate) fn remaining_before_send(
    deadline: std::time::Instant,
    header_timeout: std::time::Duration,
) -> Result<std::time::Duration, ProviderError> {
    let remaining = deadline.saturating_duration_since(std::time::Instant::now());
    if remaining.is_zero() {
        return Err(ProviderError::RequestDeadlineBeforeDispatch);
    }
    Ok(remaining.min(header_timeout))
}
