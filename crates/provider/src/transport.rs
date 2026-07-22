//! The provider's network-I/O capability port.
//!
//! Every live adapter used to build its own `reqwest::Client` inline with an
//! identical, security-critical policy (redirects disabled — the configured API
//! root is an authority boundary — plus a bounded connect timeout). That direct
//! construction left the network seam unmediated: a host could neither broker,
//! observe, nor substitute transport for the provider adapters. This module turns
//! that seam into an injected port ([`HttpTransport`]) with one default
//! implementation ([`DefaultHttpTransport`]); adapters now obtain their client
//! from the port instead of constructing it inline (D2-21).

use crate::ProviderError;
use std::time::Duration;

/// Bounded connect timeout shared by every adapter's HTTP client.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

/// Injected network-I/O port for provider adapters. An implementation hands out
/// the `reqwest::Client` an adapter dispatches through, so transport construction
/// is a brokered capability rather than something each adapter builds for itself.
///
/// This is the network half of the "injected provider port" the architecture
/// roadmap targets: the adapter receives its transport instead of reaching for
/// the runtime's HTTP stack directly.
pub trait HttpTransport: Send + Sync {
    /// Produce the HTTP client an adapter will send requests through.
    ///
    /// Implementations MUST disable transparent redirects: the configured API
    /// root is an authority boundary, and an API key, prompt, or POST body must
    /// never be replayed to a redirect target chosen by the remote endpoint.
    fn client(&self) -> Result<reqwest::Client, ProviderError>;
}

/// Default transport: the mandated secure client construction the adapters used
/// to copy-paste. It disables redirects and applies the shared connect timeout.
#[derive(Debug, Default, Clone, Copy)]
pub struct DefaultHttpTransport;

impl HttpTransport for DefaultHttpTransport {
    fn client(&self) -> Result<reqwest::Client, ProviderError> {
        reqwest::Client::builder()
            .connect_timeout(CONNECT_TIMEOUT)
            // The configured API root is an authority boundary. Never replay an
            // API key, prompt, or POST body through an endpoint-chosen redirect.
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|_| ProviderError::Configuration("HTTP client could not be built".into()))
    }
}
