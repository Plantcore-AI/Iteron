//! D2-21 oracle — provider network I/O is an *injected* transport port, not an
//! inline `reqwest::Client::builder()`.
//!
//! Constructing a live adapter with a custom [`HttpTransport`] must route client
//! construction through the port: it is consulted exactly once, and a port that
//! refuses transport fails adapter construction (proving the port — not an inline
//! builder — owns network I/O). This target and the `with_transport` /
//! `HttpTransport` API are absent on the base branch (RED), and present once the
//! injected network-I/O port lands (GREEN).

use core_provider::{
    Anthropic, ApiRoot, DefaultHttpTransport, HttpTransport, OpenAiResponses, ProviderError,
};
use std::sync::atomic::{AtomicU32, Ordering};

/// A transport whose client construction is observable and can be forced to fail.
struct ProbeTransport {
    built: AtomicU32,
    fail: bool,
}

impl HttpTransport for ProbeTransport {
    fn client(&self) -> Result<reqwest::Client, ProviderError> {
        self.built.fetch_add(1, Ordering::SeqCst);
        if self.fail {
            Err(ProviderError::Configuration("probe refused transport".into()))
        } else {
            // Delegate to the default secure client so the adapter is otherwise real.
            DefaultHttpTransport.client()
        }
    }
}

#[tokio::test]
async fn anthropic_obtains_its_client_from_the_injected_transport_port() {
    let transport = ProbeTransport {
        built: AtomicU32::new(0),
        fail: false,
    };
    let root = ApiRoot::parse("https://api.anthropic.com/v1").expect("valid root");

    let provider = Anthropic::with_transport("k".into(), root, &transport);
    assert!(
        provider.is_ok(),
        "adapter builds through the injected transport"
    );
    assert_eq!(
        transport.built.load(Ordering::SeqCst),
        1,
        "the client came from the injected transport port, not an inline reqwest builder"
    );
}

#[tokio::test]
async fn injected_transport_failure_fails_adapter_construction() {
    // A refused transport port must fail construction. This is only observable if
    // the adapter actually goes through the injected port for its network I/O; an
    // inline `reqwest::Client::builder()` could never surface this error.
    let transport = ProbeTransport {
        built: AtomicU32::new(0),
        fail: true,
    };
    let root = ApiRoot::parse("https://api.openai.com/v1").expect("valid root");

    let provider = OpenAiResponses::with_transport("k".into(), root, &transport);
    assert!(
        matches!(provider, Err(ProviderError::Configuration(_))),
        "a refused transport port must fail adapter construction"
    );
    assert_eq!(
        transport.built.load(Ordering::SeqCst),
        1,
        "the adapter consulted the injected transport port exactly once"
    );
}
