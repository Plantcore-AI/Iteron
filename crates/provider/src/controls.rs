//! Typed controls that may change one physical provider request.
//!
//! The provider trait reports the exact values an adapter can put on the wire.  The governor
//! validates a request against that report before a transport is opened, so a configured control
//! is never silently ignored by an unknown gateway.

use std::collections::BTreeSet;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord)]
pub enum ServiceTier {
    #[default]
    ProviderDefault,
    Auto,
    Standard,
    Flex,
    Priority,
}

impl ServiceTier {
    pub const fn label(self) -> &'static str {
        match self {
            Self::ProviderDefault => "provider_default",
            Self::Auto => "auto",
            Self::Standard => "standard",
            Self::Flex => "flex",
            Self::Priority => "priority",
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord)]
pub enum ResponseVerbosity {
    #[default]
    ModelDefault,
    Concise,
    Balanced,
    Detailed,
}

impl ResponseVerbosity {
    pub const fn label(self) -> &'static str {
        match self {
            Self::ModelDefault => "model_default",
            Self::Concise => "concise",
            Self::Balanced => "balanced",
            Self::Detailed => "detailed",
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord)]
pub enum RequestCompression {
    #[default]
    None,
    Gzip,
    Zstd,
}

impl RequestCompression {
    pub const fn label(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Gzip => "gzip",
            Self::Zstd => "zstd",
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord)]
pub enum CacheBreakpoint {
    #[default]
    None,
    Rolling,
    Explicit,
}

impl CacheBreakpoint {
    pub const fn label(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Rolling => "rolling",
            Self::Explicit => "explicit",
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord)]
pub enum CacheScope {
    Request,
    #[default]
    Session,
    Tenant,
}

impl CacheScope {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Request => "request",
            Self::Session => "session",
            Self::Tenant => "tenant",
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PromptCacheControl {
    /// Zero selects the provider's documented default lifetime.
    pub ttl_seconds: u32,
    pub breakpoint: CacheBreakpoint,
    pub invalidate_on_tool_change: bool,
    pub scope: CacheScope,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ProviderRequestControls {
    pub service_tier: ServiceTier,
    pub verbosity: ResponseVerbosity,
    pub compression: RequestCompression,
    pub prompt_cache: PromptCacheControl,
    /// A governor may duplicate a request only when both this bit and the provider capability are
    /// true. It is deliberately semantic rather than inferred from an empty tool list.
    pub idempotent: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderControlCapabilities {
    pub service_tiers: BTreeSet<ServiceTier>,
    pub verbosity: BTreeSet<ResponseVerbosity>,
    pub compression: BTreeSet<RequestCompression>,
    pub cache_breakpoints: BTreeSet<CacheBreakpoint>,
    /// Empty means no non-default TTL is attested. Zero is always the provider default.
    pub cache_ttl_seconds: BTreeSet<u32>,
    /// Cache isolation scopes whose semantics the adapter can actually preserve.
    pub cache_scopes: BTreeSet<CacheScope>,
    /// Whether changing the tool catalog necessarily changes the provider cache key/prefix.
    pub cache_invalidates_on_tool_change: bool,
    pub idempotent_requests: bool,
}

impl Default for ProviderControlCapabilities {
    fn default() -> Self {
        Self {
            service_tiers: BTreeSet::from([ServiceTier::ProviderDefault]),
            verbosity: BTreeSet::from([ResponseVerbosity::ModelDefault]),
            compression: BTreeSet::from([RequestCompression::None]),
            cache_breakpoints: BTreeSet::from([CacheBreakpoint::None]),
            cache_ttl_seconds: BTreeSet::new(),
            cache_scopes: BTreeSet::new(),
            cache_invalidates_on_tool_change: false,
            idempotent_requests: false,
        }
    }
}

impl ProviderControlCapabilities {
    pub fn validate(&self, controls: &ProviderRequestControls) -> Result<(), ControlError> {
        if !self.service_tiers.contains(&controls.service_tier) {
            return Err(ControlError::UnsupportedServiceTier(controls.service_tier));
        }
        if !self.verbosity.contains(&controls.verbosity) {
            return Err(ControlError::UnsupportedVerbosity(controls.verbosity));
        }
        if !self.compression.contains(&controls.compression) {
            return Err(ControlError::UnsupportedCompression(controls.compression));
        }
        if !self
            .cache_breakpoints
            .contains(&controls.prompt_cache.breakpoint)
        {
            return Err(ControlError::UnsupportedCacheBreakpoint(
                controls.prompt_cache.breakpoint,
            ));
        }
        if controls.prompt_cache.ttl_seconds != 0
            && !self
                .cache_ttl_seconds
                .contains(&controls.prompt_cache.ttl_seconds)
        {
            return Err(ControlError::UnsupportedCacheTtl(
                controls.prompt_cache.ttl_seconds,
            ));
        }
        let cache_active = controls.prompt_cache.breakpoint != CacheBreakpoint::None;
        if cache_active && !self.cache_scopes.contains(&controls.prompt_cache.scope) {
            return Err(ControlError::UnsupportedCacheScope(
                controls.prompt_cache.scope,
            ));
        }
        if cache_active
            && controls.prompt_cache.invalidate_on_tool_change
            && !self.cache_invalidates_on_tool_change
        {
            return Err(ControlError::CacheToolInvalidationNotAttested);
        }
        if controls.idempotent && !self.idempotent_requests {
            return Err(ControlError::IdempotencyNotAttested);
        }
        Ok(())
    }
}

#[derive(Debug, thiserror::Error, Clone, Copy, PartialEq, Eq)]
pub enum ControlError {
    #[error("provider route does not support service tier `{0:?}`")]
    UnsupportedServiceTier(ServiceTier),
    #[error("provider route does not support response verbosity `{0:?}`")]
    UnsupportedVerbosity(ResponseVerbosity),
    #[error("provider route does not support request compression `{0:?}`")]
    UnsupportedCompression(RequestCompression),
    #[error("provider route does not support cache breakpoint `{0:?}`")]
    UnsupportedCacheBreakpoint(CacheBreakpoint),
    #[error("provider route does not support prompt-cache TTL {0} seconds")]
    UnsupportedCacheTtl(u32),
    #[error("provider route does not support prompt-cache scope `{0:?}`")]
    UnsupportedCacheScope(CacheScope),
    #[error("provider route does not attest cache invalidation when the tool catalog changes")]
    CacheToolInvalidationNotAttested,
    #[error("provider route has no attested idempotent-request contract")]
    IdempotencyNotAttested,
}
