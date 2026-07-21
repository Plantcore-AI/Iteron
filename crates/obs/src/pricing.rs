//! Pure pricing strategy and verification port.
//!
//! The kernel sees only [`PricingPort`]. HMAC keys remain inside the strategy implementation: they
//! have no serde surface, their `Debug` representation is redacted, and cloning an agent clones only
//! an `Arc<dyn PricingPort>`, never the key bytes.

mod codec;
mod replay;

use codec::{
    decode_hex, projection_auth_bytes, projection_content_bytes, rate_card_auth_bytes,
    rate_card_content_bytes, sha256_label, sign_mac, validate_prefixed_hex, verify_mac,
};
use core_protocol::{
    CostAttribution, CostProjection, CostProjectionIdentity, PricingRoute, PricingVersion,
    RateCard, SignedRateCard, TokenRateCard, Usage,
};
use std::collections::{BTreeMap, HashMap};
use std::fmt;
use zeroize::Zeroizing;

pub use replay::PricingReplay;

const MICROTOKENS_PER_TOKEN_CLASS: u128 = 1_000_000;
pub const MAX_TRUSTED_RATE_CARDS: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PricingError {
    InvalidField(&'static str),
    InvalidDigest,
    InvalidSignature,
    InvalidSigningKey,
    DigestMismatch,
    SignatureMismatch,
    ThinkingExceedsOutput,
    AmountOverflow,
    UntrustedRateCard,
    RateCardNotYetValid,
    RateCardExpired,
    AmbiguousRateCard,
    DuplicateRateCard,
    RateCardManifestTooLarge,
    ProjectionNotAdjacent,
    MissingProjectionIdentity,
    ProjectionIdentityMismatch,
    DuplicateProjection,
    WorkflowEvidenceMismatch,
    DuplicateWorkflowTerminal,
}

impl fmt::Display for PricingError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::InvalidField(field) => return write!(formatter, "invalid pricing field {field}"),
            Self::InvalidDigest => "invalid pricing digest encoding",
            Self::InvalidSignature => "invalid pricing signature encoding",
            Self::InvalidSigningKey => "invalid pricing signing key",
            Self::DigestMismatch => "pricing content digest mismatch",
            Self::SignatureMismatch => "pricing signature mismatch",
            Self::ThinkingExceedsOutput => "thinking tokens exceeded total output tokens",
            Self::AmountOverflow => "pricing amount exceeds fixed-point range",
            Self::UntrustedRateCard => "rate card is absent from the trusted pricing manifest",
            Self::RateCardNotYetValid => "rate card is not active yet",
            Self::RateCardExpired => "rate card has expired",
            Self::AmbiguousRateCard => "multiple trusted rate cards are active for this route",
            Self::DuplicateRateCard => "duplicate rate-card digest in trusted pricing manifest",
            Self::RateCardManifestTooLarge => {
                "trusted pricing manifest exceeds the fixed rate-card bound"
            }
            Self::ProjectionNotAdjacent => "cost projection is not adjacent to its provider usage",
            Self::MissingProjectionIdentity => {
                "cost projection has no authenticated rollout identity"
            }
            Self::ProjectionIdentityMismatch => {
                "cost projection does not match its rollout or terminal identity"
            }
            Self::DuplicateProjection => "cost projection identity or digest was already consumed",
            Self::WorkflowEvidenceMismatch => "child workflow pricing evidence is inconsistent",
            Self::DuplicateWorkflowTerminal => {
                "child workflow terminal was duplicated or reused across terminal forms"
            }
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for PricingError {}

/// Secret HMAC material admitted through a process-local composition seam. It cannot be cloned,
/// serialized, or formatted, and its bytes are zeroized on drop.
pub struct HmacPricingKey(Zeroizing<[u8; 32]>);

impl HmacPricingKey {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// Parse exactly 32 bytes of hexadecimal key material without retaining the source string.
    pub fn from_hex(value: &str) -> Result<Self, PricingError> {
        let bytes = Zeroizing::new(decode_hex(value).map_err(|_| PricingError::InvalidSigningKey)?);
        if bytes.len() != 32 {
            return Err(PricingError::InvalidSigningKey);
        }
        let mut key = Zeroizing::new([0u8; 32]);
        key.copy_from_slice(&bytes);
        Ok(Self(key))
    }

    fn bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for HmacPricingKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("HmacPricingKey([REDACTED])")
    }
}

/// Injected strategy port. Implementations may read operator-trusted world data during
/// composition, but these methods are pure and perform no provider/network/filesystem operation.
pub trait PricingPort: Send + Sync {
    /// Resolve the unique currently-active immutable card for an exact durable route.
    fn resolve_rate_card(
        &self,
        route: &PricingRoute,
        at_unix_secs: u64,
    ) -> Result<Option<SignedRateCard>, PricingError>;

    /// Authenticate a durable card against the current operator trust manifest. Historical cards
    /// may be expired now; replay freshness is proved by each signed projection timestamp.
    fn verify_rate_card(&self, signed: &SignedRateCard) -> Result<(), PricingError>;

    /// Produce the signed projection handed to the kernel for recording.
    fn project(
        &self,
        signed: &SignedRateCard,
        identity: CostProjectionIdentity,
        usage: Usage,
        projected_at_unix_secs: u64,
    ) -> Result<CostProjection, PricingError>;

    /// Authenticate route, card, timestamp, amount, digest, and HMAC during replay.
    fn verify_projection(
        &self,
        signed: &SignedRateCard,
        projection: &CostProjection,
    ) -> Result<(), PricingError>;

    /// Authenticate a child-workflow projection by its configured immutable card digest.
    fn verify_projection_by_digest(&self, projection: &CostProjection) -> Result<(), PricingError>;
}

struct TrustedCard {
    signed: SignedRateCard,
    key: HmacPricingKey,
}

/// Immutable operator-trusted HMAC strategy. Multiple non-overlapping revisions may exist for one
/// route so historical replay remains possible while live resolution selects exactly one card.
pub struct HmacPricingAuthority {
    cards: HashMap<String, TrustedCard>,
    routes: BTreeMap<PricingRoute, Vec<String>>,
}

impl fmt::Debug for HmacPricingAuthority {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HmacPricingAuthority")
            .field("trusted_cards", &self.cards.len())
            .field("routes", &self.routes.len())
            .finish()
    }
}

impl HmacPricingAuthority {
    pub fn new(entries: Vec<(SignedRateCard, HmacPricingKey)>) -> Result<Self, PricingError> {
        if entries.len() > MAX_TRUSTED_RATE_CARDS {
            return Err(PricingError::RateCardManifestTooLarge);
        }
        let mut cards = HashMap::new();
        let mut routes: BTreeMap<PricingRoute, Vec<String>> = BTreeMap::new();
        for (signed, key) in entries {
            validate_rate_card_digest(&signed)?;
            verify_mac(
                key.bytes(),
                &rate_card_auth_bytes(&signed),
                &signed.signature,
            )?;
            let digest = signed.rate_card_digest.clone();
            if cards.contains_key(&digest) {
                return Err(PricingError::DuplicateRateCard);
            }
            routes
                .entry(signed.rate_card.route.clone())
                .or_default()
                .push(digest.clone());
            cards.insert(digest, TrustedCard { signed, key });
        }
        Ok(Self { cards, routes })
    }

    pub fn is_empty(&self) -> bool {
        self.cards.is_empty()
    }

    fn trusted_card(&self, signed: &SignedRateCard) -> Result<&TrustedCard, PricingError> {
        validate_rate_card_digest(signed)?;
        let trusted = self
            .cards
            .get(&signed.rate_card_digest)
            .ok_or(PricingError::UntrustedRateCard)?;
        verify_mac(
            trusted.key.bytes(),
            &rate_card_auth_bytes(signed),
            &signed.signature,
        )?;
        if trusted.signed.rate_card != signed.rate_card
            || trusted.signed.signer_id != signed.signer_id
        {
            return Err(PricingError::UntrustedRateCard);
        }
        Ok(trusted)
    }

    fn trusted_card_for_projection(
        &self,
        projection: &CostProjection,
    ) -> Result<&TrustedCard, PricingError> {
        self.cards
            .get(&projection.rate_card_digest)
            .ok_or(PricingError::UntrustedRateCard)
    }
}

impl PricingPort for HmacPricingAuthority {
    fn resolve_rate_card(
        &self,
        route: &PricingRoute,
        at_unix_secs: u64,
    ) -> Result<Option<SignedRateCard>, PricingError> {
        let Some(digests) = self.routes.get(route) else {
            return Ok(None);
        };
        let active: Vec<&TrustedCard> = digests
            .iter()
            .filter_map(|digest| self.cards.get(digest))
            .filter(|card| card_is_fresh(&card.signed.rate_card, at_unix_secs))
            .collect();
        match active.as_slice() {
            [] => {
                let newest_issue = digests
                    .iter()
                    .filter_map(|digest| self.cards.get(digest))
                    .map(|card| card.signed.rate_card.issued_at_unix_secs)
                    .max()
                    .unwrap_or(0);
                if at_unix_secs < newest_issue {
                    Err(PricingError::RateCardNotYetValid)
                } else {
                    Err(PricingError::RateCardExpired)
                }
            }
            [card] => Ok(Some(card.signed.clone())),
            _ => Err(PricingError::AmbiguousRateCard),
        }
    }

    fn verify_rate_card(&self, signed: &SignedRateCard) -> Result<(), PricingError> {
        self.trusted_card(signed).map(|_| ())
    }

    fn project(
        &self,
        signed: &SignedRateCard,
        identity: CostProjectionIdentity,
        usage: Usage,
        projected_at_unix_secs: u64,
    ) -> Result<CostProjection, PricingError> {
        let trusted = self.trusted_card(signed)?;
        validate_projection_identity(&identity)?;
        ensure_card_fresh(&signed.rate_card, projected_at_unix_secs)?;
        let amount_microusd = project_amount(signed.rate_card.rates, usage)?;
        let mut projection = CostProjection {
            version: signed.rate_card.version,
            identity: Some(identity),
            route: signed.rate_card.route.clone(),
            usage,
            amount_microusd,
            projected_at_unix_secs,
            rate_card_digest: signed.rate_card_digest.clone(),
            signer_id: signed.signer_id.clone(),
            projection_digest: String::new(),
            signature: String::new(),
        };
        projection.projection_digest = sha256_label(&projection_content_bytes(&projection));
        projection.signature = sign_mac(trusted.key.bytes(), &projection_auth_bytes(&projection));
        Ok(projection)
    }

    fn verify_projection(
        &self,
        signed: &SignedRateCard,
        projection: &CostProjection,
    ) -> Result<(), PricingError> {
        let trusted = self.trusted_card(signed)?;
        verify_projection_with_card(trusted, projection)
    }

    fn verify_projection_by_digest(&self, projection: &CostProjection) -> Result<(), PricingError> {
        let trusted = self.trusted_card_for_projection(projection)?;
        self.verify_rate_card(&trusted.signed)?;
        verify_projection_with_card(trusted, projection)
    }
}

fn verify_projection_with_card(
    trusted: &TrustedCard,
    projection: &CostProjection,
) -> Result<(), PricingError> {
    validate_projection_digest(projection)?;
    let signed = &trusted.signed;
    if projection.version != signed.rate_card.version
        || projection.route != signed.rate_card.route
        || projection.rate_card_digest != signed.rate_card_digest
        || projection.signer_id != signed.signer_id
    {
        return Err(PricingError::InvalidField("projection_route_binding"));
    }
    ensure_card_fresh(&signed.rate_card, projection.projected_at_unix_secs)?;
    let amount = project_amount(signed.rate_card.rates, projection.usage)?;
    if amount != projection.amount_microusd {
        return Err(PricingError::WorkflowEvidenceMismatch);
    }
    verify_mac(
        trusted.key.bytes(),
        &projection_auth_bytes(projection),
        &projection.signature,
    )
}

/// Sign one immutable card in an external/operator pricing strategy. Core never calls this from the
/// kernel or frontend composition path; it is exposed for offline manifest tooling and tests.
pub fn sign_rate_card(
    rate_card: RateCard,
    signer_id: impl Into<String>,
    signing_key: [u8; 32],
) -> Result<SignedRateCard, PricingError> {
    validate_rate_card(&rate_card)?;
    let signer_id = signer_id.into();
    validate_identifier("signer_id", &signer_id, 128, false)?;
    let mut signed = SignedRateCard {
        rate_card_digest: sha256_label(&rate_card_content_bytes(&rate_card)),
        rate_card,
        signer_id,
        signature: String::new(),
    };
    signed.signature = sign_mac(&signing_key, &rate_card_auth_bytes(&signed));
    Ok(signed)
}

pub fn validate_rate_card_digest(signed: &SignedRateCard) -> Result<(), PricingError> {
    validate_rate_card(&signed.rate_card)?;
    validate_identifier("signer_id", &signed.signer_id, 128, false)?;
    validate_prefixed_hex(&signed.rate_card_digest, "sha256:")
        .map_err(|_| PricingError::InvalidDigest)?;
    validate_prefixed_hex(&signed.signature, "hmac-sha256:")
        .map_err(|_| PricingError::InvalidSignature)?;
    if sha256_label(&rate_card_content_bytes(&signed.rate_card)) != signed.rate_card_digest {
        return Err(PricingError::DigestMismatch);
    }
    Ok(())
}

pub fn validate_projection_digest(projection: &CostProjection) -> Result<(), PricingError> {
    validate_route(&projection.route)?;
    if let Some(identity) = &projection.identity {
        validate_projection_identity(identity)?;
    }
    validate_identifier("signer_id", &projection.signer_id, 128, false)?;
    validate_prefixed_hex(&projection.rate_card_digest, "sha256:")
        .map_err(|_| PricingError::InvalidDigest)?;
    validate_prefixed_hex(&projection.projection_digest, "sha256:")
        .map_err(|_| PricingError::InvalidDigest)?;
    validate_prefixed_hex(&projection.signature, "hmac-sha256:")
        .map_err(|_| PricingError::InvalidSignature)?;
    if sha256_label(&projection_content_bytes(projection)) != projection.projection_digest {
        return Err(PricingError::DigestMismatch);
    }
    Ok(())
}

fn validate_projection_identity(identity: &CostProjectionIdentity) -> Result<(), PricingError> {
    validate_context_identifier("tenant_id", &identity.tenant_id, 512)?;
    validate_context_identifier("run_id", &identity.run_id, 200)?;
    if identity.provider_attempt == 0 {
        return Err(PricingError::InvalidField("provider_attempt"));
    }
    match &identity.attribution {
        None => {}
        Some(CostAttribution::DirectSubagent {
            parent_run_id,
            sub_run,
        }) => {
            validate_context_identifier("parent_run_id", parent_run_id, 200)?;
            validate_context_identifier("sub_run", sub_run, 200)?;
            if sub_run != &identity.run_id {
                return Err(PricingError::InvalidField("sub_run_identity"));
            }
        }
        Some(CostAttribution::WorkflowChild {
            parent_run_id,
            workflow_id,
            sub_run,
            ..
        }) => {
            validate_context_identifier("parent_run_id", parent_run_id, 200)?;
            validate_context_identifier("workflow_id", workflow_id, 512)?;
            validate_context_identifier("sub_run", sub_run, 200)?;
            if sub_run != &identity.run_id {
                return Err(PricingError::InvalidField("sub_run_identity"));
            }
        }
    }
    Ok(())
}

fn validate_context_identifier(
    field: &'static str,
    value: &str,
    max_bytes: usize,
) -> Result<(), PricingError> {
    if value.is_empty() || value.len() > max_bytes || value.chars().any(char::is_control) {
        Err(PricingError::InvalidField(field))
    } else {
        Ok(())
    }
}

fn validate_rate_card(rate_card: &RateCard) -> Result<(), PricingError> {
    if rate_card.version != PricingVersion::V1 {
        return Err(PricingError::InvalidField("version"));
    }
    validate_route(&rate_card.route)?;
    if rate_card.provenance.is_empty()
        || rate_card.provenance.len() > 512
        || rate_card.provenance.chars().any(char::is_control)
    {
        return Err(PricingError::InvalidField("provenance"));
    }
    if rate_card.issued_at_unix_secs >= rate_card.expires_at_unix_secs {
        return Err(PricingError::InvalidField("rate_card_validity"));
    }
    Ok(())
}

fn validate_route(route: &PricingRoute) -> Result<(), PricingError> {
    validate_identifier("provider_id", &route.provider_id, 64, false)?;
    validate_identifier("model_id", &route.model_id, 512, false)?;
    validate_route_digest("catalog_digest", &route.catalog_digest)?;
    validate_route_digest("capability_digest", &route.capability_digest)
}

fn validate_route_digest(field: &'static str, value: &str) -> Result<(), PricingError> {
    if value
        .strip_prefix("sha256:")
        .is_some_and(|hex| hex.len() == 64 && hex.bytes().all(|byte| byte.is_ascii_hexdigit()))
    {
        Ok(())
    } else {
        Err(PricingError::InvalidField(field))
    }
}

fn validate_identifier(
    field: &'static str,
    value: &str,
    max_bytes: usize,
    allow_empty: bool,
) -> Result<(), PricingError> {
    if (!allow_empty && value.is_empty())
        || value.len() > max_bytes
        || value
            .chars()
            .any(|character| character.is_control() || character.is_whitespace())
    {
        return Err(PricingError::InvalidField(field));
    }
    Ok(())
}

fn ensure_card_fresh(rate_card: &RateCard, at_unix_secs: u64) -> Result<(), PricingError> {
    if at_unix_secs < rate_card.issued_at_unix_secs {
        Err(PricingError::RateCardNotYetValid)
    } else if at_unix_secs >= rate_card.expires_at_unix_secs {
        Err(PricingError::RateCardExpired)
    } else {
        Ok(())
    }
}

fn card_is_fresh(rate_card: &RateCard, at_unix_secs: u64) -> bool {
    ensure_card_fresh(rate_card, at_unix_secs).is_ok()
}

fn project_amount(rates: TokenRateCard, usage: Usage) -> Result<u64, PricingError> {
    if usage.thinking > usage.output {
        return Err(PricingError::ThinkingExceedsOutput);
    }
    let classes = [
        (usage.input, rates.input_microusd_per_million),
        (
            usage.output - usage.thinking,
            rates.output_microusd_per_million,
        ),
        (
            usage.cache_creation,
            rates.cache_creation_microusd_per_million,
        ),
        (usage.cache_read, rates.cache_read_microusd_per_million),
        (usage.thinking, rates.thinking_microusd_per_million),
    ];
    let mut total = 0u128;
    for (tokens, rate) in classes {
        let numerator = u128::from(tokens)
            .checked_mul(u128::from(rate))
            .ok_or(PricingError::AmountOverflow)?;
        let class_cost = numerator
            .checked_add(MICROTOKENS_PER_TOKEN_CLASS - 1)
            .ok_or(PricingError::AmountOverflow)?
            / MICROTOKENS_PER_TOKEN_CLASS;
        total = total
            .checked_add(class_cost)
            .ok_or(PricingError::AmountOverflow)?;
    }
    u64::try_from(total).map_err(|_| PricingError::AmountOverflow)
}

#[cfg(test)]
mod tests;
