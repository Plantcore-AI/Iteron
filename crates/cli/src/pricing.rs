//! Operator-trusted pricing composition.
//!
//! The user configuration carries immutable signed artifacts and names the environment variables
//! that hold their HMAC keys. This module is the only production seam that reads those variables;
//! the kernel receives an opaque [`core_obs::PricingPort`] and never sees key bytes or price tables.

use core_obs::{HmacPricingAuthority, HmacPricingKey, PricingPort};
use core_protocol::{PricingRoute, PricingVersion, RateCard, SignedRateCard, TokenRateCard};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::ffi::OsString;
use std::sync::Arc;

const MAX_RATE_CARDS: usize = core_obs::MAX_TRUSTED_RATE_CARDS;

/// One public signed rate-card artifact plus an indirect process-local key reference.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RateCardConfig {
    pub version: PricingVersion,
    pub provider_id: String,
    pub model_id: String,
    pub catalog_digest: String,
    pub capability_digest: String,
    pub provenance: String,
    pub issued_at_unix_secs: u64,
    pub expires_at_unix_secs: u64,
    pub rates: TokenRateCard,
    pub signer_id: String,
    /// Uppercase environment-variable name only. Plaintext key fields are outside this schema.
    pub key_env: String,
    pub rate_card_digest: String,
    pub signature: String,
}

impl RateCardConfig {
    fn signed_artifact(&self) -> SignedRateCard {
        SignedRateCard {
            rate_card: RateCard {
                version: self.version,
                route: PricingRoute {
                    provider_id: self.provider_id.clone(),
                    model_id: self.model_id.clone(),
                    catalog_digest: self.catalog_digest.clone(),
                    capability_digest: self.capability_digest.clone(),
                },
                provenance: self.provenance.clone(),
                issued_at_unix_secs: self.issued_at_unix_secs,
                expires_at_unix_secs: self.expires_at_unix_secs,
                rates: self.rates,
            },
            signer_id: self.signer_id.clone(),
            rate_card_digest: self.rate_card_digest.clone(),
            signature: self.signature.clone(),
        }
    }
}

pub fn validate_rate_card_configs(cards: &[RateCardConfig]) -> Result<(), String> {
    if cards.len() > MAX_RATE_CARDS {
        return Err(format!(
            "rate_cards exceeds the {MAX_RATE_CARDS}-artifact configuration bound"
        ));
    }
    let mut digests = BTreeSet::new();
    for card in cards {
        validate_key_env(&card.key_env)?;
        let signed = card.signed_artifact();
        core_obs::validate_rate_card_digest(&signed)
            .map_err(|error| format!("invalid signed rate card: {error}"))?;
        if !digests.insert(signed.rate_card_digest) {
            return Err("duplicate rate-card digest in configuration".into());
        }
    }
    Ok(())
}

pub fn key_env_names(cards: &[RateCardConfig]) -> Vec<String> {
    cards
        .iter()
        .map(|card| card.key_env.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

/// Build the immutable authority before opening a rollout. Errors identify only the configured
/// environment-variable name and never include key material.
pub fn load_authority(cards: &[RateCardConfig]) -> anyhow::Result<Option<Arc<dyn PricingPort>>> {
    load_authority_with(cards, |name| std::env::var_os(name))
}

fn load_authority_with<F>(
    cards: &[RateCardConfig],
    mut lookup: F,
) -> anyhow::Result<Option<Arc<dyn PricingPort>>>
where
    F: FnMut(&str) -> Option<OsString>,
{
    validate_rate_card_configs(cards).map_err(anyhow::Error::msg)?;
    if cards.is_empty() {
        return Ok(None);
    }

    let mut entries = Vec::with_capacity(cards.len());
    for card in cards {
        let value = lookup(&card.key_env).ok_or_else(|| {
            anyhow::anyhow!(
                "pricing key environment variable `{}` is not set",
                card.key_env
            )
        })?;
        let value = value.to_str().ok_or_else(|| {
            anyhow::anyhow!(
                "pricing key environment variable `{}` must contain exactly 32 bytes of hexadecimal key material",
                card.key_env
            )
        })?;
        let key = HmacPricingKey::from_hex(value).map_err(|_| {
            anyhow::anyhow!(
                "pricing key environment variable `{}` must contain exactly 32 bytes of hexadecimal key material",
                card.key_env
            )
        })?;
        entries.push((card.signed_artifact(), key));
    }
    let authority = HmacPricingAuthority::new(entries)
        .map_err(|error| anyhow::anyhow!("invalid trusted rate-card manifest: {error}"))?;
    Ok(Some(Arc::new(authority)))
}

fn validate_key_env(name: &str) -> Result<(), String> {
    if name.is_empty()
        || name.len() > 128
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
    {
        return Err("rate-card key_env must be an uppercase ASCII environment name".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use core_obs::sign_rate_card;

    const NOW: u64 = 1_800_000_000;

    fn config(key: [u8; 32]) -> (RateCardConfig, String) {
        let rate_card = RateCard {
            version: PricingVersion::V1,
            route: PricingRoute {
                provider_id: "provider-a".into(),
                model_id: "model-a".into(),
                catalog_digest: format!("sha256:{}", "a".repeat(64)),
                capability_digest: format!("sha256:{}", "b".repeat(64)),
            },
            provenance: "operator-manifest@v1".into(),
            issued_at_unix_secs: NOW - 60,
            expires_at_unix_secs: NOW + 60,
            rates: TokenRateCard {
                input_microusd_per_million: 1,
                output_microusd_per_million: 2,
                cache_creation_microusd_per_million: 1,
                cache_read_microusd_per_million: 1,
                thinking_microusd_per_million: 3,
            },
        };
        let signed = sign_rate_card(rate_card.clone(), "pricing-root-v1", key).unwrap();
        let config = RateCardConfig {
            version: rate_card.version,
            provider_id: rate_card.route.provider_id,
            model_id: rate_card.route.model_id,
            catalog_digest: rate_card.route.catalog_digest,
            capability_digest: rate_card.route.capability_digest,
            provenance: rate_card.provenance,
            issued_at_unix_secs: rate_card.issued_at_unix_secs,
            expires_at_unix_secs: rate_card.expires_at_unix_secs,
            rates: rate_card.rates,
            signer_id: signed.signer_id,
            key_env: "CORE_PRICING_TEST_KEY".into(),
            rate_card_digest: signed.rate_card_digest,
            signature: signed.signature,
        };
        let hex = key.iter().map(|byte| format!("{byte:02x}")).collect();
        (config, hex)
    }

    #[test]
    fn production_composition_resolves_only_the_exact_signed_route() {
        let (config, hex) = config([7; 32]);
        let expected_route = config.signed_artifact().rate_card.route;
        let authority = load_authority_with(&[config], |_| Some(hex.clone().into()))
            .unwrap()
            .unwrap();
        assert!(
            authority
                .resolve_rate_card(&expected_route, NOW)
                .unwrap()
                .is_some()
        );

        let mut changed_route = expected_route;
        changed_route.capability_digest = format!("sha256:{}", "c".repeat(64));
        assert_eq!(
            authority.resolve_rate_card(&changed_route, NOW).unwrap(),
            None
        );
    }

    #[test]
    fn key_errors_name_only_the_environment_variable() {
        let (config, _) = config([9; 32]);
        let secret = "definitely-not-valid-secret-material";
        let error = match load_authority_with(&[config], |_| Some(secret.into())) {
            Ok(_) => panic!("invalid key material must be rejected"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("CORE_PRICING_TEST_KEY"));
        assert!(!error.contains(secret));
    }

    #[test]
    fn plaintext_key_fields_are_rejected_by_the_strict_schema() {
        let json = r#"{
            "version":"v1",
            "provider_id":"p",
            "model_id":"m",
            "catalog_digest":"",
            "capability_digest":"",
            "provenance":"manifest",
            "issued_at_unix_secs":1,
            "expires_at_unix_secs":2,
            "rates":{
                "input_microusd_per_million":1,
                "output_microusd_per_million":1,
                "cache_creation_microusd_per_million":1,
                "cache_read_microusd_per_million":1,
                "thinking_microusd_per_million":1
            },
            "signer_id":"root",
            "key_env":"CORE_PRICING_KEY",
            "rate_card_digest":"sha256:0000000000000000000000000000000000000000000000000000000000000000",
            "signature":"hmac-sha256:0000000000000000000000000000000000000000000000000000000000000000",
            "signing_key":"plaintext"
        }"#;
        assert!(serde_json::from_str::<RateCardConfig>(json).is_err());
    }
}
