//! Canonical v1 pricing bytes and cryptographic encoding.
//!
//! Every field is length-framed or fixed-width. This module is deliberately private: callers use
//! typed artifacts and the pricing port rather than reimplementing the signature format.

use super::PricingError;
use iteron_protocol::{CostAttribution, CostProjection, PricingRoute, RateCard, SignedRateCard};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

pub(super) fn rate_card_content_bytes(rate_card: &RateCard) -> Vec<u8> {
    let mut bytes = Vec::new();
    push_bytes(&mut bytes, b"core/rate-card/content/v1");
    push_u64(&mut bytes, 1);
    push_route(&mut bytes, &rate_card.route);
    push_bytes(&mut bytes, rate_card.provenance.as_bytes());
    push_u64(&mut bytes, rate_card.issued_at_unix_secs);
    push_u64(&mut bytes, rate_card.expires_at_unix_secs);
    for rate in [
        rate_card.rates.input_microusd_per_million,
        rate_card.rates.output_microusd_per_million,
        rate_card.rates.cache_creation_microusd_per_million,
        rate_card.rates.cache_read_microusd_per_million,
        rate_card.rates.thinking_microusd_per_million,
    ] {
        push_u64(&mut bytes, rate);
    }
    bytes
}

pub(super) fn rate_card_auth_bytes(signed: &SignedRateCard) -> Vec<u8> {
    let mut bytes = Vec::new();
    push_bytes(&mut bytes, b"core/rate-card/auth/v1");
    push_bytes(&mut bytes, &rate_card_content_bytes(&signed.rate_card));
    push_bytes(&mut bytes, signed.signer_id.as_bytes());
    push_bytes(&mut bytes, signed.rate_card_digest.as_bytes());
    bytes
}

pub(super) fn projection_content_bytes(projection: &CostProjection) -> Vec<u8> {
    let mut bytes = Vec::new();
    // Preserve the historical byte contract for identity-less evidence so old records continue
    // to deserialize and pass content-integrity checks. Such evidence is never billing authority;
    // new projections use the domain-separated v2 payload below.
    push_bytes(
        &mut bytes,
        if projection.identity.is_some() {
            b"core/cost-projection/content/v2"
        } else {
            b"core/cost-projection/content/v1"
        },
    );
    push_u64(&mut bytes, 1);
    if let Some(identity) = &projection.identity {
        push_bytes(&mut bytes, identity.tenant_id.as_bytes());
        push_bytes(&mut bytes, identity.run_id.as_bytes());
        push_u64(&mut bytes, u64::from(identity.turn_id));
        push_u64(&mut bytes, u64::from(identity.provider_attempt));
        match &identity.attribution {
            None => push_u64(&mut bytes, 0),
            Some(CostAttribution::DirectSubagent {
                parent_run_id,
                sub_run,
            }) => {
                push_u64(&mut bytes, 1);
                push_bytes(&mut bytes, parent_run_id.as_bytes());
                push_bytes(&mut bytes, sub_run.as_bytes());
            }
            Some(CostAttribution::WorkflowChild {
                parent_run_id,
                workflow_id,
                task_id,
                sub_run,
            }) => {
                push_u64(&mut bytes, 2);
                push_bytes(&mut bytes, parent_run_id.as_bytes());
                push_bytes(&mut bytes, workflow_id.as_bytes());
                push_u64(&mut bytes, u64::from(*task_id));
                push_bytes(&mut bytes, sub_run.as_bytes());
            }
        }
    }
    push_route(&mut bytes, &projection.route);
    for count in [
        projection.usage.input,
        projection.usage.output,
        projection.usage.cache_creation,
        projection.usage.cache_read,
        projection.usage.thinking,
        projection.amount_microusd,
        projection.projected_at_unix_secs,
    ] {
        push_u64(&mut bytes, count);
    }
    push_bytes(&mut bytes, projection.rate_card_digest.as_bytes());
    push_bytes(&mut bytes, projection.signer_id.as_bytes());
    bytes
}

pub(super) fn projection_auth_bytes(projection: &CostProjection) -> Vec<u8> {
    let mut bytes = Vec::new();
    push_bytes(
        &mut bytes,
        if projection.identity.is_some() {
            b"core/cost-projection/auth/v2"
        } else {
            b"core/cost-projection/auth/v1"
        },
    );
    push_bytes(&mut bytes, &projection_content_bytes(projection));
    push_bytes(&mut bytes, projection.projection_digest.as_bytes());
    bytes
}

fn push_route(target: &mut Vec<u8>, route: &PricingRoute) {
    for value in [
        &route.provider_id,
        &route.model_id,
        &route.catalog_digest,
        &route.capability_digest,
    ] {
        push_bytes(target, value.as_bytes());
    }
}

fn push_bytes(target: &mut Vec<u8>, value: &[u8]) {
    target.extend_from_slice(&(value.len() as u64).to_be_bytes());
    target.extend_from_slice(value);
}

fn push_u64(target: &mut Vec<u8>, value: u64) {
    target.extend_from_slice(&value.to_be_bytes());
}

pub(super) fn sha256_label(value: &[u8]) -> String {
    format!("sha256:{}", hex_lower(&Sha256::digest(value)))
}

pub(super) fn sign_mac(key: &[u8; 32], value: &[u8]) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts every key length");
    mac.update(value);
    format!("hmac-sha256:{}", hex_lower(&mac.finalize().into_bytes()))
}

pub(super) fn verify_mac(
    key: &[u8; 32],
    value: &[u8],
    signature: &str,
) -> Result<(), PricingError> {
    let bytes = decode_prefixed_hex(signature, "hmac-sha256:")
        .map_err(|_| PricingError::InvalidSignature)?;
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts every key length");
    mac.update(value);
    mac.verify_slice(&bytes)
        .map_err(|_| PricingError::SignatureMismatch)
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

pub(super) fn validate_prefixed_hex(value: &str, prefix: &str) -> Result<(), ()> {
    let bytes = decode_prefixed_hex(value, prefix)?;
    if bytes.len() == 32 { Ok(()) } else { Err(()) }
}

fn decode_prefixed_hex(value: &str, prefix: &str) -> Result<Vec<u8>, ()> {
    decode_hex(value.strip_prefix(prefix).ok_or(())?)
}

pub(super) fn decode_hex(value: &str) -> Result<Vec<u8>, ()> {
    if !value.len().is_multiple_of(2) || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(());
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = (pair[0] as char).to_digit(16).ok_or(())?;
            let low = (pair[1] as char).to_digit(16).ok_or(())?;
            Ok(((high << 4) | low) as u8)
        })
        .collect()
}
