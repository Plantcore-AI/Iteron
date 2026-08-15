//! Bounded, content-free per-route correction learned from provider-accounted input usage.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};

pub const TOKEN_CALIBRATION_SCHEMA_VERSION: u8 = 1;
const MAX_ROUTE_PROFILES: usize = 64;
struct TokenCalibrationWire {
    max_route_id_bytes: usize,
    ratio_scale: u64,
}

/// Persisted ratios and joined route identities use this immutable encoding envelope. Changing it
/// requires a schema migration, so it is deliberately outside the learned parameter plane.
const TOKEN_CALIBRATION_WIRE: TokenCalibrationWire = TokenCalibrationWire {
    max_route_id_bytes: 192,
    ratio_scale: 1_000_000,
};
const MIN_RATIO_PPM: u64 = 500_000;
const MAX_RATIO_PPM: u64 = 4_000_000;
const DRIFT_ERROR_PPM: u64 = 500_000;
const MIN_STABLE_OBSERVATIONS: u32 = 3;
const SAFETY_MARGIN_PPM: u64 = 1_150_000;

#[derive(Clone, Copy)]
struct CalibrationParams {
    max_route_profiles: usize,
    max_route_id_bytes: usize,
    ratio_scale: u64,
    min_ratio_ppm: u64,
    max_ratio_ppm: u64,
    drift_error_ppm: u64,
    min_stable_observations: u32,
    safety_margin_ppm: u64,
}

fn calibration_params() -> CalibrationParams {
    let ratio_scale = TOKEN_CALIBRATION_WIRE.ratio_scale;
    let min_ratio_ppm =
        iteron_tunables::param_u64("ctx.token_calibration.min_ratio_ppm", MIN_RATIO_PPM)
            .clamp(1, ratio_scale);
    let max_ratio_ppm =
        iteron_tunables::param_u64("ctx.token_calibration.max_ratio_ppm", MAX_RATIO_PPM)
            .clamp(ratio_scale, MAX_RATIO_PPM);
    CalibrationParams {
        max_route_profiles: iteron_tunables::param_usize(
            "ctx.token_calibration.max_route_profiles",
            MAX_ROUTE_PROFILES,
        )
        .clamp(1, MAX_ROUTE_PROFILES),
        max_route_id_bytes: TOKEN_CALIBRATION_WIRE.max_route_id_bytes,
        ratio_scale,
        min_ratio_ppm,
        max_ratio_ppm,
        drift_error_ppm: iteron_tunables::param_u64(
            "ctx.token_calibration.drift_error_ppm",
            DRIFT_ERROR_PPM,
        )
        .min(max_ratio_ppm),
        min_stable_observations: iteron_tunables::param_integer(
            "ctx.token_calibration.min_stable_observations",
            MIN_STABLE_OBSERVATIONS,
        )
        .clamp(1, MIN_STABLE_OBSERVATIONS),
        safety_margin_ppm: iteron_tunables::param_u64(
            "ctx.token_calibration.safety_margin_ppm",
            SAFETY_MARGIN_PPM,
        )
        .clamp(ratio_scale, max_ratio_ppm),
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteTokenCalibration {
    pub ratio_ppm: u64,
    pub observations: u32,
    pub stable_observations: u32,
    pub drifted: bool,
    pub max_error_ppm: u64,
    pub high_water_ratio_ppm: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TokenCalibrationSnapshot {
    pub schema_version: u8,
    pub profiles: BTreeMap<String, RouteTokenCalibration>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CalibrationObservation {
    pub ratio_ppm: u64,
    pub error_ppm: u64,
    pub drifted: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TokenCalibrationError {
    #[error("token calibration route identity is invalid")]
    InvalidRoute,
    #[error("token calibration observation must be non-zero")]
    InvalidObservation,
    #[error("token calibration route bound reached")]
    ProfileLimit,
    #[error("token calibration snapshot is corrupt or unsupported")]
    InvalidSnapshot,
}

#[derive(Clone, Default)]
pub struct TokenCalibrationStore {
    profiles: Arc<RwLock<BTreeMap<String, RouteTokenCalibration>>>,
}

impl TokenCalibrationStore {
    /// Observe one provider-accounted input total against that turn's *uncalibrated* estimator
    /// baseline. Feeding a prior calibrated result back here would create an oscillating controller
    /// and is intentionally excluded from this contract. The ratio is clamped before the bounded
    /// EWMA; a >50% instantaneous error marks the route drifted and reads fail conservative.
    pub fn observe_actual_input(
        &self,
        provider_id: &str,
        model_id: &str,
        uncalibrated_input_estimate: u64,
        actual_input_tokens: u64,
    ) -> Result<CalibrationObservation, TokenCalibrationError> {
        let params = calibration_params();
        let key = route_key(provider_id, model_id, params.max_route_id_bytes)?;
        if uncalibrated_input_estimate == 0 || actual_input_tokens == 0 {
            return Err(TokenCalibrationError::InvalidObservation);
        }
        let raw_ratio = actual_input_tokens
            .saturating_mul(params.ratio_scale)
            .checked_div(uncalibrated_input_estimate)
            .unwrap_or(params.max_ratio_ppm);
        let ratio = raw_ratio.clamp(params.min_ratio_ppm, params.max_ratio_ppm);
        let error = raw_ratio.abs_diff(params.ratio_scale);
        let mut profiles = self
            .profiles
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !profiles.contains_key(&key) && profiles.len() == params.max_route_profiles {
            return Err(TokenCalibrationError::ProfileLimit);
        }
        let profile = profiles.entry(key).or_insert(RouteTokenCalibration {
            ratio_ppm: params.ratio_scale,
            observations: 0,
            stable_observations: 0,
            drifted: false,
            max_error_ppm: 0,
            high_water_ratio_ppm: params.ratio_scale,
        });
        profile.ratio_ppm = if profile.observations == 0 {
            ratio
        } else {
            profile
                .ratio_ppm
                .saturating_mul(7)
                .saturating_add(ratio)
                .div_ceil(8)
        };
        profile.observations = profile.observations.saturating_add(1);
        profile.max_error_ppm = profile.max_error_ppm.max(error);
        profile.drifted = error > params.drift_error_ppm;
        profile.high_water_ratio_ppm = profile.high_water_ratio_ppm.max(ratio);
        profile.stable_observations = if profile.drifted {
            0
        } else {
            profile.stable_observations.saturating_add(1)
        };
        Ok(CalibrationObservation {
            ratio_ppm: profile.ratio_ppm,
            error_ppm: error,
            drifted: profile.drifted,
        })
    }

    pub fn calibrated_estimate(
        &self,
        provider_id: &str,
        model_id: &str,
        conservative_estimate: u64,
    ) -> u64 {
        let params = calibration_params();
        let Ok(key) = route_key(provider_id, model_id, params.max_route_id_bytes) else {
            return conservative_estimate;
        };
        let profiles = self
            .profiles
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some(profile) = profiles.get(&key) else {
            return conservative_estimate;
        };
        if !profile.drifted && profile.stable_observations < params.min_stable_observations {
            return conservative_estimate;
        }
        let ratio = if profile.drifted {
            profile.high_water_ratio_ppm.max(params.ratio_scale)
        } else {
            profile
                .ratio_ppm
                .saturating_mul(params.safety_margin_ppm)
                .div_ceil(params.ratio_scale)
                .clamp(params.min_ratio_ppm, params.max_ratio_ppm)
        };
        conservative_estimate
            .saturating_mul(ratio)
            .div_ceil(params.ratio_scale)
    }

    pub fn snapshot(&self) -> TokenCalibrationSnapshot {
        TokenCalibrationSnapshot {
            schema_version: TOKEN_CALIBRATION_SCHEMA_VERSION,
            profiles: self
                .profiles
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone(),
        }
    }

    pub fn restore(snapshot: TokenCalibrationSnapshot) -> Result<Self, TokenCalibrationError> {
        let params = calibration_params();
        if snapshot.schema_version != TOKEN_CALIBRATION_SCHEMA_VERSION
            || snapshot.profiles.len() > params.max_route_profiles
            || snapshot.profiles.iter().any(|(key, profile)| {
                route_key_from_joined(key, params.max_route_id_bytes).is_err()
                    || !(params.min_ratio_ppm..=params.max_ratio_ppm).contains(&profile.ratio_ppm)
                    || !(params.ratio_scale..=params.max_ratio_ppm)
                        .contains(&profile.high_water_ratio_ppm)
                    || profile.stable_observations > profile.observations
            })
        {
            return Err(TokenCalibrationError::InvalidSnapshot);
        }
        Ok(Self {
            profiles: Arc::new(RwLock::new(snapshot.profiles)),
        })
    }
}

fn route_key(
    provider_id: &str,
    model_id: &str,
    max_route_id_bytes: usize,
) -> Result<String, TokenCalibrationError> {
    if provider_id.is_empty()
        || model_id.is_empty()
        || provider_id
            .len()
            .saturating_add(model_id.len())
            .saturating_add(1)
            > max_route_id_bytes
        || provider_id.contains('\0')
        || model_id.contains('\0')
    {
        return Err(TokenCalibrationError::InvalidRoute);
    }
    Ok(format!("{provider_id}\0{model_id}"))
}

fn route_key_from_joined(
    key: &str,
    max_route_id_bytes: usize,
) -> Result<(), TokenCalibrationError> {
    let Some((provider, model)) = key.split_once('\0') else {
        return Err(TokenCalibrationError::InvalidRoute);
    };
    route_key(provider, model, max_route_id_bytes).map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn actual_usage_updates_bounded_ewma_and_snapshot_round_trips() {
        let store = TokenCalibrationStore::default();
        let observation = store
            .observe_actual_input("provider", "model", 100, 120)
            .unwrap();
        assert_eq!(observation.ratio_ppm, 1_200_000);
        assert_eq!(store.calibrated_estimate("provider", "model", 100), 100);
        store
            .observe_actual_input("provider", "model", 100, 120)
            .unwrap();
        store
            .observe_actual_input("provider", "model", 100, 120)
            .unwrap();
        assert_eq!(store.calibrated_estimate("provider", "model", 100), 138);
        let restored = TokenCalibrationStore::restore(store.snapshot()).unwrap();
        assert_eq!(restored.calibrated_estimate("provider", "model", 100), 138);
    }

    #[test]
    fn drift_fails_conservative() {
        let store = TokenCalibrationStore::default();
        let observed = store
            .observe_actual_input("provider", "model", 100, 400)
            .unwrap();
        assert!(observed.drifted);
        assert_eq!(store.calibrated_estimate("provider", "model", 100), 400);
    }

    #[test]
    fn stable_overestimate_can_fall_with_a_safety_margin() {
        let store = TokenCalibrationStore::default();
        for _ in 0..3 {
            store
                .observe_actual_input("provider", "model", 100, 70)
                .unwrap();
        }
        let corrected = store.calibrated_estimate("provider", "model", 100);
        assert!(corrected < 100);
        assert!(corrected >= 70);
        assert_eq!(corrected, 81);
    }

    #[test]
    fn stable_fixture_keeps_p95_error_within_fifteen_percent() {
        let store = TokenCalibrationStore::default();
        for _ in 0..3 {
            store
                .observe_actual_input("provider", "model", 10_000, 7_000)
                .unwrap();
        }
        let mut relative_errors_ppm = (10_000u64..10_100)
            .map(|baseline| {
                let actual = baseline.saturating_mul(7).div_ceil(10);
                let estimate = store.calibrated_estimate("provider", "model", baseline);
                estimate
                    .abs_diff(actual)
                    .saturating_mul(TOKEN_CALIBRATION_WIRE.ratio_scale)
                    .div_ceil(actual)
            })
            .collect::<Vec<_>>();
        relative_errors_ppm.sort_unstable();
        let p95 = relative_errors_ppm[relative_errors_ppm.len() * 95 / 100];
        assert!(
            p95 <= 151_000,
            "p95 relative error was {p95} ppm (15% plus one-token integer rounding)"
        );
    }
}
