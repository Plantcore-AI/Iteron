use super::*;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

pub(super) fn initial_state(spec: &TunerSpec) -> TunerState {
    TunerState {
        round: 0,
        eligible: spec
            .candidates
            .iter()
            .map(|candidate| candidate.id.clone())
            .collect(),
        inflight: BTreeMap::new(),
        results: Vec::new(),
        selected: None,
        issued: 0,
    }
}

pub(super) fn apply_event(
    spec: &TunerSpec,
    state: &mut TunerState,
    event: &TunerEvent,
) -> Result<(), TunerError> {
    match event {
        TunerEvent::Initialized { .. } => return Err(invalid("duplicate initialization")),
        TunerEvent::TrialIssued { request } => {
            let expected_trial_id = format!("trial-{:04}", state.issued.saturating_add(1));
            let expected_candidate = spec
                .candidates
                .iter()
                .find(|candidate| candidate.id == request.candidate.id);
            if state.selected.is_some()
                || request.trial_id != expected_trial_id
                || request.round != state.round
                || request.budget != spec.round_budgets[usize::from(state.round)]
                || state.issued >= spec.max_trials
                || state.inflight.len() >= usize::from(spec.max_concurrency)
                || !state.eligible.contains(&request.candidate.id)
                || expected_candidate != Some(&request.candidate)
                || request.candidate_digest != digest(&request.candidate)?
                || state.inflight.contains_key(&request.trial_id)
                || state
                    .inflight
                    .values()
                    .any(|trial| trial.candidate.id == request.candidate.id)
                || state.results.iter().any(|result| {
                    result.trial_id == request.trial_id
                        || (result.round == state.round
                            && result.candidate_id == request.candidate.id)
                })
            {
                return Err(invalid("invalid trial issue"));
            }
            state.issued = state.issued.saturating_add(1);
            state
                .inflight
                .insert(request.trial_id.clone(), request.clone());
        }
        TunerEvent::TrialAbandoned { trial_id } => {
            if state.inflight.remove(trial_id).is_none() {
                return Err(invalid("only an in-flight trial can be abandoned"));
            }
        }
        TunerEvent::ObservationRecorded { result } => {
            let Some(request) = state.inflight.remove(&result.trial_id) else {
                return Err(invalid("observation trial is not in flight"));
            };
            if request.candidate.id != result.candidate_id
                || request.round != result.round
                || !result.resolved_rate.is_finite()
                || !(0.0..=1.0).contains(&result.resolved_rate)
                || !result.average_latency_ms.is_finite()
                || result.average_latency_ms < 0.0
                || result
                    .average_cost_usd
                    .is_some_and(|cost| !cost.is_finite() || cost < 0.0)
                || !valid_digest(&result.manifest_digest)
            {
                return Err(invalid("observation does not match its issued trial"));
            }
            state.results.push(result.clone());
        }
        TunerEvent::RoundAdvanced { round, survivors } => {
            let ranked = ranked_current(state);
            let expected = ranked.as_ref().map(|ranked| {
                ranked
                    .iter()
                    .take(ranked.len().div_ceil(usize::from(spec.reduction_factor)))
                    .map(|result| result.candidate_id.clone())
                    .collect::<Vec<_>>()
            });
            if *round != state.round.saturating_add(1)
                || usize::from(*round) >= spec.round_budgets.len()
                || survivors.is_empty()
                || !state.inflight.is_empty()
                || expected.as_ref() != Some(survivors)
            {
                return Err(invalid("invalid successive-halving transition"));
            }
            state.round = *round;
            state.eligible = survivors.clone();
        }
        TunerEvent::Completed { selected_candidate } => {
            let expected = ranked_current(state)
                .and_then(|ranked| ranked.first().map(|result| result.candidate_id.as_str()));
            if state.selected.is_some()
                || !state.inflight.is_empty()
                || usize::from(state.round) + 1 != spec.round_budgets.len()
                || expected != Some(selected_candidate.as_str())
            {
                return Err(invalid("invalid tuner completion"));
            }
            state.selected = Some(selected_candidate.clone());
        }
    }
    Ok(())
}

pub(super) fn validate_spec(spec: &TunerSpec) -> Result<(), TunerError> {
    let bytes = serde_json::to_vec(spec).map_err(|error| TunerError::Encode(error.to_string()))?;
    if bytes.len() > iteron_tunables::param_integer("eval.tuner.max_spec_bytes", MAX_SPEC_BYTES)
        || spec.schema_version != 1
        || spec.experiment_id.trim().is_empty()
        || spec.experiment_id.len() > 128
        || !valid_digest(&spec.train_dataset_digest)
        || spec.tunables_registry_digest != iteron_tunables::REGISTRY_DIGEST_SHA256
        || !(1..=iteron_tunables::param_integer("eval.tuner.max_tuner_trials", MAX_TUNER_TRIALS))
            .contains(&spec.max_trials)
        || !(1..=iteron_tunables::param_integer(
            "eval.tuner.max_tuner_concurrency",
            MAX_TUNER_CONCURRENCY,
        ))
            .contains(&spec.max_concurrency)
        || spec.max_concurrency > spec.max_trials
        || !(2..=8).contains(&spec.reduction_factor)
        || spec.round_budgets.is_empty()
        || spec.round_budgets.len() > 8
        || spec.round_budgets.contains(&0)
        || !spec.round_budgets.windows(2).all(|pair| pair[0] < pair[1])
        || spec.candidates.is_empty()
        || spec.candidates.len()
            > iteron_tunables::param_integer("eval.tuner.max_candidates", MAX_CANDIDATES)
    {
        return Err(TunerError::InvalidSpec(
            "bounded spec invariant failed".into(),
        ));
    }
    let registry = iteron_tunables::families()
        .iter()
        .map(|family| (family.id, family.optimization.class))
        .collect::<BTreeMap<_, _>>();
    let mut ids = BTreeSet::new();
    for candidate in &spec.candidates {
        if candidate.id.trim().is_empty()
            || candidate.id.len() > 128
            || candidate.id.chars().any(char::is_control)
            || !ids.insert(&candidate.id)
            || candidate.values.len() > MAX_FAMILIES_PER_CANDIDATE
        {
            return Err(TunerError::InvalidSpec(
                "invalid candidate identity or width".into(),
            ));
        }
        for family in candidate.values.keys() {
            match registry.get(family.as_str()) {
                Some(iteron_tunables::OptimizationClass::Pin) | None => {
                    return Err(TunerError::InvalidSpec(format!(
                        "family `{family}` is pinned or unknown"
                    )));
                }
                Some(_) => {}
            }
        }
        if candidate.values.values().any(serde_json::Value::is_null) {
            return Err(TunerError::InvalidSpec(
                "a present conditional value cannot be null; omit inactive families".into(),
            ));
        }
    }
    let mut round_count = spec.candidates.len();
    let mut required = 0_usize;
    for _ in &spec.round_budgets {
        required = required.saturating_add(round_count);
        round_count = round_count.div_ceil(usize::from(spec.reduction_factor));
    }
    if required > usize::from(spec.max_trials) {
        return Err(TunerError::InvalidSpec(format!(
            "successive-halving schedule needs {required} trials"
        )));
    }
    Ok(())
}

fn ranked_current(state: &TunerState) -> Option<Vec<&TrialResult>> {
    if !state.inflight.is_empty() {
        return None;
    }
    let mut ranked = state
        .results
        .iter()
        .filter(|result| result.round == state.round)
        .collect::<Vec<_>>();
    let ids = ranked
        .iter()
        .map(|result| result.candidate_id.as_str())
        .collect::<BTreeSet<_>>();
    if ranked.len() != state.eligible.len()
        || ids.len() != state.eligible.len()
        || state.eligible.iter().any(|id| !ids.contains(id.as_str()))
    {
        return None;
    }
    ranked.sort_by(result_order);
    Some(ranked)
}

pub(super) fn result_order(left: &&TrialResult, right: &&TrialResult) -> Ordering {
    right
        .resolved_rate
        .partial_cmp(&left.resolved_rate)
        .unwrap_or(Ordering::Equal)
        .then_with(|| match (left.average_cost_usd, right.average_cost_usd) {
            (Some(left), Some(right)) => left.partial_cmp(&right).unwrap_or(Ordering::Equal),
            (Some(_), None) => Ordering::Less,
            (None, Some(_)) => Ordering::Greater,
            (None, None) => Ordering::Equal,
        })
        .then_with(|| {
            left.average_latency_ms
                .partial_cmp(&right.average_latency_ms)
                .unwrap_or(Ordering::Equal)
        })
        .then_with(|| left.candidate_id.cmp(&right.candidate_id))
}

pub(super) fn tpe_score(
    spec: &TunerSpec,
    candidate_id: &str,
    good: &[&TrialResult],
    bad: &[&TrialResult],
) -> f64 {
    let values = &spec
        .candidates
        .iter()
        .find(|candidate| candidate.id == candidate_id)
        .expect("validated candidate")
        .values;
    values
        .iter()
        .map(|(family, value)| {
            let token = serde_json::to_string(value).unwrap_or_default();
            let count = |rows: &[&TrialResult]| {
                rows.iter()
                    .filter(|row| {
                        spec.candidates
                            .iter()
                            .find(|candidate| candidate.id == row.candidate_id)
                            .and_then(|candidate| candidate.values.get(family))
                            .and_then(|value| serde_json::to_string(value).ok())
                            .as_deref()
                            == Some(token.as_str())
                    })
                    .count() as f64
            };
            ((count(good) + 1.0) / (good.len() as f64 + 2.0)).ln()
                - ((count(bad) + 1.0) / (bad.len() as f64 + 2.0)).ln()
        })
        .sum()
}

fn valid_digest(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|digest| {
        digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit())
    })
}

pub(super) fn digest(value: &impl Serialize) -> Result<String, TunerError> {
    let bytes = serde_json::to_vec(value).map_err(|error| TunerError::Encode(error.to_string()))?;
    Ok(format!("sha256:{}", hex::encode(Sha256::digest(bytes))))
}

fn invalid(reason: &str) -> TunerError {
    TunerError::InvalidTransition(reason.into())
}
