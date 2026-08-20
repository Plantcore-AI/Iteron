use super::*;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::path::{Component, Path};

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
                .insert(request.trial_id.clone(), request.as_ref().clone());
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
                    .average_agent_latency_ms
                    .is_some_and(|latency| !latency.is_finite() || latency < 0.0)
                || result
                    .average_cost_usd
                    .is_some_and(|cost| !cost.is_finite() || cost < 0.0)
                || result
                    .average_tokens
                    .is_some_and(|tokens| !tokens.is_finite() || tokens < 0.0)
                || !valid_digest(&result.manifest_digest)
            {
                return Err(invalid("observation does not match its issued trial"));
            }
            state.results.push(result.as_ref().clone());
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
        || !(1..=3).contains(&spec.schema_version)
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
    if spec.schema_version == 1 {
        if spec.param_registry_digest.is_some()
            || spec.tool_text_registry_digest.is_some()
            || spec.trainer_bridge.is_some()
        {
            return Err(TunerError::InvalidSpec(
                "schema v1 cannot carry universal trainer fields".into(),
            ));
        }
    } else {
        let bridge = spec
            .trainer_bridge
            .as_ref()
            .ok_or_else(|| TunerError::InvalidSpec("schema v2 requires trainer_bridge".into()))?;
        bridge
            .validate()
            .map_err(|error| TunerError::InvalidSpec(error.to_string()))?;
        if spec.param_registry_digest.as_deref()
            != Some(iteron_tunables::param_registry_digest_sha256().as_str())
            || spec.tool_text_registry_digest.as_deref()
                != Some(iteron_tunables::tool_text_registry_digest_sha256().as_str())
            || spec.train_dataset_digest != bridge.train.digest
            || spec.experiment_id != bridge.experiment_id
            || spec.max_trials > bridge.resources.max_trials
            || spec.max_concurrency > bridge.resources.max_concurrency
        {
            return Err(TunerError::InvalidSpec(
                "universal schema registry, dataset, or resource identity mismatch".into(),
            ));
        }
        if spec.schema_version == 3
            && (bridge.schema_version != crate::trainer_bridge::TRAINER_BRIDGE_SCHEMA_VERSION
                || spec.candidates.iter().any(|candidate| {
                    candidate.schema_version != CANDIDATE_GRAPH_SCHEMA_VERSION
                        || candidate.graph.as_ref().is_none_or(|graph| {
                            graph.experiment.dataset_sha256 != spec.train_dataset_digest
                        })
                }))
        {
            return Err(TunerError::InvalidSpec(
                "schema v3 requires candidate graphs bound to the training experiment".into(),
            ));
        }
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
        {
            return Err(TunerError::InvalidSpec(
                "invalid candidate identity or width".into(),
            ));
        }
        if spec.schema_version == 1 {
            if candidate.profile.is_some()
                || !candidate.implementations.is_empty()
                || candidate.graph.is_some()
                || candidate.values.len() > MAX_FAMILIES_PER_CANDIDATE
            {
                return Err(TunerError::InvalidSpec(
                    "schema v1 candidate must contain only bounded family values".into(),
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
        } else {
            if (spec.schema_version == 2
                && candidate.schema_version != LEGACY_UNIVERSAL_CANDIDATE_SCHEMA_VERSION)
                || (spec.schema_version == 3
                    && candidate.schema_version != CANDIDATE_GRAPH_SCHEMA_VERSION)
            {
                return Err(TunerError::InvalidSpec(
                    "tuner and candidate schema versions are incompatible".into(),
                ));
            }
            candidate.validate_universal()?;
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
        .then_with(|| match (left.average_tokens, right.average_tokens) {
            (Some(left), Some(right)) => left.partial_cmp(&right).unwrap_or(Ordering::Equal),
            (Some(_), None) => Ordering::Less,
            (None, Some(_)) => Ordering::Greater,
            (None, None) => Ordering::Equal,
        })
        .then_with(|| {
            match (
                left.average_agent_latency_ms,
                right.average_agent_latency_ms,
            ) {
                (Some(left), Some(right)) => left.partial_cmp(&right).unwrap_or(Ordering::Equal),
                (Some(_), None) => Ordering::Less,
                (None, Some(_)) => Ordering::Greater,
                (None, None) => left
                    .average_latency_ms
                    .partial_cmp(&right.average_latency_ms)
                    .unwrap_or(Ordering::Equal),
            }
        })
        .then_with(|| match (left.average_cost_usd, right.average_cost_usd) {
            (Some(left), Some(right)) => left.partial_cmp(&right).unwrap_or(Ordering::Equal),
            (Some(_), None) => Ordering::Less,
            (None, Some(_)) => Ordering::Greater,
            (None, None) => Ordering::Equal,
        })
        .then_with(|| left.candidate_id.cmp(&right.candidate_id))
}

pub(super) fn tpe_score(
    spec: &TunerSpec,
    candidate_id: &str,
    good: &[&TrialResult],
    bad: &[&TrialResult],
) -> f64 {
    let candidate = spec
        .candidates
        .iter()
        .find(|candidate| candidate.id == candidate_id)
        .expect("validated candidate");
    let values = candidate_features(candidate);
    values
        .iter()
        .map(|(address, token)| {
            let count = |rows: &[&TrialResult]| {
                rows.iter()
                    .filter(|row| {
                        spec.candidates
                            .iter()
                            .find(|candidate| candidate.id == row.candidate_id)
                            .and_then(|candidate| candidate_features(candidate).remove(address))
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

pub(super) fn validate_universal_candidate(candidate: &TunerCandidate) -> Result<(), TunerError> {
    if candidate.id.trim().is_empty()
        || candidate.id.len() > 128
        || candidate.id.chars().any(char::is_control)
    {
        return Err(TunerError::InvalidSpec(
            "invalid candidate identity or width".into(),
        ));
    }
    if candidate.schema_version == CANDIDATE_GRAPH_SCHEMA_VERSION {
        if !candidate.values.is_empty()
            || candidate.profile.is_some()
            || !candidate.implementations.is_empty()
        {
            return Err(TunerError::InvalidSpec(
                "schema v3 has one canonical graph; legacy fields must be empty".into(),
            ));
        }
        let graph = candidate
            .graph
            .as_ref()
            .ok_or_else(|| TunerError::InvalidSpec("schema v3 candidate needs a graph".into()))?;
        graph.validate(candidate)?;
        graph.materialize(candidate)?;
        return Ok(());
    }
    if candidate.schema_version != LEGACY_UNIVERSAL_CANDIDATE_SCHEMA_VERSION {
        return Err(TunerError::InvalidSpec(format!(
            "universal candidate schema must be 2 or {CANDIDATE_GRAPH_SCHEMA_VERSION}"
        )));
    }
    if candidate.graph.is_some() {
        return Err(TunerError::InvalidSpec(
            "schema v2 cannot carry a candidate graph".into(),
        ));
    }
    if !candidate.values.is_empty() {
        return Err(TunerError::InvalidSpec(
            "schema v2 has one address space; legacy values must be empty".into(),
        ));
    }
    let profile = candidate
        .profile
        .as_ref()
        .ok_or_else(|| TunerError::InvalidSpec("schema v2 candidate needs a profile".into()))?;
    iteron_tunables::validate_profile(profile)
        .map_err(|error| TunerError::InvalidSpec(error.to_string()))?;
    if profile.profile_id != candidate.id {
        return Err(TunerError::InvalidSpec(
            "candidate id must equal profile_id".into(),
        ));
    }
    let dimensions = profile
        .values
        .len()
        .saturating_add(profile.params.len())
        .saturating_add(profile.artifacts.len())
        .saturating_add(candidate.implementations.len());
    if dimensions == 0 || dimensions > MAX_UNIVERSAL_CANDIDATE_DIMENSIONS {
        return Err(TunerError::InvalidSpec(
            "universal candidate is empty or exceeds its dimension bound".into(),
        ));
    }
    for implementation in &candidate.implementations {
        validate_implementation_binding(implementation, profile.module_scope)?;
    }
    let modules = candidate
        .implementations
        .iter()
        .map(|implementation| implementation.module)
        .collect::<BTreeSet<_>>();
    let implementation_ids = candidate
        .implementations
        .iter()
        .map(|implementation| implementation.implementation_id.as_str())
        .collect::<BTreeSet<_>>();
    if modules.len() != candidate.implementations.len()
        || implementation_ids.len() != candidate.implementations.len()
    {
        return Err(TunerError::InvalidSpec(
            "invalid or duplicate implementation binding".into(),
        ));
    }
    Ok(())
}

fn candidate_features(candidate: &TunerCandidate) -> BTreeMap<String, String> {
    let mut features = candidate
        .values
        .iter()
        .filter_map(|(id, value)| {
            serde_json::to_string(value)
                .ok()
                .map(|value| (format!("family/{id}"), value))
        })
        .collect::<BTreeMap<_, _>>();
    if let Some(profile) = &candidate.profile {
        for value in &profile.values {
            if let Ok(token) = serde_json::to_string(&value.value) {
                features.insert(format!("family/{}", value.family), token);
            }
        }
        for assignment in &profile.params {
            if let Ok(token) = serde_json::to_string(&assignment.value) {
                features.insert(format!("param/{}", assignment.param), token);
            }
        }
        for artifact in &profile.artifacts {
            if let Ok(token) = serde_json::to_string(&artifact.text) {
                features.insert(format!("artifact/{}", artifact.artifact), token);
            }
        }
    }
    for implementation in &candidate.implementations {
        if let Ok(token) = serde_json::to_string(implementation) {
            features.insert(
                format!("implementation/{}", implementation.module.as_str()),
                token,
            );
        }
    }
    if let Some(graph) = &candidate.graph {
        for dimension in &graph.dimensions {
            if let Ok(token) = serde_json::to_string(dimension) {
                features.insert(format!("graph/{}", dimension.address().selector), token);
            }
        }
        for implementation in &graph.implementations {
            if let Ok(token) = serde_json::to_string(implementation) {
                features.insert(
                    format!("implementation/{}", implementation.module.as_str()),
                    token,
                );
            }
        }
    }
    features
}

pub(super) fn validate_implementation_binding(
    implementation: &CandidateImplementation,
    module_scope: Option<iteron_tunables::ModuleId>,
) -> Result<(), TunerError> {
    if !valid_identity(&implementation.implementation_id)
        || !matches!(
            implementation.protocol.as_str(),
            IMPLEMENTATION_PROTOCOL | LEGACY_IMPLEMENTATION_PROTOCOL
        )
        || !valid_source_path(&implementation.catalog_path)
        || !valid_source_path(&implementation.artifact_root)
        || !valid_digest(&implementation.manifest_sha256)
        || !valid_digest(&implementation.artifact_sha256)
    {
        return Err(TunerError::InvalidSpec(
            "invalid implementation binding".into(),
        ));
    }
    if module_scope.is_some_and(|scope| scope != implementation.module) {
        return Err(TunerError::InvalidSpec(
            "implementation is outside the candidate module scope".into(),
        ));
    }
    Ok(())
}

fn valid_identity(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= iteron_marketplace::MAX_IMPLEMENTATION_ID_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

pub(super) fn valid_digest(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|digest| {
        digest.len() == 64
            && digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

fn valid_source_path(value: &str) -> bool {
    let path = Path::new(value);
    !value.is_empty()
        && value.len() <= iteron_marketplace::MAX_IMPLEMENTATION_PATH_BYTES
        && !value.contains('\0')
        && path.is_absolute()
        && !path.components().any(|component| {
            matches!(
                component,
                Component::CurDir | Component::ParentDir | Component::Prefix(_)
            )
        })
}

pub(super) fn digest(value: &impl Serialize) -> Result<String, TunerError> {
    let bytes = serde_json::to_vec(value).map_err(|error| TunerError::Encode(error.to_string()))?;
    Ok(format!("sha256:{}", hex::encode(Sha256::digest(bytes))))
}

fn invalid(reason: &str) -> TunerError {
    TunerError::InvalidTransition(reason.into())
}
