use crate::resolution_types::{
    EvidenceState, EvidenceSubject, MAX_ACTIVATION_EVIDENCE, MAX_CATALOG_VALUES, MAX_CATALOGS,
    MAX_CONSTRAINTS, MAX_DECLARED_VALUES, MAX_DEFAULT_EVIDENCE, MAX_ID_BYTES, MAX_PROFILE_VALUES,
    MAX_ROUTES, RESOLUTION_INPUT_MAX_BYTES, ResolutionInput, ResolutionValue,
};

pub(super) fn preflight(input: &ResolutionInput) -> Result<(), String> {
    bounded_len(
        input.declared_values.len(),
        MAX_DECLARED_VALUES,
        "declared values",
    )?;
    bounded_len(
        input.default_evidence.len(),
        MAX_DEFAULT_EVIDENCE,
        "default evidence",
    )?;
    bounded_len(
        input.activation_evidence.len(),
        MAX_ACTIVATION_EVIDENCE,
        "activation evidence",
    )?;
    bounded_len(
        input.constraint_evidence.len(),
        MAX_CONSTRAINTS,
        "constraints",
    )?;
    bounded_len(input.runtime.admitted_routes.len(), MAX_ROUTES, "routes")?;
    bounded_len(input.runtime.catalogs.len(), MAX_CATALOGS, "catalogs")?;
    if let Some(profile) = &input.profile {
        bounded_len(profile.values.len(), MAX_PROFILE_VALUES, "profile values")?;
    }

    let mut budget = InputBudget::default();
    budget.add_text(&input.registry_id)?;
    budget.add_text(&input.registry_digest)?;
    if let Some(profile) = &input.profile {
        budget.add_text(&profile.profile_id)?;
        budget.add_text(&profile.registry_digest)?;
        for value in &profile.values {
            budget.add_text(&value.family)?;
            budget.add_value(&value.value)?;
        }
    }
    for value in &input.declared_values {
        budget.add_text(&value.family)?;
        budget.add_digest(&value.evidence_digest_sha256)?;
        budget.add_value(&value.value)?;
    }
    for evidence in &input.default_evidence {
        budget.add_text(&evidence.family)?;
        budget.add_text(&evidence.resolver_id)?;
        budget.add_digest(&evidence.evidence_digest_sha256)?;
        budget.add_subject(&evidence.subject)?;
        match &evidence.state {
            EvidenceState::Present { value } => budget.add_value(value)?,
            EvidenceState::Absent { code } | EvidenceState::Unsupported { code } => {
                budget.add_machine_id(code)?;
            }
        }
    }
    for evidence in &input.activation_evidence {
        budget.add_machine_id(&evidence.family)?;
        budget.add_machine_id(&evidence.seam)?;
        budget.add_digest(&evidence.subject_digest_sha256)?;
        budget.add_digest(&evidence.evidence_digest_sha256)?;
    }
    for evidence in &input.constraint_evidence {
        budget.add_text(&evidence.family)?;
        budget.add_text(&evidence.field)?;
        budget.add_digest(&evidence.evidence_digest_sha256)?;
        budget.add_subject(&evidence.subject)?;
        budget.add_constraint(&evidence.value)?;
    }
    for route in &input.runtime.admitted_routes {
        budget.add_route(&route.route)?;
        budget.add_digest(&route.attestation_digest_sha256)?;
    }
    if let Some(route) = &input.runtime.selected_route {
        budget.add_route(route)?;
    }
    for catalog in &input.runtime.catalogs {
        budget.add_machine_id(&catalog.catalog_id)?;
        budget.add_digest(&catalog.digest_sha256)?;
        bounded_len(catalog.values.len(), MAX_CATALOG_VALUES, "catalog values")?;
        for value in &catalog.values {
            budget.add_text(value)?;
        }
    }
    let bytes = serde_json::to_vec(input).map_err(|_| "input encoding failed".to_owned())?;
    if bytes.len() > RESOLUTION_INPUT_MAX_BYTES {
        return Err("input exceeds the byte ceiling".into());
    }
    Ok(())
}

pub(super) fn safe_machine_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_ID_BYTES
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b':' | b'/' | b'+')
        })
}

fn bounded_len(actual: usize, maximum: usize, label: &str) -> Result<(), String> {
    if actual <= maximum {
        Ok(())
    } else {
        Err(format!("{label} exceed their declared ceiling"))
    }
}

#[derive(Default)]
struct InputBudget {
    bytes: usize,
    nodes: usize,
}

impl InputBudget {
    fn add(&mut self, bytes: usize, nodes: usize) -> Result<(), String> {
        self.bytes = self
            .bytes
            .checked_add(bytes)
            .ok_or_else(|| "input size overflow".to_owned())?;
        self.nodes = self
            .nodes
            .checked_add(nodes)
            .ok_or_else(|| "input node count overflow".to_owned())?;
        if self.bytes > RESOLUTION_INPUT_MAX_BYTES || self.nodes > RESOLUTION_INPUT_MAX_BYTES / 4 {
            return Err("input structural budget exceeded".into());
        }
        Ok(())
    }

    fn add_text(&mut self, value: &str) -> Result<(), String> {
        self.add(value.len(), 1)
    }

    fn add_machine_id(&mut self, value: &str) -> Result<(), String> {
        if !safe_machine_id(value) {
            return Err("input contains an invalid machine identifier".into());
        }
        self.add_text(value)
    }

    fn add_digest(&mut self, value: &str) -> Result<(), String> {
        if !crate::resolution_value::valid_sha256(value) {
            return Err("input contains an invalid sha256 digest".into());
        }
        self.add(64, 1)
    }

    fn add_route(&mut self, route: &crate::RouteIdentity) -> Result<(), String> {
        self.add_machine_id(&route.provider_id)?;
        self.add_machine_id(&route.model_id)?;
        self.add_machine_id(&route.route_revision)?;
        self.add_digest(&route.catalog_digest_sha256)
    }

    fn add_subject(&mut self, subject: &EvidenceSubject) -> Result<(), String> {
        match subject {
            EvidenceSubject::Global => self.add(0, 1),
            EvidenceSubject::Operator {
                authority_digest_sha256,
            } => self.add_digest(authority_digest_sha256),
            EvidenceSubject::Route { route } => self.add_route(route),
            EvidenceSubject::RuntimeSeam {
                seam,
                subject_digest_sha256,
            } => {
                self.add_machine_id(seam)?;
                self.add_digest(subject_digest_sha256)
            }
            EvidenceSubject::Catalog {
                catalog_id,
                digest_sha256,
            } => {
                self.add_machine_id(catalog_id)?;
                self.add_digest(digest_sha256)
            }
        }
    }

    fn add_value(&mut self, value: &ResolutionValue) -> Result<(), String> {
        self.add_value_at(value, 0)
    }

    fn add_value_at(&mut self, value: &ResolutionValue, depth: u8) -> Result<(), String> {
        if depth > 32 {
            return Err("input value nesting exceeds the depth ceiling".into());
        }
        self.add(0, 1)?;
        match value {
            ResolutionValue::Text { value } | ResolutionValue::Enum { value } => {
                self.add_text(value)
            }
            ResolutionValue::List { items } => {
                bounded_len(items.len(), RESOLUTION_INPUT_MAX_BYTES / 4, "value items")?;
                let child_depth = depth
                    .checked_add(1)
                    .ok_or_else(|| "input value depth overflow".to_owned())?;
                items
                    .iter()
                    .try_for_each(|value| self.add_value_at(value, child_depth))
            }
            ResolutionValue::Map { entries } => {
                bounded_len(
                    entries.len(),
                    RESOLUTION_INPUT_MAX_BYTES / 4,
                    "value fields",
                )?;
                let child_depth = depth
                    .checked_add(1)
                    .ok_or_else(|| "input value depth overflow".to_owned())?;
                for (key, value) in entries {
                    self.add_text(key)?;
                    self.add_value_at(value, child_depth)?;
                }
                Ok(())
            }
            ResolutionValue::Object { fields } => {
                bounded_len(fields.len(), RESOLUTION_INPUT_MAX_BYTES / 4, "value fields")?;
                let child_depth = depth
                    .checked_add(1)
                    .ok_or_else(|| "input value depth overflow".to_owned())?;
                for (key, value) in fields {
                    self.add_text(key)?;
                    self.add_value_at(value, child_depth)?;
                }
                Ok(())
            }
            ResolutionValue::CatalogRef {
                catalog_id,
                digest_sha256,
                ..
            } => {
                self.add_machine_id(catalog_id)?;
                self.add_digest(digest_sha256)
            }
            ResolutionValue::Boolean { .. }
            | ResolutionValue::Integer { .. }
            | ResolutionValue::Decimal { .. } => Ok(()),
        }
    }

    fn add_constraint(
        &mut self,
        value: &crate::resolution_types::ConstraintValue,
    ) -> Result<(), String> {
        use crate::resolution_types::ConstraintValue;
        match value {
            ConstraintValue::UpperBound { value } | ConstraintValue::Exact { value } => {
                self.add_value(value)
            }
            ConstraintValue::Domain {
                minimum,
                maximum,
                allowed_values,
                required_values,
                preferred,
            } => {
                for value in minimum.iter().chain(maximum).chain(preferred) {
                    self.add_value(value)?;
                }
                for set in [allowed_values, required_values].into_iter().flatten() {
                    bounded_len(set.len(), MAX_CATALOG_VALUES, "constraint domain values")?;
                    for value in set {
                        self.add_value(value)?;
                    }
                }
                Ok(())
            }
        }
    }
}
