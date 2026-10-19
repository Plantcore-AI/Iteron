//! The resident memory fixture binds the real bounded byte envelope before atomic resolution.
use iteron_tunables::{ConstraintValue, ResolutionValue};

pub(super) fn install(input: &mut iteron_tunables::ResolutionInput, memory: iteron_ctx::MemBudget) {
    // Only the resident memory journey opts into real bounded materializer defaults.
    // The schema sampler's tiny byte fields cannot hold an actual record's framing.
    let value = ResolutionValue::Object {
        fields: [
            ("index_bytes", memory.index_bytes),
            ("recall_bytes", memory.recall_bytes),
            ("instruction_bytes", memory.instr_bytes),
            (
                "fact_bytes",
                iteron_tunables::param_usize(
                    "cli.runtime_tunables.core_facts.memory_fact_bytes",
                    8_000,
                ),
            ),
            ("total_bytes", memory.total),
        ]
        .into_iter()
        .map(|(field, bytes)| {
            (
                field.into(),
                ResolutionValue::Integer {
                    value: i64::try_from(bytes).unwrap(),
                },
            )
        })
        .collect(),
    };
    input
        .declared_values
        .iter_mut()
        .find(|row| row.family == "memory_budgets")
        .unwrap()
        .value = value.clone();
    for evidence in input
        .constraint_evidence
        .iter_mut()
        .filter(|row| row.family == "memory_budgets")
    {
        let ResolutionValue::Object { fields } = &value else {
            unreachable!()
        };
        let selected = if evidence.field == "$" {
            &value
        } else {
            fields
                .get(&evidence.field)
                .expect("actual memory budget field")
        };
        match &mut evidence.value {
            ConstraintValue::Domain {
                allowed_values,
                preferred,
                ..
            } => {
                *allowed_values = Some([selected.clone()].into_iter().collect());
                if preferred.is_some() {
                    *preferred = Some(selected.clone());
                }
            }
            ConstraintValue::Exact { value } | ConstraintValue::UpperBound { value } => {
                *value = selected.clone()
            }
        }
    }
}
