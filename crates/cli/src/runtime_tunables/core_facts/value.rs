use super::*;

pub(super) fn instruction_discovery_value() -> Result<ResolutionValue, CoreFactError> {
    let owner = iteron_ctx::InstructionDiscoveryPolicy::owner();
    Ok(object([
        (
            "max_depth",
            int(i64u(owner.max_depth, "instruction_discovery_render")?),
        ),
        (
            "max_files",
            int(i64u(owner.max_files, "instruction_discovery_render")?),
        ),
        (
            "per_file_bytes",
            int(i64u(owner.per_file_bytes, "instruction_discovery_render")?),
        ),
        (
            "total_bytes",
            int(i64u(owner.total_bytes, "instruction_discovery_render")?),
        ),
    ]))
}

pub(super) fn verify_route(input: &CoreFactsInput<'_>) -> Result<(), CoreFactError> {
    (input.route.route.provider_id == input.selection.provider_id
        && input.route.route.model_id == input.selection.model_id)
        .then_some(())
        .ok_or(CoreFactError::RouteIdentityMismatch)
}

pub(super) fn declare(
    builder: &mut RuntimeResolutionBuilder,
    family: &str,
    origin: ConfigOrigin,
    value: ResolutionValue,
) -> Result<(), CoreFactError> {
    builder.declare(family, source(origin), value)?;
    Ok(())
}

/// Sample the immutable embedded owner before admitting an authorized override. A non-Builtin
/// source may narrow/replace according to its canonical merge policy; a Builtin value that differs
/// from the literal is deliberately sent through `declare` so the builder rejects the drift.
pub(super) fn literal_with_override(
    builder: &mut RuntimeResolutionBuilder,
    family: &str,
    literal: ResolutionValue,
    origin: ConfigOrigin,
    value: ResolutionValue,
) -> Result<(), CoreFactError> {
    builder.attest_literal_owner(family, literal.clone())?;
    if origin != ConfigOrigin::Builtin || value != literal {
        declare(builder, family, origin, value)?;
    }
    Ok(())
}

const fn source(origin: ConfigOrigin) -> SourceKind {
    match origin {
        ConfigOrigin::Cli => SourceKind::Cli,
        ConfigOrigin::Environment => SourceKind::Environment,
        ConfigOrigin::UserConfig => SourceKind::UserConfig,
        ConfigOrigin::ProjectConfig => SourceKind::ProjectConfig,
        ConfigOrigin::Builtin => SourceKind::Builtin,
    }
}

pub(super) fn rules(rules: &PermissionRules) -> Result<ResolutionValue, CoreFactError> {
    let mut entries = BTreeMap::new();
    for (capability, verdict) in rules.capability_rules() {
        entries.insert(
            format!("capability:{}", capability_name(capability)),
            en(verdict_name(verdict)),
        );
    }
    for (tool, verdict) in rules.tool_rules() {
        let key = format!("tool:{tool}");
        if key.len() > 96
            || !key.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b':' | b'/')
            })
        {
            return Err(CoreFactError::InvalidPermissionRuleKey);
        }
        entries.insert(key, en(verdict_name(verdict)));
    }
    if entries.len() > 256 {
        return Err(CoreFactError::InvalidPermissionRuleKey);
    }
    Ok(ResolutionValue::Map { entries })
}

const fn capability_name(capability: iteron_protocol::Capability) -> &'static str {
    match capability {
        iteron_protocol::Capability::ReadOnly => "read_only",
        iteron_protocol::Capability::ReversibleLocal => "reversible_local",
        iteron_protocol::Capability::CodeExecuting => "code_executing",
        iteron_protocol::Capability::TrustMutating => "trust_mutating",
        iteron_protocol::Capability::IrreversibleExternal => "irreversible_external",
    }
}

const fn verdict_name(verdict: Verdict) -> &'static str {
    match verdict {
        Verdict::Auto => "allow",
        Verdict::Ask => "ask",
        Verdict::Deny => "deny",
    }
}

pub(super) fn effort_reasoning_map() -> ResolutionValue {
    map(Effort::ALL.map(|effort| (effort.label(), en(effort.reasoning_effort().label()))))
}

pub(super) fn thinking_map() -> ResolutionValue {
    map(Effort::ALL.map(|effort| (effort.label(), int(effort.thinking_budget().into()))))
}

pub(super) fn orchestration_map() -> ResolutionValue {
    map(Effort::ALL.map(|effort| {
        (
            effort.label(),
            en(if effort.orchestrates() {
                "orchestrated"
            } else {
                "direct"
            }),
        )
    }))
}

pub(super) fn boolv(value: bool) -> ResolutionValue {
    ResolutionValue::Boolean { value }
}

pub(super) fn int(value: i64) -> ResolutionValue {
    ResolutionValue::Integer { value }
}

pub(super) fn dec(value: DecimalValue) -> ResolutionValue {
    ResolutionValue::Decimal { value }
}

pub(super) fn text(value: &str) -> ResolutionValue {
    ResolutionValue::Text {
        value: value.to_owned(),
    }
}

pub(super) fn en(value: &str) -> ResolutionValue {
    ResolutionValue::Enum {
        value: value.to_owned(),
    }
}

pub(super) fn text_list(values: &[String]) -> ResolutionValue {
    ResolutionValue::List {
        items: values.iter().map(|value| text(value)).collect(),
    }
}

pub(super) fn map<const N: usize>(values: [(&str, ResolutionValue); N]) -> ResolutionValue {
    ResolutionValue::Map {
        entries: values
            .into_iter()
            .map(|(key, value)| (key.to_owned(), value))
            .collect(),
    }
}

pub(super) fn object<const N: usize>(values: [(&str, ResolutionValue); N]) -> ResolutionValue {
    ResolutionValue::Object {
        fields: values
            .into_iter()
            .map(|(key, value)| (key.to_owned(), value))
            .collect(),
    }
}

pub(super) fn money(value: f64) -> Result<ResolutionValue, CoreFactError> {
    let scaled = value * 1_000_000.0;
    if !scaled.is_finite()
        || scaled < i64::MIN as f64
        || scaled > i64::MAX as f64
        || (scaled - scaled.round()).abs() > 1e-6
    {
        return Err(CoreFactError::MonetaryScaleLoss);
    }
    Ok(dec(DecimalValue {
        coefficient: scaled.round() as i64,
        scale: 6,
    }))
}

pub(super) fn i64v(value: u64, family: &'static str) -> Result<i64, CoreFactError> {
    i64::try_from(value).map_err(|_| CoreFactError::IntegerOverflow(family))
}

pub(super) fn i64u(value: usize, family: &'static str) -> Result<i64, CoreFactError> {
    i64::try_from(value).map_err(|_| CoreFactError::IntegerOverflow(family))
}

pub(super) fn upper(
    builder: &mut RuntimeResolutionBuilder,
    family: &str,
    field: &str,
    ceiling: ExternalCeiling,
    value: ResolutionValue,
) -> Result<(), CoreFactError> {
    builder.constrain(
        family,
        field,
        ceiling,
        ConstraintValue::UpperBound { value },
    )?;
    Ok(())
}

pub(super) fn operator_one(
    builder: &mut RuntimeResolutionBuilder,
    family: &str,
    value: ResolutionValue,
) -> Result<(), CoreFactError> {
    domain_one(
        builder,
        family,
        "$",
        ExternalCeiling::OperatorAuthority,
        value,
    )
}

pub(super) fn domain_one(
    builder: &mut RuntimeResolutionBuilder,
    family: &str,
    field: &str,
    ceiling: ExternalCeiling,
    value: ResolutionValue,
) -> Result<(), CoreFactError> {
    domain_many(builder, family, field, ceiling, [value])
}

pub(super) fn domain_many(
    builder: &mut RuntimeResolutionBuilder,
    family: &str,
    field: &str,
    ceiling: ExternalCeiling,
    values: impl IntoIterator<Item = ResolutionValue>,
) -> Result<(), CoreFactError> {
    builder.constrain(
        family,
        field,
        ceiling,
        ConstraintValue::Domain {
            minimum: None,
            maximum: None,
            allowed_values: Some(values.into_iter().collect()),
            required_values: None,
            preferred: None,
        },
    )?;
    Ok(())
}

pub(super) fn domain_min(
    builder: &mut RuntimeResolutionBuilder,
    family: &str,
    field: &str,
    ceiling: ExternalCeiling,
    value: ResolutionValue,
) -> Result<(), CoreFactError> {
    builder.constrain(
        family,
        field,
        ceiling,
        ConstraintValue::Domain {
            minimum: Some(value),
            maximum: None,
            allowed_values: None,
            required_values: None,
            preferred: None,
        },
    )?;
    Ok(())
}

pub(super) fn domain_max(
    builder: &mut RuntimeResolutionBuilder,
    family: &str,
    field: &str,
    ceiling: ExternalCeiling,
    value: ResolutionValue,
) -> Result<(), CoreFactError> {
    builder.constrain(
        family,
        field,
        ceiling,
        ConstraintValue::Domain {
            minimum: None,
            maximum: Some(value),
            allowed_values: None,
            required_values: None,
            preferred: None,
        },
    )?;
    Ok(())
}

fn owner_digest(label: &'static str, value: &impl Serialize) -> Result<String, CoreFactError> {
    let encoded =
        serde_json::to_vec(&(label, value)).map_err(|_| CoreFactError::EvidenceEncoding)?;
    Ok(hex::encode(Sha256::digest(encoded)))
}
