use super::KernelError;

pub(super) fn validate_route_identifier(
    field: &'static str,
    value: &str,
    max_bytes: usize,
    allow_empty: bool,
) -> Result<(), KernelError> {
    let valid_empty = allow_empty && value.is_empty();
    if (value.trim().is_empty() && !valid_empty)
        || value.len() > max_bytes
        || value.chars().any(char::is_control)
    {
        return Err(KernelError::InvalidRouteMetadata {
            field,
            reason: "must be non-empty, control-free, and within its byte bound",
        });
    }
    if iteron_record::redact::scrub_route_identifier(value) != value {
        return Err(KernelError::InvalidRouteMetadata {
            field,
            reason: "looks like a credential and cannot enter the durable route record",
        });
    }
    Ok(())
}

pub(super) fn validate_route_digest(field: &'static str, value: &str) -> Result<(), KernelError> {
    let valid = value
        .strip_prefix("sha256:")
        .is_some_and(|hex| hex.len() == 64 && hex.bytes().all(|byte| byte.is_ascii_hexdigit()));
    if !value.is_empty() && !valid {
        return Err(KernelError::InvalidRouteMetadata {
            field,
            reason: "must be empty or a sha256 digest",
        });
    }
    Ok(())
}

pub(super) fn validate_pricing_route_digest(
    field: &'static str,
    value: &str,
) -> Result<(), KernelError> {
    let valid = value
        .strip_prefix("sha256:")
        .is_some_and(|hex| hex.len() == 64 && hex.bytes().all(|byte| byte.is_ascii_hexdigit()));
    if !valid {
        return Err(KernelError::InvalidRouteMetadata {
            field,
            reason: "priced routes require a sha256 provenance digest",
        });
    }
    Ok(())
}

pub(super) fn replay_logical_rollout(
    path: &std::path::Path,
) -> Result<Vec<iteron_protocol::Event>, iteron_record::RecordError> {
    match (
        path.parent(),
        path.file_stem().and_then(|stem| stem.to_str()),
    ) {
        (Some(dir), Some(stem)) => {
            iteron_record::load_forked(dir, &iteron_protocol::RunId(stem.to_string()))
        }
        _ => iteron_record::replay(path),
    }
}

pub(super) fn replay_scoped_rollout(
    path: &std::path::Path,
) -> Result<Vec<iteron_record::ScopedEvent>, iteron_record::RecordError> {
    match (
        path.parent(),
        path.file_stem().and_then(|stem| stem.to_str()),
    ) {
        (Some(dir), Some(stem)) => {
            iteron_record::load_forked_scoped(dir, &iteron_protocol::RunId(stem.to_string()))
        }
        _ => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "rollout path has no run identity",
        )
        .into()),
    }
}
