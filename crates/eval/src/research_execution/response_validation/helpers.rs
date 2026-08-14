use super::*;

pub(super) fn command_valid(command: &AdapterCommand) -> Result<(), ResearchProtocolError> {
    for value in [&command.program, &command.cwd, &command.stdout_path] {
        path(value)?;
    }
    if !command.clear_environment
        || command.argv.len() > 128
        || command
            .argv
            .iter()
            .any(|arg| arg.len() > MAX_ARGUMENT || arg.contains('\0'))
        || !(1..=MAX_OUTPUT).contains(&command.stdout_limit_bytes)
        || !(1..=MAX_OUTPUT).contains(&command.stderr_limit_bytes)
        || !command
            .inherit_environment
            .windows(2)
            .all(|pair| pair[0] < pair[1])
        || command
            .inherit_environment
            .iter()
            .any(|name| CREDENTIALS.binary_search(&name.as_str()).is_err())
    {
        return invalid("adapter command");
    }
    let expected = BTreeMap::from([
        ("LANG".into(), "C.UTF-8".into()),
        ("LC_ALL".into(), "C.UTF-8".into()),
        ("NO_COLOR".into(), "1".into()),
        ("TZ".into(), "UTC".into()),
    ]);
    if command.environment != expected {
        return invalid("adapter command environment");
    }
    Ok(())
}

pub(super) fn path(value: &str) -> Result<(), ResearchProtocolError> {
    let path = Path::new(value);
    if value.len() > MAX_PATH
        || value.contains('\0')
        || !path.is_absolute()
        || path.components().any(|part| {
            matches!(
                part,
                Component::CurDir | Component::ParentDir | Component::Prefix(_)
            )
        })
    {
        return invalid("path");
    }
    Ok(())
}

pub(super) fn mode(mode: &str, run_id: &str) -> Result<bool, ResearchProtocolError> {
    if !matches!(mode, "dry_run" | "execute") {
        return invalid("execution_mode");
    }
    id(run_id, "run_id")?;
    Ok(mode == "execute")
}

pub(super) fn candidate(
    candidate_id: &str,
    candidate_sha256: &str,
    profile_sha256: &str,
) -> Result<(), ResearchProtocolError> {
    validate_candidate_id(candidate_id)?;
    candidate_digest(candidate_sha256)?;
    digest(profile_sha256, "profile_sha256")
}

pub(super) fn activation(
    digest_value: &Option<String>,
    count: u64,
) -> Result<(), ResearchProtocolError> {
    if count > iteron_tunables::ModuleId::ALL.len() as u64 || (count == 0) != digest_value.is_none()
    {
        return invalid("implementation activation identity");
    }
    if let Some(digest_value) = digest_value {
        digest(digest_value, "implementation_activation_sha256")?;
    }
    Ok(())
}

pub(super) fn graph_identity(
    identity: Option<&crate::tuner::CandidateGraphIdentity>,
) -> Result<(), ResearchProtocolError> {
    let Some(identity) = identity else {
        return Ok(());
    };
    if identity.schema_id != crate::tuner::CANDIDATE_GRAPH_SCHEMA_ID {
        return invalid("candidate graph schema");
    }
    candidate_digest(&identity.materialization_sha256)?;
    candidate_digest(&identity.experiment_sha256)?;
    candidate_digest(&identity.topology_sha256)
}

pub(super) fn validate_candidate_id(value: &str) -> Result<(), ResearchProtocolError> {
    if value.is_empty()
        || value.len() > 256
        || !value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(byte, b'-' | b'_' | b'.' | b'/' | b':' | b'@' | b'+')
        })
    {
        return invalid("candidate_id");
    }
    Ok(())
}

pub(super) fn candidate_digest(value: &str) -> Result<(), ResearchProtocolError> {
    let Some(digest_value) = value.strip_prefix("sha256:") else {
        return invalid("candidate_sha256");
    };
    digest(digest_value, "candidate_sha256")
}

pub(super) fn id(value: &str, name: &str) -> Result<(), ResearchProtocolError> {
    if value.is_empty()
        || value.len() > 256
        || !value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'@' | b'+')
        })
    {
        return invalid(name);
    }
    Ok(())
}

pub(super) fn digest(value: &str, name: &str) -> Result<(), ResearchProtocolError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return invalid(name);
    }
    Ok(())
}

pub(super) fn text(value: &str, max: usize, name: &str) -> Result<(), ResearchProtocolError> {
    if value.is_empty()
        || value.len() > max
        || value
            .chars()
            .any(|character| ['\0', '\n', '\r'].contains(&character))
    {
        return invalid(name);
    }
    Ok(())
}

pub(super) fn invalid<T>(name: &str) -> Result<T, ResearchProtocolError> {
    Err(ResearchProtocolError::InvalidField(name.into()))
}
