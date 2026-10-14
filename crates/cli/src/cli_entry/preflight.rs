//! Launch validation and explicit operator profile installation before workspace/session IO.
use super::{Cli, tunables_surface_view};
use crate::{machine_contract, output, runtime_tunables, session_view};

pub(crate) struct ValidatedLaunch {
    pub(crate) machine_schema_version: u32,
    pub(crate) tunables_profile_document: Option<iteron_tunables::ProfileDocument>,
}
pub(crate) enum PreflightOutcome {
    Exit(u8),
    Run(ValidatedLaunch),
}
pub(crate) fn validate(cli: &Cli) -> anyhow::Result<PreflightOutcome> {
    if cli.implementation_candidate.is_some() {
        if cli.command.is_some()
            || cli.machine_contract
            || cli.tunables_export
            || cli.tunables_explain
            || cli.sessions
            || cli.transcript.is_some()
            || cli.otel_export.is_some()
            || cli.timeline.is_some()
            || cli.fork.is_some()
        {
            anyhow::bail!(
                "--implementation-candidate is available only to a research-profile agent run"
            );
        }
        let profile = cli
            .harness_profile
            .map(iteron_tunables::RuntimeProfile::from)
            .unwrap_or_else(|| {
                if cli.benchmark_attempt_scope.is_some() {
                    iteron_tunables::RuntimeProfile::Benchmark
                } else {
                    iteron_tunables::RuntimeProfile::Interactive
                }
            });
        if profile != iteron_tunables::RuntimeProfile::Research {
            anyhow::bail!("--implementation-candidate requires --harness-profile research");
        }
    }

    let machine_schema_version = cli
        .output_schema_version
        .unwrap_or(output::DEFAULT_SCHEMA_VERSION);
    if !output::SUPPORTED_SCHEMA_VERSIONS.contains(&machine_schema_version) {
        anyhow::bail!(
            "unsupported --output-schema-version {machine_schema_version}; supported versions: 4, 5, 6, 8"
        );
    }
    if cli.output_schema_version.is_some()
        && !cli.output_format.is_machine()
        && !cli.machine_contract
    {
        anyhow::bail!("--output-schema-version requires --output-format json or stream-json");
    }
    if cli.output_schema_version.is_some() && (cli.timeline.is_some() || cli.otel_export.is_some())
    {
        anyhow::bail!(
            "--output-schema-version applies to agent runs and schema-selected session operations"
        );
    }
    if cli.machine_contract {
        if cli.task.is_some()
            || cli.command.is_some()
            || cli.sessions
            || cli.transcript.is_some()
            || cli.otel_export.is_some()
            || cli.timeline.is_some()
            || cli.fork.is_some()
            || cli.resume.is_some()
            || cli.continue_recent
            || cli.tunables_export
            || cli.tunables_explain
            || cli.tunables_profile.is_some()
            || cli.tunables_profile_json.is_some()
            || cli.tunables_profile_digest.is_some()
            || !cli.set_tunable.is_empty()
            || cli.emit_tunables_profile.is_some()
        {
            anyhow::bail!("--machine-contract is a standalone capability query");
        }
        println!("{}", machine_contract::render()?);
        return Ok(PreflightOutcome::Exit(output::EXIT_SUCCESS));
    }
    if let Some(tag) = cli.agent_definition_tag.as_deref() {
        session_view::validate_agent_definition_tag(tag)?;
    }
    let mut tunables_profile_document: Option<iteron_tunables::ProfileDocument> = None;
    if cli.tunables_export {
        print!(
            "{}",
            tunables_surface_view(
                cli.tunables_format,
                cli.tunables_module.as_deref(),
                cli.tunables_filter.as_deref(),
            )?
        );
        return Ok(PreflightOutcome::Exit(output::EXIT_SUCCESS));
    }
    {
        let loaded = runtime_tunables::adhoc::load(
            cli.tunables_profile.as_deref(),
            cli.tunables_profile_json.as_deref(),
            cli.tunables_profile_digest.as_deref(),
        )?;
        let origin = loaded.as_ref().map(|(_, origin)| *origin);
        let document = runtime_tunables::adhoc::apply_set_arguments(
            loaded.map(|(document, _)| document),
            &cli.set_tunable,
        )?;
        if let Some(document) = document {
            // An unpinned profile is legitimate for debugging and must never be mistaken for a
            // reproducible one, so it announces itself rather than being inferred from its absence
            // in the record.
            if !origin.is_some_and(runtime_tunables::adhoc::ProfileOrigin::is_pinned) {
                eprintln!(
                    "tunables: applying an UNPINNED ad-hoc profile ({} value(s), {} parameter(s), \
                     {} artifact(s)); this run is not byte-reproducible from a digest",
                    document.values.len(),
                    document.params.len(),
                    document.artifacts.len()
                );
            }
            let overrides = document
                .params
                .iter()
                .map(|assignment| (assignment.param.clone(), assignment.value.clone()))
                .collect::<Vec<_>>();
            if !overrides.is_empty() {
                let installed =
                    iteron_tunables::install_param_overrides(overrides).map_err(|error| {
                        anyhow::anyhow!("tier-2 parameter override refused: {error}")
                    })?;
                eprintln!("tunables: installed {installed} tier-2 parameter override(s)");
            }
            let family_overrides = document
                .values
                .iter()
                .map(|assignment| (assignment.family.clone(), assignment.value.clone()))
                .collect::<Vec<_>>();
            if !family_overrides.is_empty() {
                let installed = iteron_tunables::install_family_overrides(family_overrides)
                    .map_err(|error| anyhow::anyhow!("Tier-1 family override refused: {error}"))?;
                eprintln!("tunables: installed {installed} governed-family override(s)");
            }
            let artifact_overrides = document
                .artifacts
                .iter()
                .map(|artifact| (artifact.artifact.clone(), artifact.text.clone()))
                .collect::<Vec<_>>();
            if !artifact_overrides.is_empty() {
                let installed =
                    iteron_tunables::install_prompt_artifact_overrides(artifact_overrides)
                        .map_err(|error| {
                            anyhow::anyhow!("prompt artifact override refused: {error}")
                        })?;
                eprintln!("tunables: installed {installed} prompt artifact override(s)");
            }
            if cli.tunables_explain {
                print!("{}", runtime_tunables::adhoc::render_effect(&document));
                return Ok(PreflightOutcome::Exit(output::EXIT_SUCCESS));
            }
            tunables_profile_document = Some(document);
        }
    }
    if cli.tunables_explain {
        print!("{}", runtime_tunables::adhoc::render_noop_effect());
        return Ok(PreflightOutcome::Exit(output::EXIT_SUCCESS));
    }
    if let Some(path) = cli.emit_tunables_profile.as_deref() {
        // Emit what reproduces this run. With no profile loaded the document is empty, which is
        // the correct round-trip: an empty profile resolves to exactly the defaults this run used.
        let document =
            tunables_profile_document
                .clone()
                .unwrap_or_else(|| iteron_tunables::ProfileDocument {
                    schema_version: iteron_tunables::PROFILE_DOCUMENT_SCHEMA_VERSION,
                    profile_id: "emitted/effective".to_owned(),
                    registry_revision: iteron_tunables::REGISTRY_REVISION,
                    registry_digest: iteron_tunables::REGISTRY_DIGEST_SHA256.to_owned(),
                    param_registry_digest: Some(iteron_tunables::param_registry_digest_sha256()),
                    module_scope: None,
                    values: Vec::new(),
                    params: Vec::new(),
                    artifacts: Vec::new(),
                });
        let rendered = iteron_tunables::render_profile(&document)
            .map_err(|error| anyhow::anyhow!("rendering tunables profile: {error}"))?;
        std::fs::write(path, &rendered).map_err(|error| {
            anyhow::anyhow!("writing tunables profile {}: {error}", path.display())
        })?;
        eprintln!(
            "wrote {} (sha256 {})",
            path.display(),
            iteron_tunables::document_digest(&rendered)
        );
    }
    // Local maintenance subcommands predate the machine contract and keep human output. Session
    // list/transcript reads and fork now have explicit typed machine frames; no client needs to
    // couple to the private `.iteron/runs` layout (#77/#179).
    if cli.output_format.is_machine() && cli.command.is_some() {
        anyhow::bail!(
            "--output-format json/stream-json is not supported for local maintenance subcommands"
        );
    }
    if cli.session_cursor.is_some() && !cli.sessions {
        anyhow::bail!("--session-cursor requires --sessions");
    }
    if cli.transcript_cursor.is_some() && cli.transcript.is_none() {
        anyhow::bail!("--transcript-cursor requires --transcript RUN_ID");
    }
    if cli.agent_definition_tag.is_some()
        && (cli.transcript.is_some()
            || cli.otel_export.is_some()
            || cli.timeline.is_some()
            || cli.fork.is_some())
    {
        anyhow::bail!(
            "--agent-definition-tag applies to a fresh/resumed run or a --sessions filter; forks inherit it"
        );
    }
    if cli.timeline.is_some() && (cli.transcript.is_some() || cli.sessions) {
        anyhow::bail!("--timeline, --transcript and --sessions are separate reads; ask for one");
    }
    if cli.transcript.is_some() && cli.sessions {
        anyhow::bail!("--transcript and --sessions are separate reads; ask for one");
    }

    Ok(PreflightOutcome::Run(ValidatedLaunch {
        machine_schema_version,
        tunables_profile_document,
    }))
}
