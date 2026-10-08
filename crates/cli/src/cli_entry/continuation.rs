//! Exclusive resume admission and route continuity from durable session truth.
//! Holds the original rollout writer lease until the composition transfers it into the runtime.
use super::provider_bootstrap::InitialRoute;
use super::{CLI_OVERRIDE_PROVIDER_ID, Cli, safe_agent_diagnostic};
use crate::{config, providers};
use iteron_protocol::{RunId, TenantId};
use iteron_record::Rollout;
use std::path::{Path, PathBuf};

pub(crate) struct Continuation {
    pub(crate) resume_id: Option<String>,
    pub(crate) resumed_run: Option<RunId>,
    pub(crate) locked_resume: Option<Rollout>,
    pub(crate) resolved_agent_definition_tag: Option<String>,
    pub(crate) resumed_tunables_checkpoint: Option<iteron_record::TunablesCheckpoint>,
    pub(crate) last_success_route_path: Option<PathBuf>,
    pub(crate) route_source: &'static str,
    pub(crate) route_fallback_reason: Option<String>,
    pub(crate) resumed_transcript_events:
        Option<iteron_protocol::session_navigation::SessionTranscriptV1>,
}
pub(crate) struct ResumeAdmission {
    pub(crate) initial: InitialRoute,
    pub(crate) continuation: Continuation,
}
pub(crate) fn admit(
    cli: &Cli,
    runs_dir: &Path,
    repo: &Path,
    tenant: &TenantId,
    initial: InitialRoute,
) -> anyhow::Result<ResumeAdmission> {
    let InitialRoute {
        mut provider_name,
        mut provider_origin,
        mut provider_was_explicit,
        configured_providers,
        mut requested_model,
        mut model_origin,
        provider_directory,
        recording_provider_transport,
        credential_env_names,
    } = initial;
    // Resolve continuation before provider/model selection so a resumed run inherits its last
    // durably recorded route. CLI/environment routing overrides remain authoritative; user/project
    // defaults do not silently reinterpret an existing session.
    let resume_id = cli.resume.clone().or_else(|| {
        if cli.continue_recent {
            match iteron_record::most_recent(&runs_dir, &repo, &tenant).map(|run| run.0) {
                Some(id) => {
                    eprintln!("continuing most recent session in this repo: {id}");
                    Some(id)
                }
                None => {
                    eprintln!("no session to continue in this repo; starting fresh");
                    None
                }
            }
        } else {
            None
        }
    });
    // Acquire the existing rollout's exclusive writer lock before reading any route or message
    // state. Holding this object through Agent construction makes resume one coherent snapshot:
    // another process cannot append between replay and the descriptor used for continuation.
    let resumed_run = resume_id.as_ref().map(|id| RunId(id.clone()));
    let locked_resume = match &resumed_run {
        Some(run) => Some(
            Rollout::open_existing(&runs_dir, run, tenant.clone())
                .map_err(|error| anyhow::anyhow!("cannot resume {run}: {error}"))?,
        ),
        None => None,
    };
    let mut resolved_agent_definition_tag = cli.agent_definition_tag.clone();
    let mut resumed_tunables_checkpoint = None;
    let last_success_route_path =
        config::config_home().map(|home| home.join(".iteron/cache/last-success-route-v1.json"));
    let mut route_source = if provider_was_explicit || requested_model.is_some() {
        "operator_config"
    } else {
        "versioned_default"
    };
    let mut route_fallback_reason: Option<String> = None;
    let mut resumed_transcript_events = None;
    if let Some(resume) = &resume_id {
        let scoped = iteron_record::bounded_replay::load_forked_scoped_bounded(
            &runs_dir,
            &RunId(resume.clone()),
            iteron_record::bounded_replay::ReplayReadLimits {
                physical_bytes: 64 * 1024 * 1024,
                hydrated_bytes: 64 * 1024 * 1024,
                events: 100_000,
            },
        )?;
        let projection = crate::session_transcript::project(&scoped);
        let recorded = scoped
            .into_iter()
            .map(|scoped| scoped.event)
            .collect::<Vec<_>>();
        resumed_tunables_checkpoint = Some(
            iteron_record::tunables_checkpoint_from_events(&recorded)?.ok_or_else(|| {
                anyhow::anyhow!(
                    "cannot resume {resume}: rollout has no immutable tunables checkpoint"
                )
            })?,
        );
        let recorded_agent_definition_tag = recorded.iter().find_map(|event| match &event.kind {
            iteron_protocol::EventKind::RunStart {
                agent_definition_tag,
                ..
            } => Some(agent_definition_tag.clone()),
            _ => None,
        });
        let recorded_agent_definition_tag = recorded_agent_definition_tag.flatten();
        if let Some(requested) = cli.agent_definition_tag.as_deref()
            && recorded_agent_definition_tag.as_deref() != Some(requested)
        {
            anyhow::bail!(
                "--agent-definition-tag cannot change on resume; omit it or repeat the recorded tag"
            );
        }
        resolved_agent_definition_tag = recorded_agent_definition_tag;
        let last_route = recorded.iter().rev().find_map(|event| match &event.kind {
            iteron_protocol::EventKind::ModelSelected {
                provider_id,
                model_id,
                ..
            } => Some((provider_id.clone(), model_id.clone())),
            _ => None,
        });
        if let Some((recorded_provider, recorded_model)) = last_route {
            route_source = "resumed_run";
            let provider_runtime_override = matches!(
                provider_origin,
                config::ConfigOrigin::Cli | config::ConfigOrigin::Environment
            );
            let model_runtime_override = matches!(
                model_origin,
                Some(config::ConfigOrigin::Cli | config::ConfigOrigin::Environment)
            );
            // A recorded route that no longer resolves is not a route. The one-run `--base-url`
            // id is the only synthetic name Core can write, so name it: adopting it silently
            // resurfaces "provider `cli-override` has no selectable discovered model" for a
            // provider the operator never typed.
            let recorded_is_unresolvable_override = recorded_provider == CLI_OVERRIDE_PROVIDER_ID
                && provider_directory.entry(&recorded_provider).is_none();
            if recorded_is_unresolvable_override {
                eprintln!(
                    "session {resume} ran against a one-run --base-url endpoint override, which is not part of this invocation; re-run with the same --base-url and --key-env to continue on that endpoint, or declare it as a named provider in ~/.iteron/config.json. Continuing on `{provider_name}`."
                );
            } else if !provider_runtime_override {
                provider_name = recorded_provider.clone();
                provider_origin = config::ConfigOrigin::UserConfig;
                provider_was_explicit = true;
            }
            if !recorded_is_unresolvable_override
                && !model_runtime_override
                && provider_name == recorded_provider
            {
                requested_model = Some(recorded_model);
                model_origin = Some(config::ConfigOrigin::UserConfig);
            }
        } else if !matches!(
            model_origin,
            Some(config::ConfigOrigin::Cli | config::ConfigOrigin::Environment)
        ) && let Some(legacy_model) =
            recorded.iter().find_map(|event| match &event.kind {
                iteron_protocol::EventKind::RunStart { model, .. } if !model.is_empty() => {
                    Some(model.clone())
                }
                _ => None,
            })
        {
            // Legacy records predate provider identity. Preserve their model but keep the trusted
            // current provider; never guess a cross-provider destination from the model name.
            requested_model = Some(legacy_model);
            model_origin = Some(config::ConfigOrigin::UserConfig);
        }
        resumed_transcript_events = Some(projection);
    }

    // With no operator or resume authority, prefer the last route that completed a real provider
    // turn, but only while both catalog and capability digests still validate. The snapshot is
    // content-free and never contains a credential. Invalid/stale state falls back visibly.
    if resume_id.is_none()
        && !provider_was_explicit
        && requested_model.is_none()
        && let Some(path) = last_success_route_path.as_deref()
    {
        match providers::LastSuccessRouteSnapshot::load_validated(path, &provider_directory) {
            Ok(Some(snapshot)) => {
                let prior = snapshot.selection();
                provider_name = prior.provider_id;
                requested_model = Some(prior.model_id);
                model_origin = Some(config::ConfigOrigin::Builtin);
                provider_was_explicit = true;
                route_source = "last_success";
            }
            Ok(None) => {
                route_fallback_reason = Some("no successful route snapshot".into());
            }
            Err(reason) => {
                route_fallback_reason = Some(safe_agent_diagnostic(&reason));
            }
        }
    }

    Ok(ResumeAdmission {
        initial: InitialRoute {
            provider_name,
            provider_origin,
            provider_was_explicit,
            configured_providers,
            requested_model,
            model_origin,
            provider_directory,
            recording_provider_transport,
            credential_env_names,
        },
        continuation: Continuation {
            resume_id,
            resumed_run,
            locked_resume,
            resolved_agent_definition_tag,
            resumed_tunables_checkpoint,
            last_success_route_path,
            route_source,
            route_fallback_reason,
            resumed_transcript_events,
        },
    })
}
