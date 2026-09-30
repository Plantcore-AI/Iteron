//! Actual bounded native session preparation, invoked by the single navigation task slot.
//! This bootstrap remains local until the trusted host factory takes ownership; it is never
//! callable from a public wire locator or from the model.
use super::{PreparationKind, PreparationSource};
use crate::providers::ModelSelection;
use crate::tui::{
    PreparedAdoption, PreparedAdoptionResult, app_server, recorded_route, ui_safe_text,
};

pub(super) fn prepare(source: PreparationSource) -> PreparedAdoptionResult {
    let PreparationSource {
        runs,
        directory,
        selection,
        kind,
    } = source;
    match kind {
        PreparationKind::Existing(worker_run_id) => {
            prepare_existing(runs, directory, selection, worker_run_id)
        }
        PreparationKind::Fresh => prepare_fresh(runs, directory, selection),
    }
}
fn prepare_existing(
    runs: std::path::PathBuf,
    directory: crate::providers::ProviderDirectory,
    current_selection: ModelSelection,
    worker_run_id: String,
) -> PreparedAdoptionResult {
    let run = iteron_protocol::RunId(worker_run_id.clone());
    let validated = iteron_protocol::thread_lifecycle::ThreadLifecycleCommandV1::Read {
        run_id: run.clone(),
    }
    .validate();
    if let Err(reason) = validated {
        return PreparedAdoptionResult::Failed {
            message: reason.into(),
            handoff_run: None,
        };
    }
    let events = match iteron_record::bounded_replay::load_forked_scoped_bounded(
        &runs,
        &run,
        iteron_record::bounded_replay::ReplayReadLimits {
            physical_bytes: 64 * 1024 * 1024,
            hydrated_bytes: 64 * 1024 * 1024,
            events: 100_000,
        },
    ) {
        Ok(events) => events
            .into_iter()
            .map(|scoped| scoped.event)
            .collect::<Vec<_>>(),
        Err(error) => {
            return PreparedAdoptionResult::Failed {
                message: format!(
                    "cannot read session {}: {error}",
                    ui_safe_text(&worker_run_id)
                ),
                handoff_run: None,
            };
        }
    };
    let recorded = recorded_route(&events);
    let (selection, built, substituted) = match &recorded {
        Some((Some(provider_id), model_id)) => {
            let candidate = ModelSelection {
                provider_id: provider_id.clone(),
                model_id: model_id.clone(),
            };
            match directory.build(&candidate) {
                Ok(provider) => (candidate, Some(provider), None),
                Err(error) => (
                    current_selection,
                    None,
                    Some(format!(
                        "the recorded route {provider_id}:{model_id} is not usable here ({error})"
                    )),
                ),
            }
        }
        Some((None, model_id)) => (
            current_selection,
            None,
            Some(format!(
                "this session predates provider identity and records only model `{model_id}`"
            )),
        ),
        None => (
            current_selection,
            None,
            Some("this session records no route".into()),
        ),
    };
    let provider = match built {
        Some(provider) => provider,
        None => match directory.build(&selection) {
            Ok(provider) => provider,
            Err(error) => {
                return PreparedAdoptionResult::Failed {
                    message: format!("cannot resume that session here: {error}"),
                    handoff_run: None,
                };
            }
        },
    };
    let rollout = match iteron_record::Rollout::open_existing(
        &runs,
        &run,
        iteron_protocol::TenantId::default(),
    ) {
        Ok(rollout) => rollout,
        Err(error) => {
            return PreparedAdoptionResult::Failed {
                message: format!(
                    "cannot take over session {}: {error}. Another iteron process may still be running it.",
                    ui_safe_text(&worker_run_id)
                ),
                handoff_run: Some(worker_run_id),
            };
        }
    };
    let (catalog_digest, capability_digest) = directory.selection_digests(&selection);
    let capabilities = directory.selection_capabilities(&selection);
    PreparedAdoptionResult::Ready(PreparedAdoption {
        fresh: false,
        control: app_server::Control::AdoptRun(Box::new(app_server::AdoptRun {
            rollout,
            fresh: false,
            route: Box::new(app_server::ModelSelection {
                provider,
                provider_id: selection.provider_id.clone(),
                model_id: selection.model_id.clone(),
                catalog_digest,
                capability_digest,
                context_window_tokens: capabilities.context_window_tokens,
                max_output_tokens: capabilities.max_output_tokens,
            }),
        })),
        run_id: worker_run_id,
        events,
        selection,
        substituted,
        context_window_tokens: capabilities.context_window_tokens,
    })
}
fn prepare_fresh(
    runs: std::path::PathBuf,
    directory: crate::providers::ProviderDirectory,
    selection: ModelSelection,
) -> PreparedAdoptionResult {
    let provider = match directory.build(&selection) {
        Ok(provider) => provider,
        Err(error) => {
            return PreparedAdoptionResult::Failed {
                message: format!("cannot create a session on the current route: {error}"),
                handoff_run: None,
            };
        }
    };
    let nanos = match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        Ok(duration) => duration.as_nanos(),
        Err(_) => {
            return PreparedAdoptionResult::Failed {
                message: "clock unavailable for new session identity".into(),
                handoff_run: None,
            };
        }
    };
    let run = iteron_protocol::RunId(format!("run-{}-{nanos}", std::process::id()));
    let rollout =
        match iteron_record::Rollout::open(&runs, &run, iteron_protocol::TenantId::default()) {
            Ok(rollout) => rollout,
            Err(error) => {
                return PreparedAdoptionResult::Failed {
                    message: format!("cannot create session: {error}"),
                    handoff_run: None,
                };
            }
        };
    let (catalog_digest, capability_digest) = directory.selection_digests(&selection);
    let capabilities = directory.selection_capabilities(&selection);
    PreparedAdoptionResult::Ready(PreparedAdoption {
        fresh: true,
        control: app_server::Control::AdoptRun(Box::new(app_server::AdoptRun {
            rollout,
            fresh: true,
            route: Box::new(app_server::ModelSelection {
                provider,
                provider_id: selection.provider_id.clone(),
                model_id: selection.model_id.clone(),
                catalog_digest,
                capability_digest,
                context_window_tokens: capabilities.context_window_tokens,
                max_output_tokens: capabilities.max_output_tokens,
            }),
        })),
        run_id: run.0,
        events: Vec::new(),
        selection,
        substituted: None,
        context_window_tokens: capabilities.context_window_tokens,
    })
}
