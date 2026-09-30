//! Instruction discovery and frontend route projection from already admitted immutable policy.
//! This owner cannot change authority or select another provider route.
use super::{SystemPromptAssembly, assemble_system_prompt, safe_agent_diagnostic};
use crate::{providers, route, runtime_tunables};

pub(crate) struct AdmittedView {
    pub(crate) base_system: String,
    pub(crate) instruction_bytes: String,
    pub(crate) instruction_trust: iteron_protocol::Trust,
    pub(crate) model: String,
    pub(crate) budget: iteron_protocol::Budget,
    pub(crate) route: route::RouteView,
}
pub(crate) struct ViewAdmissionInput<'a> {
    pub(crate) plantcore_serve: bool,
    pub(crate) home_core: Option<&'a std::path::Path>,
    pub(crate) repo: &'a std::path::Path,
    pub(crate) effective_settings: &'a runtime_tunables::effective_core::EffectiveCoreSettings,
    pub(crate) tunables_profile_document: &'a Option<iteron_tunables::ProfileDocument>,
    pub(crate) mcp_runtime: &'a crate::mcp::McpRuntimeControl,
    pub(crate) provider_directory: &'a providers::ProviderDirectory,
    pub(crate) selection: &'a providers::ModelSelection,
    pub(crate) route_source: &'a str,
    pub(crate) route_fallback_reason: &'a Option<String>,
    pub(crate) run: &'a iteron_protocol::RunId,
    pub(crate) provider_id: &'a str,
    pub(crate) runs_dir: &'a std::path::Path,
}
pub(crate) fn assemble(input: ViewAdmissionInput<'_>) -> anyhow::Result<AdmittedView> {
    let ViewAdmissionInput {
        plantcore_serve,
        home_core,
        repo,
        effective_settings,
        tunables_profile_document,
        mcp_runtime,
        provider_directory,
        selection,
        route_source,
        route_fallback_reason,
        run,
        provider_id,
        runs_dir,
    } = input;
    // Discovery happens only after the fresh atomic resolver result or historical checkpoint has
    // been decoded. A resumed run therefore cannot silently traverse/render with today's machine
    // defaults before learning the policy it originally pinned.
    let SystemPromptAssembly {
        base_system,
        instruction_bytes,
        instruction_trust,
        bundle: instruction_bundle,
    } = if plantcore_serve {
        SystemPromptAssembly {
            base_system: String::new(),
            instruction_bytes: String::new(),
            instruction_trust: iteron_protocol::Trust::Trusted,
            bundle: iteron_ctx::InstructionBundle::default(),
        }
    } else {
        assemble_system_prompt(
            home_core.as_deref(),
            &repo,
            &repo,
            effective_settings
                .context_materialization
                .instruction_discovery,
            tunables_profile_document.as_ref(),
        )
    };
    for source in instruction_bundle.sources() {
        eprintln!(
            "instructions: loaded `{}` (untrusted guidance)",
            source.source
        );
    }
    for rejection in instruction_bundle.rejections() {
        eprintln!(
            "instructions: REJECTED `{}`: {}",
            rejection.source, rejection.reason
        );
    }
    if instruction_bundle.omitted_sources() > 0 {
        eprintln!(
            "instructions: {} sources omitted at the discovery/render bounds",
            instruction_bundle.omitted_sources()
        );
    }
    eprintln!("{}", "-".repeat(72));
    let model = effective_settings.model_id.clone();
    mcp_runtime.configure(
        effective_settings.mcp,
        effective_settings.mcp_exposure.clone(),
    )?;
    let budget = effective_settings.budget.clone();
    let mut route = route::RouteView::resolve(
        &provider_directory,
        &selection,
        route::RouteLimits {
            max_turns: budget.max_turns,
            max_usd: budget.max_usd,
            max_tokens: budget.max_tokens,
            max_wall_secs: budget.max_wall_secs,
        },
    );
    route
        .catalog_provenance
        .push_str(&format!(" · route source {route_source}"));
    if let Some(reason) = route_fallback_reason.as_deref() {
        route
            .catalog_provenance
            .push_str(&format!(" · fallback {}", safe_agent_diagnostic(reason)));
    }
    eprintln!(
        "iteron · repo={} · model={} · run={}",
        repo.display(),
        model,
        run
    );
    eprintln!(
        "route: {}:{} · {} · {}",
        route.provider_id, route.model_id, route.api_root, route.credential
    );
    eprintln!("route source: {route_source}");
    if let Some(reason) = route_fallback_reason.as_deref() {
        eprintln!("route fallback: {}", safe_agent_diagnostic(reason));
    }
    if let Some(reason) = &route.blocked_reason {
        eprintln!("route blocked: {reason}");
    }
    eprintln!(
        "record: {}",
        runs_dir.join(format!("{run}.jsonl")).display()
    );

    Ok(AdmittedView {
        base_system,
        instruction_bytes,
        instruction_trust,
        model,
        budget,
        route,
    })
}
