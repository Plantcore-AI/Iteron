//! `iteron` — the coding agent CLI. Point it at a repo, give it a task, watch it work.
//!
//! This is the first thin frontend adapter on the iteron (ADR-010): it constructs an `Op`,
//! wires the five collaborators, and streams events. A server frontend can follow without
//! touching the kernel.

pub use iteron_host::app_server;
pub use iteron_host::artifacts;
mod block;
mod cli_entry;
pub use iteron_host::client_effects;
pub use iteron_host::client_inventory;
mod commands;
pub use iteron_host::config;
mod editor;
pub use iteron_host::effective_config;
pub use iteron_host::environment;
pub use iteron_host::external_editor;
pub use iteron_host::file_input;
mod highlight;
pub use iteron_host::image_input;
mod iteron_workspace_hook;
mod keymap;
pub use iteron_host::keyword_trigger;
pub use iteron_host::machine_contract;
pub use iteron_host::machine_projection;
pub use iteron_host::maintenance;
mod markdown;
pub use iteron_host::mcp;
pub use iteron_host::model_route;
pub use iteron_host::output;
mod paste_input;
pub use iteron_host::plugin;
pub use iteron_host::plugin_runtime;
pub use iteron_host::pricing;
pub use iteron_host::prompt_history;
pub use iteron_host::providers;
pub use iteron_host::queue_policy;
pub use iteron_host::recording_provider;
mod render;
pub use iteron_host::resident_service;
pub use iteron_host::session_transcript;
// The published client-event vocabulary. Nothing in this binary consumes it yet: it is the
// payload contract #44 will put on a socket, landed first so the transport does not get to
// decide which of the four documented losses stands. Its round trips are covered by tests.
// The composition root's evolve -> agents bundle projection. Nothing in this binary boots
// against it yet; it is the seam #28 declares, with its two-boot behavioural diff covered
// by tests.
pub use iteron_host::bundle_adapter;
pub use iteron_host::client_event;
pub use iteron_host::route;
pub use iteron_host::runtime;
pub use iteron_host::runtime_tunables;
mod semantic_text;
pub use iteron_host::session_isolation;
pub use iteron_host::session_view;
pub use iteron_host::setup;
pub use iteron_host::startup;
mod surface;
mod theme;
mod tui;
pub use iteron_host::tunables;
mod workflow;
pub use iteron_host::workspace_review;

use clap::Parser;

// Windows starts the main thread with the executable's default stack. Passing a large async
// value into Tokio still constructs/moves that value before Tokio can box it. Keep construction
// of the measured large launch futures in separate frames, then retain only their heap pointers
// in the caller. The factory must accept a constructor, not an already constructed future.
#[cfg(windows)]
#[inline(never)]
fn boxed_startup_future<F: std::future::Future>(
    construct: impl FnOnce() -> F,
) -> std::pin::Pin<Box<F>> {
    Box::pin(construct())
}

macro_rules! startup_future {
    ($future:expr) => {{
        #[cfg(windows)]
        {
            boxed_startup_future(|| $future)
        }
        #[cfg(not(windows))]
        {
            $future
        }
    }};
}

/// Enter the private confinement helper before creating threads, then admit one CLI launch.
fn main() -> std::process::ExitCode {
    // The confined file mutator must enter before Tokio creates any worker thread: Landlock is
    // inherited by threads created afterward, not retroactively imposed on an existing pool.
    // This private self-exec path has no CLI/config/provider initialization or recursive helper.
    let mut arguments = std::env::args_os().skip(1);
    if arguments.next().as_deref() == Some(std::ffi::OsStr::new("--internal-confined-write")) {
        if arguments.next().is_some() {
            eprintln!("error: internal confined write helper accepts no extra arguments");
            return std::process::ExitCode::from(output::EXIT_HARNESS);
        }
        std::process::exit(iteron_tools::confined_helper_entry());
    }
    if iteron_workspace_hook::invoked_as_workspace_hook() {
        return iteron_workspace_hook::main();
    }
    let result = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime.block_on(startup_future!(run_cli())),
        Err(error) => Err(error.into()),
    };
    match result {
        Ok(code) => std::process::ExitCode::from(code),
        Err(error) => {
            let error = iteron_record::redact::scrub(&format!("{error:#}"));
            eprintln!("error: {error}");
            std::process::ExitCode::from(output::EXIT_HARNESS)
        }
    }
}

async fn run_cli() -> anyhow::Result<u8> {
    if client_effects::worker_requested() {
        return Ok(client_effects::worker_main());
    }
    let startup = startup::StartupTiming::from_env();
    cli_entry::warn_if_stale();
    let cli = cli_entry::Cli::parse();
    let validated = match cli_entry::preflight::validate(&cli)? {
        cli_entry::preflight::PreflightOutcome::Exit(code) => return Ok(code),
        cli_entry::preflight::PreflightOutcome::Run(launch) => launch,
    };
    if let Some(code) = startup_future!(cli_entry::local_commands::machine(&cli)).await? {
        return Ok(code);
    }
    let repo = cli
        .repo
        .canonicalize()
        .map_err(|error| anyhow::anyhow!("repo {:?}: {error}", cli.repo))?;
    let runs_dir = cli_entry::resolve_runs_dir(&cli, &repo);
    if let Some(code) =
        startup_future!(cli_entry::local_commands::workspace(&cli, &repo, &runs_dir)).await?
    {
        return Ok(code);
    }
    if cli.sessions
        || cli.transcript.is_some()
        || cli.otel_export.is_some()
        || cli.timeline.is_some()
        || cli.fork.is_some()
    {
        let plantcore = matches!(
            cli.command,
            Some(cli_entry::LocalCommand::Serve {
                plantcore: true,
                ..
            })
        );
        cli_entry::load_project_config(&repo, plantcore)?;
    }
    if let Some(code) = cli_entry::local_commands::history(
        &cli,
        &repo,
        &runs_dir,
        &iteron_protocol::TenantId::default(),
        validated.machine_schema_version,
    )? {
        return Ok(code);
    }
    match startup_future!(iteron_host::launch::assemble(cli, startup, validated)).await? {
        iteron_host::launch::AssemblyOutcome::Exit(code) => Ok(code),
        iteron_host::launch::AssemblyOutcome::Ready(launch) => {
            startup_future!(cli_entry::frontend::drive(launch)).await
        }
    }
}
