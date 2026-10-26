//! Independent AppServer launch and transport ownership.

use crate::cli_entry::{Cli, LocalCommand};
use crate::launch::{AssemblyOutcome, FrontendLaunch};

// Keep both large nested futures out of the caller's Windows default-stack frame. Receiving a
// constructor is necessary: receiving the future would construct it before the boxing boundary.
#[cfg(windows)]
#[inline(never)]
fn boxed_startup_future<F: std::future::Future>(
    construct: impl FnOnce() -> F,
) -> std::pin::Pin<Box<F>> {
    Box::pin(construct())
}

/// Admit exactly one server launch through the shared runtime assembly.
pub async fn run(options: Cli) -> anyhow::Result<u8> {
    if !matches!(options.command, Some(LocalCommand::Serve { .. })) {
        anyhow::bail!("the AppServer host requires server launch options");
    }
    let startup = crate::startup::StartupTiming::from_env();
    let validated = match crate::cli_entry::preflight::validate(&options)? {
        crate::cli_entry::preflight::PreflightOutcome::Exit(code) => return Ok(code),
        crate::cli_entry::preflight::PreflightOutcome::Run(launch) => launch,
    };
    #[cfg(windows)]
    let assembled =
        boxed_startup_future(|| crate::launch::assemble(options, startup, validated)).await?;
    #[cfg(not(windows))]
    let assembled = crate::launch::assemble(options, startup, validated).await?;
    match assembled {
        AssemblyOutcome::Exit(code) => Ok(code),
        AssemblyOutcome::Ready(launch) => {
            #[cfg(windows)]
            {
                boxed_startup_future(|| serve(*launch)).await
            }
            #[cfg(not(windows))]
            {
                serve(*launch).await
            }
        }
    }
}

/// The CLI compatibility command and independent process attach the same resident Agent.
pub async fn serve(launch: FrontendLaunch) -> anyhow::Result<u8> {
    let FrontendLaunch {
        agent,
        cli,
        selected_api_root: _selected_api_root,
        recording_app_server_fault,
        diagnostic_drain,
        ..
    } = launch;
    let Some(LocalCommand::Serve {
        listen,
        plantcore,
        client_approvals,
        ..
    }) = cli.command
    else {
        anyhow::bail!("the AppServer transport requires a server launch");
    };
    if let Some(fault) = recording_app_server_fault {
        fault.consume_marker()?;
    }
    #[cfg(feature = "legacy-plantcore")]
    let attached = if plantcore {
        crate::app_server::attach_plantcore(agent, false, true, _selected_api_root)?
    } else {
        crate::app_server::attach_remote(agent, true, client_approvals)?
    };
    #[cfg(not(feature = "legacy-plantcore"))]
    let attached = {
        if plantcore || recording_app_server_fault.is_some() {
            anyhow::bail!("legacy resident transport is unavailable in standalone Iteron");
        }
        crate::app_server::attach_remote(agent, true, client_approvals)?
    };
    crate::transport::headless::serve(attached, listen, plantcore, recording_app_server_fault)
        .await?;
    diagnostic_drain.flush();
    Ok(crate::output::EXIT_SUCCESS)
}
