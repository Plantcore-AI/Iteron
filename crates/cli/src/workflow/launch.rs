//! Directional launch/collect/cancel contract and in-turn engine adapter.

use super::progress::DegradedAgentSink;
use iteron_workflow::{AgentSpawner, ProgressSink, RunHandle, RunSpec, WorkflowEngine};
use std::path::PathBuf;
use std::sync::Arc;

/// Everything a workflow run needs in order to start, resolved inside the turn that asked for it.
///
/// Produced by `runtime.rs`'s `Agent::prepare_workflow` and consumed by a [`WorkflowLauncher`].
/// Preparation is where every check that must fail the `Workflow` tool call happens — an unreadable
/// `scriptPath`, an unbound route, an exhausted parent turn budget, an unwritable manifest — so a
/// value of this type is a run that has already been admitted and whose re-launchable sidecar is
/// already on disk under [`Self::workflows_dir`]. Nothing here has been started.
///
/// The three fields the engine consumes ([`Self::spec`], [`Self::spawner`], [`Self::sink`]) travel
/// with the four the caller still needs once the run exists — the run id and name for the launch
/// banner and the terminal sidecar, the declared phases that seed the live card's first frame, and
/// the [`DegradedAgentSink`] whose reasons are read after the run settles. A launcher that outlives
/// the turn will need exactly that second group too, which is why they are one value rather than a
/// tuple the launcher would have to re-derive.
pub struct PreparedWorkflow {
    /// The run's identity: its journal namespace, its sidecar directory name, and the correlation
    /// key of every [`super::projection::WorkflowRunUiEvent`] the live card renders.
    pub run_id: String,
    /// The script's declared `meta.name`, or `workflow` when it declared none.
    pub name: String,
    /// The script's declared `meta.phases`, so the card shows the shape of the run on frame one
    /// instead of growing it phase by phase.
    pub declared_phases: Vec<String>,
    /// The directory `iteron workflow list` enumerates. The manifest is already written into it.
    pub workflows_dir: PathBuf,
    /// The engine's run request: script, args, run id, workflows dir and aggregate limits.
    pub spec: RunSpec,
    /// The parent-derived spawner every `agent()` call is admitted through.
    pub spawner: Arc<dyn AgentSpawner>,
    /// The progress sink, already fanned out to the frontend when one is attached.
    pub sink: Arc<dyn ProgressSink>,
    /// The reasons agents resolved to JS `null`. Only meaningful after the run settles.
    pub degraded: Arc<DegradedAgentSink>,
    /// This run should outlive its turn. **True unless the model asked to wait**
    /// (`Workflow({background: false})`), because a workflow that holds the conversation open for
    /// its whole fan-out is the thing the supervisor exists to stop.
    ///
    /// A **request**, not a guarantee. Only a launcher that can own a run past the turn may honour
    /// it; [`InTurnWorkflowLauncher`] deliberately ignores it and runs in-turn, and the kernel says
    /// so in the tool result rather than pretending the run detached. That asymmetry is what keeps
    /// a run from ever being started by nobody: the request is granted only where an owner exists.
    pub background: bool,
}

/// What a [`WorkflowLauncher`] did with a [`PreparedWorkflow`] — the answer to "does this run
/// belong to the turn or to something that outlives it".
///
/// This is the S9 half of the S8 seam. S8 could only say *who starts* a run because the return type
/// was a bare handle and the kernel always joined it; a launcher that detaches has to be able to
/// say "do not join, and here is what to tell the model instead", which is exactly the two variants
/// below.
pub enum Launched {
    /// The run belongs to this turn. The kernel joins the handle, bridges its interrupt surfaces
    /// onto it, settles the card and returns the aggregated report to the model — byte-for-byte the
    /// behavior that existed before this variant did.
    InTurn(Arc<RunHandle>),
    /// The run belongs to a session-scoped owner that outlives this turn. The kernel does **not**
    /// join, does **not** settle the card and does **not** persist a terminal sidecar: all three are
    /// the owner's obligations now, because it is the only thing still holding the run.
    Detached(DetachedRun),
}

/// A run an owner took off the turn's hands.
pub struct DetachedRun {
    pub run_id: String,
    pub name: String,
    /// One sentence naming who owns the run and what ends it, written by the owner because the
    /// owner — not the kernel — decides the session-exit rule. It is rendered verbatim into the
    /// tool result, so the model is never told a lifetime the owner does not actually enforce.
    pub ownership: String,
}

/// What an owner knows about one of its runs, in the vocabulary the `Workflow` tool answers in.
///
/// Every variant is a complete, honest answer. There is deliberately no "maybe" and no silent
/// `None`: a `collect` that returned nothing would be indistinguishable from a lost result, which
/// is the one failure a detached run must not have.
pub enum Collected {
    /// This run id is not one this owner started (or nothing owns runs here at all).
    Unknown(String),
    /// The run exists and has not settled. `elapsed_ms` is wall-clock since launch.
    Running {
        run_id: String,
        name: String,
        elapsed_ms: u64,
    },
    /// The run settled. `summary` is the SAME string the in-turn path returns to the model, built
    /// by [`run_result_summary`] so a detached result and an in-turn result cannot drift. It names
    /// the run, which is why this variant carries no separate id.
    Settled { summary: String },
    /// The run ended without a report (the engine itself failed). Reported as a tool error.
    Failed { run_id: String, error: String },
}

/// Who starts a [`PreparedWorkflow`], and whether the turn is still holding it afterwards.
///
/// The `Workflow` tool prepares a run and then hands it here. This trait is the single point where
/// "who starts the run" and "who owns it once started" are decided, so a session-scoped owner can be
/// installed through `Agent::set_workflow_launcher` without the tool handler learning what a session
/// is.
///
/// Installing [`InTurnWorkflowLauncher`] — or installing nothing at all — is byte-for-byte the
/// behavior that existed before this trait: [`Launched::InTurn`], joined by the turn.
///
/// The handle is shared rather than owned because a detaching launcher must keep it: both
/// [`RunHandle::cancel`] and [`RunHandle::join`] take `&self`, so the turn's 25 ms interrupt poll and
/// an owner's later bookkeeping can hold the same run at once.
pub trait WorkflowLauncher: Send + Sync {
    fn launch(&self, prepared: PreparedWorkflow) -> Launched;

    /// Report on a run this owner started. Non-blocking on purpose: a `collect` that awaited would
    /// put the run back inside a turn, which is the thing detaching exists to stop.
    ///
    /// The default is the truth for every launcher that owns nothing past the turn.
    fn collect(&self, run_id: &str) -> Collected {
        Collected::Unknown(format!(
            "Workflow: run `{run_id}` is not owned by this session. Runs launched here complete \
             inside the turn that started them, so there is nothing to collect; \
             `iteron workflow list` shows every run on disk."
        ))
    }

    /// Stop a run this owner started. Same vocabulary as [`Self::collect`] so the tool has one
    /// answer shape; cancellation is a request, and the settled result is read by a later collect.
    fn cancel(&self, run_id: &str) -> Collected {
        self.collect(run_id)
    }
}

/// The default launcher: exactly [`WorkflowEngine::launch`], owned by nobody but its caller.
///
/// This is what the kernel uses when no launcher is installed, and it is what makes "no launcher"
/// and "the in-turn launcher" the same run.
pub struct InTurnWorkflowLauncher;

impl WorkflowLauncher for InTurnWorkflowLauncher {
    fn launch(&self, prepared: PreparedWorkflow) -> Launched {
        // `prepared.background` is ignored here, and that is the point: this launcher has no life
        // beyond the caller's stack frame, so honouring the request would leave the run owned by a
        // frame that is about to return. The kernel tells the model the request was not granted.
        Launched::InTurn(Arc::new(WorkflowEngine::launch(
            prepared.spec,
            prepared.spawner,
            prepared.sink,
        )))
    }
}

/// Start `prepared` through `launcher`, or through [`InTurnWorkflowLauncher`] when none is
/// installed.
///
/// The equivalence of those two arms is the property this slice rests on, so it lives here next to
/// the trait rather than being spelled out at the one call site: "no launcher installed" and "the
/// in-turn launcher installed" must remain the same run.
pub fn launch_prepared(
    launcher: Option<&Arc<dyn WorkflowLauncher>>,
    prepared: PreparedWorkflow,
) -> Launched {
    match launcher {
        Some(launcher) => launcher.launch(prepared),
        None => InTurnWorkflowLauncher.launch(prepared),
    }
}
