//! The QuickJS host: source transform, prelude injection, determinism, cancellation, and the
//! AsyncRuntime driver. This is the proven B4 spike pattern, promoted to a per-run engine (fresh
//! state, no statics), now threaded with the run's [`CancellationToken`] (B3) and [`Journal`] (B2).

use std::sync::Arc;

use rquickjs::{AsyncContext, AsyncRuntime, CatchResultExt, Promise};
use tokio_util::sync::CancellationToken;

use crate::bindings::{AgentEnv, RunState};
use crate::events::ProgressSink;
use crate::journal::Journal;
use crate::spawner::AgentSpawner;
use crate::task_dag::runtime::ExecutionLedger;
use crate::{AGENT_SPAWNER_PORT_VERSION, PROGRESS_SINK_PORT_VERSION, RunId, RunLimits, RunReport};
use crate::{EarlyStopQuorumPolicy, SchemaRetryPolicy, SpeculativeSiblingPolicy, TaskRetryPolicy};

const PRELUDE: &str = include_str!("prelude.js");

/// Wrap the meta-stripped body so top-level `await`/`return` are legal (review B1), and marshal the
/// return value out as a JSON string (any JS value -> serde_json::Value on the Rust side).
fn wrap_body(body: &str) -> String {
    format!(
        "globalThis.__run = async function() {{\n{body}\n}};\n__run().then(function(v){{ return JSON.stringify(v === undefined ? null : v); }});"
    )
}

/// Run one workflow to completion, returning a [`RunReport`] (value + stopped flag + cache metrics).
/// The whole JS engine lives on a current-thread `LocalSet`; each `agent()` bridges to a SEND child
/// on the surrounding multi-thread runtime. `cancel` aborts in-flight children and interrupts a sync
/// JS loop; on cancel the run resolves as `stopped`. `journal` provides the resume cache (B2).
///
/// Not `Send` (it holds the `!Send` `LocalSet`/QuickJS across awaits): the blocking `execute` path
/// awaits it directly, and `launch` drives it via `block_on` on a dedicated OS thread.
pub struct RunCoreRequest<'a> {
    pub script: &'a str,
    pub args: serde_json::Value,
    pub run_id: RunId,
    pub limits: RunLimits,
    pub early_stop_quorum: EarlyStopQuorumPolicy,
    pub speculative_siblings: SpeculativeSiblingPolicy,
    pub task_retry: TaskRetryPolicy,
    pub schema_retry: SchemaRetryPolicy,
    pub cancel: CancellationToken,
    pub journal: Arc<Journal>,
    pub task_dag: Arc<ExecutionLedger>,
    pub spawner: Arc<dyn AgentSpawner>,
    pub sink: Arc<dyn ProgressSink>,
}

pub async fn run_core(request: RunCoreRequest<'_>) -> anyhow::Result<RunReport> {
    let RunCoreRequest {
        script,
        args,
        run_id,
        limits,
        early_stop_quorum,
        speculative_siblings,
        task_retry,
        schema_retry,
        cancel,
        journal,
        task_dag,
        spawner,
        sink,
    } = request;
    if spawner.port_version() != AGENT_SPAWNER_PORT_VERSION {
        anyhow::bail!(
            "unsupported AgentSpawner port version {}; expected {}",
            spawner.port_version(),
            AGENT_SPAWNER_PORT_VERSION
        );
    }
    if sink.port_version() != PROGRESS_SINK_PORT_VERSION {
        anyhow::bail!(
            "unsupported ProgressSink port version {}; expected {}",
            sink.port_version(),
            PROGRESS_SINK_PORT_VERSION
        );
    }
    let body = crate::meta::strip_meta(script);
    let code = wrap_body(&body);
    let args_js = format!(
        "globalThis.args = {};",
        serde_json::to_string(&args).unwrap_or_else(|_| "null".into())
    );

    let gov = iteron_sched::Governor::new(limits.max_concurrency());
    // Keep a handle to the token for the post-run `stopped` check; the rest moves into the JS driver.
    let report_cancel = cancel.clone();
    // The run clock + the per-run metric accumulator both outlive the JS driver, so the report can
    // carry real totals instead of only cache counters.
    let run_started = std::time::Instant::now();
    let state = Arc::new(RunState::new(limits.max_agent_calls(), early_stop_quorum));
    let report_state = state.clone();
    let report_task_dag = task_dag.clone();
    let env = Arc::new(AgentEnv {
        state,
        spawner,
        sink,
        gov,
        cancel: cancel.clone(),
        journal: journal.clone(),
        task_dag,
        speculative_siblings,
        task_retry,
        schema_retry,
    });

    // A LocalSet lets the `!Send` QuickJS runtime run on the current thread while `tokio::spawn`
    // children still land on the shared multi-thread runtime. `run_until` returns when the workflow
    // future resolves (the abandoned `drive()` task is fine).
    let local = tokio::task::LocalSet::new();
    let out: anyhow::Result<String> = local
        .run_until(async move {
            let rt = AsyncRuntime::new()?;

            // Interrupt handler (B3): poll the cancel token so a tight synchronous JS loop breaks.
            // Returns true -> QuickJS throws an uncatchable interrupt and unwinds the script.
            let interrupt_token = cancel.clone();
            rt.set_interrupt_handler(Some(Box::new(move || interrupt_token.is_cancelled())))
                .await;

            let ctx = AsyncContext::full(&rt).await?;

            let driver = rt.clone();
            tokio::task::spawn_local(async move { driver.drive().await });

            // rquickjs 0.12 deprecates `async_with!` now that async closures are stable; the macro
            // expanded to exactly this call, so the borrow of `env`/`args_js`/`code` is unchanged.
            let result: anyhow::Result<String> = AsyncContext::async_with(&ctx, async |ctx| {
                crate::bindings::install(&ctx, &env)
                    .map_err(|error| anyhow::anyhow!("install host fns: {error}"))?;
                ctx.eval::<(), _>(PRELUDE)
                    .catch(&ctx)
                    .map_err(|error| anyhow::anyhow!("prelude: {error}"))?;
                ctx.eval::<(), _>(args_js.as_bytes())
                    .catch(&ctx)
                    .map_err(|error| anyhow::anyhow!("args injection: {error}"))?;
                let promise: Promise = ctx
                    .eval(code.as_bytes())
                    .catch(&ctx)
                    .map_err(|error| anyhow::anyhow!("script eval: {error}"))?;
                let json: String = promise
                    .into_future::<String>()
                    .await
                    .catch(&ctx)
                    .map_err(|error| anyhow::anyhow!("workflow run: {error}"))?;
                Ok(json)
            })
            .await;

            rt.idle().await;
            result
        })
        .await;

    // QuickJS may drop an in-flight host future while unwinding a cancellation interrupt. Reconcile
    // the controller ledger before returning so no physical attempt is silently left running.
    report_task_dag
        .reconcile_nonterminal()
        .await
        .map_err(|error| anyhow::anyhow!("workflow task-DAG reconciliation failed: {error}"))?;

    journal
        .flush()
        .map_err(|error| anyhow::anyhow!("workflow journal durability failed: {error}"))?;
    let stopped = report_cancel.is_cancelled();
    let value = match out {
        Ok(json) => {
            serde_json::from_str::<serde_json::Value>(&json).unwrap_or(serde_json::Value::Null)
        }
        // A cancel-driven interrupt surfaces as an error; that is a `stopped` run, not a failure.
        Err(_) if stopped => serde_json::Value::Null,
        Err(error) => return Err(error),
    };
    // When stopped mid-flight, the partial JS value is meaningless — resolve as a stopped run.
    let value = if stopped {
        serde_json::Value::Null
    } else {
        value
    };

    let (errors, tokens, tool_calls) = report_state.totals();
    Ok(RunReport {
        run_id,
        value,
        stopped,
        cache_hits: journal.hits(),
        cache_misses: journal.misses(),
        errors,
        tokens,
        tool_calls,
        elapsed_ms: run_started.elapsed().as_millis() as u64,
    })
}
