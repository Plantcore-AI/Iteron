//! The QuickJS host: source transform, prelude injection, determinism, cancellation, and the
//! AsyncRuntime driver. This is the proven B4 spike pattern, promoted to a per-run engine (fresh
//! state, no statics), now threaded with the run's [`CancellationToken`] (B3) and [`Journal`] (B2).

use std::sync::Arc;

use rquickjs::{AsyncContext, AsyncRuntime, CatchResultExt, Promise, async_with};
use tokio_util::sync::CancellationToken;

use crate::bindings::{AgentEnv, RunState};
use crate::events::ProgressSink;
use crate::journal::Journal;
use crate::spawner::AgentSpawner;
use crate::{RunId, RunReport};

const PRELUDE: &str = include_str!("prelude.js");

/// The one global slot pool cap: `max(1, min(16, cores - 2))` (design §2.4).
fn concurrency_cap() -> usize {
    let cores = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4);
    cores.saturating_sub(2).min(16).max(1)
}

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
pub async fn run_core(
    script: &str,
    args: serde_json::Value,
    run_id: RunId,
    cancel: CancellationToken,
    journal: Arc<Journal>,
    spawner: Arc<dyn AgentSpawner>,
    sink: Arc<dyn ProgressSink>,
) -> anyhow::Result<RunReport> {
    let body = crate::meta::strip_meta(script);
    let code = wrap_body(&body);
    let args_js = format!(
        "globalThis.args = {};",
        serde_json::to_string(&args).unwrap_or_else(|_| "null".into())
    );

    let gov = core_sched::Governor::new(concurrency_cap());
    // Keep a handle to the token for the post-run `stopped` check; the rest moves into the JS driver.
    let report_cancel = cancel.clone();
    let env = Arc::new(AgentEnv {
        state: Arc::new(RunState::new()),
        spawner,
        sink,
        gov,
        cancel: cancel.clone(),
        journal: journal.clone(),
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

            let result: anyhow::Result<String> = async_with!(ctx => |ctx| {
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

    journal.flush();
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

    Ok(RunReport {
        run_id,
        value,
        stopped,
        cache_hits: journal.hits(),
        cache_misses: journal.misses(),
    })
}
