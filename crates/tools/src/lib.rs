//! core-tools — the tool ABI and the concrete tools.
//!
//! The ABI's job is to make the design's type rules true *at registration*:
//!   - A `Pure` tool coupled with an egress capability is a registration error (ADR-007 R16).
//!   - Every tool declares its `Purity` and `Capability`, which the scheduler and policy read.
//!
//! Vertical-slice tools: read_file, list_dir, grep (Pure/ReadOnly), edit (Effecting/
//! ReversibleLocal, minimal structured diff with a uniqueness guard — Codex's first-match
//! patcher is a named defect), and bash (Effecting/CodeExecuting). The full egress-off
//! sandbox for bash is ADR-007's job and is stubbed here with an honest boundary: this crate
//! runs bash in-process for the slice; `sandbox` wraps it next.

use core_protocol::{Capability, Purity, ToolResult, ToolSpec, ToolUse, Trust};
use std::path::{Path, PathBuf};
use std::time::Instant;

mod edit;
mod fs_tools;
mod git;
mod mem;
mod shell;
mod skill;
mod web;

pub use edit::apply_unique_edit;

/// Shared hardened Git observation used by the registry tool and the operator `/diff` surface.
/// It remains an observable process effect; callers outside the registry must provide their own
/// operator/audit boundary.
pub async fn git_diff_observation(
    root: &Path,
    stat: bool,
    requested_path: Option<&str>,
) -> Result<String, String> {
    git::run_git_diff(root, stat, requested_path).await
}

#[derive(Debug, thiserror::Error)]
pub enum ToolError {
    #[error("registration: {0}")]
    Registration(String),
    #[error("unknown tool: {0}")]
    Unknown(String),
}

/// A boxed-future alias so the registry can hold heterogeneous async executors. Public so
/// external tool sources (e.g. the MCP client, wired by the CLI) can register their own tools.
pub mod boxfut {
    use core_protocol::ToolResult;
    use std::future::Future;
    use std::pin::Pin;
    pub type BoxFut = Pin<Box<dyn Future<Output = ToolResult> + Send>>;
    pub fn box_it(f: impl Future<Output = ToolResult> + Send + 'static) -> BoxFut {
        Box::pin(f)
    }
}

/// Certainty of an effecting executor attempt. `Definite` covers both success and a failure that
/// is known not to be an unresolved remote/partial outcome. `Unknown` means dispatch may have
/// happened but no authoritative terminal response was observed; the kernel must durably block
/// automatic replay instead of flattening it into `ToolResult::is_error`.
#[derive(Debug, Clone)]
pub enum ToolExecution {
    Definite(ToolResult),
    Unknown(ToolResult),
}

impl ToolExecution {
    fn result_mut(&mut self) -> &mut ToolResult {
        match self {
            Self::Definite(result) | Self::Unknown(result) => result,
        }
    }

    pub fn into_result(self) -> ToolResult {
        match self {
            Self::Definite(result) | Self::Unknown(result) => result,
        }
    }
}

impl From<ToolResult> for ToolExecution {
    fn from(result: ToolResult) -> Self {
        Self::Definite(result)
    }
}

/// Outcome-aware future used only by effect executors that can distinguish a durable terminal
/// from an externally unknown result (currently MCP). Ordinary tools use [`boxfut`] and are
/// conservatively adapted to `Definite` until their own effect family is brokered.
pub mod effectfut {
    use super::ToolExecution;
    use std::future::Future;
    use std::pin::Pin;
    pub type BoxFut = Pin<Box<dyn Future<Output = ToolExecution> + Send>>;
    pub fn box_it(f: impl Future<Output = ToolExecution> + Send + 'static) -> BoxFut {
        Box::pin(f)
    }
}

/// A registered tool: its spec plus its executor.
pub struct Tool {
    pub spec: ToolSpec,
    run: Box<dyn Fn(ToolUse, PathBuf) -> effectfut::BoxFut + Send + Sync>,
}

/// The tool registry. Enforces the purity/capability coupling at registration, and memoizes
/// PURE tool results within a "generation" (ADR-004: content-addressed memoization of pure
/// tools). The generation is bumped whenever an EFFECTING tool runs, so any write invalidates
/// every cached read — a stale read can never be served (the correctness precondition).
pub struct Registry {
    tools: Vec<Tool>,
    root: PathBuf,
    memo: std::sync::Arc<std::sync::Mutex<MemoState>>,
    sensitive_env_names: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
}

#[derive(Default)]
struct MemoState {
    generation: u64,
    cache: std::collections::HashMap<String, ToolResult>,
    hits: u64,
    misses: u64,
}

fn memo_key(call: &ToolUse) -> String {
    format!("{}::{}", call.name, call.input)
}

impl Registry {
    /// Build the default coding-agent tool set rooted at `root` (the repo the agent works in).
    pub fn coding_agent(root: impl Into<PathBuf>) -> Result<Self, ToolError> {
        let root = root.into();
        let mut r = Registry {
            tools: Vec::new(),
            root,
            memo: Default::default(),
            sensitive_env_names: Default::default(),
        };
        fs_tools::register(&mut r)?;
        git::register(&mut r)?;
        mem::register(&mut r)?;
        skill::register(&mut r)?;
        edit::register(&mut r)?;
        shell::register(&mut r)?;
        // Web egress (web_fetch/web_search): Effecting/IrreversibleExternal, so the capability gate
        // never auto-approves them (ADR-007 §3) and they are absent from the read_only subagent set.
        web::register(&mut r)?;
        register_dispatch_agent(&mut r)?;
        Ok(r)
    }

    /// Build a READ-ONLY tool set (read_file, list_dir, grep, repo_map). This is what a
    /// subagent gets: it explores and reports, it never writes (ADR-001, the single-writer
    /// invariant — the parent is the sole writer).
    pub fn read_only(root: impl Into<PathBuf>) -> Result<Self, ToolError> {
        let root = root.into();
        let mut r = Registry {
            tools: Vec::new(),
            root,
            memo: Default::default(),
            sensitive_env_names: Default::default(),
        };
        fs_tools::register(&mut r)?; // read_file, list_dir, grep, repo_map only
        git::register(&mut r)?; // git_diff (Pure/ReadOnly) — safe for read-only subagents too
        mem::register(&mut r)?; // read_memory (Pure/ReadOnly) — progressive-disclosure recall
        skill::register(&mut r)?; // use_skill (Pure/ReadOnly) — on-demand skill load
        Ok(r)
    }

    /// Register a tool, checking the type rules (ADR-007 R16).
    pub fn register(&mut self, tool: Tool) -> Result<(), ToolError> {
        let s = &tool.spec;
        // The load-bearing invariant: purity licenses early dispatch, so a Pure tool that can
        // egress or execute code is a contradiction we refuse at registration.
        if s.purity == Purity::Pure && !matches!(s.capability, Capability::ReadOnly) {
            return Err(ToolError::Registration(format!(
                "tool `{}` is Pure but capability is {:?}; Pure requires ReadOnly (ADR-007 R16)",
                s.name, s.capability
            )));
        }
        if self.tools.iter().any(|t| t.spec.name == s.name) {
            return Err(ToolError::Registration(format!(
                "duplicate tool `{}`",
                s.name
            )));
        }
        self.tools.push(tool);
        Ok(())
    }

    pub fn specs(&self) -> Vec<ToolSpec> {
        self.tools.iter().map(|t| t.spec.clone()).collect()
    }

    pub fn purity_of(&self, name: &str) -> Option<Purity> {
        self.tools
            .iter()
            .find(|t| t.spec.name == name)
            .map(|t| t.spec.purity)
    }

    pub fn capability_of(&self, name: &str) -> Option<Capability> {
        self.tools
            .iter()
            .find(|t| t.spec.name == name)
            .map(|t| t.spec.capability)
    }

    /// Install the trusted provider directory's exact credential environment names. The shell
    /// executor holds the same shared cell, so this may be called after provider discovery without
    /// rebuilding tool specs or invalidating prompt-cache identity.
    pub fn set_sensitive_env_names(&mut self, mut names: Vec<String>) {
        names.sort();
        names.dedup();
        *self.sensitive_env_names.lock().unwrap() = names;
    }

    pub(crate) fn sensitive_env_names_handle(
        &self,
    ) -> std::sync::Arc<std::sync::Mutex<Vec<String>>> {
        self.sensitive_env_names.clone()
    }

    /// Execute a tool call. `latency_ms` is measured here (tau_wall contribution for obs). An
    /// EFFECTING tool bumps the memo generation on completion, invalidating every cached pure
    /// read (a write must never leave a stale read servable).
    pub async fn run_effect(&self, call: ToolUse) -> ToolExecution {
        let started = Instant::now();
        let root = self.root.clone();
        let id = call.id.clone();
        let is_effecting = self.purity_of(&call.name) == Some(Purity::Effecting);
        let found = self.tools.iter().find(|t| t.spec.name == call.name);
        let mut outcome = match found {
            Some(t) => (t.run)(call, root).await,
            None => ToolExecution::Definite(ToolResult {
                tool_use_id: id.clone(),
                content: format!("unknown tool `{}`", call.name),
                is_error: true,
                trust: Trust::Trusted,
                latency_ms: 0,
            }),
        };
        // A plugin closure does not own provider correlation identity. Normalize it at the
        // registry boundary so a buggy/malicious implementation cannot mis-associate a result.
        let result = outcome.result_mut();
        result.tool_use_id = id;
        result.latency_ms = started.elapsed().as_millis() as u64;
        if is_effecting {
            // An effecting implementation may mutate partially before returning an error. The
            // only safe cache rule is therefore to invalidate on every completed attempt, not
            // only on a success-shaped ToolResult.
            let mut m = self.memo.lock().unwrap();
            m.generation += 1;
            m.cache.clear();
        }
        outcome
    }

    /// Compatibility projection for callers that do not own effect recovery. The kernel's
    /// effecting path must use [`Registry::run_effect`] so it cannot erase `Unknown` certainty.
    pub async fn run(&self, call: ToolUse) -> ToolResult {
        self.run_effect(call).await.into_result()
    }

    /// Memo hit/miss counts (for obs telemetry).
    pub fn memo_stats(&self) -> (u64, u64) {
        let m = self.memo.lock().unwrap();
        (m.hits, m.misses)
    }

    /// Hand back an owned, `'static` future for a tool call — so the scheduler can
    /// `tokio::spawn` a *pure* tool the instant its `content_block_stop` arrives, overlapping
    /// it with the still-decoding turn (ADR-004, the flagship). The borrow of `&self` ends
    /// when this returns; the future it yields owns everything it needs.
    pub fn dispatch(&self, call: ToolUse) -> boxfut::BoxFut {
        let root = self.root.clone();
        let is_pure = self.purity_of(&call.name) == Some(Purity::Pure);
        // Memoize pure tools within the current generation: a repeated identical read/grep
        // during exploration is served from cache instead of hitting the filesystem again
        // (ADR-004). Correct because any effecting tool bumps the generation.
        if is_pure {
            let key = memo_key(&call);
            let (gen0, cached) = {
                let m = self.memo.lock().unwrap();
                (m.generation, m.cache.get(&key).cloned())
            };
            if let Some(mut hit) = cached {
                self.memo.lock().unwrap().hits += 1;
                hit.tool_use_id = call.id.clone(); // this call's id, cached content
                hit.latency_ms = 0;
                return boxfut::box_it(async move { hit });
            }
            self.memo.lock().unwrap().misses += 1;
            match self.tools.iter().find(|t| t.spec.name == call.name) {
                Some(t) => {
                    let id = call.id.clone();
                    let inner = (t.run)(call, root);
                    let memo = self.memo.clone();
                    return boxfut::box_it(async move {
                        let started = Instant::now();
                        let mut r = inner.await.into_result();
                        r.tool_use_id = id;
                        r.latency_ms = started.elapsed().as_millis() as u64;
                        // Insert only if the generation has not advanced (no write raced us) and
                        // the result is not an error (errors are never cached, per ADR-004).
                        if !r.is_error {
                            let mut m = memo.lock().unwrap();
                            if m.generation == gen0 {
                                m.cache.insert(key, r.clone());
                            }
                        }
                        r
                    });
                }
                None => {
                    let id = call.id.clone();
                    let name = call.name.clone();
                    return boxfut::box_it(async move {
                        err_result(id, format!("unknown tool `{name}`"))
                    });
                }
            }
        }
        // Non-pure (or unknown): no memo.
        match self.tools.iter().find(|t| t.spec.name == call.name) {
            Some(t) => {
                let id = call.id.clone();
                let inner = (t.run)(call, root);
                let memo = self.memo.clone();
                boxfut::box_it(async move {
                    let started = Instant::now();
                    let mut r = inner.await.into_result();
                    r.tool_use_id = id;
                    r.latency_ms = started.elapsed().as_millis() as u64;
                    if !is_pure {
                        let mut memo = memo.lock().unwrap();
                        memo.generation += 1;
                        memo.cache.clear();
                    }
                    r
                })
            }
            None => {
                let id = call.id.clone();
                let name = call.name.clone();
                boxfut::box_it(async move { err_result(id, format!("unknown tool `{name}`")) })
            }
        }
    }

    pub(crate) fn push_tool(
        &mut self,
        spec: ToolSpec,
        run: impl Fn(ToolUse, PathBuf) -> boxfut::BoxFut + Send + Sync + 'static,
    ) -> Result<(), ToolError> {
        let adapted = move |call, root| {
            let future = run(call, root);
            effectfut::box_it(async move { ToolExecution::Definite(future.await) })
        };
        self.register(Tool {
            spec,
            run: Box::new(adapted),
        })
    }

    /// Public registration hook for an externally-sourced tool (e.g. an MCP tool wired by the
    /// CLI). The executor receives the call and the workspace root and returns a boxed future.
    /// Purity/capability rules in `register` still apply (ADR-007 R16).
    pub fn register_external(
        &mut self,
        spec: ToolSpec,
        run: impl Fn(ToolUse, PathBuf) -> boxfut::BoxFut + Send + Sync + 'static,
    ) -> Result<(), ToolError> {
        self.push_tool(spec, run)
    }

    /// Register an effect executor that can conservatively report an externally unknown outcome.
    /// This API is intentionally unavailable to `Pure` tools: uncertainty is an effect-state
    /// concern and must never enter the early-dispatch/memoized path.
    pub fn register_external_effect(
        &mut self,
        spec: ToolSpec,
        run: impl Fn(ToolUse, PathBuf) -> effectfut::BoxFut + Send + Sync + 'static,
    ) -> Result<(), ToolError> {
        if spec.purity != Purity::Effecting {
            return Err(ToolError::Registration(format!(
                "outcome-aware tool `{}` must be Effecting",
                spec.name
            )));
        }
        self.register(Tool {
            spec,
            run: Box::new(run),
        })
    }
}

/// The name the kernel intercepts to spawn a read-only subagent (ADR-001 fan-out). Registered
/// here only so the model sees the spec; its executor is never run (the kernel handles it).
pub const DISPATCH_AGENT: &str = "dispatch_agent";

fn register_dispatch_agent(r: &mut Registry) -> Result<(), ToolError> {
    r.push_tool(
        ToolSpec {
            name: DISPATCH_AGENT.into(),
            description: "Delegate a READ-ONLY investigation to a subagent with its own fresh \
                          context: it explores the repo (read/grep/list/repo_map) and returns a \
                          concise summary. Use for wide search or multi-file investigation to \
                          keep your own context clean. The subagent cannot edit or run code; you \
                          remain the only writer. Give it a specific question and the output you \
                          want."
                .into(),
            input_schema: serde_json::json!({
                "type":"object",
                "properties":{"task":{"type":"string","description":"the investigation question + desired output"}},
                "required":["task"]
            }),
            // Effecting so it is not early-dispatched; the kernel intercepts by name before the
            // normal effecting path and runs the subagent itself.
            purity: Purity::Effecting,
            capability: Capability::ReversibleLocal,
        },
        |call, _root| {
            boxfut::box_it(async move {
                // Never reached: the kernel intercepts DISPATCH_AGENT. This is a safety net.
                err_result(call.id, "dispatch_agent must be handled by the kernel".into())
            })
        },
    )
}

/// Resolve a caller-supplied path against the workspace root and reject escapes — **including
/// via symlinks** (code review CRITICAL SEC-1: a lexical `..` check alone lets a symlink inside
/// the repo point outside, so an fs tool reads/writes out of the workspace). We canonicalize the
/// resolved path (following symlinks) and require the result to stay under the canonical root.
/// For a not-yet-existing path (a new file to write), we canonicalize its nearest existing
/// ancestor and re-check.
pub(crate) fn resolve_in_root(root: &Path, rel: &str) -> Result<PathBuf, String> {
    // Cheap lexical pre-check (fast rejection of the obvious cases).
    let mut depth: i32 = 0;
    for comp in Path::new(rel).components() {
        use std::path::Component::*;
        match comp {
            ParentDir => depth -= 1,
            Normal(_) | CurDir => {}
            RootDir | Prefix(_) => return Err(format!("absolute path not allowed: {rel}")),
        }
        if depth < 0 {
            return Err(format!("path escapes the workspace: {rel}"));
        }
    }
    let canon_root = root
        .canonicalize()
        .map_err(|e| format!("workspace root: {e}"))?;
    let joined = canon_root.join(rel);

    // Canonicalize the path if it exists; otherwise canonicalize the nearest existing ancestor
    // (the target file may not exist yet) and append the remainder. This follows symlinks, so a
    // symlink escape is caught by the containment check below.
    let resolved = match joined.canonicalize() {
        Ok(p) => p,
        Err(_) => {
            let mut ancestor = joined.as_path();
            let mut tail: Vec<std::ffi::OsString> = Vec::new();
            let canon_ancestor = loop {
                match ancestor.parent() {
                    Some(parent) => {
                        if let Some(name) = ancestor.file_name() {
                            tail.push(name.to_os_string());
                        }
                        if let Ok(c) = parent.canonicalize() {
                            break c;
                        }
                        ancestor = parent;
                    }
                    None => return Err(format!("cannot resolve path: {rel}")),
                }
            };
            let mut p = canon_ancestor;
            for name in tail.iter().rev() {
                p.push(name);
            }
            p
        }
    };

    if !resolved.starts_with(&canon_root) {
        return Err(format!("path escapes the workspace (symlink or ..): {rel}"));
    }
    Ok(resolved)
}

/// Helper: build a successful workspace-trust result.
pub(crate) fn ok_result(id: String, content: String) -> ToolResult {
    ToolResult {
        tool_use_id: id,
        content,
        is_error: false,
        trust: Trust::Workspace,
        latency_ms: 0,
    }
}
/// Helper: build an error result.
pub(crate) fn err_result(id: String, msg: String) -> ToolResult {
    ToolResult {
        tool_use_id: id,
        content: msg,
        is_error: true,
        trust: Trust::Workspace,
        latency_ms: 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pure_plus_egress_is_a_registration_error() {
        let mut r = Registry {
            tools: Vec::new(),
            root: ".".into(),
            memo: Default::default(),
            sensitive_env_names: Default::default(),
        };
        let bad = ToolSpec {
            name: "leaky".into(),
            description: "".into(),
            input_schema: serde_json::json!({}),
            purity: Purity::Pure,
            capability: Capability::IrreversibleExternal, // egress + Pure = contradiction
        };
        let err = r.push_tool(bad, |c, _| {
            boxfut::box_it(async move { ok_result(c.id, String::new()) })
        });
        assert!(err.is_err(), "Pure+egress must be refused at registration");
    }

    #[test]
    fn path_escape_is_refused() {
        let root = std::env::temp_dir().join(format!("core-resolve-{}", std::process::id()));
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::write(root.join("src/main.rs"), "x").unwrap();
        // lexical escapes
        assert!(resolve_in_root(&root, "../etc/passwd").is_err());
        assert!(resolve_in_root(&root, "/abs").is_err());
        // a real in-workspace path resolves
        assert!(resolve_in_root(&root, "src/main.rs").is_ok());
        // a not-yet-existing file in the workspace is allowed (write path)
        assert!(resolve_in_root(&root, "src/new_file.rs").is_ok());
        std::fs::remove_dir_all(&root).ok();
    }

    #[tokio::test]
    async fn memo_serves_repeats_but_invalidates_after_a_write() {
        let root = std::env::temp_dir().join(format!("core-memo-{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("a.txt"), "v1").unwrap();
        let reg = Registry::coding_agent(&root).unwrap();

        let read = |n: &str| ToolUse {
            id: n.into(),
            name: "read_file".into(),
            input: serde_json::json!({"path":"a.txt"}),
        };
        // first read = miss; second identical read = hit (served from cache)
        let _ = reg.dispatch(read("1")).await;
        let _ = reg.dispatch(read("2")).await;
        let (hits, misses) = reg.memo_stats();
        assert_eq!(
            (hits, misses),
            (1, 1),
            "1st read misses+caches, 2nd identical read hits"
        );

        // an effecting edit bumps the generation -> the next read must MISS (no stale serve)
        let edit = ToolUse {
            id: "e".into(),
            name: "edit".into(),
            input: serde_json::json!({"path":"a.txt","old":"v1","new":"v2"}),
        };
        let _ = reg.run(edit).await;
        let _ = reg.dispatch(read("3")).await;
        let (hits2, misses2) = reg.memo_stats();
        assert_eq!(hits2, 1, "no new hit after a write");
        assert_eq!(
            misses2, 2,
            "the post-write read must miss, never serve the stale cache"
        );
        std::fs::remove_dir_all(&root).ok();
    }

    #[tokio::test]
    async fn failed_effect_invalidates_reads_and_cannot_replace_call_identity() {
        let root =
            std::env::temp_dir().join(format!("core-memo-failed-effect-{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("a.txt"), "v1").unwrap();
        let mut registry = Registry::read_only(&root).unwrap();
        registry
            .register_external(
                ToolSpec {
                    name: "partial_failure".into(),
                    description: "test partial mutation".into(),
                    input_schema: serde_json::json!({"type":"object"}),
                    purity: Purity::Effecting,
                    capability: Capability::ReversibleLocal,
                },
                |_, root| {
                    boxfut::box_it(async move {
                        std::fs::write(root.join("a.txt"), "partially changed").unwrap();
                        ToolResult {
                            tool_use_id: "plugin-chosen-id".into(),
                            content: "reported failure after mutation".into(),
                            is_error: true,
                            trust: Trust::Workspace,
                            latency_ms: 0,
                        }
                    })
                },
            )
            .unwrap();

        let read = |id: &str| ToolUse {
            id: id.into(),
            name: "read_file".into(),
            input: serde_json::json!({"path":"a.txt"}),
        };
        let _ = registry.dispatch(read("read-1")).await;
        let _ = registry.dispatch(read("read-2")).await;
        assert_eq!(registry.memo_stats(), (1, 1));

        let result = registry
            .run(ToolUse {
                id: "effect-call".into(),
                name: "partial_failure".into(),
                input: serde_json::json!({}),
            })
            .await;
        assert!(result.is_error);
        assert_eq!(
            result.tool_use_id, "effect-call",
            "executor output cannot replace provider correlation identity"
        );
        let reread = registry.dispatch(read("read-3")).await;
        assert!(reread.content.contains("partially changed"));
        assert_eq!(registry.memo_stats(), (1, 2));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn outcome_aware_effect_preserves_unknown_and_normalizes_identity() {
        let mut registry = Registry::read_only(".").unwrap();
        registry
            .register_external_effect(
                ToolSpec {
                    name: "uncertain_remote".into(),
                    description: "test-only remote effect".into(),
                    input_schema: serde_json::json!({"type":"object"}),
                    purity: Purity::Effecting,
                    capability: Capability::IrreversibleExternal,
                },
                |_, _| {
                    effectfut::box_it(async {
                        ToolExecution::Unknown(ToolResult {
                            tool_use_id: "executor-id".into(),
                            content: "remote outcome unknown".into(),
                            is_error: true,
                            trust: Trust::Untrusted,
                            latency_ms: 0,
                        })
                    })
                },
            )
            .unwrap();

        let outcome = registry
            .run_effect(ToolUse {
                id: "provider-id".into(),
                name: "uncertain_remote".into(),
                input: serde_json::json!({}),
            })
            .await;
        match outcome {
            ToolExecution::Unknown(result) => {
                assert_eq!(result.tool_use_id, "provider-id");
                assert!(result.is_error);
            }
            ToolExecution::Definite(_) => panic!("unknown effect was flattened"),
        }
    }

    #[cfg(unix)]
    #[test]
    fn symlink_escape_is_refused() {
        // SEC-1: a symlink inside the workspace pointing OUT must not be followed to escape.
        let root = std::env::temp_dir().join(format!("core-symlink-{}", std::process::id()));
        let outside = std::env::temp_dir().join(format!("core-outside-{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(outside.join("secret"), "top secret").unwrap();
        // create a symlink `root/escape` -> outside
        std::os::unix::fs::symlink(&outside, root.join("escape")).unwrap();
        // resolving through the symlink must be refused (it canonicalizes outside the root)
        let r = resolve_in_root(&root, "escape/secret");
        assert!(
            r.is_err(),
            "a symlink escaping the workspace must be refused, got {r:?}"
        );
        std::fs::remove_dir_all(&root).ok();
        std::fs::remove_dir_all(&outside).ok();
    }
}
