//! Lifecycle hooks for the CLI-composed concrete runtime (Claude Code parity, R5). A hook is an operator-configured command run at a
//! harness lifecycle point: `PreToolUse` (can BLOCK a tool), `PostToolUse` (observe), `Stop`
//! (run finished), `UserPromptSubmit`, `SessionStart`.
//!
//! SECURITY (the load-bearing decision, and why the R5 review deferred external hooks): a hook runs
//! an ARBITRARY COMMAND. It is therefore honored ONLY from the operator's USER config
//! (`~/.iteron/config.json`) — NEVER from a project/`.iteron/config.json` that could arrive with a
//! cloned repo. This is the same trust-by-origin discipline as skills/memory/agents (ADR-007 §6):
//! tree-discovered config is untrusted and must not be able to run code. Hooks are the operator's
//! own infrastructure (like the git hooks they wrote), so they run un-sandboxed but with a
//! default-deny, credential-sanitized helper environment — and only because their PROVENANCE is
//! the trusted user config. Each run is bounded by a timeout (invariant #1). A `PreToolUse` hook
//! that exits with code 2 DENIES the tool.
//!
//! Security caveats a hook AUTHOR must know (surfaced per the adversarial review, not hidden):
//! - **Fail-OPEN.** Only exit code **2** blocks. A hook that times out (bounded at 30s), fails to
//!   spawn, or exits with any other code (1, 127 from a typo) is "no opinion" → the tool RUNS. A
//!   PreToolUse hook is a best-effort guardrail, not an airtight sandbox: do not rely on a hook
//!   whose cost scales with its (model-controlled) input — crafted input can push it past the
//!   timeout → bypass. The capability gate (ADR-014), not the hook, is the load-bearing control;
//!   hooks only *tighten* it.
//! - **Coverage.** PreToolUse fires for every EFFECTING tool. For pure/read-only tools it fires
//!   ONLY when a `PreToolUse` hook is configured — which then disables their mid-stream early
//!   dispatch so the hook can speak before the read runs (the kernel handles this). With no
//!   `PreToolUse` hook, reads early-dispatch ungated (the flagship overlap); a hook bound to some
//!   OTHER event says nothing about reads and never costs the session that overlap.
//! - **Un-redacted context.** The JSON on the hook's stdin carries the LIVE tool input/result — a
//!   hook that logs its stdin captures secrets the rollout's redaction would mask. The hook is
//!   operator-authored (trusted), so this is the operator's responsibility.

use serde::Deserialize;
use sha2::{Digest as _, Sha256};
use std::collections::{BTreeMap, VecDeque};
use std::path::Path;
use std::time::Duration;

use self::journal::HookEffectJournal;

pub(crate) mod journal;

const HOOK_CAPTURE_HEAD_BYTES: usize = 32 * 1024;
const HOOK_CAPTURE_TAIL_BYTES: usize = 32 * 1024;
const HOOK_READ_CHUNK_BYTES: usize = 8 * 1024;
const MAX_HOOKS_PER_EVENT: usize = 128;
pub(crate) const MAX_HOOK_CATALOG_ENTRIES: usize = 256;
const MAX_HOOK_COMMAND_BYTES: usize = 4_096;
/// Per-hook wall bound (invariant #1). A hook that outlives it is "no opinion", so the bound is the
/// only thing keeping an operator command from wedging the turn.
const DEFAULT_HOOK_TIMEOUT_SECS: u64 = 30;

/// A lifecycle event a hook can bind to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)] // Config accepts the complete lifecycle vocabulary before every site emits it.
pub enum HookEvent {
    PreToolUse,
    PostToolUse,
    Stop,
    UserPromptSubmit,
    SessionStart,
}

impl HookEvent {
    /// The wire name of this lifecycle event. Public because the effect boundary records it as the
    /// audit projection of a hook dispatch (#16).
    pub const fn key(self) -> &'static str {
        match self {
            HookEvent::PreToolUse => "PreToolUse",
            HookEvent::PostToolUse => "PostToolUse",
            HookEvent::Stop => "Stop",
            HookEvent::UserPromptSubmit => "UserPromptSubmit",
            HookEvent::SessionStart => "SessionStart",
        }
    }
}

/// The `hooks` block of the USER config: event name -> list of shell commands.
#[derive(Debug, Clone, Default, Deserialize)]
struct HooksFile {
    #[serde(default)]
    hooks: BTreeMap<String, Vec<String>>,
}

/// The loaded hooks (from the user config only) plus a per-hook timeout.
#[derive(Debug, Clone)]
pub struct Hooks {
    by_event: BTreeMap<String, Vec<String>>,
    timeout_secs: u64,
    sensitive_env_names: Vec<String>,
}

impl Default for Hooks {
    fn default() -> Self {
        Self {
            by_event: BTreeMap::new(),
            timeout_secs: DEFAULT_HOOK_TIMEOUT_SECS,
            sensitive_env_names: Vec::new(),
        }
    }
}

/// Content-free identity of the exact executable hook map installed in one runtime.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HookCatalogIdentity {
    pub digest_sha256: String,
    pub entry_count: usize,
    pub canonical_bytes: usize,
}

/// What a `PreToolUse` hook decided.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HookDecision {
    /// No hook, or the hook allowed (exit 0 / errored / timed out — a broken hook does not wedge).
    Allow,
    /// A hook deliberately blocked the tool; the string is the reason (its stderr).
    Deny(String),
}

/// Bounded result of a canonical lifecycle hook chain. Augmentations are admitted only for the
/// catalog's fixed Augment events and are kept in-memory for the owning boundary; the lifecycle
/// recorder stores counts and outcome codes, never hook-provided content.
#[derive(Debug, Clone, PartialEq)]
pub struct LifecycleHookReport {
    pub decision: HookDecision,
    pub matched: u32,
    pub completed: u32,
    pub failed: u32,
    pub timed_out: u32,
    pub augmentations: Vec<iteron_protocol::LifecyclePayload>,
}

const MAX_LIFECYCLE_HOOK_AUGMENTATIONS: usize = 32;
const LIFECYCLE_GATE_TIMEOUT: Duration = Duration::from_secs(2);
const LIFECYCLE_OBSERVER_TIMEOUT: Duration = Duration::from_secs(10);
/// Exit code attributed to a hook process that carried none because a signal killed it; negative so
/// it can never collide with a real hook exit status.
const SIGNAL_TERMINATED_EXIT_CODE: i32 = -1;
/// Cancel/drain poll cadence while awaiting a hook process, so an operator interrupt is observed
/// without busy-waiting on the child.
const HOOK_CANCEL_POLL: Duration = Duration::from_millis(25);

impl Hooks {
    /// Load hooks from the USER config `<home>/.iteron/config.json` only. A project config is
    /// NEVER read here — a cloned repo must not be able to run a command (trust-by-origin). A
    /// missing/malformed file yields no hooks (hooks are opt-in; a broken config does not brick).
    pub fn load_user(home: &Path) -> Hooks {
        let path = iteron_protocol::home::path(home, "config.json");
        let by_event = std::fs::read_to_string(&path)
            .ok()
            .and_then(|s| serde_json::from_str::<HooksFile>(&s).ok())
            .map(|f| bounded_hook_map(f.hooks))
            .unwrap_or_default();
        Hooks {
            by_event,
            timeout_secs: DEFAULT_HOOK_TIMEOUT_SECS,
            sensitive_env_names: Vec::new(),
        }
    }

    /// Append one hook selected from a signature-verified plugin manifest. The plugin runtime has
    /// already enforced capability intersection and conflict order; this method keeps the
    /// executable surface bounded and rejects event spellings that could otherwise no-op silently.
    pub(crate) fn append_verified_plugin(
        &mut self,
        event: &str,
        command: String,
    ) -> Result<(), &'static str> {
        let legacy = [
            HookEvent::PreToolUse.key(),
            HookEvent::PostToolUse.key(),
            HookEvent::Stop.key(),
            HookEvent::UserPromptSubmit.key(),
            HookEvent::SessionStart.key(),
        ];
        if !legacy.contains(&event) && !iteron_protocol::lifecycle::is_registered(event) {
            return Err("unknown lifecycle event");
        }
        if !valid_hook_command(&command) {
            return Err("command must be visible text of 1..=4096 bytes");
        }
        if self.command_count() >= MAX_HOOK_CATALOG_ENTRIES {
            return Err("hook catalog exceeds 256 commands");
        }
        let commands = self.by_event.entry(event.to_owned()).or_default();
        if commands.len() >= MAX_HOOKS_PER_EVENT {
            return Err("hook chain exceeds 128 commands");
        }
        commands.push(command);
        Ok(())
    }

    /// Remove these exact credential indirections from every hook process. Hook commands are
    /// operator-authored, but they do not need provider or pricing signing keys.
    pub fn set_sensitive_env_names(&mut self, mut names: Vec<String>) {
        names.sort();
        names.dedup();
        self.sensitive_env_names = names;
    }

    pub fn is_empty(&self) -> bool {
        self.by_event.values().all(|v| v.is_empty())
    }

    /// Hash exact behavior without returning command text or credential-shaped environment names.
    pub(crate) fn catalog_identity(&self) -> HookCatalogIdentity {
        let mut digest = Sha256::new();
        digest.update(b"iteron-hook-catalog-v1");
        digest.update(self.timeout_secs.to_be_bytes());
        let mut canonical_bytes = std::mem::size_of::<u64>();
        for (event, commands) in &self.by_event {
            digest_part(&mut digest, event.as_bytes());
            canonical_bytes = canonical_bytes
                .saturating_add(std::mem::size_of::<u64>())
                .saturating_add(event.len());
            for command in commands {
                digest_part(&mut digest, command.as_bytes());
                canonical_bytes = canonical_bytes
                    .saturating_add(std::mem::size_of::<u64>())
                    .saturating_add(command.len());
            }
        }
        for name in &self.sensitive_env_names {
            digest_part(&mut digest, name.as_bytes());
            canonical_bytes = canonical_bytes
                .saturating_add(std::mem::size_of::<u64>())
                .saturating_add(name.len());
        }
        HookCatalogIdentity {
            digest_sha256: digest
                .finalize()
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect(),
            entry_count: self.command_count(),
            canonical_bytes,
        }
    }

    fn command_count(&self) -> usize {
        self.by_event.values().map(Vec::len).sum()
    }

    /// True when no command is bound to this exact lifecycle event.
    ///
    /// The whole-map [`Self::is_empty`] is the wrong question at a dispatch site: it answers "does
    /// this operator use hooks at all", and a dispatch site needs "does anything actually run
    /// here". Asking the coarse question made one configured `Stop` hook route every `PreToolUse`
    /// and `PostToolUse` through the effect broker — an intent append, a terminal append and their
    /// fsyncs per tool call — to invoke nothing.
    pub fn is_empty_for(&self, event: HookEvent) -> bool {
        self.commands(event).is_empty()
    }

    /// The commands bound to exactly one lifecycle event. `pub(crate)` because the kernel's
    /// early-dispatch decision is about `PreToolUse` alone: asking "is anything configured?" made a
    /// single `Stop` cleanup hook cost the whole session its concurrent reads.
    pub(crate) fn commands(&self, event: HookEvent) -> &[String] {
        self.by_event
            .get(event.key())
            .map(|v| v.as_slice())
            .unwrap_or(&[])
    }

    /// Run every command bound to `event`, passing `context_json` on stdin. For `PreToolUse` the
    /// FIRST command that exits 2 DENIES the tool (its bounded stderr is the reason). All other
    /// events are observational (the exit code is ignored). Bounded by the per-hook timeout.
    #[cfg(test)]
    pub async fn run(&self, event: HookEvent, context_json: &str) -> HookDecision {
        self.run_cancellable(event, context_json, None).await
    }

    #[cfg(test)]
    pub async fn run_cancellable(
        &self,
        event: HookEvent,
        context_json: &str,
        cancel: Option<&std::sync::atomic::AtomicBool>,
    ) -> HookDecision {
        self.run_cancellable_inner(event, context_json, cancel, None, None)
            .await
    }

    pub(crate) async fn run_cancellable_journaled(
        &self,
        event: HookEvent,
        context_json: &str,
        cancel: Option<&std::sync::atomic::AtomicBool>,
        drain: Option<&std::sync::atomic::AtomicBool>,
        journal: &HookEffectJournal,
    ) -> HookDecision {
        self.run_cancellable_inner(event, context_json, cancel, drain, Some(journal))
            .await
    }

    async fn run_cancellable_inner(
        &self,
        event: HookEvent,
        context_json: &str,
        cancel: Option<&std::sync::atomic::AtomicBool>,
        drain: Option<&std::sync::atomic::AtomicBool>,
        journal: Option<&HookEffectJournal>,
    ) -> HookDecision {
        // Compatibility and canonical lifecycle subscriptions are deliberately disjoint. The
        // lifecycle dispatcher owns canonical IDs; chaining their commands here made
        // `tool.call_completed` and `session.idle` execute once through this compatibility path
        // and a second time through the dispatcher.
        for cmd in self.commands(event) {
            let ticket = match journal.map(|journal| journal.begin(event.key())) {
                Some(Ok(ticket)) => Some(ticket),
                Some(Err(reason)) => {
                    eprintln!(
                        "warning: {} hook intent was not durable and the command was not started: {reason}",
                        event.key()
                    );
                    continue;
                }
                None => None,
            };
            let mut out = run_one_cancellable(
                cmd,
                context_json,
                self.timeout_secs,
                &self.sensitive_env_names,
                cancel,
                drain,
            )
            .await;
            if let (Some(journal), Some(ticket)) = (journal, ticket)
                && journal
                    .finish(ticket, event.key(), hook_run_outcome(&out))
                    .is_err()
            {
                out = HookRun::Failed;
            }
            // A hook that never started is still fail-open, but it is no longer SILENT. The
            // operator configured a guardrail; if the interpreter or the script is missing the
            // hook no-ops forever with nothing to see. Say so once per dispatch, on stderr.
            if let HookRun::NotStarted(reason) = &out {
                eprintln!(
                    "warning: {} hook did not start and had no opinion: {reason}",
                    event.key()
                );
            }
            // DENY convention (matches the leading agent): ONLY exit code 2 blocks. exit 0 allows;
            // any OTHER non-zero (1, 127 from a typo'd command, a spawn error, a timeout) is a hook
            // ERROR, treated as "no opinion" -> allow. This makes a misconfigured hook fail SAFE
            // (it does not wedge every tool), while a deliberate `exit 2` is respected.
            if event == HookEvent::PreToolUse
                && let HookRun::Completed(out) = out
                && out.code == 2
            {
                return HookDecision::Deny(if out.stderr.trim().is_empty() {
                    "blocked by a PreToolUse hook (exit 2)".to_string()
                } else {
                    out.stderr.trim().to_string()
                });
            }
        }
        HookDecision::Allow
    }

    /// Dispatch one canonical lifecycle event. Every one of the 192 catalog IDs is subscribable;
    /// only the catalog's fixed 12 Gate events may deny by exit code 2.
    #[cfg(test)]
    #[allow(dead_code)]
    pub async fn run_lifecycle(
        &self,
        event_id: &str,
        context_json: &str,
    ) -> Result<LifecycleHookReport, &'static str> {
        self.run_lifecycle_cancellable(event_id, context_json, None)
            .await
    }

    #[cfg(test)]
    #[allow(dead_code)]
    pub async fn run_lifecycle_cancellable(
        &self,
        event_id: &str,
        context_json: &str,
        cancel: Option<&std::sync::atomic::AtomicBool>,
    ) -> Result<LifecycleHookReport, &'static str> {
        self.run_lifecycle_cancellable_inner(event_id, context_json, cancel, None, None)
            .await
    }

    pub(crate) async fn run_lifecycle_cancellable_journaled(
        &self,
        event_id: &str,
        context_json: &str,
        cancel: Option<&std::sync::atomic::AtomicBool>,
        drain: Option<&std::sync::atomic::AtomicBool>,
        journal: &HookEffectJournal,
    ) -> Result<LifecycleHookReport, &'static str> {
        self.run_lifecycle_cancellable_inner(event_id, context_json, cancel, drain, Some(journal))
            .await
    }

    async fn run_lifecycle_cancellable_inner(
        &self,
        event_id: &str,
        context_json: &str,
        cancel: Option<&std::sync::atomic::AtomicBool>,
        drain: Option<&std::sync::atomic::AtomicBool>,
        journal: Option<&HookEffectJournal>,
    ) -> Result<LifecycleHookReport, &'static str> {
        let Some(spec) = iteron_protocol::lifecycle::event_spec(event_id) else {
            return Err("unknown lifecycle event");
        };
        let Some(commands) = self.by_event.get(event_id) else {
            return Ok(LifecycleHookReport {
                decision: HookDecision::Allow,
                matched: 0,
                completed: 0,
                failed: 0,
                timed_out: 0,
                augmentations: Vec::new(),
            });
        };
        let timeout = if spec.hook_capability == iteron_protocol::HookCapability::Gate {
            LIFECYCLE_GATE_TIMEOUT
        } else {
            LIFECYCLE_OBSERVER_TIMEOUT
        };
        let mut report = LifecycleHookReport {
            decision: HookDecision::Allow,
            matched: u32::try_from(commands.len()).unwrap_or(u32::MAX),
            completed: 0,
            failed: 0,
            timed_out: 0,
            augmentations: Vec::new(),
        };
        for command in commands {
            let ticket = match journal.map(|journal| journal.begin(event_id)) {
                Some(Ok(ticket)) => Some(ticket),
                Some(Err(_)) => {
                    report.failed = report.failed.saturating_add(1);
                    if spec.hook_capability == iteron_protocol::HookCapability::Gate {
                        report.decision = HookDecision::Deny(format!(
                            "{event_id} gate hook intent could not be recorded"
                        ));
                        return Ok(report);
                    }
                    continue;
                }
                None => None,
            };
            let mut outcome = run_one_with_sensitive_env_names_cancellable(
                command,
                context_json,
                timeout,
                &self.sensitive_env_names,
                cancel,
                drain,
            )
            .await;
            if let (Some(journal), Some(ticket)) = (journal, ticket)
                && journal
                    .finish(ticket, event_id, hook_run_outcome(&outcome))
                    .is_err()
            {
                outcome = HookRun::Failed;
            }
            match outcome {
                HookRun::Completed(output)
                    if output.code == 2
                        && spec.hook_capability == iteron_protocol::HookCapability::Gate =>
                {
                    report.completed = report.completed.saturating_add(1);
                    report.decision = HookDecision::Deny(if output.stderr.trim().is_empty() {
                        format!("blocked by {event_id} hook (exit 2)")
                    } else {
                        output.stderr.trim().to_owned()
                    });
                    return Ok(report);
                }
                HookRun::Completed(output) => {
                    report.completed = report.completed.saturating_add(1);
                    if output.code != 0 {
                        report.failed = report.failed.saturating_add(1);
                    } else if spec.hook_capability == iteron_protocol::HookCapability::Augment
                        && !output.stdout.trim().is_empty()
                    {
                        let augmentation =
                            serde_json::from_str::<iteron_protocol::LifecyclePayload>(
                                output.stdout.trim(),
                            )
                            .ok()
                            .filter(|payload| payload.validate().is_ok());
                        if let Some(augmentation) = augmentation {
                            if report.augmentations.len() < MAX_LIFECYCLE_HOOK_AUGMENTATIONS {
                                report.augmentations.push(augmentation);
                            } else {
                                report.failed = report.failed.saturating_add(1);
                            }
                        } else {
                            report.failed = report.failed.saturating_add(1);
                        }
                    }
                }
                HookRun::TimedOut => {
                    report.timed_out = report.timed_out.saturating_add(1);
                    if spec.hook_capability == iteron_protocol::HookCapability::Gate {
                        report.decision = HookDecision::Deny(format!(
                            "{event_id} gate hook timed out without an allow decision"
                        ));
                        return Ok(report);
                    }
                }
                HookRun::NotStarted(_) | HookRun::Failed | HookRun::Cancelled => {
                    report.failed = report.failed.saturating_add(1);
                    if spec.hook_capability == iteron_protocol::HookCapability::Gate {
                        report.decision = HookDecision::Deny(format!(
                            "{event_id} gate hook failed without an allow decision"
                        ));
                        return Ok(report);
                    }
                }
            }
        }
        Ok(report)
    }

    pub fn subscribed_lifecycle_events(&self) -> Vec<&'static str> {
        iteron_protocol::lifecycle::EVENTS
            .into_iter()
            .filter(|event| {
                self.by_event
                    .get(*event)
                    .is_some_and(|hooks| !hooks.is_empty())
            })
            .collect()
    }

    pub(crate) fn is_empty_for_lifecycle(&self, event_id: &str) -> bool {
        self.by_event.get(event_id).is_none_or(Vec::is_empty)
    }
}

fn bounded_hook_map(input: BTreeMap<String, Vec<String>>) -> BTreeMap<String, Vec<String>> {
    let mut output = BTreeMap::new();
    let mut total = 0_usize;
    for (event, commands) in input {
        if !valid_hook_event(&event) || total >= MAX_HOOK_CATALOG_ENTRIES {
            continue;
        }
        let admitted = commands
            .into_iter()
            .filter(|command| valid_hook_command(command))
            .take(MAX_HOOKS_PER_EVENT.min(MAX_HOOK_CATALOG_ENTRIES - total))
            .collect::<Vec<_>>();
        total = total.saturating_add(admitted.len());
        if !admitted.is_empty() {
            output.insert(event, admitted);
        }
    }
    output
}

fn valid_hook_event(event: &str) -> bool {
    matches!(
        event,
        "PreToolUse" | "PostToolUse" | "Stop" | "UserPromptSubmit" | "SessionStart"
    ) || iteron_protocol::lifecycle::is_registered(event)
}

fn valid_hook_command(command: &str) -> bool {
    !command.is_empty()
        && command.len() <= MAX_HOOK_COMMAND_BYTES
        && !command.chars().any(char::is_control)
}

fn digest_part(digest: &mut Sha256, bytes: &[u8]) {
    digest.update(u64::try_from(bytes.len()).unwrap_or(u64::MAX).to_be_bytes());
    digest.update(bytes);
}

impl super::Agent {
    /// Install exactly the hook catalog named by the immutable tunables checkpoint.
    pub(crate) fn install_hooks(&mut self, hooks: Hooks) -> Result<(), super::KernelError> {
        if self.hooks_runtime_installed {
            return Err(super::KernelError::ExecutionPolicy(
                "hook runtime was already installed".into(),
            ));
        }
        let expected = self
            .effective_content
            .as_ref()
            .ok_or(super::KernelError::TunablesNotResolved)?
            .hooks
            .as_ref();
        let actual = (!hooks.is_empty()).then(|| hooks.catalog_identity());
        if expected != actual.as_ref() {
            return Err(super::KernelError::ExecutionPolicy(
                "installed hooks differ from the immutable hooks_map identity".into(),
            ));
        }
        self.hooks = hooks;
        self.hooks_runtime_installed = true;
        Ok(())
    }
}

/// What one hook dispatch actually did. `NotStarted` used to be indistinguishable from a timeout
/// or a clean exit 0, which is how a permanently broken hook stayed invisible.
#[derive(Debug)]
enum HookRun {
    /// The process ran to completion; its exit code is the hook's opinion.
    Completed(HookRunOutput),
    /// The process never started (missing path, not executable, no pipe). The string says why.
    NotStarted(String),
    /// It started but its bounded deadline expired.
    TimedOut,
    /// It started but a read/wait boundary failed before a terminal exit was observed.
    Failed,
    /// The session was cancelled while this command was running.
    Cancelled,
}

fn hook_run_outcome(run: &HookRun) -> &'static str {
    match run {
        HookRun::Completed(output) if output.code == 2 => "blocked",
        HookRun::Completed(output) if output.code == 0 => "completed",
        HookRun::Completed(_) | HookRun::NotStarted(_) | HookRun::Failed => "failed",
        HookRun::TimedOut => "timed_out",
        HookRun::Cancelled => "cancelled",
    }
}

impl HookRun {
    /// The completed output, if the hook actually ran to completion.
    #[cfg_attr(not(test), allow(dead_code))]
    fn completed(self) -> Option<HookRunOutput> {
        match self {
            HookRun::Completed(output) => Some(output),
            HookRun::NotStarted(_) | HookRun::TimedOut | HookRun::Failed | HookRun::Cancelled => {
                None
            }
        }
    }
}

#[derive(Debug)]
struct HookRunOutput {
    code: i32,
    // stdout remains observational, but retaining its bounded rendering makes the capture contract
    // testable and leaves room for future diagnostics without reintroducing `wait_with_output`.
    #[allow(dead_code)]
    stdout: String,
    stderr: String,
}

/// Fixed-memory head/tail capture. Bytes between the two windows are drained and counted but never
/// retained, so a hook can flood either pipe without growing the parent process.
#[derive(Debug, Default)]
struct BoundedCapture {
    head: Vec<u8>,
    tail: VecDeque<u8>,
    total: u64,
}

impl BoundedCapture {
    fn push(&mut self, bytes: &[u8]) {
        self.total = self.total.saturating_add(bytes.len() as u64);

        let head_bytes = bytes
            .len()
            .min(HOOK_CAPTURE_HEAD_BYTES.saturating_sub(self.head.len()));
        self.head.extend_from_slice(&bytes[..head_bytes]);
        let remainder = &bytes[head_bytes..];
        if remainder.len() >= HOOK_CAPTURE_TAIL_BYTES {
            self.tail.clear();
            self.tail
                .extend(&remainder[remainder.len() - HOOK_CAPTURE_TAIL_BYTES..]);
            return;
        }

        let overflow = self
            .tail
            .len()
            .saturating_add(remainder.len())
            .saturating_sub(HOOK_CAPTURE_TAIL_BYTES);
        if overflow > 0 {
            self.tail.drain(..overflow);
        }
        self.tail.extend(remainder);
    }

    fn into_marked_string(self, stream: &str) -> String {
        let retained = self.head.len().saturating_add(self.tail.len()) as u64;
        let omitted = self.total.saturating_sub(retained);

        let (mut rendered, invalid_utf8) = if omitted == 0 {
            let mut bytes = self.head;
            bytes.extend(self.tail);
            decode_lossy(bytes)
        } else {
            let (head, head_invalid) = decode_lossy(self.head);
            let (tail, tail_invalid) = decode_lossy(self.tail.into_iter().collect());
            (
                format!(
                    "{head}\n[... hook {stream} truncated: {omitted} bytes omitted ...]\n{tail}"
                ),
                head_invalid || tail_invalid,
            )
        };

        if invalid_utf8 {
            rendered.insert_str(
                0,
                &format!("[hook {stream} contained invalid UTF-8; invalid bytes replaced]\n"),
            );
        }
        rendered
    }
}

fn decode_lossy(bytes: Vec<u8>) -> (String, bool) {
    match String::from_utf8(bytes) {
        Ok(text) => (text, false),
        Err(error) => (String::from_utf8_lossy(error.as_bytes()).into_owned(), true),
    }
}

async fn capture_pipe<R>(mut reader: R) -> std::io::Result<BoundedCapture>
where
    R: tokio::io::AsyncRead + Unpin,
{
    use tokio::io::AsyncReadExt;

    let mut capture = BoundedCapture::default();
    let mut chunk = [0u8; HOOK_READ_CHUNK_BYTES];
    // This loop's memory is fixed by `BoundedCapture`; its wall-clock lifetime is bounded by the
    // outer per-hook timeout, which cancels the read and then kills/reaps the producer.
    loop {
        let read = reader.read(&mut chunk).await?;
        if read == 0 {
            return Ok(capture);
        }
        capture.push(&chunk[..read]);
    }
}

/// Run one hook command with `ctx` on stdin, bounded by `timeout_secs`. Returns its exit and
/// bounded, marked output if it ran to completion; spawn/read/wait errors and timeouts remain no
/// opinion, preserving the existing fail-open hook semantics, but a hook that could not be STARTED
/// is reported as such rather than collapsing into the same silent `None` as a timeout.
async fn run_one_cancellable(
    cmd: &str,
    ctx: &str,
    timeout_secs: u64,
    sensitive_env_names: &[String],
    cancel: Option<&std::sync::atomic::AtomicBool>,
    drain: Option<&std::sync::atomic::AtomicBool>,
) -> HookRun {
    run_one_with_sensitive_env_names_cancellable(
        cmd,
        ctx,
        Duration::from_secs(timeout_secs),
        sensitive_env_names,
        cancel,
        drain,
    )
    .await
}

#[cfg(test)]
async fn run_one_with_timeout(cmd: &str, ctx: &str, timeout: Duration) -> HookRun {
    run_one_with_sensitive_env_names(cmd, ctx, timeout, &[]).await
}

#[cfg(test)]
async fn run_one_with_sensitive_env_names(
    cmd: &str,
    ctx: &str,
    timeout: Duration,
    sensitive_env_names: &[String],
) -> HookRun {
    run_one_with_sensitive_env_names_cancellable(cmd, ctx, timeout, sensitive_env_names, None, None)
        .await
}

async fn run_one_with_sensitive_env_names_cancellable(
    cmd: &str,
    ctx: &str,
    timeout: Duration,
    sensitive_env_names: &[String],
    cancel: Option<&std::sync::atomic::AtomicBool>,
    drain: Option<&std::sync::atomic::AtomicBool>,
) -> HookRun {
    // The interpreter is resolved rather than hardcoded: the Linux musl artifact's natural home
    // has `/bin/sh` and no `/bin/bash`, and on a platform with neither the hook must say so
    // instead of no-opping forever.
    run_one_with_shell(
        iteron_sandbox::confined_shell(),
        cmd,
        ctx,
        timeout,
        sensitive_env_names,
        cancel,
        drain,
    )
    .await
}

async fn run_one_with_shell(
    shell: &str,
    cmd: &str,
    ctx: &str,
    timeout: Duration,
    sensitive_env_names: &[String],
    cancel: Option<&std::sync::atomic::AtomicBool>,
    drain: Option<&std::sync::atomic::AtomicBool>,
) -> HookRun {
    use tokio::io::AsyncWriteExt;

    let mut command = tokio::process::Command::new(shell);
    iteron_sandbox::clear_to_safe_child_env_with_exact(&mut command, sensitive_env_names);
    iteron_sandbox::configure_process_group(&mut command);
    let spawned = command
        .arg("-c")
        .arg(cmd)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn();
    let mut child = match spawned {
        Ok(child) => child,
        Err(error) => return HookRun::NotStarted(format!("{shell} -c: {error}")),
    };
    let mut group_guard = HookProcessGroupDropGuard::new(child.id());

    let Some(mut stdin) = child.stdin.take() else {
        terminate_and_reap(&mut child).await;
        return HookRun::NotStarted("hook stdin was not piped".to_string());
    };
    let Some(stdout) = child.stdout.take() else {
        terminate_and_reap(&mut child).await;
        return HookRun::NotStarted("hook stdout was not piped".to_string());
    };
    let Some(stderr) = child.stderr.take() else {
        terminate_and_reap(&mut child).await;
        return HookRun::NotStarted("hook stderr was not piped".to_string());
    };

    use std::sync::atomic::Ordering;
    let stopped = || {
        cancel.is_some_and(|flag| flag.load(Ordering::Relaxed))
            || drain.is_some_and(|flag| flag.load(Ordering::Relaxed))
    };
    if stopped() {
        terminate_and_reap(&mut child).await;
        group_guard.disarm();
        return HookRun::Cancelled;
    }

    // Stdin, stdout and stderr progress concurrently. Unlike `wait_with_output`, both readers
    // continuously drain their pipes while retaining a fixed-size head/tail only.
    let work = async {
        let writer = async move {
            let _ = stdin.write_all(ctx.as_bytes()).await;
            // `stdin` drops with this future, closing the pipe so hooks reading to EOF proceed.
        };
        let ((), stdout, stderr, status) = tokio::join!(
            writer,
            capture_pipe(stdout),
            capture_pipe(stderr),
            child.wait()
        );
        let stdout = stdout.ok()?.into_marked_string("stdout");
        let stderr = stderr.ok()?.into_marked_string("stderr");
        Some(HookRunOutput {
            code: status.ok()?.code().unwrap_or(SIGNAL_TERMINATED_EXIT_CODE),
            stdout,
            stderr,
        })
    };

    enum WaitOutcome {
        Completed(Option<HookRunOutput>),
        TimedOut,
        Cancelled,
    }
    let outcome = {
        tokio::pin!(work);
        let deadline = tokio::time::sleep(timeout);
        tokio::pin!(deadline);
        loop {
            tokio::select! {
                result = &mut work => break WaitOutcome::Completed(result),
                () = &mut deadline => break WaitOutcome::TimedOut,
                () = tokio::time::sleep(HOOK_CANCEL_POLL),
                    if cancel.is_some() || drain.is_some() =>
                {
                    if stopped() {
                        break WaitOutcome::Cancelled;
                    }
                }
            }
        }
    };

    match outcome {
        WaitOutcome::Completed(Some(output)) => {
            group_guard.disarm();
            HookRun::Completed(output)
        }
        WaitOutcome::Completed(None) => {
            terminate_and_reap(&mut child).await;
            group_guard.disarm();
            HookRun::Failed
        }
        WaitOutcome::TimedOut => {
            // Do not rely on `kill_on_drop`: a timed-out hook is explicitly killed and waited so
            // the direct child cannot survive the decision or remain as a zombie.
            terminate_and_reap(&mut child).await;
            group_guard.disarm();
            HookRun::TimedOut
        }
        WaitOutcome::Cancelled => {
            // Ctrl-C/drain has the same ownership rule as timeout: terminate the dedicated process
            // group and reap the direct child before publishing the cancelled terminal.
            terminate_and_reap(&mut child).await;
            group_guard.disarm();
            HookRun::Cancelled
        }
    }
}

/// Cancellation-by-future-drop must kill the whole dedicated hook process group. The ordinary
/// completion/timeout paths disarm after reaping; task abortion remains a last-resort SIGKILL.
struct HookProcessGroupDropGuard {
    pid: Option<u32>,
    armed: bool,
}

impl HookProcessGroupDropGuard {
    fn new(pid: Option<u32>) -> Self {
        Self { pid, armed: true }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for HookProcessGroupDropGuard {
    fn drop(&mut self) {
        #[cfg(unix)]
        if self.armed
            && let Some(pid) = self.pid.and_then(|pid| i32::try_from(pid).ok())
        {
            // SAFETY: hooks are spawned with `process_group(0)`, so `-pid` addresses only the
            // hook-owned group and cannot signal Core's own process group.
            unsafe {
                libc::kill(-pid, libc::SIGKILL);
            }
        }
    }
}

async fn terminate_and_reap(child: &mut tokio::process::Child) {
    iteron_sandbox::terminate_process_group_and_reap(child).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("core-hooks-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(d.join(".iteron")).unwrap();
        d
    }

    #[tokio::test]
    async fn pretooluse_hook_can_deny_a_tool() {
        let home = tmp("deny");
        std::fs::write(
            home.join(".iteron").join("config.json"),
            r#"{"hooks":{"PreToolUse":["grep -q secret && echo 'no secrets' >&2 && exit 2 || exit 0"]}}"#,
        )
        .unwrap();
        let hooks = Hooks::load_user(&home);
        assert!(!hooks.is_empty());
        // context mentions "secret" -> the hook exits non-zero -> deny
        let d = hooks
            .run(
                HookEvent::PreToolUse,
                r#"{"tool":"edit","input":{"path":"secret.rs"}}"#,
            )
            .await;
        assert!(
            matches!(d, HookDecision::Deny(_)),
            "hook should deny: {d:?}"
        );
        // context without the trigger -> allow
        let d2 = hooks
            .run(
                HookEvent::PreToolUse,
                r#"{"tool":"edit","input":{"path":"main.rs"}}"#,
            )
            .await;
        assert_eq!(d2, HookDecision::Allow);
        let _ = std::fs::remove_dir_all(&home);
    }

    #[tokio::test]
    async fn a_broken_hook_does_not_wedge_allows() {
        let home = tmp("broken");
        std::fs::write(
            home.join(".iteron").join("config.json"),
            r#"{"hooks":{"PreToolUse":["/nonexistent/command/xyz"]}}"#,
        )
        .unwrap();
        let hooks = Hooks::load_user(&home);
        // the command cannot spawn -> "no opinion" -> allow (a broken hook must not brick the agent)
        assert_eq!(
            hooks.run(HookEvent::PreToolUse, "{}").await,
            HookDecision::Allow
        );
        let _ = std::fs::remove_dir_all(&home);
    }

    #[tokio::test]
    async fn a_hook_that_could_not_be_started_is_reported_not_swallowed() {
        // The shell was hardcoded outside any cfg and its spawn error went through `.ok()?`, so on
        // a host without that interpreter every configured hook no-opped with nothing to observe.
        // Fail-open is still the contract; being silent about it is not.
        let outcome = run_one_with_shell(
            "/nonexistent/interpreter/for/hooks",
            "exit 2",
            "",
            Duration::from_secs(2),
            &[],
            None,
            None,
        )
        .await;
        let HookRun::NotStarted(reason) = &outcome else {
            panic!("a missing interpreter must be reported: {outcome:?}");
        };
        assert!(
            reason.contains("/nonexistent/interpreter/for/hooks"),
            "the report must name what could not be started: {reason}"
        );
        assert!(outcome.completed().is_none(), "it produced no opinion");
    }

    #[tokio::test]
    async fn hook_child_gets_toolchain_env_but_no_exact_pricing_credential() {
        unsafe {
            std::env::set_var(
                "ITERON_TEST_PRICING_KEY",
                "hook-pricing-sentinel-must-not-cross",
            );
            std::env::set_var("XDG_CONFIG_HOME", "hook-allowlist-sentinel-must-not-cross");
        }
        let sensitive = vec!["ITERON_TEST_PRICING_KEY".into(), "XDG_CONFIG_HOME".into()];
        let output = run_one_with_sensitive_env_names(
            "test -z \"${ITERON_TEST_PRICING_KEY+x}\" && test -z \"${XDG_CONFIG_HOME+x}\" && command -v sh >/dev/null",
            "",
            Duration::from_secs(2),
            &sensitive,
        )
        .await
        .completed()
        .expect("hook should run");
        unsafe {
            std::env::remove_var("ITERON_TEST_PRICING_KEY");
            std::env::remove_var("XDG_CONFIG_HOME");
        }
        assert_eq!(output.code, 0);
        assert!(!output.stdout.contains("sentinel"));
        assert!(!output.stderr.contains("sentinel"));
    }

    #[test]
    fn no_user_config_means_no_hooks() {
        let home = tmp("empty");
        assert!(Hooks::load_user(&home).is_empty());
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn hook_catalog_identity_is_exact_deterministic_and_content_free() {
        let home = tmp("catalog-identity");
        std::fs::write(
            home.join(".iteron").join("config.json"),
            serde_json::json!({
                "hooks": {
                    "Stop": ["printf stop"],
                    "PreToolUse": ["printf pre"]
                }
            })
            .to_string(),
        )
        .unwrap();
        let mut hooks = Hooks::load_user(&home);
        hooks.set_sensitive_env_names(vec!["SECRET_B".into(), "SECRET_A".into()]);
        let first = hooks.catalog_identity();
        assert_eq!(first, hooks.catalog_identity());
        assert_eq!(first.entry_count, 2);
        assert_eq!(first.digest_sha256.len(), 64);

        let changed_home = tmp("catalog-identity-changed");
        std::fs::write(
            changed_home.join(".iteron").join("config.json"),
            serde_json::json!({
                "hooks": {
                    "Stop": ["printf changed"],
                    "PreToolUse": ["printf pre"]
                }
            })
            .to_string(),
        )
        .unwrap();
        let mut changed = Hooks::load_user(&changed_home);
        changed.set_sensitive_env_names(vec!["SECRET_A".into(), "SECRET_B".into()]);
        assert_ne!(
            first.digest_sha256,
            changed.catalog_identity().digest_sha256
        );
        let debug = format!("{first:?}");
        assert!(!debug.contains("printf"));
        assert!(!debug.contains("SECRET"));
        let _ = std::fs::remove_dir_all(home);
        let _ = std::fs::remove_dir_all(changed_home);
    }

    #[test]
    fn user_hook_catalog_is_bounded_per_event_and_in_total() {
        let home = tmp("catalog-bounds");
        let hooks = (0..MAX_HOOK_CATALOG_ENTRIES + 20)
            .map(|ordinal| format!("printf {ordinal}"))
            .collect::<Vec<_>>();
        std::fs::write(
            home.join(".iteron").join("config.json"),
            serde_json::json!({
                "hooks": {
                    "PreToolUse": hooks,
                    "UnknownEvent": ["printf never-admitted"]
                }
            })
            .to_string(),
        )
        .unwrap();
        let loaded = Hooks::load_user(&home);
        assert_eq!(loaded.command_count(), MAX_HOOKS_PER_EVENT);
        assert!(!loaded.by_event.contains_key("UnknownEvent"));
        let _ = std::fs::remove_dir_all(home);
    }

    #[tokio::test]
    async fn stdout_and_stderr_floods_are_drained_with_bounded_marked_capture() {
        let command = concat!(
            "i=0; while [ \"$i\" -lt 12000 ]; do ",
            "printf '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\\n'; ",
            "printf 'fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210\\n' >&2; ",
            "i=$((i + 1)); done; ",
            "printf 'stdout-tail-marker'; printf 'stderr-tail-marker' >&2; exit 2"
        );
        let output = run_one_with_timeout(command, "", Duration::from_secs(10))
            .await
            .completed()
            .expect("flooding hook should complete while both pipes are drained");

        assert_eq!(output.code, 2);
        assert!(output.stdout.contains("hook stdout truncated"));
        assert!(output.stderr.contains("hook stderr truncated"));
        assert!(output.stdout.contains("stdout-tail-marker"));
        assert!(output.stderr.contains("stderr-tail-marker"));
        let rendered_ceiling = HOOK_CAPTURE_HEAD_BYTES + HOOK_CAPTURE_TAIL_BYTES + 512;
        assert!(output.stdout.len() <= rendered_ceiling);
        assert!(output.stderr.len() <= rendered_ceiling);
    }

    #[test]
    fn invalid_utf8_is_lossy_with_an_explicit_marker() {
        let mut capture = BoundedCapture::default();
        capture.push(b"before\xffafter");
        let rendered = capture.into_marked_string("stderr");
        assert!(rendered.contains("invalid UTF-8; invalid bytes replaced"));
        assert!(rendered.contains('\u{fffd}'));
    }

    #[cfg(unix)]
    fn process_exists(pid: u32) -> bool {
        std::process::Command::new("kill")
            .args(["-0", &pid.to_string()])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .is_ok_and(|status| status.success())
    }

    #[cfg(unix)]
    fn shell_quote(path: &Path) -> String {
        format!("'{}'", path.to_string_lossy().replace('\'', "'\"'\"'"))
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn timeout_explicitly_kills_and_reaps_hook() {
        let pid_path = std::env::temp_dir().join(format!(
            "core-hook-timeout-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let command = format!("echo $$ > {}; exec sleep 60", shell_quote(&pid_path));
        let output = run_one_with_timeout(&command, "", Duration::from_millis(500)).await;
        assert!(
            matches!(output, HookRun::TimedOut),
            "timed-out hook must have no opinion: {output:?}"
        );

        let pid: u32 = std::fs::read_to_string(&pid_path)
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        assert!(!process_exists(pid), "timed-out hook {pid} was not reaped");
        let _ = std::fs::remove_file(pid_path);
    }

    #[tokio::test]
    async fn journal_brackets_each_external_command_not_the_chain() {
        let home = tmp("journal-per-command");
        std::fs::write(
            home.join(".iteron").join("config.json"),
            serde_json::json!({"hooks": {"SessionStart": [":", ":"]}}).to_string(),
        )
        .unwrap();
        let hooks = Hooks::load_user(&home);
        let journal_path = home.join("hooks.jsonl");
        let journal = HookEffectJournal::open(&journal_path).unwrap();

        assert_eq!(
            hooks
                .run_cancellable_journaled(HookEvent::SessionStart, "{}", None, None, &journal,)
                .await,
            HookDecision::Allow
        );
        drop(journal);

        let entries = std::fs::read_to_string(&journal_path).unwrap();
        assert_eq!(
            entries.lines().count(),
            4,
            "two commands each own an intent and terminal"
        );
        assert_eq!(
            HookEffectJournal::open(&journal_path)
                .unwrap()
                .recovered_unknown(),
            0
        );
        let _ = std::fs::remove_dir_all(home);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn drain_cancels_kills_reaps_and_journals_a_running_hook() {
        let home = tmp("drain-running-hook");
        let pid_path = home.join("hook.pid");
        let command = format!("echo $$ > {}; exec sleep 60", shell_quote(&pid_path));
        std::fs::write(
            home.join(".iteron").join("config.json"),
            serde_json::json!({"hooks": {"SessionStart": [command]}}).to_string(),
        )
        .unwrap();
        let hooks = Hooks::load_user(&home);
        let journal_path = home.join("hooks.jsonl");
        let journal = HookEffectJournal::open(&journal_path).unwrap();
        let drain = std::sync::atomic::AtomicBool::new(false);
        let started = std::time::Instant::now();

        let (decision, ()) = tokio::join!(
            hooks.run_cancellable_journaled(
                HookEvent::SessionStart,
                "{}",
                None,
                Some(&drain),
                &journal,
            ),
            async {
                tokio::time::sleep(Duration::from_millis(100)).await;
                drain.store(true, std::sync::atomic::Ordering::SeqCst);
            }
        );
        assert_eq!(decision, HookDecision::Allow);
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "drain must not wait for the hook timeout"
        );
        let pid: u32 = std::fs::read_to_string(&pid_path)
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        assert!(!process_exists(pid), "cancelled hook {pid} was not reaped");
        drop(journal);
        let entries = std::fs::read_to_string(&journal_path).unwrap();
        assert_eq!(entries.lines().count(), 2);
        assert!(entries.contains("\"outcome\":\"cancelled\""));
        assert_eq!(
            HookEffectJournal::open(&journal_path)
                .unwrap()
                .recovered_unknown(),
            0
        );
        let _ = std::fs::remove_dir_all(home);
    }
}
