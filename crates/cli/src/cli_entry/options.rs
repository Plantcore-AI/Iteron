//! Command vocabulary and immutable launch arguments; performs no provider or journal IO.

use super::build_identity::long_version;
use crate::output::OutputFormat;
use crate::{app_server, config, mcp, plugin, session_view, tunables};
use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Debug, Clone, PartialEq, Eq, Subcommand)]
pub(crate) enum LocalCommand {
    /// Rebuild session metadata and the sessions index from hash-chained rollout truth.
    Reindex,
    /// Delete old run journals under the runs dir according to an explicit retention policy.
    /// Journals are append-only and nothing else ever removes them.
    Prune {
        /// Delete runs whose last recorded activity is older than this many days.
        #[arg(long, value_name = "DAYS")]
        older_than_days: Option<u64>,
        /// Keep only the newest N runs; delete every older one.
        #[arg(long, value_name = "N")]
        keep_last: Option<usize>,
        /// Print exactly what the policy names without deleting anything.
        #[arg(long)]
        dry_run: bool,
    },
    /// Run a local-only versioned App Server for headless clients.
    Serve {
        /// Loopback TCP address for bounded JSONL frames. Port 0 asks the OS to choose one.
        #[arg(long, default_value = "127.0.0.1:0")]
        listen: std::net::SocketAddr,
        /// Require one digest-verified PlantCore bootstrap before the first user input.
        #[cfg_attr(feature = "legacy-plantcore", arg(long))]
        #[cfg_attr(not(feature = "legacy-plantcore"), arg(skip))]
        plantcore: bool,
        /// Install one case-local CA only for the selected recording Provider route.
        #[cfg_attr(
            feature = "legacy-plantcore",
            arg(
                long,
                value_name = "ABSOLUTE_CA_PEM",
                hide = true,
                requires = "plantcore"
            )
        )]
        #[cfg_attr(not(feature = "legacy-plantcore"), arg(skip))]
        recording_provider_ca_file: Option<PathBuf>,
        /// Arm the deterministic pre-dispatch harness fault used by release recording.
        #[cfg_attr(feature = "legacy-plantcore", arg(
            long,
            hide = true,
            requires_all = ["plantcore", "recording_provider_ca_file"]
        ))]
        #[cfg_attr(not(feature = "legacy-plantcore"), arg(skip))]
        recording_inject_harness_error: bool,
        /// Emit one fixed malformed App Server sequence for Worker parser release recording.
        #[cfg_attr(feature = "legacy-plantcore", arg(
            long,
            hide = true,
            value_enum,
            requires_all = ["plantcore", "recording_provider_ca_file"]
        ))]
        #[cfg_attr(not(feature = "legacy-plantcore"), arg(skip))]
        recording_app_server_fault: Option<app_server::RecordingAppServerFault>,
    },
    /// Run a bounded JavaScript workflow end-to-end, streaming progress to stdout.
    Workflow {
        #[command(subcommand)]
        action: WorkflowAction,
    },
    /// First-run setup: choose a hosted plan or your own provider key, and validate it.
    Setup {
        /// Sign in with a hosted subscription plan.
        #[arg(long, conflicts_with = "byok")]
        plan: bool,
        /// Bring your own key for this provider id.
        #[arg(long, value_name = "PROVIDER")]
        byok: Option<String>,
        /// Provider id for a flow that does not name one positionally, such as `--plan`.
        #[arg(long, value_name = "PROVIDER", conflicts_with = "byok")]
        provider: Option<String>,
        /// Read the credential from stdin instead of prompting, so setup runs without a terminal.
        ///
        /// The credential never appears on the command line, where it would reach the process
        /// table and the shell history: `printenv DEEPSEEK_API_KEY | iteron setup --byok deepseek
        /// --stdin`.
        #[arg(long)]
        stdin: bool,
        /// Unix timestamp a hosted-plan credential expires at.
        ///
        /// Refused on a BYOK key, which does not expire. The check lives in setup rather than in
        /// the argument parser because the wizard can also arrive at BYOK without `--byok`.
        #[arg(long, value_name = "UNIX")]
        expires_at: Option<u64>,
    },
    /// Inspect or drop the credential in use.
    Auth {
        #[command(subcommand)]
        action: AuthAction,
    },
    /// Read or write one operator setting in the user config.
    Config {
        #[command(subcommand)]
        action: ConfigAction,
    },
    /// Execute, inspect, or resume receipt-backed record erasure operations.
    Record {
        #[command(subcommand)]
        action: RecordAction,
    },
    /// Produce the operator pricing material a USD ceiling and a cost display require.
    Pricing {
        #[command(subcommand)]
        action: PricingAction,
    },
    /// Resolve or explain one explicit tunables request without binding it to a live run.
    Tunables {
        #[command(subcommand)]
        action: tunables::Action,
    },
    /// Run local configuration, recovery, and terminal diagnostics without contacting a provider.
    Doctor,
    /// Build a deterministic redacted support bundle; it is never transmitted by this command.
    Support {
        /// Create this new mode-0600 file instead of printing the bundle. Existing files are never
        /// overwritten.
        #[arg(long, value_name = "PATH")]
        output: Option<PathBuf>,
    },
    /// Manage signed, cached plugins without contacting a provider.
    Plugin {
        #[command(subcommand)]
        action: plugin::Action,
    },
    /// Configure, authenticate, test, and diagnose MCP servers.
    Mcp {
        #[command(subcommand)]
        action: mcp::commands::Action,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Subcommand)]
pub(crate) enum AuthAction {
    /// Print provider, api_root, credential source, validation state, and expiry.
    Status {
        /// Limit the report to one provider id.
        provider: Option<String>,
    },
    /// Remove the stored credential, leaving the provider entry intact.
    Logout {
        /// Limit the removal to one provider id.
        provider: Option<String>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Subcommand)]
pub(crate) enum ConfigAction {
    /// Print one persisted setting, or every settable key.
    Get {
        /// The setting to read; omit for all of them.
        key: Option<String>,
    },
    /// Persist one setting atomically at mode 0600.
    Set {
        /// The setting to write.
        key: String,
        /// Its new value.
        value: String,
    },
    /// Explain the exact immutable settings that would govern this run.
    Explain {
        /// Resolve the production composition root rather than an offline simulation.
        #[arg(long)]
        effective: bool,
        /// Limit output to one canonical family id or semantic key.
        #[arg(long)]
        family: Option<String>,
        /// Human text or machine-readable JSON.
        #[arg(long, value_enum, default_value_t = tunables::ExplainFormat::Text)]
        format: tunables::ExplainFormat,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Subcommand)]
pub(crate) enum RecordAction {
    /// Delete one inactive session and all private-content references owned only by it.
    Delete {
        run_id: String,
        #[arg(long, value_name = "ID")]
        operation_id: String,
    },
    /// Crypto-shred one content digest and invalidate every derivative handle.
    Revoke {
        digest: String,
        #[arg(long, value_name = "ID")]
        operation_id: String,
    },
    /// Apply a durable, resumable retention operation.
    Prune {
        #[arg(long, value_name = "DAYS")]
        older_than_days: Option<u64>,
        #[arg(long, value_name = "N")]
        keep_last: Option<u32>,
        #[arg(long, value_name = "ID")]
        operation_id: String,
    },
    /// Print one content-free erasure receipt.
    Receipt { operation_id: String },
    /// List the bounded receipt inventory, including incomplete operations.
    Receipts {
        #[arg(long, default_value_t = 200)]
        limit: usize,
    },
    /// Resume an incomplete operation from its durable receipt request.
    Resume { operation_id: String },
}

/// `iteron pricing …` — the shipped path from "I know what this model costs" to a run that reports a
/// dollar figure.
///
/// Rate cards default to empty, so the pricing port is never installed and any positive `--max-usd`
/// aborts at startup. Producing a card requires two route digests, a content digest and an HMAC
/// signature, and the routine that computes the last two was a library function with no subcommand
/// anywhere — so no public user could ever reach a priced run (I-40).
#[derive(Debug, Clone, PartialEq, Eq, Subcommand)]
pub(crate) enum PricingAction {
    /// Print the exact route a rate card must pin for the selected provider and model.
    PrintDigests,
    /// Sign an operator-authored rate card and print the `rate_cards[]` entry that installs it.
    Sign {
        /// Unsigned rate-card JSON: `{version, route, provenance, issued_at_unix_secs,
        /// expires_at_unix_secs, rates}`. Use `-` to read stdin.
        card: PathBuf,
        /// Environment variable holding exactly 32 bytes of hexadecimal HMAC key material. Only
        /// the NAME is written to the configuration; the bytes never leave this process.
        #[arg(long, default_value = "ITERON_PRICING_KEY")]
        key_env: String,
        /// Signer identity recorded on the artifact.
        #[arg(long, default_value = "pricing-root-v1")]
        signer_id: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Subcommand)]
pub(crate) enum WorkflowAction {
    /// Execute a workflow script now (agent()/parallel()/pipeline()/phase()/log()).
    Run {
        /// Path to the `.js` workflow script.
        script: PathBuf,
        /// JSON passed to the script as the ambient `args` (e.g. --args '{"n":3}').
        #[arg(long)]
        args: Option<String>,
    },
    /// List persisted workflow runs (id, status, agents, model) under the workflows dir.
    List,
    /// Resume a prior run by id, replaying its journaled agent outcomes and continuing (blocking).
    Resume {
        /// The prior run id (see `iteron workflow list`).
        run_id: String,
        /// Override the script source; defaults to the run's persisted `script.js`.
        #[arg(long)]
        script: Option<PathBuf>,
        /// Override the ambient `args`; defaults to the run's persisted args.
        #[arg(long)]
        args: Option<String>,
    },
    /// Re-launch a prior run in the BACKGROUND (RunHandle) and attach the live tree to it.
    Watch {
        /// The prior run id (see `iteron workflow list`).
        run_id: String,
        /// Override the ambient `args`; defaults to the run's persisted args.
        #[arg(long)]
        args: Option<String>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub(crate) enum TunablesExportFormat {
    Json,
    Table,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub(crate) enum HarnessProfileArg {
    Interactive,
    Benchmark,
    Research,
}

impl From<HarnessProfileArg> for iteron_tunables::RuntimeProfile {
    fn from(value: HarnessProfileArg) -> Self {
        match value {
            HarnessProfileArg::Interactive => Self::Interactive,
            HarnessProfileArg::Benchmark => Self::Benchmark,
            HarnessProfileArg::Research => Self::Research,
        }
    }
}

#[derive(Parser)]
#[command(
    name = "iteron",
    version,
    long_version = long_version(),
    about = "Iteron — a terminal-native coding agent built on a bounded controller."
)]
pub(crate) struct Cli {
    #[command(subcommand)]
    pub(crate) command: Option<LocalCommand>,

    /// The task for the agent to perform. Optional in --tui mode (type it in the UI).
    pub(crate) task: Option<String>,

    /// Force the interactive TUI (it is the default when a terminal is attached).
    #[arg(long)]
    pub(crate) tui: bool,

    /// One-shot / non-interactive: run the task, stream text, exit (like `claude -p`). Requires a
    /// task. Without -p, iteron opens the interactive TUI (the default).
    #[arg(short = 'p', long)]
    pub(crate) print: bool,

    /// Attach a local PNG, JPEG, GIF, or WebP to a one-shot task. On macOS, HEIC/HEIF is locally
    /// normalized to bounded JPEG. Repeat up to the attachment limit; bytes are sniffed before SQ.
    #[arg(long = "image", value_name = "PATH")]
    pub(crate) images: Vec<PathBuf>,

    /// One-shot stdout contract: text | json | stream-json. Machine formats keep stdout as valid
    /// JSON/JSONL; diagnostics continue on stderr. Only valid in one-shot mode.
    #[arg(long, value_enum, default_value = "text")]
    pub(crate) output_format: OutputFormat,

    /// Pin a published machine stdout schema. Supported versions are reported by
    /// `--machine-contract`; omission keeps the current v8 default.
    #[arg(long, value_name = "VERSION")]
    pub(crate) output_schema_version: Option<u32>,

    /// Print the bounded, provider-free CLI capability report as JSON and exit.
    #[arg(long)]
    pub(crate) machine_contract: bool,

    /// The repository to work in (defaults to the current directory).
    #[arg(short = 'C', long, default_value = ".")]
    pub(crate) repo: PathBuf,

    /// Model id (overrides config / default).
    #[arg(long)]
    pub(crate) model: Option<String>,

    /// Maximum provider turns, or `unlimited` (the default).
    #[arg(long, value_parser = config::parse_turn_limit)]
    pub(crate) max_turns: Option<u32>,

    /// Max spend in USD (bounded invariant; overrides config / default).
    #[arg(long)]
    pub(crate) max_usd: Option<f64>,

    /// Aggregate provider-token ceiling across this run and all descendants.
    #[arg(long)]
    pub(crate) max_tokens: Option<u64>,

    /// Consecutive failing tool calls before the run stops as stuck (stability floor; overrides
    /// the default of 50).
    #[arg(long, value_parser = clap::value_parser!(u32).range(1..))]
    pub(crate) max_consecutive_tool_errors: Option<u32>,

    /// Wall-clock ceiling for ONE submission, in seconds (bounded invariant; overrides config /
    /// default). The default is 86400s (24h).
    #[arg(long)]
    pub(crate) max_wall_secs: Option<u64>,

    /// Enable code execution (bash/build/test). ON by default; a
    /// trusted or project `allow_code: false`, or `--mode plan`, can tighten it back off.
    #[arg(long)]
    pub(crate) allow_code: bool,

    /// Tighten execution to the workspace sandbox even with the default dangerous bypass.
    /// The sandbox denies network and out-of-workspace shell writes, and fails
    /// closed if the platform cannot enforce it. Built-in file writers also reapply their
    /// workspace-write boundary when this flag is combined with dangerous bypass.
    #[arg(long)]
    pub(crate) confine: bool,

    /// Explicitly request dangerous bypass (already the default for fresh ordinary sessions).
    /// Without `--confine`, code has host authority. Plan mode and explicit denies still apply.
    #[arg(long)]
    pub(crate) dangerously_bypass_permissions: bool,

    /// Disable the fresh-session bypass and use `default` mode unless `--mode` was supplied.
    /// Execution is confined; one-shot (`-p`) refuses decisions requiring an interactive answer.
    /// On resume, this must agree with the recorded bypass authority.
    #[arg(long, conflicts_with = "dangerously_bypass_permissions")]
    pub(crate) ask_permissions: bool,

    /// Permission mode: default | acceptEdits | plan | yolo (ADR-007 §3). Reads always auto; the
    /// fresh default is `acceptEdits` with dangerous bypass. Explicit default/acceptEdits restores
    /// approval gates unless the dangerous flag is also given; plan is always confined read-only.
    #[arg(long)]
    pub(crate) mode: Option<String>,

    /// Directory for the append-only rollout (the audit record).
    #[arg(long, default_value = ".iteron/runs")]
    pub(crate) runs_dir: PathBuf,

    /// Internal eval-harness attempt identity. Activates strict parent-memory isolation and
    /// content-free contamination evidence; hidden because ordinary sessions must inherit memory.
    #[arg(long, hide = true, value_name = "ATTEMPT")]
    pub(crate) benchmark_attempt_scope: Option<String>,

    /// Immutable runtime-tunables profile. Benchmark attempts select `benchmark` automatically;
    /// ordinary runs select `interactive` unless this operator-owned flag says otherwise.
    #[arg(long, value_enum)]
    pub(crate) harness_profile: Option<HarnessProfileArg>,

    /// Operator/eval-harness pinned external implementation activation document.
    #[arg(
        long,
        hide = true,
        value_name = "PATH",
        requires = "implementation_candidate_digest"
    )]
    pub(crate) implementation_candidate: Option<PathBuf>,

    /// Exact lowercase SHA-256 of --implementation-candidate bytes.
    #[arg(
        long,
        hide = true,
        value_name = "SHA256",
        requires = "implementation_candidate"
    )]
    pub(crate) implementation_candidate_digest: Option<String>,

    /// Prepare a signed local plugin package for installation from the plugin management panel.
    /// Requires a configured plugin store; at most 16 operator-selected packages are retained.
    #[arg(long, value_name = "PACKAGE_PATH")]
    pub(crate) plugin_candidate: Vec<PathBuf>,

    /// Explicit local W3C ChromeDriver for optional fresh isolated browser/computer tools.
    /// Registration is not per-action external-effect approval. No driver is installed by default.
    #[arg(long, value_name = "LOOPBACK_HTTP_DRIVER", requires = "browser_origin")]
    pub(crate) browser_webdriver: Option<String>,

    /// Exact http(s) origin the isolated browser may contact; repeat at most 32 times.
    /// Only operator launch arguments supply this authority, never project/model configuration.
    #[arg(long, value_name = "ORIGIN", requires = "browser_webdriver")]
    pub(crate) browser_origin: Vec<String>,

    /// Explicit local Appium Mac2 driver for native desktop control and MAIN desktop screenshots.
    /// Registration does not authorize individual effects or isolate the operating system.
    #[arg(long, value_name = "LOOPBACK_HTTP_DRIVER", requires = "desktop_bundle")]
    pub(crate) desktop_webdriver: Option<String>,

    /// Native macOS application bundle selected by the operator, never project/model input.
    #[arg(long, value_name = "BUNDLE_ID", requires = "desktop_webdriver")]
    pub(crate) desktop_bundle: Option<String>,

    /// Print the whole machine-readable optimization surface as JSON and exit: every family,
    /// every exposed parameter, the module axis and the addressable prompt artifacts. This is
    /// what an external optimizer reads to construct a legal profile.
    #[arg(long)]
    pub(crate) tunables_export: bool,

    /// Apply a tunables profile document to this run. Requires --tunables-profile-digest; a
    /// candidate that can be swapped between digesting and applying is not pinned to anything.
    #[arg(long, value_name = "PATH")]
    pub(crate) tunables_profile: Option<PathBuf>,

    /// A tunables profile as inline JSON, for a one-off experiment. Mutually exclusive with
    /// --tunables-profile; neither can be digest-pinned, because bytes produced in the same breath
    /// as the claim about them have nothing prior to pin to.
    #[arg(long, value_name = "JSON", conflicts_with = "tunables_profile")]
    pub(crate) tunables_profile_json: Option<String>,

    /// Set one tunable for this run: `--set compaction_trigger=120000`. Repeatable. Accepts a
    /// family id, semantic key, alias, or exposed parameter id; the source kind is inferred from
    /// the family's own declared bindings.
    #[arg(long = "set", value_name = "KEY=VALUE")]
    pub(crate) set_tunable: Vec<String>,

    /// Print the exact assembled profile and whether each tier-2 parameter has a production use
    /// site, then exit without running anything.
    #[arg(long)]
    pub(crate) tunables_explain: bool,

    /// Restrict --tunables-export to one optimization module.
    #[arg(long, value_name = "MODULE")]
    pub(crate) tunables_module: Option<String>,

    /// Restrict --tunables-export to entries whose id or summary contains this substring.
    #[arg(long, value_name = "SUBSTRING")]
    pub(crate) tunables_filter: Option<String>,

    /// --tunables-export output shape: json for machines, table for a human scanning the surface.
    #[arg(long, value_enum, default_value_t = TunablesExportFormat::Json)]
    pub(crate) tunables_format: TunablesExportFormat,

    /// The SHA-256 the profile file must have. Any mismatch refuses the run.
    #[arg(long, value_name = "SHA256")]
    pub(crate) tunables_profile_digest: Option<String>,

    /// Write the profile that reproduces this run's effective tunables, then continue.
    #[arg(long, value_name = "PATH")]
    pub(crate) emit_tunables_profile: Option<PathBuf>,

    /// Resume a prior run by id: reconstruct its transcript from the rollout and continue
    /// (invariant #2, recoverable). When set, the task argument may be a follow-up instruction.
    #[arg(long)]
    pub(crate) resume: Option<String>,

    /// Continue the most recent session in this repo (like `claude --continue`).
    #[arg(short = 'c', long = "continue")]
    pub(crate) continue_recent: bool,

    /// List sessions in this repo (id, turns, model, cost, title) and exit.
    #[arg(long)]
    pub(crate) sessions: bool,

    /// How many sessions `--sessions` lists. Defaults to one page (200); the machine document
    /// keeps its published page ceiling and reports `truncated` instead.
    #[arg(long, value_name = "N")]
    pub(crate) limit: Option<usize>,

    /// Opaque continuation token returned by a prior `session_list_page`.
    #[arg(long, value_name = "TOKEN")]
    pub(crate) session_cursor: Option<String>,

    /// Maximum session rows in one machine page.
    #[arg(long, default_value_t = session_view::MAX_SESSIONS_PER_PAGE)]
    pub(crate) session_limit: usize,

    /// Bounded immutable grouping metadata for a fresh run, or an exact filter for `--sessions`.
    #[arg(long, value_name = "TAG")]
    pub(crate) agent_definition_tag: Option<String>,

    /// Read one session's transcript and exit. Pair with `--output-format json` for the machine
    /// document; a client should never open a file under `.iteron/runs` itself.
    #[arg(long, value_name = "RUN_ID")]
    pub(crate) transcript: Option<String>,

    /// Project one session into its OTel export payload and print it, without sending anything
    /// anywhere (#105). The offline half of the exporter: same projection the live sink ships, so
    /// an operator can see exactly what would leave the machine before enabling it.
    #[arg(long, value_name = "RUN_ID")]
    pub(crate) otel_export: Option<String>,

    /// Opaque continuation token returned by a prior `session_transcript_page`.
    #[arg(long, value_name = "TOKEN")]
    pub(crate) transcript_cursor: Option<String>,

    /// Read one session's latency timeline and exit: the per-class effect breakdown, the
    /// distribution behind it, and what could not be accounted for. Pair with
    /// `--output-format json` for the machine document. Purely offline -- it reads the
    /// hash-verified record and measures nothing itself.
    #[arg(long, value_name = "RUN_ID")]
    pub(crate) timeline: Option<String>,

    /// Fork a prior run at its tail into a new branch (shared past, divergent future) and print the
    /// new run id. The fork is tamper-evident: its genesis pins the parent chain's hash at the fork
    /// point (ADR-008 §4), so a later edit to the parent prefix is detected on resume.
    #[arg(long)]
    pub(crate) fork: Option<String>,

    /// Verification gate: a test command the harness runs itself when the agent claims done.
    /// If it fails, "done" is refused and the failure is fed back (don't trust the self-report).
    /// e.g. --verify "python3 -m pytest -q". Code execution must remain enabled (the default).
    #[arg(long)]
    pub(crate) verify: Option<String>,

    /// Trust an already-attested outer sandbox for --verify and skip Iteron's nested sandbox.
    /// DANGEROUS without that outer boundary: this flag does not itself confine filesystem or
    /// network access. Timeout, output limits, and credential-environment scrubbing still apply.
    #[arg(long, requires = "verify")]
    pub(crate) verify_preconfined: bool,

    /// Effort level: low | medium | high | xhigh | max | ultracode. Higher = more model reasoning
    /// budget; ultracode additionally exposes model-directed bounded workflows.
    #[arg(long)]
    pub(crate) effort: Option<String>,

    /// Provider instance id. Built-ins: anthropic, openai, deepseek, glm, minimax, fireworks.
    #[arg(long)]
    pub(crate) provider: Option<String>,

    /// Trusted one-run OpenAI-compatible API root, including its full path/version prefix. Prefer a
    /// named provider in ~/.iteron/config.json for persistent configuration. Requires --key-env.
    #[arg(long)]
    pub(crate) base_url: Option<String>,

    /// Environment variable holding the credential for --base-url. Required alongside it: without
    /// it a gateway would silently receive the default provider's key.
    #[arg(long, value_name = "NAME")]
    pub(crate) key_env: Option<String>,
}

#[cfg(all(test, not(feature = "legacy-plantcore")))]
mod standalone_tests {
    use super::{Cli, LocalCommand};
    use clap::Parser;

    #[test]
    fn actual_standalone_serve_parser_has_no_legacy_controls() {
        let cli = Cli::try_parse_from(["iteron", "serve"]).unwrap();
        assert!(matches!(
            cli.command,
            Some(LocalCommand::Serve {
                plantcore: false,
                recording_provider_ca_file: None,
                recording_inject_harness_error: false,
                recording_app_server_fault: None,
                ..
            })
        ));
        for option in [
            "--plantcore",
            "--recording-provider-ca-file",
            "--recording-inject-harness-error",
            "--recording-app-server-fault",
        ] {
            let error = Cli::try_parse_from(["iteron", "serve", option])
                .err()
                .expect("legacy option must be absent");
            assert_eq!(error.kind(), clap::error::ErrorKind::UnknownArgument);
        }
    }
}
