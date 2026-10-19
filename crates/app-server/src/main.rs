//! Independent AppServer executable. It owns no terminal renderer or input event loop.

use clap::Parser;
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(
    name = "iteron-app-server",
    version,
    long_version = iteron_host::cli_entry::build_identity::long_version(),
    about = "Iteron AppServer — authenticated local sessions for independent clients."
)]
struct ServerArgs {
    /// Workspace whose tools and sessions the server owns.
    #[arg(short = 'C', long, default_value = ".")]
    repo: PathBuf,
    /// Loopback TCP endpoint. Port zero allocates an available port.
    #[arg(long, default_value = "127.0.0.1:0")]
    listen: std::net::SocketAddr,
    /// Let authenticated clients answer permission prompts.
    #[arg(long)]
    client_approvals: bool,
    /// Print the provider-free protocol and build contract, then exit.
    #[arg(long)]
    machine_contract: bool,
    #[arg(long)]
    provider: Option<String>,
    #[arg(long)]
    model: Option<String>,
    #[arg(long)]
    base_url: Option<String>,
    /// Credential environment variable name; never a credential value.
    #[arg(long)]
    key_env: Option<String>,
    #[arg(long, default_value = ".iteron/runs")]
    runs_dir: PathBuf,
    #[arg(long)]
    resume: Option<String>,
    #[arg(short = 'c', long = "continue")]
    continue_recent: bool,
    #[arg(long)]
    archive_requests: bool,
    #[arg(long)]
    allow_code: bool,
    #[arg(long)]
    confine: bool,
    #[arg(long, conflicts_with = "ask_permissions")]
    dangerously_bypass_permissions: bool,
    #[arg(long, conflicts_with = "dangerously_bypass_permissions")]
    ask_permissions: bool,
    #[arg(long)]
    mode: Option<String>,
    #[arg(long)]
    effort: Option<String>,
    #[arg(long, value_parser = iteron_host::config::parse_turn_limit)]
    max_turns: Option<u32>,
    #[arg(long)]
    max_tokens: Option<u64>,
    #[arg(long)]
    max_usd: Option<f64>,
    #[arg(long)]
    max_wall_secs: Option<u64>,
    #[arg(long, value_parser = clap::value_parser!(u32).range(1..))]
    max_consecutive_tool_errors: Option<u32>,
    #[arg(long)]
    verify: Option<String>,
    #[arg(long, requires = "verify")]
    verify_preconfined: bool,
    #[arg(long)]
    agent_definition_tag: Option<String>,
    #[arg(long)]
    tunables_profile: Option<PathBuf>,
    #[arg(long)]
    tunables_profile_digest: Option<String>,
    #[arg(long = "set")]
    set_tunable: Vec<String>,
}

impl ServerArgs {
    fn into_launch(self) -> iteron_host::cli_entry::Cli {
        let mut launch =
            iteron_host::cli_entry::Cli::for_server(self.listen, self.client_approvals);
        launch.repo = self.repo;
        launch.provider = self.provider;
        launch.model = self.model;
        launch.base_url = self.base_url;
        launch.key_env = self.key_env;
        launch.runs_dir = self.runs_dir;
        launch.resume = self.resume;
        launch.continue_recent = self.continue_recent;
        launch.archive_requests = self.archive_requests;
        launch.allow_code = self.allow_code;
        launch.confine = self.confine;
        launch.dangerously_bypass_permissions = self.dangerously_bypass_permissions;
        launch.ask_permissions = self.ask_permissions;
        launch.mode = self.mode;
        launch.effort = self.effort;
        launch.max_turns = self.max_turns;
        launch.max_tokens = self.max_tokens;
        launch.max_usd = self.max_usd;
        launch.max_wall_secs = self.max_wall_secs;
        launch.max_consecutive_tool_errors = self.max_consecutive_tool_errors;
        launch.verify = self.verify;
        launch.verify_preconfined = self.verify_preconfined;
        launch.agent_definition_tag = self.agent_definition_tag;
        launch.tunables_profile = self.tunables_profile;
        launch.tunables_profile_digest = self.tunables_profile_digest;
        launch.set_tunable = self.set_tunable;
        launch
    }
}

// Construct large launch futures in a separate frame on Windows's default main-thread stack.
#[cfg(windows)]
#[inline(never)]
fn boxed_startup_future<F: std::future::Future>(
    construct: impl FnOnce() -> F,
) -> std::pin::Pin<Box<F>> {
    Box::pin(construct())
}

fn main() -> std::process::ExitCode {
    let mut arguments = std::env::args_os().skip(1);
    if arguments.next().as_deref() == Some(std::ffi::OsStr::new("--internal-confined-write")) {
        if arguments.next().is_some() {
            eprintln!("error: internal confined write helper accepts no extra arguments");
            return std::process::ExitCode::from(iteron_host::output::EXIT_HARNESS);
        }
        std::process::exit(iteron_tools::confined_helper_entry());
    }
    if iteron_host::client_effects::worker_requested() {
        return std::process::ExitCode::from(iteron_host::client_effects::worker_main());
    }
    let args = ServerArgs::parse();
    let result = if args.machine_contract {
        print_contract()
    } else {
        run(args)
    };
    match result {
        Ok(code) => std::process::ExitCode::from(code),
        Err(error) => {
            eprintln!(
                "error: {}",
                iteron_record::redact::scrub(&format!("{error:#}"))
            );
            std::process::ExitCode::from(iteron_host::output::EXIT_HARNESS)
        }
    }
}

fn print_contract() -> anyhow::Result<u8> {
    let shared: serde_json::Value =
        serde_json::from_str(&iteron_host::machine_contract::render()?)?;
    println!(
        "{}",
        serde_json::json!({
            "application": "iteron-app-server",
            "version": env!("CARGO_PKG_VERSION"),
            "build_commit": iteron_host::cli_entry::BUILD_COMMIT,
            "build_date": iteron_host::cli_entry::BUILD_DATE,
            "protocol_version": iteron_protocol::PROTOCOL_VERSION,
            "transport": "authenticated-loopback-jsonl",
            "terminal_frontend": false,
            "shared_contract": shared,
        })
    );
    Ok(iteron_host::output::EXIT_SUCCESS)
}

fn run(args: ServerArgs) -> anyhow::Result<u8> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    #[cfg(windows)]
    let launch = boxed_startup_future(|| iteron_host::server::run(args.into_launch()));
    #[cfg(not(windows))]
    let launch = iteron_host::server::run(args.into_launch());
    runtime.block_on(launch)
}
