//! First-run setup, credential inspection, and the operator config writer.
//!
//! Before this module there was no setup, login or auth surface anywhere in the product: no
//! subcommand, no slash command, no wizard, and no supported way to persist a choice — both
//! non-test readers of the user config path were reads (I-25, I-27, I-28). A clean machine could
//! only be made to work by hand-writing `~/.iteron/config.json` and exporting the right variable,
//! and a syntactically valid but wrong key passed every startup check and failed on the first
//! paid turn.
//!
//! Three questions, one state machine: hosted plan or BYOK, which provider, paste the credential.
//! The answers are collected through [`Ask`] so the machine is testable without a terminal, and
//! nothing is written until the provider itself has accepted the credential on a real request.

use crate::config::{self, FileConfig, ProviderCredential};
use crate::providers;
use std::io::Write as _;

/// Which credential a wizard run is collecting.
///
/// The hosted plan is not a separate wizard: it is this one flag. A plan token is a credential
/// that expires, so it is stored as a file source with an expiry and re-read ahead of it, while a
/// BYOK key is the same file source with no expiry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SetupKind {
    HostedPlan,
    Byok,
}

impl SetupKind {
    fn label(self) -> &'static str {
        match self {
            Self::HostedPlan => "hosted plan",
            Self::Byok => "BYOK",
        }
    }
}

/// One completed wizard, independent of how the answers were obtained.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SetupAnswers {
    pub kind: SetupKind,
    pub provider_id: String,
    pub token: String,
    /// Present only for a hosted plan token, which rotates while Core is running.
    pub expires_at_unix: Option<u64>,
}

/// The question-asking side of the wizard, so the state machine can be exercised without a TTY.
pub(crate) trait Ask {
    /// Ask a question with a closed answer set. An empty answer selects `default`.
    fn choose(
        &mut self,
        question: &str,
        options: &[String],
        default: &str,
    ) -> anyhow::Result<String>;
    /// Ask for a credential, appending the visibility the implementation can actually deliver.
    ///
    /// An implementation that cannot suppress echo must say so rather than claim it did: the
    /// operator decides whether to paste a production key into a terminal that will remember it.
    fn secret(&mut self, question: &str) -> anyhow::Result<String>;
    /// Ask for an optional plain line.
    fn line(&mut self, question: &str) -> anyhow::Result<String>;
}

/// Run the three questions. Answers already supplied on the command line are not asked again, so
/// `iteron setup --byok glm` asks exactly one question and `iteron setup` asks three.
pub(crate) fn collect_answers(
    ask: &mut dyn Ask,
    kind: Option<SetupKind>,
    provider_id: Option<String>,
    known_providers: &[String],
) -> anyhow::Result<SetupAnswers> {
    let kind = match kind {
        Some(kind) => kind,
        None => {
            let answer = ask.choose(
                "Sign in with a hosted plan, or bring your own provider key?",
                &["plan".to_string(), "byok".to_string()],
                "byok",
            )?;
            match answer.as_str() {
                "plan" => SetupKind::HostedPlan,
                "byok" => SetupKind::Byok,
                other => anyhow::bail!("answer `{other}` is neither `plan` nor `byok`"),
            }
        }
    };
    let default_provider = known_providers
        .first()
        .cloned()
        .unwrap_or_else(|| "glm".into());
    let provider_id = match provider_id {
        Some(provider_id) => provider_id,
        None => ask.choose("Which provider?", known_providers, &default_provider)?,
    };
    if !known_providers.iter().any(|known| known == &provider_id) {
        anyhow::bail!(
            "provider `{provider_id}` is not configured (known: {}); declare it in ~/.iteron/config.json first",
            known_providers.join(", ")
        );
    }
    // Whether the line is actually hidden is a property of the terminal, not of this string, so
    // the implementation appends the claim it can keep.
    let token = ask.secret(&format!(
        "Paste the {} credential for `{provider_id}`",
        kind.label()
    ))?;
    let token = token.trim().to_owned();
    if token.is_empty() {
        anyhow::bail!("no credential was entered");
    }
    let expires_at_unix = match kind {
        SetupKind::Byok => None,
        SetupKind::HostedPlan => {
            let answer = ask.line(
                "Unix timestamp this plan token expires at (blank if it does not expire): ",
            )?;
            let answer = answer.trim();
            if answer.is_empty() {
                None
            } else {
                Some(
                    answer
                        .parse::<u64>()
                        .map_err(|_| anyhow::anyhow!("`{answer}` is not a unix timestamp"))?,
                )
            }
        }
    };
    Ok(SetupAnswers {
        kind,
        provider_id,
        token,
        expires_at_unix,
    })
}

/// The bytes a credential file holds for one set of answers.
///
/// A bare token is the simple BYOK case; a plan token becomes a document so its expiry travels
/// with it and [`iteron_provider::CredentialSource`] can refresh ahead of it without a restart.
pub(crate) fn credential_document(answers: &SetupAnswers) -> String {
    match answers.expires_at_unix {
        Some(expires_at_unix) => format!(
            "{}\n",
            serde_json::json!({ "token": answers.token, "expires_at_unix": expires_at_unix })
        ),
        None => format!("{}\n", answers.token),
    }
}

/// Persist a validated credential and make it the active route.
///
/// Every byte written here goes through the one atomic 0600 writer: the credential file through
/// [`config::write_private_atomic`], the config document through [`config::update_user_config`].
/// A built-in provider needs no config entry at all — it picks the file up when its environment
/// variable is absent — while a configured provider has its `credential` repointed at the file.
pub(crate) fn persist(answers: &SetupAnswers) -> anyhow::Result<std::path::PathBuf> {
    let path = config::credential_file_path(&answers.provider_id).ok_or_else(|| {
        anyhow::anyhow!(
            "no config root: set HOME or ITERON_CONFIG_HOME before running setup, and use a plain provider id"
        )
    })?;
    config::write_private_atomic(&path, credential_document(answers).as_bytes())?;
    let provider_id = answers.provider_id.clone();
    let credential = ProviderCredential::File {
        path: path.display().to_string(),
    };
    config::update_user_config(move |config| {
        if let Some(providers) = config.providers.as_mut()
            && let Some(configured) = providers
                .iter_mut()
                .find(|configured| configured.id == provider_id)
        {
            configured.credential = Some(credential.clone());
            configured.key_env = None;
        }
        config.provider = Some(provider_id.clone());
        Ok(())
    })?;
    Ok(path)
}

/// One invocation of setup, however the operator spelled it.
///
/// The non-interactive fields exist because a wizard is not a provisioning interface. Setup that
/// can only run at a terminal cannot run in CI, in a container image, from a configuration
/// management run, or from an agent, which left "export the variable and hand-write
/// `config.json`" as the only automatable path -- exactly the state this module was written to
/// end.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct SetupRequest {
    pub kind: Option<SetupKind>,
    pub provider_id: Option<String>,
    /// Take the credential from stdin and ask nothing.
    pub read_credential_from_stdin: bool,
    pub expires_at_unix: Option<u64>,
}

/// Read a credential from stdin for `--stdin`.
///
/// A credential is passed this way precisely so it never becomes an argument, where the process
/// table and the shell history would both see it. Trailing newlines are stripped because `printenv`
/// and here-strings add one; interior whitespace is not, because no provider issues a key
/// containing it and silently repairing a malformed key would hide the operator's mistake until
/// the first paid turn.
fn read_credential_from_stdin() -> anyhow::Result<String> {
    use std::io::Read as _;
    let mut buffer = String::new();
    std::io::stdin().read_to_string(&mut buffer)?;
    Ok(buffer)
}

/// Assemble the answers a `--stdin` run supplies entirely from flags and the piped credential.
///
/// Everything a wizard would have asked must already be on the command line. Refusing here, by
/// name, beats prompting into a pipe that will never answer.
fn answers_without_a_terminal(
    request: &SetupRequest,
    known: &[String],
    piped: &str,
) -> anyhow::Result<SetupAnswers> {
    let kind = request.kind.ok_or_else(|| {
        anyhow::anyhow!(
            "`--stdin` cannot ask which credential this is; pass `--byok <provider>` or `--plan`"
        )
    })?;
    let provider_id = request.provider_id.clone().ok_or_else(|| {
        anyhow::anyhow!("`--stdin` cannot ask which provider this is; pass `--byok <provider>` or `--provider <provider>`")
    })?;
    if !known.iter().any(|id| id == &provider_id) {
        anyhow::bail!(
            "provider `{provider_id}` is not configured (known: {}); declare it in ~/.iteron/config.json first",
            known.join(", ")
        );
    }
    if kind == SetupKind::Byok && request.expires_at_unix.is_some() {
        anyhow::bail!("`--expires-at` describes a hosted-plan token; a BYOK key does not expire");
    }
    // `printenv` and here-strings both add a trailing newline. Interior whitespace is left alone:
    // no provider issues a key containing it, and silently repairing a malformed one would hide
    // the operator's mistake until the first paid turn.
    let token = piped.trim_matches(['\r', '\n']).to_owned();
    if token.is_empty() {
        anyhow::bail!("no credential arrived on stdin");
    }
    Ok(SetupAnswers {
        kind,
        provider_id,
        token,
        expires_at_unix: request.expires_at_unix,
    })
}

/// `iteron setup`, `iteron setup --plan`, `iteron setup --byok <provider>`.
pub(crate) async fn run_setup(request: SetupRequest) -> anyhow::Result<u8> {
    let user_file = FileConfig::load_user()?;
    let configured = user_file.providers.clone().unwrap_or_default();
    let known = providers::configured_provider_ids(&configured);
    let answers = if request.read_credential_from_stdin {
        answers_without_a_terminal(&request, &known, &read_credential_from_stdin()?)?
    } else {
        let mut ask = TerminalAsk::new()?;
        let mut answers =
            collect_answers(&mut ask, request.kind, request.provider_id.clone(), &known)?;
        // A `--expires-at` supplied on the command line is an answer already given, so the wizard
        // must not ask for it again. It is refused on a BYOK key for the same reason the piped
        // path refuses it: an expiry on a key that never expires would stop working on a date
        // nobody chose.
        if let Some(expires_at_unix) = request.expires_at_unix {
            if answers.kind == SetupKind::Byok {
                anyhow::bail!(
                    "`--expires-at` describes a hosted-plan token; a BYOK key does not expire"
                );
            }
            answers.expires_at_unix = Some(expires_at_unix);
        }
        answers
    };

    eprintln!("checking the credential against `{}`…", answers.provider_id);
    let proof =
        match providers::validate_credential(&answers.provider_id, &configured, &answers.token)
            .await
        {
            Ok(proof) => proof,
            Err(reason) => {
                // Refuse BEFORE writing. A rejected key that has already been persisted is worse
                // than no setup at all: the next launch looks configured and fails on a paid turn.
                eprintln!("setup failed: {reason}");
                eprintln!("nothing was written; the previous credential (if any) is untouched.");
                return Ok(crate::output::EXIT_HARNESS);
            }
        };
    eprintln!(
        "credential accepted by `{}` on model `{}`",
        answers.provider_id, proof.model_id
    );

    let path = persist(&answers)?;
    eprintln!("wrote {} (mode 0600)", path.display());

    // Re-run discovery through exactly the path a normal launch takes, so what setup prints is
    // what the next launch will do — including the blocked reason, if the route is still not
    // usable for a reason a single request could not show.
    let user_file = FileConfig::load_user()?;
    let configured = user_file.providers.clone().unwrap_or_default();
    let directory = providers::ProviderDirectory::discover(&configured).await?;
    match directory.entry(&answers.provider_id) {
        Some(entry) => {
            eprintln!("credential: {}", entry.credential_display());
            match directory.blocked_reason(entry) {
                Some(reason) => eprintln!("still blocked: {reason}"),
                None => match directory.default_selection(&answers.provider_id) {
                    Some(selection) => eprintln!(
                        "ready: {}:{} — run `iteron` to start",
                        selection.provider_id, selection.model_id
                    ),
                    None => eprintln!("{}", directory.resolution_error(&answers.provider_id)),
                },
            }
        }
        None => eprintln!("{}", directory.resolution_error(&answers.provider_id)),
    }
    Ok(crate::output::EXIT_SUCCESS)
}

/// `iteron auth status [provider]` — where the current credential came from, and whether it works.
pub(crate) async fn run_auth_status(provider_id: Option<String>) -> anyhow::Result<u8> {
    let user_file = FileConfig::load_user()?;
    let configured = user_file.providers.clone().unwrap_or_default();
    // Status reports value-free local credential provenance. It does not synchronously probe every
    // endpoint the machine has ever configured: a black-holed provider must not hang `iteron auth`,
    // and absent live evidence is rendered honestly as an unknown account state.
    let directory = providers::ProviderDirectory::inspect_local(&configured)?;
    // Which provider a run would route to, and which providers this report covers, are two
    // different questions. Deriving `(active)` from the filter argument would mark whatever the
    // operator asked about as active, which is the opposite of what they are asking.
    let active = user_file.provider.clone();
    // With no argument this is a listing, so it reports what the operator can act on: every
    // provider he declared, plus the built-ins this machine actually holds a credential for. A
    // built-in with no credential is a known endpoint, not an account, and printing six of them
    // buries the two lines that matter. Naming one explicitly is a question rather than a listing
    // and always answers, even when it is filtered out of the listing — that is how an operator
    // finds the variable to export for a provider he has not set up yet.
    let listed: Vec<_> = match &provider_id {
        Some(filter) => directory
            .entries()
            .iter()
            .filter(|entry| entry.id() == filter)
            .collect(),
        None => directory.offerable_entries().collect(),
    };
    for entry in listed {
        let status = entry.instance.credential_status();
        println!(
            "{}{}",
            entry.id(),
            if active.as_deref() == Some(entry.id()) {
                "  (active)"
            } else {
                ""
            }
        );
        // Which of these lines the operator is responsible for. Without it the report is nine
        // providers with no way to tell what he wrote from what the binary ships.
        println!("  origin:      {}", entry.origin().label());
        println!("  api_root:    {}", entry.instance.api_root().as_str());
        // The service actually reached. Several entries sharing one host are access methods for one
        // account, not separate vendors, which is what three DeepSeek spellings otherwise imply.
        println!("  service:     {}", entry.service_key());
        println!("  credential:  {} {}", status.kind.label(), status.name);
        println!(
            "  present:     {}",
            if status.present { "yes" } else { "no" }
        );
        println!(
            "  expires_at:  {}",
            status
                .expires_at_unix
                .map(|value| value.to_string())
                .unwrap_or_else(|| "never".into())
        );
        println!(
            "  validation:  {}",
            directory
                .blocked_reason(entry)
                .unwrap_or_else(|| directory.status_label(entry))
        );
        if let Some(error) = status.error {
            println!("  note:        {error}");
        }
    }
    Ok(crate::output::EXIT_SUCCESS)
}

/// `iteron auth logout [provider]` — drop the credential, keep everything else.
///
/// The provider entry, its api_root, its declared models and its capabilities all survive: logging
/// out of an account is not the same as deleting the route to it. Only the credential file is
/// removed, which is why the config entry keeps pointing at a path that now resolves to absent.
pub(crate) async fn run_auth_logout(provider_id: Option<String>) -> anyhow::Result<u8> {
    let user_file = FileConfig::load_user()?;
    let configured = user_file.providers.clone().unwrap_or_default();
    let known = providers::configured_provider_ids(&configured);
    let targets: Vec<String> = match provider_id {
        Some(provider_id) => {
            if !known.iter().any(|id| id == &provider_id) {
                anyhow::bail!(
                    "provider `{provider_id}` is not configured (known: {})",
                    known.join(", ")
                );
            }
            vec![provider_id]
        }
        None => known,
    };
    let mut removed = 0;
    for target in &targets {
        let Some(path) = config::credential_file_path(target) else {
            continue;
        };
        if path.exists() {
            std::fs::remove_file(&path)?;
            println!("{target}: removed {}", path.display());
            removed += 1;
        }
        if let Some(name) = configured
            .iter()
            .find(|configured| &configured.id == target)
            .and_then(|configured| configured.resolved_credential().ok())
            .as_ref()
            .and_then(ProviderCredential::env_name)
        {
            println!(
                "{target}: credential comes from the environment variable {name}; unset it in your shell to finish signing out"
            );
        }
    }
    if removed == 0 {
        println!("no stored credential file to remove");
    }
    Ok(crate::output::EXIT_SUCCESS)
}

/// `iteron config get [key]` — the persisted operator value, never the layered runtime value.
pub(crate) fn run_config_get(key: Option<String>) -> anyhow::Result<u8> {
    let user_file = FileConfig::load_user()?;
    match key {
        Some(key) => {
            if !config::settable_keys().contains(&key.as_str()) {
                anyhow::bail!(
                    "unknown config key `{key}`; settable keys: {}",
                    config::settable_keys().join(", ")
                );
            }
            match config::setting_value(&user_file, &key) {
                Some(value) => println!("{value}"),
                None => println!("(unset)"),
            }
        }
        None => {
            for key in config::settable_keys() {
                println!(
                    "{key} = {}",
                    config::setting_value(&user_file, key).unwrap_or_else(|| "(unset)".into())
                );
            }
        }
    }
    Ok(crate::output::EXIT_SUCCESS)
}

/// `iteron config set <key> <value>` — THE writer. Every other persist path calls into it.
pub(crate) fn run_config_set(key: &str, value: &str) -> anyhow::Result<u8> {
    let path = config::set_user_setting(key, value)?;
    println!("{key} = {value}  ({})", path.display());
    Ok(crate::output::EXIT_SUCCESS)
}

/// The terminal implementation of [`Ask`]. Kept out of the state machine so the machine has no
/// terminal dependency and can be tested exhaustively.
/// Terminal echo, switched off for as long as this value lives.
///
/// Restoration happens in `Drop` rather than after the read, so an error or a panic between the
/// two cannot leave the operator at a shell that has stopped showing what they type.
struct EchoGuard {
    #[cfg(unix)]
    fd: std::os::fd::RawFd,
    #[cfg(unix)]
    original: libc::termios,
}

impl EchoGuard {
    /// Turn echo off, or report that this terminal does not allow it.
    #[cfg(unix)]
    fn suppress() -> Option<Self> {
        use std::os::fd::AsRawFd as _;
        let fd = std::io::stdin().as_raw_fd();
        let mut original: libc::termios = unsafe { std::mem::zeroed() };
        // SAFETY: `fd` is this process's stdin, and `original` is a live, correctly sized
        // `termios` this call is allowed to fill.
        if unsafe { libc::tcgetattr(fd, &mut original) } != 0 {
            return None;
        }
        let mut quiet = original;
        quiet.c_lflag &= !libc::ECHO;
        // SAFETY: same descriptor, and `quiet` is the attribute set just read with one flag
        // cleared. TCSAFLUSH discards anything typed ahead of the prompt, so a keystroke buffered
        // before echo went off cannot be echoed afterwards.
        if unsafe { libc::tcsetattr(fd, libc::TCSAFLUSH, &quiet) } != 0 {
            return None;
        }
        Some(Self { fd, original })
    }

    #[cfg(not(unix))]
    fn suppress() -> Option<Self> {
        None
    }
}

impl Drop for EchoGuard {
    fn drop(&mut self) {
        #[cfg(unix)]
        // SAFETY: restores exactly the attributes `suppress` read from this same descriptor.
        unsafe {
            libc::tcsetattr(self.fd, libc::TCSAFLUSH, &self.original);
        }
    }
}

struct TerminalAsk {
    stdin: std::io::Stdin,
}

impl TerminalAsk {
    fn new() -> anyhow::Result<Self> {
        use std::io::IsTerminal as _;
        if !std::io::stdin().is_terminal() {
            anyhow::bail!(
                "iteron setup asks questions and needs a terminal; run it directly, or set the credential with `iteron config set` and an environment variable"
            );
        }
        Ok(Self {
            stdin: std::io::stdin(),
        })
    }

    fn read_line(&mut self) -> anyhow::Result<String> {
        let mut buffer = String::new();
        if self.stdin.read_line(&mut buffer)? == 0 {
            anyhow::bail!("setup was cancelled");
        }
        Ok(buffer.trim_end_matches(['\r', '\n']).to_owned())
    }
}

impl Ask for TerminalAsk {
    fn choose(
        &mut self,
        question: &str,
        options: &[String],
        default: &str,
    ) -> anyhow::Result<String> {
        loop {
            eprint!("{question} [{}] ({default}): ", options.join("/"));
            std::io::stderr().flush()?;
            let answer = self.read_line()?;
            let answer = if answer.trim().is_empty() {
                default.to_owned()
            } else {
                answer.trim().to_owned()
            };
            if options.iter().any(|option| option == &answer) {
                return Ok(answer);
            }
            eprintln!("`{answer}` is not one of {}", options.join(", "));
        }
    }

    fn secret(&mut self, question: &str) -> anyhow::Result<String> {
        // Suppress echo before the prompt is drawn, so what the prompt claims is already true by
        // the time anyone can type. Whether it worked decides which claim is printed: this line
        // used to promise "input is not echoed" while reading a plain, fully echoed line, which
        // put every pasted credential into terminal scrollback.
        let quiet = EchoGuard::suppress();
        eprint!(
            "{question}{}: ",
            if quiet.is_some() {
                " (input is not echoed)"
            } else {
                " (input will be visible)"
            }
        );
        std::io::stderr().flush()?;
        let answer = self.read_line();
        if quiet.is_some() {
            // The terminal swallowed the operator's Enter along with the credential.
            eprintln!();
        }
        drop(quiet);
        answer
    }

    fn line(&mut self, question: &str) -> anyhow::Result<String> {
        eprint!("{question}");
        std::io::stderr().flush()?;
        self.read_line()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A scripted operator: answers in order, and records the questions it was asked.
    struct Scripted {
        answers: Vec<String>,
        asked: Vec<String>,
    }

    impl Scripted {
        fn new(answers: &[&str]) -> Self {
            Self {
                answers: answers.iter().map(|answer| (*answer).to_owned()).collect(),
                asked: Vec::new(),
            }
        }

        fn next(&mut self, question: &str) -> anyhow::Result<String> {
            self.asked.push(question.to_owned());
            if self.answers.is_empty() {
                anyhow::bail!("the wizard asked more questions than the script answers");
            }
            Ok(self.answers.remove(0))
        }
    }

    impl Ask for Scripted {
        fn choose(
            &mut self,
            question: &str,
            _options: &[String],
            default: &str,
        ) -> anyhow::Result<String> {
            let answer = self.next(question)?;
            Ok(if answer.is_empty() {
                default.to_owned()
            } else {
                answer
            })
        }

        fn secret(&mut self, question: &str) -> anyhow::Result<String> {
            self.next(question)
        }

        fn line(&mut self, question: &str) -> anyhow::Result<String> {
            self.next(question)
        }
    }

    fn known() -> Vec<String> {
        vec!["glm".into(), "anthropic".into(), "kimi".into()]
    }

    /// I-27 — there was no setup surface at all. The wizard is exactly three questions, and BYOK
    /// is the default branch so an operator who just presses enter ends up bringing their own key.
    #[test]
    fn i27_the_wizard_is_three_questions_and_byok_is_one_branch() {
        let mut ask = Scripted::new(&["", "kimi", "sk-live-token"]);
        let answers = collect_answers(&mut ask, None, None, &known()).unwrap();
        assert_eq!(
            answers,
            SetupAnswers {
                kind: SetupKind::Byok,
                provider_id: "kimi".into(),
                token: "sk-live-token".into(),
                expires_at_unix: None,
            }
        );
        assert_eq!(ask.asked.len(), 3, "asked: {:?}", ask.asked);
        assert_eq!(credential_document(&answers), "sk-live-token\n");
    }

    /// The hosted plan is the SAME machine with one flag: it takes an expiry, which is what makes
    /// the stored credential refreshable without a restart.
    #[test]
    fn i27_the_hosted_plan_is_one_branch_of_the_same_wizard() {
        let mut ask = Scripted::new(&["plan-token", "1893456000"]);
        let answers = collect_answers(
            &mut ask,
            Some(SetupKind::HostedPlan),
            Some("glm".into()),
            &known(),
        )
        .unwrap();
        assert_eq!(answers.kind, SetupKind::HostedPlan);
        assert_eq!(answers.expires_at_unix, Some(1_893_456_000));
        let document = credential_document(&answers);
        assert!(
            document.contains("\"expires_at_unix\":1893456000"),
            "{document}"
        );
        assert!(
            document.starts_with('{'),
            "an expiring token must be stored as a document so the expiry travels with it"
        );
    }

    /// Answers already supplied on the command line are not asked again.
    #[test]
    fn i27_supplied_answers_are_not_asked_again() {
        let mut ask = Scripted::new(&["sk-1"]);
        let answers = collect_answers(
            &mut ask,
            Some(SetupKind::Byok),
            Some("glm".into()),
            &known(),
        )
        .unwrap();
        assert_eq!(answers.provider_id, "glm");
        assert_eq!(ask.asked.len(), 1, "asked: {:?}", ask.asked);
    }

    /// A provider the configuration cannot route to is refused before a credential is collected
    /// into a file for a route that does not exist.
    #[test]
    fn i27_an_unknown_provider_is_refused() {
        let mut ask = Scripted::new(&["sk-1"]);
        let error = collect_answers(
            &mut ask,
            Some(SetupKind::Byok),
            Some("nope".into()),
            &known(),
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("`nope` is not configured"), "{error}");
        assert!(
            error.contains("glm"),
            "the error must list the real ids: {error}"
        );
    }

    /// An empty paste is not a credential. Writing it would produce a config that looks complete
    /// and fails on the first turn — the exact failure the wizard exists to remove.
    #[test]
    fn i27_an_empty_credential_is_refused() {
        let mut ask = Scripted::new(&["   "]);
        let error = collect_answers(
            &mut ask,
            Some(SetupKind::Byok),
            Some("glm".into()),
            &known(),
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("no credential"), "{error}");
    }

    fn stdin_request(kind: SetupKind, provider: &str) -> SetupRequest {
        SetupRequest {
            kind: Some(kind),
            provider_id: Some(provider.into()),
            read_credential_from_stdin: true,
            expires_at_unix: None,
        }
    }

    /// The wizard could only ever run at a terminal, which left "export the variable and
    /// hand-write config.json" as the only path available to CI, a container build, a
    /// configuration management run, or an agent. Piping the credential answers every question.
    #[test]
    fn a_piped_credential_needs_no_terminal() {
        let answers = answers_without_a_terminal(
            &stdin_request(SetupKind::Byok, "kimi"),
            &known(),
            "sk-live-token\n",
        )
        .unwrap();
        assert_eq!(
            answers,
            SetupAnswers {
                kind: SetupKind::Byok,
                provider_id: "kimi".into(),
                token: "sk-live-token".into(),
                expires_at_unix: None,
            }
        );
        assert_eq!(credential_document(&answers), "sk-live-token\n");
    }

    /// Only the trailing newline every pipe adds is removed. A key with interior whitespace is
    /// wrong, and repairing it here would surface the mistake on a paid turn instead of now.
    #[test]
    fn only_the_trailing_newline_is_stripped() {
        let answers = answers_without_a_terminal(
            &stdin_request(SetupKind::Byok, "glm"),
            &known(),
            "sk with space\r\n",
        )
        .unwrap();
        assert_eq!(answers.token, "sk with space");
    }

    /// A hosted-plan expiry is supplied by flag, because there is no prompt left to ask it in.
    #[test]
    fn a_piped_plan_token_takes_its_expiry_from_the_flag() {
        let mut request = stdin_request(SetupKind::HostedPlan, "glm");
        request.expires_at_unix = Some(1_893_456_000);
        let answers = answers_without_a_terminal(&request, &known(), "plan-token\n").unwrap();
        assert_eq!(answers.expires_at_unix, Some(1_893_456_000));
        assert!(
            credential_document(&answers).contains("\"expires_at_unix\":1893456000"),
            "the expiry must travel with the stored token"
        );
    }

    /// An expiry on a BYOK key is a category error, not a harmless extra flag: it would make a key
    /// that never expires look like one that does, and stop working on a date nobody chose.
    #[test]
    fn an_expiry_on_a_byok_key_is_refused() {
        let mut request = stdin_request(SetupKind::Byok, "glm");
        request.expires_at_unix = Some(1_893_456_000);
        let error = answers_without_a_terminal(&request, &known(), "sk-1\n")
            .unwrap_err()
            .to_string();
        assert!(error.contains("does not expire"), "{error}");
    }

    /// Piping cannot answer a question, so anything the wizard would have asked must already be on
    /// the command line. Each refusal names the flag that supplies the missing answer.
    #[test]
    fn a_piped_run_refuses_by_naming_the_missing_flag() {
        let mut without_kind = stdin_request(SetupKind::Byok, "glm");
        without_kind.kind = None;
        let error = answers_without_a_terminal(&without_kind, &known(), "sk-1\n")
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("--byok") && error.contains("--plan"),
            "{error}"
        );

        let mut without_provider = stdin_request(SetupKind::Byok, "glm");
        without_provider.provider_id = None;
        let error = answers_without_a_terminal(&without_provider, &known(), "sk-1\n")
            .unwrap_err()
            .to_string();
        assert!(error.contains("--provider"), "{error}");

        let error =
            answers_without_a_terminal(&stdin_request(SetupKind::Byok, "nope"), &known(), "sk-1\n")
                .unwrap_err()
                .to_string();
        assert!(error.contains("`nope` is not configured"), "{error}");

        let error =
            answers_without_a_terminal(&stdin_request(SetupKind::Byok, "glm"), &known(), "\n")
                .unwrap_err()
                .to_string();
        assert!(error.contains("no credential arrived on stdin"), "{error}");
    }
}
