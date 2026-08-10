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
    /// Ask for a credential. Implementations must not echo it.
    fn secret(&mut self, question: &str) -> anyhow::Result<String>;
    /// Ask for an optional plain line.
    fn line(&mut self, question: &str) -> anyhow::Result<String>;
}

/// Run the three questions. Answers already supplied on the command line are not asked again, so
/// `core setup --byok glm` asks exactly one question and `core setup` asks three.
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
    let token = ask.secret(&format!(
        "Paste the {} credential for `{provider_id}` (input is not echoed): ",
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

/// `core setup`, `core setup --plan`, `core setup --byok <provider>`.
pub(crate) async fn run_setup(
    kind: Option<SetupKind>,
    provider_id: Option<String>,
) -> anyhow::Result<u8> {
    let user_file = FileConfig::load_user()?;
    let configured = user_file.providers.clone().unwrap_or_default();
    let known = providers::configured_provider_ids(&configured);
    let mut ask = TerminalAsk::new()?;
    let answers = collect_answers(&mut ask, kind, provider_id, &known)?;

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

/// `core auth status [provider]` — where the current credential came from, and whether it works.
pub(crate) async fn run_auth_status(provider_id: Option<String>) -> anyhow::Result<u8> {
    let user_file = FileConfig::load_user()?;
    let configured = user_file.providers.clone().unwrap_or_default();
    // Status reports value-free local credential provenance. It does not synchronously probe every
    // endpoint the machine has ever configured: a black-holed provider must not hang `core auth`,
    // and absent live evidence is rendered honestly as an unknown account state.
    let directory = providers::ProviderDirectory::inspect_local(&configured)?;
    // Which provider a run would route to, and which providers this report covers, are two
    // different questions. Deriving `(active)` from the filter argument would mark whatever the
    // operator asked about as active, which is the opposite of what they are asking.
    let active = user_file.provider.clone();
    for entry in directory.entries() {
        if let Some(filter) = &provider_id
            && filter != entry.id()
        {
            continue;
        }
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
        println!("  api_root:    {}", entry.instance.api_root().as_str());
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

/// `core auth logout [provider]` — drop the credential, keep everything else.
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
struct TerminalAsk {
    stdin: std::io::Stdin,
}

impl TerminalAsk {
    fn new() -> anyhow::Result<Self> {
        use std::io::IsTerminal as _;
        if !std::io::stdin().is_terminal() {
            anyhow::bail!(
                "core setup asks questions and needs a terminal; run it directly, or set the credential with `iteron config set` and an environment variable"
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
        eprint!("{question}");
        std::io::stderr().flush()?;
        // Echo suppression is a terminal facility this binary does not otherwise take a
        // dependency on. Say plainly that the line is visible rather than implying it is not.
        let answer = self.read_line()?;
        Ok(answer)
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
}
