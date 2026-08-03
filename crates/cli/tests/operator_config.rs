//! The public onboarding surfaces, exercised through the real binary.
//!
//! Every behaviour here is process-global (the config root, the environment, a file lock), so it
//! is pinned by spawning `core` rather than by mutating this test process. That also makes the
//! assertions exactly what an operator sees.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

const PROCESS_TIMEOUT: Duration = Duration::from_secs(20);
static NEXT_ROOT: AtomicU64 = AtomicU64::new(0);

struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> Self {
        let serial = NEXT_ROOT.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "core-cli-operator-{name}-{}-{serial}",
            std::process::id()
        ));
        std::fs::create_dir_all(root.join("home/.core")).unwrap();
        std::fs::create_dir_all(root.join("repo")).unwrap();
        Self(root)
    }

    fn home(&self) -> PathBuf {
        self.0.join("home")
    }

    fn repo(&self) -> PathBuf {
        self.0.join("repo")
    }

    fn config_path(&self) -> PathBuf {
        self.home().join(".core/config.json")
    }

    fn write_config(&self, text: &str) {
        std::fs::write(self.config_path(), text).unwrap();
    }

    fn read_config(&self) -> String {
        std::fs::read_to_string(self.config_path()).unwrap()
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Run `core` with NO ambient HOME, so only `CORE_CONFIG_HOME` can select a config root.
fn run(home: &Path, repo: &Path, arguments: &[&str]) -> (ExitStatus, String, String) {
    run_with(home, repo, arguments, &[])
}

fn run_with(
    home: &Path,
    repo: &Path,
    arguments: &[&str],
    extra_env: &[(&str, &str)],
) -> (ExitStatus, String, String) {
    let mut command = Command::new(env!("CARGO_BIN_EXE_core"));
    command
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("LANG", "C.UTF-8")
        .env("CORE_CONFIG_HOME", home)
        .current_dir(repo)
        .args(arguments)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (name, value) in extra_env {
        command.env(name, value);
    }
    let mut child = command.spawn().unwrap();
    let deadline = Instant::now() + PROCESS_TIMEOUT;
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("core exceeded {PROCESS_TIMEOUT:?}");
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    let mut stdout = String::new();
    let mut stderr = String::new();
    child
        .stdout
        .take()
        .unwrap()
        .read_to_string(&mut stdout)
        .unwrap();
    child
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut stderr)
        .unwrap();
    (status, stdout, stderr)
}

/// I-25 — both non-test readers of the user config path were reads and the only writes lived in
/// test code, so there was no supported way to persist a choice at all. `core config set` is the
/// one writer, and the value it writes is visible to the next launch.
#[test]
fn i25_config_set_persists_and_the_next_launch_sees_it() {
    let scratch = Scratch::new("set");
    let (status, stdout, stderr) = run(
        &scratch.home(),
        &scratch.repo(),
        &["config", "set", "provider", "kimi"],
    );
    assert!(status.success(), "{stdout}{stderr}");
    assert!(stdout.contains("provider = kimi"), "{stdout}");

    let (status, stdout, _) = run(
        &scratch.home(),
        &scratch.repo(),
        &["config", "get", "provider"],
    );
    assert!(status.success());
    assert_eq!(stdout.trim(), "kimi");

    // The document itself is well-formed and at 0600 — a credential-adjacent file is never
    // world-readable, even when it holds only names.
    let document: serde_json::Value = serde_json::from_str(&scratch.read_config()).unwrap();
    assert_eq!(document["provider"], "kimi");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(scratch.config_path())
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600, "config is operator-private");
    }
}

/// A document the operator can see and fix is never "repaired" by overwriting it. Rewriting a
/// malformed config to persist one key would silently destroy every other key in it.
#[test]
fn i25_a_malformed_document_is_never_silently_rewritten() {
    let scratch = Scratch::new("malformed");
    let original = "{ this is not json";
    scratch.write_config(original);
    let (status, _, stderr) = run(
        &scratch.home(),
        &scratch.repo(),
        &["config", "set", "provider", "kimi"],
    );
    assert!(
        !status.success(),
        "a malformed config must refuse the write"
    );
    assert!(
        stderr.contains("refusing to rewrite"),
        "the refusal must say what it refused: {stderr}"
    );
    assert_eq!(
        scratch.read_config(),
        original,
        "the operator's bytes are untouched"
    );
}

/// A read-modify-write is not serializable just because each individual write is atomic: two
/// concurrent writers would both read the old document and the loser's key would vanish. The lock
/// makes every concurrent setting survive.
#[test]
fn i25_concurrent_writers_cannot_interleave() {
    let scratch = Scratch::new("concurrent");
    let keys = ["provider", "model", "effort", "max_turns"];
    let values = ["kimi", "some-model", "high", "7"];
    let handles: Vec<_> = keys
        .iter()
        .zip(values)
        .map(|(key, value)| {
            let home = scratch.home();
            let repo = scratch.repo();
            let key = (*key).to_owned();
            let value = value.to_owned();
            std::thread::spawn(move || run(&home, &repo, &["config", "set", &key, &value]))
        })
        .collect();
    for handle in handles {
        let (status, stdout, stderr) = handle.join().unwrap();
        assert!(status.success(), "{stdout}{stderr}");
    }
    let document: serde_json::Value = serde_json::from_str(&scratch.read_config()).unwrap();
    for (key, value) in keys.iter().zip(values) {
        assert!(
            !document[*key].is_null(),
            "`{key}` was lost to an interleaved read-modify-write: {document}"
        );
        assert_eq!(document[*key].to_string().trim_matches('"'), value);
    }
}

/// I-24 — every config struct was `deny_unknown_fields`, so one config shared through dotfiles
/// made any additive field written by a newer binary a hard startup failure for the older one.
/// A decorative top-level key now warns and loads.
#[test]
fn i24_an_unknown_top_level_key_warns_and_loads() {
    let scratch = Scratch::new("unknown-top");
    scratch.write_config(r#"{"schema_version":2,"provider":"glm","favourite_colour":"blue"}"#);
    let (status, stdout, stderr) = run(
        &scratch.home(),
        &scratch.repo(),
        &["config", "get", "provider"],
    );
    assert!(status.success(), "{stdout}{stderr}");
    assert_eq!(stdout.trim(), "glm", "the known keys still load");
    assert!(
        stderr.contains("favourite_colour"),
        "an unknown key degrades but is never silent: {stderr}"
    );
}

/// Strictness is retained exactly where a silently dropped key would be a security or spend
/// decision. A typo inside `providers` still fails closed.
#[test]
fn i24_an_unknown_key_inside_providers_still_fails() {
    let scratch = Scratch::new("unknown-provider");
    scratch.write_config(
        r#"{"schema_version":2,"providers":[{"id":"gw","adapter":"openai_chat","api_root":"https://gw.example/v1","key_env":"GW_KEY","catalogue":true}]}"#,
    );
    let (status, _, stderr) = run(
        &scratch.home(),
        &scratch.repo(),
        &["config", "get", "provider"],
    );
    assert!(
        !status.success(),
        "a provider-scoped unknown key must remain a hard failure"
    );
    assert!(stderr.contains("catalogue"), "{stderr}");
}

/// A container image has no HOME. Without a fallback there is no supported way to point Core at a
/// config at all in that environment; every other test in this file relies on it.
#[test]
fn i24_core_config_home_selects_the_config_root() {
    let scratch = Scratch::new("config-home");
    scratch.write_config(r#"{"schema_version":2,"model":"from-core-config-home"}"#);
    let (status, stdout, stderr) = run(
        &scratch.home(),
        &scratch.repo(),
        &["config", "get", "model"],
    );
    assert!(status.success(), "{stdout}{stderr}");
    assert_eq!(stdout.trim(), "from-core-config-home");
}

/// I-23 — `ProviderConfig` could only ever carry `key_env`, an uppercase ASCII environment name,
/// which cannot describe a hosted subscription token. Both spellings load, and the file spelling
/// resolves through the new source.
#[test]
fn i23_both_credential_spellings_load_and_a_file_entry_resolves() {
    let scratch = Scratch::new("credential-spellings");
    let token_path = scratch.home().join(".core/credentials/plan");
    std::fs::create_dir_all(token_path.parent().unwrap()).unwrap();
    std::fs::write(&token_path, "plan-token\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&token_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    scratch.write_config(&format!(
        r#"{{"schema_version":2,"providers":[
             {{"id":"legacy","adapter":"openai_chat","api_root":"https://legacy.example/v1","key_env":"LEGACY_KEY"}},
             {{"id":"plan","adapter":"openai_chat","api_root":"https://plan.example/v1","credential":{{"type":"file","path":"{}"}}}}
           ]}}"#,
        token_path.display()
    ));
    let (status, stdout, stderr) = run(&scratch.home(), &scratch.repo(), &["auth", "status"]);
    assert!(status.success(), "{stdout}{stderr}");
    assert!(
        stdout.contains("env LEGACY_KEY"),
        "an existing v2 document keeps loading verbatim: {stdout}"
    );
    assert!(
        stdout.contains(&format!("file {}", token_path.display())),
        "a credential file entry resolves through the new source: {stdout}"
    );
    assert!(
        !stdout.contains("plan-token"),
        "a credential VALUE must never reach status output: {stdout}"
    );
}

/// I-28 — nothing reported where the current credential came from or when it expires.
#[test]
fn i28_auth_status_distinguishes_env_file_and_absent() {
    let scratch = Scratch::new("auth-status");
    let token_path = scratch.home().join(".core/credentials/glm");
    std::fs::create_dir_all(token_path.parent().unwrap()).unwrap();
    std::fs::write(&token_path, r#"{"token":"t","expires_at_unix":4102444800}"#).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&token_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let (status, stdout, stderr) =
        run(&scratch.home(), &scratch.repo(), &["auth", "status", "glm"]);
    assert!(status.success(), "{stdout}{stderr}");
    assert!(stdout.contains("api_root:"), "{stdout}");
    assert!(stdout.contains("credential:  file"), "{stdout}");
    assert!(stdout.contains("present:     yes"), "{stdout}");
    assert!(stdout.contains("expires_at:  4102444800"), "{stdout}");

    // An absent credential names the variable to set rather than reporting nothing.
    let (status, stdout, _) = run(
        &scratch.home(),
        &scratch.repo(),
        &["auth", "status", "deepseek"],
    );
    assert!(status.success());
    assert!(
        stdout.contains("credential:  env DEEPSEEK_API_KEY"),
        "{stdout}"
    );
    assert!(stdout.contains("present:     no"), "{stdout}");
}

/// Logging out of an account is not deleting the route to it: the provider entry, its endpoint and
/// its declared models all survive.
#[test]
fn i28_auth_logout_removes_the_credential_and_leaves_the_provider_entry() {
    let scratch = Scratch::new("auth-logout");
    let token_path = scratch.home().join(".core/credentials/gw");
    std::fs::create_dir_all(token_path.parent().unwrap()).unwrap();
    std::fs::write(&token_path, "gw-token\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&token_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    scratch.write_config(&format!(
        r#"{{"schema_version":2,"providers":[{{"id":"gw","display_name":"Gateway","adapter":"openai_chat","api_root":"https://gw.example/v1","credential":{{"type":"file","path":"{}"}},"models":["gw-1"],"catalog":false}}]}}"#,
        token_path.display()
    ));
    let before = scratch.read_config();

    let (status, stdout, stderr) = run(&scratch.home(), &scratch.repo(), &["auth", "logout", "gw"]);
    assert!(status.success(), "{stdout}{stderr}");
    assert!(!token_path.exists(), "the credential file is gone");
    assert_eq!(
        scratch.read_config(),
        before,
        "the provider entry, endpoint and models are untouched"
    );

    let (status, stdout, _) = run(&scratch.home(), &scratch.repo(), &["auth", "status", "gw"]);
    assert!(status.success());
    assert!(stdout.contains("present:     no"), "{stdout}");
    assert!(
        stdout.contains("https://gw.example/v1"),
        "the route survives a logout: {stdout}"
    );
}

/// I-29 — the credential variable was chosen by provider NAME before the override was applied,
/// with a silent fallback to `OPENAI_API_KEY`, so `core --base-url https://gateway/v1` shipped the
/// default provider's key to an arbitrary host.
#[test]
fn i29_base_url_without_an_explicit_credential_is_refused() {
    let scratch = Scratch::new("base-url");
    let (status, _, stderr) = run_with(
        &scratch.home(),
        &scratch.repo(),
        &["-p", "hello", "--base-url", "https://gateway.example/v1"],
        &[("GLM_API_KEY", "glm-secret")],
    );
    assert!(!status.success(), "an unpaired --base-url must be refused");
    assert!(
        stderr.contains("--key-env"),
        "the refusal names the fix: {stderr}"
    );
    assert!(
        !stderr.contains("glm-secret"),
        "a refusal must not echo a credential: {stderr}"
    );
}

/// `--key-env` is meaningful only with `--base-url`; on its own it would silently do nothing.
#[test]
fn i29_key_env_without_base_url_is_refused() {
    let scratch = Scratch::new("key-env-alone");
    let (status, _, stderr) = run(
        &scratch.home(),
        &scratch.repo(),
        &["-p", "hello", "--key-env", "SOME_KEY"],
    );
    assert!(!status.success());
    assert!(
        stderr.contains("--key-env only names the credential"),
        "{stderr}"
    );
}

/// I-05 — a clean environment reported `provider glm has no selectable discovered model` while the
/// reason one layer down already said `missing credential (GLM_API_KEY)`. The env var is named,
/// and the message points at the wizard.
#[test]
fn i05_a_clean_environment_names_the_missing_variable() {
    let scratch = Scratch::new("clean-env");
    let (status, _, stderr) = run(&scratch.home(), &scratch.repo(), &["-p", "hello"]);
    assert!(!status.success());
    assert!(
        stderr.contains("GLM_API_KEY"),
        "the error names the variable to set: {stderr}"
    );
    assert!(
        stderr.contains("core setup"),
        "the error points at the wizard: {stderr}"
    );
    assert!(
        !stderr.contains("has no selectable discovered model"),
        "the unactionable line must not be what an operator sees: {stderr}"
    );
}
