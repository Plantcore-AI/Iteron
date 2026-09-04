#![cfg(unix)]

use std::io::{BufRead as _, Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

fn fixture() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/mcp_conformance/fixtures/stdio_server.py")
}

fn oauth_fixture() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/mcp_conformance/fixtures/oauth_http_server.py")
}

fn start_oauth_fixture(mode: &str) -> (std::process::Child, String) {
    start_oauth_fixture_version(mode, "2025-11-25")
}

fn start_oauth_fixture_version(
    mode: &str,
    protocol_version: &str,
) -> (std::process::Child, String) {
    let mut fixture = Command::new("python3")
        .arg(oauth_fixture())
        .args(["--mode", mode, "--protocol-version", protocol_version])
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut output = std::io::BufReader::new(fixture.stdout.take().unwrap());
    let mut resource = String::new();
    output.read_line(&mut resource).unwrap();
    (fixture, resource.trim().to_owned())
}

fn spawn_modern_login(config: &Path, callback_timeout_ms: Option<&str>) -> std::process::Child {
    let mut command = Command::new(env!("CARGO_BIN_EXE_iteron"));
    command
        .env("ITERON_CONFIG_HOME", config)
        .args([
            "mcp",
            "auth",
            "login",
            "oauth",
            "--client-id",
            "https://client.example/iteron.json",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(milliseconds) = callback_timeout_ms {
        command.env("ITERON_TEST_MCP_OAUTH_CALLBACK_TIMEOUT_MS", milliseconds);
    }
    command.spawn().unwrap()
}

fn read_authorization_url(login: &mut std::process::Child) -> String {
    let mut output = std::io::BufReader::new(login.stdout.as_mut().unwrap());
    let mut line = String::new();
    loop {
        line.clear();
        assert_ne!(output.read_line(&mut line).unwrap(), 0);
        if line.trim_start().starts_with("http://") {
            return line.trim().to_owned();
        }
    }
}

fn wait_for_login(login: &mut std::process::Child) -> std::process::ExitStatus {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(status) = login.try_wait().unwrap() {
            return status;
        }
        if Instant::now() >= deadline {
            login.kill().unwrap();
            panic!("OAuth login did not complete");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn temp_config(label: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "iteron-mcp-cli-{label}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&path).unwrap();
    path
}

fn run(config: &Path, args: &[&str], _modern: bool) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_iteron"));
    command.env("ITERON_CONFIG_HOME", config).args(args);
    command.output().unwrap()
}

fn run_with_env(config: &Path, args: &[&str], name: &str, value: &str) -> Output {
    Command::new(env!("CARGO_BIN_EXE_iteron"))
        .env("ITERON_CONFIG_HOME", config)
        .env(name, value)
        .args(args)
        .output()
        .unwrap()
}

fn stdout(output: &Output) -> String {
    String::from_utf8(output.stdout.clone()).unwrap()
}

fn assert_success(output: &Output) {
    assert!(
        output.status.success(),
        "stdout={} stderr={}",
        stdout(output),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn lifecycle(version: &str, modern: bool) {
    let config = temp_config(version);
    let fixture = fixture();
    let fixture = fixture.to_str().unwrap();
    assert_success(&run(
        &config,
        &[
            "mcp",
            "add",
            "local",
            "--stdio",
            "python3",
            "--",
            fixture,
            "--version",
            version,
        ],
        modern,
    ));
    let listed = run(&config, &["mcp", "list", "--format", "json"], modern);
    assert_success(&listed);
    assert!(stdout(&listed).contains("\"name\":\"local\""));
    assert_success(&run(
        &config,
        &["mcp", "get", "local", "--format", "json"],
        modern,
    ));
    let tested = run(
        &config,
        &["mcp", "test", "local", "--format", "json"],
        modern,
    );
    assert_success(&tested);
    let tested = stdout(&tested);
    assert!(tested.contains("\"outcome\":\"pass\""));
    assert!(tested.contains(&format!("\"protocol_version\":\"{version}\"")));
    let status = run(
        &config,
        &["mcp", "status", "local", "--format", "json"],
        modern,
    );
    assert_success(&status);
    let status = stdout(&status);
    assert!(status.contains("\"connection_state\":\"not_connected\""));
    assert!(status.contains("\"protocol_version\":null"));
    assert!(status.contains("\"tool_count\":null"));
    let connected_status = run(
        &config,
        &["mcp", "status", "local", "--connect", "--format", "json"],
        modern,
    );
    assert_success(&connected_status);
    let connected_status = stdout(&connected_status);
    assert!(connected_status.contains("\"connection_state\":\"connected\""));
    assert!(connected_status.contains(&format!("\"protocol_version\":\"{version}\"")));
    assert!(connected_status.contains("\"tool_count\":1"));
    let doctor = run(
        &config,
        &["mcp", "doctor", "--connect", "--format", "json"],
        modern,
    );
    assert_success(&doctor);
    let doctor = stdout(&doctor);
    assert!(doctor.contains("\"outcome\":\"pass\""));
    assert!(doctor.contains(&format!("\"protocol_version\":\"{version}\"")));
    assert!(doctor.contains("\"tool_count\":1"));
    assert_success(&run(&config, &["mcp", "remove", "local"], modern));
    assert!(!stdout(&run(&config, &["mcp", "list"], modern)).contains("local"));
    std::fs::remove_dir_all(config).unwrap();
}

#[test]
fn stateful_cli_lifecycle_is_provider_free() {
    lifecycle("2025-11-25", false);
}

#[test]
fn stateful_2025_06_cli_lifecycle_is_provider_free() {
    lifecycle("2025-06-18", false);
}

#[test]
fn stateless_2026_cli_lifecycle_is_provider_free() {
    lifecycle("2026-07-28", true);
}

#[test]
fn stdio_env_grant_forwards_only_the_named_runtime_value() {
    let config = temp_config("env-grant");
    let fixture = fixture();
    let fixture = fixture.to_str().unwrap();
    let env_name = "ITERON_MCP_TEST_GRANTED_VALUE";
    let secret = "local-private-marker";
    assert_success(&run(
        &config,
        &[
            "mcp",
            "add",
            "local",
            "--stdio",
            "python3",
            "--env",
            env_name,
            "--",
            fixture,
            "--version",
            "2026-07-28",
            "--require-env",
            env_name,
        ],
        false,
    ));
    let inspected = run_with_env(
        &config,
        &["mcp", "get", "local", "--format", "json"],
        env_name,
        secret,
    );
    assert_success(&inspected);
    assert!(stdout(&inspected).contains(env_name));
    assert!(!stdout(&inspected).contains(secret));
    let tested = run_with_env(
        &config,
        &["mcp", "test", "local", "--format", "json"],
        env_name,
        secret,
    );
    assert_success(&tested);
    assert!(!stdout(&tested).contains(secret));
    std::fs::remove_dir_all(config).unwrap();
}

#[test]
fn invalid_server_fails_without_touching_a_real_user_home() {
    let config = temp_config("invalid");
    let output = run(
        &config,
        &["mcp", "test", "missing", "--format", "json"],
        false,
    );
    assert!(!output.status.success());
    assert!(stdout(&output).contains("\"diagnostics\":[\"MCP_SERVER_UNKNOWN\"]"));
    assert!(!String::from_utf8_lossy(&output.stderr).contains("token"));
    std::fs::remove_dir_all(config).unwrap();
}

#[test]
fn configuration_commands_reject_conflicts_and_hide_endpoint_secrets() {
    let config = temp_config("configuration");
    let secret = "private-query-marker";
    assert_success(&run(
        &config,
        &[
            "mcp",
            "add",
            "remote",
            "--url",
            &format!("https://example.com/private?token={secret}"),
        ],
        false,
    ));
    for args in [
        vec!["mcp", "list", "--format", "json"],
        vec!["mcp", "get", "remote", "--format", "json"],
    ] {
        let output = run(&config, &args, false);
        assert_success(&output);
        assert!(!stdout(&output).contains(secret));
    }
    for args in [
        vec!["mcp", "add", "remote", "--url", "https://example.com/mcp"],
        vec!["mcp", "add", "plain", "--url", "http://example.com/mcp"],
        vec!["mcp", "get", "missing"],
        vec!["mcp", "remove", "missing"],
    ] {
        assert!(!run(&config, &args, false).status.success());
    }
    std::fs::remove_dir_all(config).unwrap();
}

#[test]
fn protocol_and_authentication_failures_have_stable_diagnostic_codes() {
    let config = temp_config("diagnostics");
    let fixture_path = fixture();
    assert_success(&run(
        &config,
        &[
            "mcp",
            "add",
            "future",
            "--stdio",
            "python3",
            "--",
            fixture_path.to_str().unwrap(),
            "--version",
            "2099-01-01",
        ],
        false,
    ));
    let unsupported = run(
        &config,
        &["mcp", "test", "future", "--format", "json"],
        false,
    );
    assert!(!unsupported.status.success());
    assert!(stdout(&unsupported).contains("MCP_PROTOCOL_UNSUPPORTED"));

    let (mut oauth, resource) = start_oauth_fixture("success");
    assert_success(&run(
        &config,
        &["mcp", "add", "locked", "--url", &resource],
        false,
    ));
    let unauthenticated = run(
        &config,
        &["mcp", "test", "locked", "--format", "json"],
        false,
    );
    assert!(!unauthenticated.status.success());
    assert!(stdout(&unauthenticated).contains("MCP_AUTH_REQUIRED"));
    oauth.kill().unwrap();
    let _ = oauth.wait();
    std::fs::remove_dir_all(config).unwrap();
}

#[test]
fn oauth_login_status_test_and_logout_use_only_loopback_and_private_storage() {
    let config = temp_config("oauth");
    let mut fixture = Command::new("python3")
        .arg(oauth_fixture())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut fixture_output = std::io::BufReader::new(fixture.stdout.take().unwrap());
    let mut resource = String::new();
    fixture_output.read_line(&mut resource).unwrap();
    let resource = resource.trim().to_owned();
    assert_success(&run(
        &config,
        &["mcp", "add", "oauth", "--url", &resource],
        false,
    ));

    let mut login = Command::new(env!("CARGO_BIN_EXE_iteron"))
        .env("ITERON_CONFIG_HOME", &config)
        .args([
            "mcp",
            "auth",
            "login",
            "oauth",
            "--client-id",
            "https://client.example/iteron.json",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut login_output = std::io::BufReader::new(login.stdout.take().unwrap());
    let mut line = String::new();
    let authorization_url = loop {
        line.clear();
        assert_ne!(login_output.read_line(&mut line).unwrap(), 0);
        if line.trim_start().starts_with("http://") {
            break line.trim().to_owned();
        }
    };
    let pending = run(
        &config,
        &["mcp", "auth", "status", "oauth", "--format", "json"],
        false,
    );
    assert_success(&pending);
    assert!(stdout(&pending).contains("\"authentication\":\"pending\""));
    let (status, location) = http_get(&authorization_url);
    assert_eq!(status, 302);
    let callback = location.expect("authorization redirect");
    assert_eq!(http_get(&callback).0, 200);
    let deadline = Instant::now() + Duration::from_secs(10);
    let login_status = loop {
        if let Some(status) = login.try_wait().unwrap() {
            break status;
        }
        if Instant::now() >= deadline {
            login.kill().unwrap();
            panic!("OAuth login did not complete");
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    assert!(login_status.success());

    let duplicate = run(&config, &["mcp", "auth", "login", "oauth"], false);
    assert_success(&duplicate);
    assert!(stdout(&duplicate).contains("already authenticated"));

    let status = run(
        &config,
        &["mcp", "auth", "status", "oauth", "--format", "json"],
        false,
    );
    assert_success(&status);
    assert!(stdout(&status).contains("\"authentication\":\"authenticated\""));
    let credential_dir = config.join(".iteron/mcp-credentials");
    let credential = std::fs::read_dir(&credential_dir)
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        assert_eq!(
            std::fs::metadata(&credential).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    assert_success(&run(
        &config,
        &["mcp", "test", "oauth", "--format", "json"],
        false,
    ));
    let doctor = run(
        &config,
        &["mcp", "doctor", "--connect", "--format", "json"],
        false,
    );
    assert_success(&doctor);
    assert!(stdout(&doctor).contains("\"protocol_version\":\"2025-11-25\""));
    assert_success(&run(&config, &["mcp", "auth", "logout", "oauth"], false));
    assert!(!credential.exists());
    let revoked = run(
        &config,
        &["mcp", "test", "oauth", "--format", "json"],
        false,
    );
    assert!(!revoked.status.success());
    assert!(stdout(&revoked).contains("MCP_AUTH_REQUIRED"));
    assert_success(&run(&config, &["mcp", "remove", "oauth"], false));

    fixture.kill().unwrap();
    let _ = fixture.wait();
    std::fs::remove_dir_all(config).unwrap();
}

#[test]
fn oauth_credentials_are_usable_with_the_2025_06_protocol() {
    oauth_protocol_roundtrip("2025-06-18", false);
}

#[test]
fn oauth_credentials_are_usable_with_the_2026_protocol() {
    oauth_protocol_roundtrip("2026-07-28", true);
}

#[test]
fn oauth_scope_omission_keeps_the_requested_scope() {
    oauth_protocol_roundtrip_mode("2026-07-28", true, "scope-missing");
}

#[test]
fn an_expired_login_credential_refreshes_before_protocol_negotiation() {
    oauth_protocol_roundtrip_mode("2026-07-28", true, "refresh-required");
}

#[test]
fn auto_registration_falls_back_to_dcr_but_forced_cimd_does_not() {
    let config = temp_config("auto-dcr");
    let (mut fixture, resource) = start_oauth_fixture("no-cimd");
    assert_success(&run(
        &config,
        &["mcp", "add", "oauth", "--url", &resource],
        false,
    ));
    let mut login = spawn_modern_login(&config, None);
    let authorization_url = read_authorization_url(&mut login);
    let (status, location) = http_get(&authorization_url);
    assert_eq!(status, 302);
    assert_eq!(http_get(&location.unwrap()).0, 200);
    assert!(wait_for_login(&mut login).success());
    assert_success(&run(&config, &["mcp", "auth", "logout", "oauth"], false));

    let forced = run(
        &config,
        &[
            "mcp",
            "auth",
            "login",
            "oauth",
            "--oauth-client-registration",
            "cimd",
            "--client-id",
            "https://client.example/iteron.json",
        ],
        false,
    );
    assert!(!forced.status.success());
    assert!(String::from_utf8_lossy(&forced.stderr).contains("MCP_AUTH_REGISTRATION_UNSUPPORTED"));
    fixture.kill().unwrap();
    let _ = fixture.wait();
    std::fs::remove_dir_all(config).unwrap();
}

#[test]
fn oauth_scope_step_up_rejects_a_different_resource_before_network_access() {
    let config = temp_config("scope-step-up-resource");
    let (mut fixture, resource) = start_oauth_fixture("success");
    assert_success(&run(
        &config,
        &["mcp", "add", "oauth", "--url", &resource],
        false,
    ));
    let mut login = spawn_modern_login(&config, None);
    let authorization_url = read_authorization_url(&mut login);
    let (status, location) = http_get(&authorization_url);
    assert_eq!(status, 302);
    assert_eq!(http_get(&location.unwrap()).0, 200);
    assert!(wait_for_login(&mut login).success());

    fixture.kill().unwrap();
    let _ = fixture.wait();
    let other_resource = resource.replace("/mcp", "/other-resource");
    let step_up = run(
        &config,
        &[
            "mcp",
            "auth",
            "login",
            "oauth",
            "--scopes",
            "write",
            "--oauth-resource",
            &other_resource,
        ],
        false,
    );
    assert!(!step_up.status.success());
    assert!(
        String::from_utf8_lossy(&step_up.stderr)
            .contains("MCP OAuth scope step-up resource mismatch"),
        "stderr={}",
        String::from_utf8_lossy(&step_up.stderr)
    );

    std::fs::remove_dir_all(config).unwrap();
}

fn oauth_protocol_roundtrip(protocol_version: &str, modern: bool) {
    oauth_protocol_roundtrip_mode(protocol_version, modern, "success");
}

fn oauth_protocol_roundtrip_mode(protocol_version: &str, modern: bool, mode: &str) {
    let config = temp_config(protocol_version);
    let (mut fixture, resource) = start_oauth_fixture_version(mode, protocol_version);
    assert_success(&run(
        &config,
        &["mcp", "add", "oauth", "--url", &resource],
        false,
    ));
    let mut login = spawn_modern_login(&config, None);
    let authorization_url = read_authorization_url(&mut login);
    let (status, location) = http_get(&authorization_url);
    assert_eq!(status, 302);
    assert_eq!(http_get(&location.expect("authorization redirect")).0, 200);
    assert!(wait_for_login(&mut login).success());
    if mode == "refresh-required" {
        let status = run(
            &config,
            &["mcp", "auth", "status", "oauth", "--format", "json"],
            false,
        );
        assert_success(&status);
        assert!(stdout(&status).contains("\"authentication\":\"expired\""));
    }
    let tested = run(
        &config,
        &["mcp", "test", "oauth", "--format", "json"],
        modern,
    );
    assert_success(&tested);
    assert!(stdout(&tested).contains(&format!("\"protocol_version\":\"{protocol_version}\"")));
    if mode == "refresh-required" {
        let status = run(
            &config,
            &["mcp", "auth", "status", "oauth", "--format", "json"],
            false,
        );
        assert_success(&status);
        assert!(stdout(&status).contains("\"authentication\":\"authenticated\""));
        assert_success(&run(
            &config,
            &["mcp", "test", "oauth", "--format", "json"],
            modern,
        ));
    }
    assert_success(&run(&config, &["mcp", "auth", "logout", "oauth"], false));
    fixture.kill().unwrap();
    let _ = fixture.wait();
    std::fs::remove_dir_all(config).unwrap();
}

#[test]
fn oauth_metadata_binding_errors_fail_before_callback_without_storing_credentials() {
    for (mode, code) in [
        ("issuer-mismatch", "MCP_AUTH_ISSUER_MISMATCH"),
        ("resource-mismatch", "MCP_AUTH_RESOURCE_MISMATCH"),
        (
            "unsupported-token-auth",
            "MCP_AUTH_TOKEN_METHOD_UNSUPPORTED",
        ),
    ] {
        let config = temp_config(mode);
        let (mut fixture, resource) = start_oauth_fixture(mode);
        assert_success(&run(
            &config,
            &["mcp", "add", "oauth", "--url", &resource],
            false,
        ));
        let output = Command::new(env!("CARGO_BIN_EXE_iteron"))
            .env("ITERON_CONFIG_HOME", &config)
            .args([
                "mcp",
                "auth",
                "login",
                "oauth",
                "--client-id",
                "https://client.example/iteron.json",
            ])
            .output()
            .unwrap();
        assert!(!output.status.success());
        let combined = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(!combined.contains("local-access"));
        assert!(!combined.contains("local-refresh"));
        assert!(combined.contains(code), "{mode}: {combined}");
        assert_success(&run(
            &config,
            &["mcp", "auth", "status", "oauth", "--format", "json"],
            false,
        ));
        fixture.kill().unwrap();
        let _ = fixture.wait();
        std::fs::remove_dir_all(config).unwrap();
    }
}

#[test]
fn oauth_login_reports_when_authentication_is_not_required() {
    let config = temp_config("no-auth");
    let (mut fixture, resource) = start_oauth_fixture("no-auth");
    assert_success(&run(
        &config,
        &["mcp", "add", "oauth", "--url", &resource],
        false,
    ));
    let login = run(
        &config,
        &[
            "mcp",
            "auth",
            "login",
            "oauth",
            "--client-id",
            "https://client.example/iteron.json",
        ],
        false,
    );
    assert_success(&login);
    assert!(stdout(&login).contains("does not require authentication"));
    let status = run(
        &config,
        &["mcp", "auth", "status", "oauth", "--format", "json"],
        false,
    );
    assert_success(&status);
    assert!(stdout(&status).contains("\"authentication\":\"unauthenticated\""));
    fixture.kill().unwrap();
    let _ = fixture.wait();
    std::fs::remove_dir_all(config).unwrap();
}

#[test]
fn oauth_scope_escalation_and_callback_timeout_fail_without_storing_credentials() {
    for (mode, callback_timeout) in [("scope-escalation", None), ("success", Some("50"))] {
        let config = temp_config(mode);
        let (mut fixture, resource) = start_oauth_fixture(mode);
        assert_success(&run(
            &config,
            &["mcp", "add", "oauth", "--url", &resource],
            false,
        ));
        let mut login = spawn_modern_login(&config, callback_timeout);
        let authorization_url = read_authorization_url(&mut login);
        if callback_timeout.is_none() {
            let (status, location) = http_get(&authorization_url);
            assert_eq!(status, 302);
            assert_eq!(http_get(&location.expect("authorization redirect")).0, 200);
        }
        assert!(!wait_for_login(&mut login).success());
        if callback_timeout.is_some() {
            let mut error = String::new();
            login
                .stderr
                .as_mut()
                .unwrap()
                .read_to_string(&mut error)
                .unwrap();
            assert!(error.contains("MCP_AUTH_CALLBACK_TIMEOUT"));
        }
        let status = run(
            &config,
            &["mcp", "auth", "status", "oauth", "--format", "json"],
            false,
        );
        assert_success(&status);
        assert!(stdout(&status).contains("\"authentication\":\"unauthenticated\""));
        fixture.kill().unwrap();
        let _ = fixture.wait();
        std::fs::remove_dir_all(config).unwrap();
    }
}

#[test]
fn discovered_scope_rejection_restarts_once_without_changing_operator_scopes() {
    let config = temp_config("scope-fallback");
    let (mut fixture, resource) = start_oauth_fixture("discovered-scope-rejected-once");
    assert_success(&run(
        &config,
        &["mcp", "add", "oauth", "--url", &resource],
        false,
    ));
    let mut login = Command::new(env!("CARGO_BIN_EXE_iteron"))
        .env("ITERON_CONFIG_HOME", &config)
        .args(["mcp", "auth", "login", "oauth"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let first = read_authorization_url(&mut login);
    assert!(
        url::Url::parse(&first)
            .unwrap()
            .query_pairs()
            .any(|(name, value)| { name == "scope" && value == "mcp" })
    );
    let (_, first_callback) = http_get(&first);
    assert_eq!(http_get(&first_callback.unwrap()).0, 400);
    let second = read_authorization_url(&mut login);
    assert!(
        !url::Url::parse(&second)
            .unwrap()
            .query_pairs()
            .any(|(name, _)| name == "scope")
    );
    let (_, second_callback) = http_get(&second);
    assert_eq!(http_get(&second_callback.unwrap()).0, 200);
    assert!(wait_for_login(&mut login).success());
    assert!(
        stdout(&run(
            &config,
            &["mcp", "auth", "status", "oauth", "--format", "json"],
            false,
        ))
        .contains("\"authentication\":\"authenticated\"")
    );
    fixture.kill().unwrap();
    let _ = fixture.wait();
    std::fs::remove_dir_all(config).unwrap();

    let config = temp_config("operator-scope-no-fallback");
    let (mut fixture, resource) = start_oauth_fixture("discovered-scope-rejected-once");
    assert_success(&run(
        &config,
        &["mcp", "add", "oauth", "--url", &resource],
        false,
    ));
    let mut login = Command::new(env!("CARGO_BIN_EXE_iteron"))
        .env("ITERON_CONFIG_HOME", &config)
        .args(["mcp", "auth", "login", "oauth", "--scopes", "mcp"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let authorization = read_authorization_url(&mut login);
    let (_, callback) = http_get(&authorization);
    assert_eq!(http_get(&callback.unwrap()).0, 400);
    assert!(!wait_for_login(&mut login).success());
    fixture.kill().unwrap();
    let _ = fixture.wait();
    std::fs::remove_dir_all(config).unwrap();
}

#[test]
fn external_bearer_status_is_truthful_and_interactive_login_leaves_no_pending_state() {
    let config = temp_config("external-bearer");
    let directory = config.join(".iteron");
    std::fs::create_dir_all(&directory).unwrap();
    std::fs::write(
        directory.join("config.json"),
        r#"{
            "schema_version":2,
            "mcp_servers":[{
                "name":"external",
                "transport":"http",
                "url":"https://mcp.example/mcp",
                "oauth":{"access_token_env":"MCP_EXTERNAL_TOKEN"}
            }]
        }"#,
    )
    .unwrap();
    let secret = "external-secret-marker";
    for args in [
        vec!["mcp", "auth", "status", "external", "--format", "json"],
        vec!["mcp", "list", "--format", "json"],
        vec!["mcp", "get", "external", "--format", "json"],
        vec!["mcp", "status", "external", "--format", "json"],
        vec!["mcp", "doctor", "--format", "json"],
    ] {
        let output = run_with_env(&config, &args, "MCP_EXTERNAL_TOKEN", secret);
        assert_success(&output);
        assert!(stdout(&output).contains("\"authentication\":\"external\""));
        assert!(!stdout(&output).contains(secret));
    }
    let login = run_with_env(
        &config,
        &["mcp", "auth", "login", "external"],
        "MCP_EXTERNAL_TOKEN",
        secret,
    );
    assert!(!login.status.success());
    assert!(!config.join(".iteron/mcp-credentials").exists());
    std::fs::remove_dir_all(config).unwrap();
}

fn http_get(url: &str) -> (u16, Option<String>) {
    let url = url::Url::parse(url).unwrap();
    assert_eq!(url.scheme(), "http");
    assert!(url.host_str().is_some_and(|host| host == "127.0.0.1"));
    let mut stream = std::net::TcpStream::connect((
        url.host_str().unwrap(),
        url.port_or_known_default().unwrap(),
    ))
    .unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let target = match url.query() {
        Some(query) => format!("{}?{query}", url.path()),
        None => url.path().to_owned(),
    };
    write!(
        stream,
        "GET {target} HTTP/1.1\r\nHost: {}:{}\r\nConnection: close\r\n\r\n",
        url.host_str().unwrap(),
        url.port_or_known_default().unwrap()
    )
    .unwrap();
    stream.flush().unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();
    let mut lines = response.lines();
    let status = lines
        .next()
        .unwrap()
        .split_whitespace()
        .nth(1)
        .unwrap()
        .parse()
        .unwrap();
    let location = lines.find_map(|line| {
        line.strip_prefix("Location: ")
            .or_else(|| line.strip_prefix("location: "))
            .map(str::to_owned)
    });
    (status, location)
}
