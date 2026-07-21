use super::*;

#[test]
fn secret_shapes_are_detected_toolchain_vars_are_not() {
    for key in [
        "ANTHROPIC_API_KEY",
        "OPENAI_API_KEY",
        "AWS_SECRET_ACCESS_KEY",
        "GITHUB_TOKEN",
        "MY_PASSWORD",
        "DB_CREDENTIAL",
        "SLACK_BOT_TOKEN",
        "x_private_key",
    ] {
        assert!(is_secret_env_key(key), "{key} must be treated as secret");
    }
    for key in [
        "PATH",
        "HOME",
        "LANG",
        "PYTHONPATH",
        "VIRTUAL_ENV",
        "CARGO_HOME",
        "NVM_DIR",
        "TERM",
        "PWD",
    ] {
        assert!(
            !is_secret_env_key(key),
            "{key} must NOT be treated as secret (toolchain needs it)"
        );
    }
}

#[test]
fn exact_sensitive_name_removes_an_explicit_command_value() {
    let mut command = tokio::process::Command::new("/usr/bin/env");
    command.env("CORE_SANDBOX_ROUTE", "synthetic-exact-must-not-leak");
    confine_env_with_exact(&mut command, &["CORE_SANDBOX_ROUTE".into()]);

    let entry = command
        .as_std()
        .get_envs()
        .find(|(name, _)| *name == "CORE_SANDBOX_ROUTE");
    assert!(
        entry.is_some_and(|(_, value)| value.is_none()),
        "an exact deny must override a value explicitly configured on the child"
    );
}

#[tokio::test]
async fn d4_13_d5_14_unsupported_backend_refuses_instead_of_running_unconfined() {
    let confinement = Confinement::egress_off(std::env::temp_dir());
    let error = Unsupported
        .run("printf must-not-run", &confinement)
        .await
        .unwrap_err();
    assert!(matches!(error, SandboxError::Unsupported));
}

#[cfg(target_os = "macos")]
#[tokio::test]
async fn sandbox_strips_secrets_but_keeps_home_and_path() {
    // SAFETY: synthetic test-only values are scoped to this test and removed before returning.
    unsafe {
        std::env::set_var("ANTHROPIC_API_KEY", "synthetic-shaped-must-not-leak");
        std::env::set_var("GATEWAY_KEY", "synthetic-exact-must-not-leak");
    }
    let dir = std::env::temp_dir();
    let sandbox = seatbelt::Seatbelt::new();
    let mut confinement = Confinement::egress_off(&dir);
    confinement.sensitive_env_names.push("GATEWAY_KEY".into());
    let output = sandbox
        .run(
            "echo home=$HOME; echo key=[${ANTHROPIC_API_KEY:-EMPTY}]; echo custom=[${GATEWAY_KEY:-EMPTY}]; echo path=$PATH",
            &confinement,
        )
        .await
        .unwrap();
    assert!(output.stdout.contains("key=[EMPTY]"));
    assert!(output.stdout.contains("custom=[EMPTY]"));
    assert!(!output.stdout.contains("must-not-leak"));
    assert!(
        output.stdout.contains("home=/") && !output.stdout.contains("home=/tmp\n"),
        "real HOME preserved: {}",
        output.stdout
    );
    assert!(output.stdout.contains("path=/"), "PATH preserved");
    unsafe {
        std::env::remove_var("ANTHROPIC_API_KEY");
        std::env::remove_var("GATEWAY_KEY");
    }
}
