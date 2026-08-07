//! Local doctor and support-bundle product surfaces.
//!
//! Neither command contacts a provider, starts MCP, or sends diagnostics anywhere. The support
//! bundle is rendered by `core-support`, whose input grammar is bounded, deterministic, allowlisted,
//! and scrubbed before storage.

use crate::config::FileConfig;
use core_support::{Bundle, Section};
use std::io::Write as _;
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Health {
    Ok,
    Warn,
    Fail,
}

impl Health {
    fn marker(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Warn => "warn",
            Self::Fail => "fail",
        }
    }
}

struct Check {
    health: Health,
    name: &'static str,
    detail: String,
}

fn checks(repo: &Path, runs_dir: &Path) -> Vec<Check> {
    let mut checks = Vec::new();
    checks.push(Check {
        health: Health::Ok,
        name: "workspace",
        detail: repo.display().to_string(),
    });
    checks.push(Check {
        health: if core_record::checkpoint_supported(repo) {
            Health::Ok
        } else {
            Health::Warn
        },
        name: "checkpoint",
        detail: if core_record::checkpoint_supported(repo) {
            "Git checkpoint + rewind available".into()
        } else {
            "not a Git worktree; conversation recovery remains available".into()
        },
    });
    checks.push(match FileConfig::load(repo) {
        Ok(_) => Check {
            health: Health::Ok,
            name: "project config",
            detail: "valid or absent".into(),
        },
        Err(error) => Check {
            health: Health::Fail,
            name: "project config",
            detail: error.to_string(),
        },
    });
    checks.push(match FileConfig::load_user() {
        Ok(_) => Check {
            health: Health::Ok,
            name: "user config",
            detail: "valid or absent".into(),
        },
        Err(error) => Check {
            health: Health::Fail,
            name: "user config",
            detail: error.to_string(),
        },
    });
    checks.push(Check {
        health: match runs_dir.parent() {
            Some(parent) if parent.exists() && parent.is_dir() => Health::Ok,
            _ => Health::Warn,
        },
        name: "runtime state",
        detail: runs_dir.display().to_string(),
    });
    let terminal = core_statusline::Capabilities::detect(|name| {
        std::env::var(name).ok().filter(|value| value.len() <= 128)
    });
    checks.push(Check {
        health: Health::Ok,
        name: "terminal",
        detail: format!(
            "color={:?}, presentation={:?}, multiplexed={}, remote={}",
            terminal.color, terminal.presentation, terminal.multiplexed, terminal.remote
        ),
    });
    checks
}

pub(crate) fn run_doctor(
    repo: &Path,
    runs_dir: &Path,
    build_commit: &str,
    build_date: &str,
) -> anyhow::Result<u8> {
    println!(
        "Core Code {} · commit {} · built {}",
        env!("CARGO_PKG_VERSION"),
        build_commit,
        build_date
    );
    let checks = checks(repo, runs_dir);
    for check in &checks {
        println!(
            "{:<4} {:<16} {}",
            check.health.marker(),
            check.name,
            check.detail
        );
    }
    let failures = checks
        .iter()
        .filter(|check| check.health == Health::Fail)
        .count();
    let warnings = checks
        .iter()
        .filter(|check| check.health == Health::Warn)
        .count();
    println!("summary: {failures} failure(s), {warnings} warning(s)");
    Ok(if failures == 0 { 0 } else { 1 })
}

pub(crate) async fn run_support(
    repo: &Path,
    runs_dir: &Path,
    output: Option<&Path>,
    build_commit: &str,
    build_date: &str,
) -> anyhow::Result<u8> {
    let build = Section::new()
        .set("version", env!("CARGO_PKG_VERSION"))?
        .set("commit", build_commit)?
        .set("date", build_date)?
        .set("os", std::env::consts::OS)?
        .set("arch", std::env::consts::ARCH)?;
    let workspace = Section::new()
        .set("path", &repo.display().to_string())?
        .set("runs_dir", &runs_dir.display().to_string())?
        .set(
            "checkpoint_supported",
            if core_record::checkpoint_supported(repo) {
                "true"
            } else {
                "false"
            },
        )?;
    let config = Section::new()
        .set(
            "project",
            if FileConfig::load(repo).is_ok() {
                "valid_or_absent"
            } else {
                "invalid"
            },
        )?
        .set(
            "user",
            if FileConfig::load_user().is_ok() {
                "valid_or_absent"
            } else {
                "invalid"
            },
        )?;
    let git = match core_tools::git_environment_observation(repo).await {
        Ok(observation) => Section::new().set("observation", &observation)?,
        Err(error) => Section::new().set("unavailable", &error)?,
    };
    let bundle = Bundle::new()
        .section("build", build)?
        .section("config", config)?
        .section(
            "environment",
            Bundle::environment(|name| std::env::var(name).ok()),
        )?
        .section("git", git)?
        .section("workspace", workspace)?;
    let rendered = bundle.render();
    match output {
        None => print!("{rendered}"),
        Some(path) => write_new_private(path, rendered.as_bytes())?,
    }
    Ok(0)
}

fn write_new_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let mut options = std::fs::OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn support_output_is_private_and_never_overwrites() {
        let root =
            std::env::temp_dir().join(format!("core-support-command-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let output = root.join("support.txt");
        run_support(&root, &root.join("runs"), Some(&output), "test", "today")
            .await
            .unwrap();
        assert!(
            std::fs::read_to_string(&output)
                .unwrap()
                .contains("[build]")
        );
        assert!(
            run_support(&root, &root.join("runs"), Some(&output), "test", "today")
                .await
                .is_err(),
            "an audited bundle must not silently replace an earlier one"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(
                std::fs::metadata(&output).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        std::fs::remove_dir_all(root).ok();
    }
}
