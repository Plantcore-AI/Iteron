//! core-eval — the fixed-model, component-toggle evaluation harness (R4).
//!
//! Why this shape (ADR-002): a coding-agent score is jointly produced by a model and a harness,
//! and cross-vendor comparison is confounded. The only falsifiable claim is a **fixed-model,
//! component-toggle** experiment reporting the harness-induced delta with the trajectory metrics.
//! So this harness holds the model fixed and toggles ONE harness component at a time, on fresh
//! copies of a task repo, using the repo's real test suite as the ground-truth oracle
//! (CI-as-ground-truth). It reports resolved / turns / cost per configuration and the delta.
//!
//! HONEST SCOPE (R10): this is the machinery + a bounded demonstration. The full statistical
//! protocol (ADR-002) needs n>=3 seeds and many tasks to resolve a small delta against the
//! variance floor; a single-seed single-task run is a demonstration of attribution, not a
//! powered result. The harness supports more seeds/tasks; the run is bounded to control cost.

use std::path::{Path, PathBuf};
use std::process::Command;

/// A task: how to set up a fresh repo, what to ask, and how to check ground truth.
struct Task {
    name: &'static str,
    /// Files to write into the fresh repo: (relative path, contents).
    files: &'static [(&'static str, &'static str)],
    prompt: &'static str,
    /// The verify command passed to core's --verify (when the verify component is on).
    verify_cmd: &'static str,
    /// The ground-truth check: run after the agent finishes; exit 0 == resolved. This is the
    /// oracle the harness itself trusts, independent of what the agent was told.
    ground_truth: &'static str,
}

/// A harness configuration: which components are on. Toggling ONE at a time is the design.
#[derive(Clone, Copy)]
struct Config {
    name: &'static str,
    verify_gate: bool,
}

struct Outcome {
    resolved: bool,
    turns: u32,
    cost_usd: f64,
    label: String,
}

fn main() -> anyhow::Result<()> {
    let core = find_core()?;
    eprintln!("eval: using binary {}", core.display());

    // Tasks with a LATENT second failure: the prompt names one fix, but a second test also
    // fails. A harness WITHOUT the verify gate accepts the model's premature "done"; WITH it,
    // the harness runs the full suite and refuses. This isolates the verify component's
    // contribution to the resolved rate at a fixed model across several task shapes.
    let tasks = [
        Task {
            name: "latent-2nd-arith",
            files: &[
                (
                    "calc.py",
                    "def multiply(a, b):\n    return a + b\n\ndef divide(a, b):\n    return a * b\n",
                ),
                (
                    "test_calc.py",
                    "from calc import multiply, divide\ndef test_multiply(): assert multiply(3, 4) == 12\ndef test_divide(): assert divide(12, 3) == 4\n",
                ),
            ],
            prompt: "Fix the multiply function in calc.py so its test passes.",
            verify_cmd: "python3 -m pytest -q",
            ground_truth: "python3 -m pytest -q",
        },
        Task {
            name: "latent-2nd-strings",
            files: &[
                (
                    "strutil.py",
                    "def upper(s):\n    return s.lower()\n\ndef reverse(s):\n    return s\n",
                ),
                (
                    "test_strutil.py",
                    "from strutil import upper, reverse\ndef test_upper(): assert upper('hi') == 'HI'\ndef test_reverse(): assert reverse('abc') == 'cba'\n",
                ),
            ],
            prompt: "Fix the upper function in strutil.py so its test passes.",
            verify_cmd: "python3 -m pytest -q",
            ground_truth: "python3 -m pytest -q",
        },
    ];

    let configs = [
        Config {
            name: "verify_OFF",
            verify_gate: false,
        },
        Config {
            name: "verify_ON",
            verify_gate: true,
        },
    ];

    // Seeds per cell (reliability). Read from CORE_EVAL_SEEDS (default 2 to bound cost); the
    // powered protocol wants >=3. Total runs = tasks * configs * seeds.
    let seeds: usize = std::env::var("CORE_EVAL_SEEDS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(2);
    let mut results: Vec<Outcome> = Vec::new();

    for task in &tasks {
        for cfg in &configs {
            for seed in 0..seeds {
                let dir = setup_repo(task, cfg.name, seed)?;
                let (turns, cost) = run_core(&core, &dir, task, cfg)?;
                let resolved = check_ground_truth(&dir, task.ground_truth);
                results.push(Outcome {
                    resolved,
                    turns,
                    cost_usd: cost,
                    label: format!("{}/{}#{seed}", task.name, cfg.name),
                });
                eprintln!(
                    "  {} -> resolved={} turns={} cost=${:.4}",
                    results.last().unwrap().label,
                    resolved,
                    turns,
                    cost
                );
            }
        }
    }

    report(&results);
    Ok(())
}

fn find_core() -> anyhow::Result<PathBuf> {
    for c in [
        "target/release/core",
        "target/debug/core",
        "target/release/core",
        "target/debug/core",
    ] {
        let p = PathBuf::from(c);
        if p.exists() {
            return Ok(std::fs::canonicalize(p)?);
        }
    }
    anyhow::bail!("build the CLI first: cargo build --release -p core-cli")
}

fn setup_repo(task: &Task, cfg: &str, seed: usize) -> anyhow::Result<PathBuf> {
    let base = std::env::temp_dir().join(format!("core-eval/{}-{cfg}-{seed}", task.name));
    let _ = std::fs::remove_dir_all(&base);
    std::fs::create_dir_all(&base)?;
    for (rel, contents) in task.files {
        let p = base.join(rel);
        if let Some(parent) = p.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(p, contents)?;
    }
    // git init so the agent's edits are diffable (and to mirror real conditions).
    run(&base, "git", &["init", "-q"]);
    run(&base, "git", &["add", "-A"]);
    let _ = Command::new("git")
        .args([
            "-c",
            "user.name=e",
            "-c",
            "user.email=e@e",
            "commit",
            "-q",
            "-m",
            "init",
        ])
        .current_dir(&base)
        .status();
    Ok(base)
}

fn run_core(core: &Path, dir: &Path, task: &Task, cfg: &Config) -> anyhow::Result<(u32, f64)> {
    let mut args: Vec<String> = vec![
        "-C".into(),
        dir.display().to_string(),
        "--allow-code".into(),
        "--max-turns".into(),
        "20".into(),
        "--max-usd".into(),
        "1.5".into(),
    ];
    if cfg.verify_gate {
        args.push("--verify".into());
        args.push(task.verify_cmd.into());
    }
    args.push(task.prompt.into());

    let out = Command::new(core).args(&args).output()?;
    let stderr = String::from_utf8_lossy(&out.stderr);
    // Parse the ledger summary line: "turns=N ... cost=$X.XXXX ..."
    let turns = grab(&stderr, "turns=")
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let cost = grab(&stderr, "cost=$")
        .and_then(|s| s.parse().ok())
        .unwrap_or(0.0);
    Ok((turns, cost))
}

fn grab(s: &str, key: &str) -> Option<String> {
    let i = s.find(key)? + key.len();
    let rest = &s[i..];
    let end = rest
        .find(|c: char| !(c.is_ascii_digit() || c == '.'))
        .unwrap_or(rest.len());
    Some(rest[..end].to_string())
}

fn check_ground_truth(dir: &Path, cmd: &str) -> bool {
    Command::new("bash")
        .arg("-lc")
        .arg(cmd)
        .current_dir(dir)
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn run(dir: &Path, cmd: &str, args: &[&str]) {
    let _ = Command::new(cmd).args(args).current_dir(dir).status();
}

fn report(results: &[Outcome]) {
    println!("\n=== R4 component-toggle result (fixed model, CI-as-ground-truth) ===\n");
    println!(
        "{:<34} {:>9} {:>7} {:>10}",
        "cell", "resolved", "turns", "cost"
    );
    for r in results {
        println!(
            "{:<34} {:>9} {:>7} {:>9.4}",
            r.label, r.resolved, r.turns, r.cost_usd
        );
    }
    let off: Vec<&Outcome> = results
        .iter()
        .filter(|r| r.label.contains("verify_OFF"))
        .collect();
    let on: Vec<&Outcome> = results
        .iter()
        .filter(|r| r.label.contains("verify_ON"))
        .collect();
    let n = |v: &[&Outcome]| v.len();
    let solved = |v: &[&Outcome]| v.iter().filter(|r| r.resolved).count();
    let rate = |v: &[&Outcome]| {
        if v.is_empty() {
            0.0
        } else {
            solved(v) as f64 / v.len() as f64
        }
    };
    let cost = |v: &[&Outcome]| {
        if v.is_empty() {
            0.0
        } else {
            v.iter().map(|r| r.cost_usd).sum::<f64>() / v.len() as f64
        }
    };

    println!("\n--- aggregate (all tasks x seeds) ---");
    println!(
        "verify_OFF: resolved {}/{} = {:.0}%,  avg cost ${:.4}",
        solved(&off),
        n(&off),
        rate(&off) * 100.0,
        cost(&off)
    );
    println!(
        "verify_ON : resolved {}/{} = {:.0}%,  avg cost ${:.4}",
        solved(&on),
        n(&on),
        rate(&on) * 100.0,
        cost(&on)
    );
    println!(
        "\nVERIFY COMPONENT delta on resolved rate: {:.0}% -> {:.0}% (Δ {:+.0} pts) at a FIXED MODEL",
        rate(&off) * 100.0,
        rate(&on) * 100.0,
        (rate(&on) - rate(&off)) * 100.0
    );
    println!(
        "cost of the gate: +${:.4}/run avg (turns to fix the caught failure)",
        cost(&on) - cost(&off)
    );

    // pass^k reliability per task per config (did EVERY seed of a task*config resolve?).
    println!("\n--- reliability (pass^k: all seeds of a task*config resolved?) ---");
    let mut task_cfgs: std::collections::BTreeMap<String, (usize, usize)> =
        std::collections::BTreeMap::new();
    for r in results {
        // label = "<task>/<cfg>#<seed>"
        let key = r
            .label
            .rsplit_once('#')
            .map(|(a, _)| a.to_string())
            .unwrap_or_else(|| r.label.clone());
        let e = task_cfgs.entry(key).or_insert((0, 0));
        e.1 += 1;
        if r.resolved {
            e.0 += 1;
        }
    }
    for (k, (s, t)) in &task_cfgs {
        println!(
            "{:<34} {}/{} seeds resolved  {}",
            k,
            s,
            t,
            if s == t {
                "(reliable)"
            } else {
                "(flaky/failed)"
            }
        );
    }

    println!(
        "\nHONEST SCOPE (R10): {} runs total. This is a SCALED demonstration, not yet the fully",
        results.len()
    );
    println!(
        "powered study — the protocol (ADR-002) wants n>=3 seeds, more + harder tasks, at least"
    );
    println!(
        "one contamination-resistant benchmark, and CIs on the harness-vs-model variance. The"
    );
    println!(
        "delta here is large by construction (tasks isolate the component). Scaling to a powered"
    );
    println!("study is API budget, not new code (set CORE_EVAL_SEEDS and add tasks).");
}
