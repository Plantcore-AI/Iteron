//! A performance floor for the harness itself (I-57).
//!
//! The suite has 1613 functional tests, process-level end-to-end runs and real PTY drives, and not
//! one of them asserts a wall-clock bound. A one-line concurrency hazard — a lock held across an
//! await, a fsync moved inside a loop, an accidentally serialized dispatch — is therefore exactly
//! the kind of change that merges green.
//!
//! # What is measured, and why that
//!
//! Not total wall time: that folds in process startup, the provider, and the CI runner's mood.
//! This measures `kernel_tax` — admission, broker and record-fsync microseconds the kernel stamps
//! around its own work — against a **fixed script replayed on the loopback fixture provider**, so
//! the provider contributes nothing and the number is harness-attributable by construction. It is
//! the same instrumentation the one-shot result document already publishes, alongside the
//! first-token measurement that landed with #103.
//!
//! # Why the minimum of several runs
//!
//! A floor is stable where a mean is not: noise only ever adds. Taking the minimum turns "how fast
//! can this machine do it" into a repeatable number, so the budget can sit close enough to the
//! real value for a 2x regression to trip it while ordinary variance does not. The default budget
//! is the calibrated floor times `BUDGET_HEADROOM_PERCENT`, which is held below 200 at compile
//! time — that is the whole trick: a doubling fails, a 40% bad day does not.
//!
//! # Why it is `#[ignore]`d
//!
//! Timing belongs in a job that cannot block a merge. The CI job runs it with `--ignored`; a
//! developer runs `cargo test -p iteron-cli --test harness_latency -- --ignored`.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::Duration;

const PROVIDER_ID: &str = "latency";
const MODEL_ID: &str = "latency-model";
const TEST_KEY_ENV: &str = "ITERON_LATENCY_TEST_KEY";
const FIXTURE_CONTEXT_WINDOW_TOKENS: u64 = 1_000_000;
const IO_TIMEOUT: Duration = Duration::from_secs(5);

/// Turns in the fixed script. Enough that per-turn amortization is meaningful and the record has
/// several fsyncs to pay for; small enough that the job stays under a minute.
const SCRIPT_TURNS: u32 = 6;
/// How many times the script is replayed. The minimum across these is the measurement.
const REPLAYS: usize = 5;
/// The floor observed while calibrating this job: min-of-`REPLAYS` on a debug build measured
/// 58.7 / 60.2 / 61.6 ms per turn across three sittings. Under 5% spread is exactly the property
/// that makes a budget of this shape usable at all.
const CALIBRATED_FLOOR_US_PER_TURN: u64 = 60_000;
/// Headroom over the calibrated floor, in percent. Below 200 by construction, checked at compile
/// time: at or above a doubling, the regression this job exists to catch would pass.
const BUDGET_HEADROOM_PERCENT: u64 = 175;
const _: () = assert!(
    BUDGET_HEADROOM_PERCENT < 200,
    "the budget must sit below a doubling of the calibrated floor"
);
/// Microseconds of kernel tax per turn this harness is allowed to spend. Overridable for a slower
/// runner, because the job's purpose is to catch a step change, not to rank hardware.
const DEFAULT_BUDGET_US_PER_TURN: u64 =
    CALIBRATED_FLOOR_US_PER_TURN * BUDGET_HEADROOM_PERCENT / 100;

static NEXT_ID: AtomicU64 = AtomicU64::new(0);

struct Scratch {
    root: PathBuf,
}

impl Scratch {
    fn new(api_root: &str) -> Self {
        let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        let root =
            std::env::temp_dir().join(format!("core-harness-latency-{}-{id}", std::process::id()));
        let scratch = Self { root };
        std::fs::create_dir_all(scratch.repo()).expect("create isolated repository");
        std::fs::create_dir_all(scratch.home().join(".iteron")).expect("create isolated Core home");
        std::fs::create_dir_all(scratch.runs()).expect("create isolated rollout directory");
        let config = serde_json::json!({
            "provider": PROVIDER_ID,
            "model": MODEL_ID,
            "effort": "low",
            "max_wall_secs": 30,
            "providers": [{
                "id": PROVIDER_ID,
                "display_name": "Latency fixture provider",
                "adapter": "openai_chat",
                "error_profile": "custom",
                "api_root": api_root,
                "key_env": TEST_KEY_ENV,
                "enabled": true,
                "catalog": false,
                "models": [MODEL_ID],
                "model_capabilities": {
                    (MODEL_ID): {
                        "context_window_tokens": FIXTURE_CONTEXT_WINDOW_TOKENS
                    }
                }
            }]
        });
        std::fs::write(
            scratch.home().join(".iteron/config.json"),
            serde_json::to_vec(&config).expect("encode fixture config"),
        )
        .expect("write fixture config");
        scratch
    }

    fn repo(&self) -> PathBuf {
        self.root.join("repo")
    }

    fn home(&self) -> PathBuf {
        self.root.join("home")
    }

    fn runs(&self) -> PathBuf {
        self.root.join("runs")
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

/// The fixed script: `SCRIPT_TURNS - 1` tool-calling turns followed by one terminal answer. Every
/// reply is fully buffered before the first byte is written, so the provider adds no latency of
/// its own and every microsecond the kernel stamps is the harness's.
fn reply_body(call: u32) -> String {
    if call + 1 < SCRIPT_TURNS {
        format!(
            concat!(
                "data: {{\"id\":\"chatcmpl-latency-{call}\",\"object\":\"chat.completion.chunk\",\"choices\":[{{\"index\":0,\"delta\":{{\"role\":\"assistant\",\"tool_calls\":[{{\"index\":0,\"id\":\"call-latency-{call}\",\"type\":\"function\",\"function\":{{\"name\":\"list_dir\",\"arguments\":\"{{\\\"path\\\":\\\".\\\"}}\"}}}}]}},\"finish_reason\":null}}],\"usage\":null}}\n\n",
                "data: {{\"id\":\"chatcmpl-latency-{call}\",\"object\":\"chat.completion.chunk\",\"choices\":[{{\"index\":0,\"delta\":{{}},\"finish_reason\":\"tool_calls\"}}],\"usage\":null}}\n\n",
                "data: {{\"id\":\"chatcmpl-latency-{call}\",\"object\":\"chat.completion.chunk\",\"choices\":[],\"usage\":{{\"prompt_tokens\":11,\"completion_tokens\":1,\"total_tokens\":12,\"prompt_tokens_details\":{{\"cached_tokens\":0}},\"completion_tokens_details\":{{\"reasoning_tokens\":0}}}}}}\n\n",
                "data: [DONE]\n\n",
            ),
            call = call,
        )
    } else {
        concat!(
            "data: {\"id\":\"chatcmpl-latency-done\",\"object\":\"chat.completion.chunk\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"content\":\"done\"},\"finish_reason\":null}],\"usage\":null}\n\n",
            "data: {\"id\":\"chatcmpl-latency-done\",\"object\":\"chat.completion.chunk\",\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}],\"usage\":null}\n\n",
            "data: {\"id\":\"chatcmpl-latency-done\",\"object\":\"chat.completion.chunk\",\"choices\":[],\"usage\":{\"prompt_tokens\":11,\"completion_tokens\":1,\"total_tokens\":12,\"prompt_tokens_details\":{\"cached_tokens\":0},\"completion_tokens_details\":{\"reasoning_tokens\":0}}}\n\n",
            "data: [DONE]\n\n",
        )
        .to_string()
    }
}

fn serve(listener: TcpListener) {
    let mut call = 0u32;
    for stream in listener.incoming() {
        let Ok(mut stream) = stream else { break };
        if read_request(&mut stream).is_none() {
            continue;
        }
        let body = reply_body(call % SCRIPT_TURNS);
        call = call.wrapping_add(1);
        let _ = stream.set_write_timeout(Some(IO_TIMEOUT));
        let _ = write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        let _ = stream.flush();
    }
}

/// Read exactly one request. Returns `None` if the peer hung up, which a cancelled run may do.
fn read_request(stream: &mut TcpStream) -> Option<()> {
    stream.set_read_timeout(Some(IO_TIMEOUT)).ok()?;
    let mut request = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        let read = stream.read(&mut chunk).ok()?;
        if read == 0 {
            return None;
        }
        request.extend_from_slice(&chunk[..read]);
        let Some(header_end) = request.windows(4).position(|window| window == b"\r\n\r\n") else {
            continue;
        };
        let headers = std::str::from_utf8(&request[..header_end]).ok()?;
        let length: usize = headers.lines().find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse().ok())?
        })?;
        if request.len() >= header_end + 4 + length {
            return Some(());
        }
    }
}

/// Kernel tax, in microseconds, for one replay of the fixed script.
fn one_replay(scratch: &Scratch) -> u64 {
    let output = Command::new(env!("CARGO_BIN_EXE_iteron"))
        .env_clear()
        .env("HOME", scratch.home())
        .env("PATH", "/usr/bin:/bin")
        .env("LANG", "C.UTF-8")
        .env("NO_PROXY", "127.0.0.1,localhost")
        .env(TEST_KEY_ENV, "harness-latency-placeholder")
        .current_dir(scratch.repo())
        .arg("-p")
        .arg("replay the fixed latency script")
        .arg("--output-format")
        .arg("json")
        .arg("--repo")
        .arg(scratch.repo())
        .arg("--runs-dir")
        .arg(scratch.runs())
        .arg("--provider")
        .arg(PROVIDER_ID)
        .arg("--model")
        .arg(MODEL_ID)
        .arg("--effort")
        .arg("low")
        .arg("--max-turns")
        .arg(SCRIPT_TURNS.to_string())
        .output()
        .expect("run the fixed script");

    let result: serde_json::Value = serde_json::from_slice(
        output
            .stdout
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty())
            .next_back()
            .unwrap_or_else(|| {
                panic!(
                    "the run produced no machine result; stderr:\n{}",
                    String::from_utf8_lossy(&output.stderr)
                )
            }),
    )
    .expect("the terminal line is the result document");
    let tax = &result["kernel_tax"];
    let field = |name: &str| {
        tax[name]
            .as_u64()
            .unwrap_or_else(|| panic!("{name} is reported"))
    };
    let turns = result["turns"].as_u64().unwrap_or(0).max(1);
    (field("admission_latency_us") + field("broker_latency_us") + field("record_fsync_latency_us"))
        / turns
}

#[test]
#[ignore = "wall-clock bound: run by the non-blocking performance job, never by the merge gate"]
fn harness_attributable_time_stays_within_its_budget() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback fixture provider");
    let api_root = format!(
        "http://{}/v1",
        listener.local_addr().expect("fixture provider address")
    );
    thread::spawn(move || serve(listener));

    let scratch = Scratch::new(&api_root);
    // One warm-up replay, discarded: the first run pays for cold page caches and a cold rollout
    // directory, which is a property of the machine and not of the harness.
    let _ = one_replay(&scratch);

    let floor = (0..REPLAYS)
        .map(|_| one_replay(&scratch))
        .min()
        .expect("REPLAYS is non-zero");

    let budget = std::env::var("ITERON_HARNESS_TAX_BUDGET_US")
        .ok()
        .and_then(|raw| raw.parse().ok())
        .unwrap_or(DEFAULT_BUDGET_US_PER_TURN);

    // Printed unconditionally: the job's log is the drift record, whether or not it fails.
    println!(
        "harness tax floor: {floor}us/turn over {REPLAYS} replays of a {SCRIPT_TURNS}-turn script \
         (budget {budget}us/turn, headroom {:.2}x)",
        budget as f64 / floor.max(1) as f64
    );
    assert!(
        floor <= budget,
        "harness-attributable time regressed: {floor}us/turn against a {budget}us/turn budget. \
         A doubling is the signal this job exists for; set ITERON_HARNESS_TAX_BUDGET_US if this \
         runner is simply slower than the machine the budget was calibrated on."
    );
}
