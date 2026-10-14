//! Actual signed pricing for the fixture-owned synthetic provider, never a vendor tariff.
use super::{Command, Read, Scratch, Stdio, Value, core_command, fs, json, thread, timeout};
use iteron_protocol::{PricingRoute, PricingVersion, RateCard, TokenRateCard};
use std::process::Child;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const KEY_ENV: &str = "ITERON_HEADLESS_PRICING_FIXTURE_KEY";
// Public, deterministic test material. No operator credential or environment is inherited.
const KEY: [u8; 32] = [7; 32];
const OUTPUT_BOUND: u64 = 64 * 1024;

pub(super) fn install_key(command: &mut Command) {
    command.env(KEY_ENV, hex::encode(KEY));
}

pub(super) fn configure(scratch: &mut Scratch) {
    let route: PricingRoute = serde_json::from_slice(&route_document(scratch)).unwrap();
    assert_eq!(route.provider_id, super::PROVIDER_ID);
    assert_eq!(route.model_id, super::MODEL_ID);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let signed = iteron_obs::sign_rate_card(
        RateCard {
            version: PricingVersion::V1,
            route,
            provenance: "headless-loopback-synthetic-fixture@v1".into(),
            issued_at_unix_secs: now.saturating_sub(60),
            expires_at_unix_secs: now.checked_add(3600).unwrap(),
            rates: TokenRateCard {
                input_microusd_per_million: 1,
                output_microusd_per_million: 1,
                cache_creation_microusd_per_million: 1,
                cache_read_microusd_per_million: 1,
                thinking_microusd_per_million: 1,
            },
        },
        "headless-loopback-fixture-v1",
        KEY,
    )
    .unwrap();
    iteron_obs::validate_rate_card_digest(&signed).unwrap();
    let card = &signed.rate_card;
    // The public config entry flattens the signed route; digest and signature come directly
    // from the actual pricing owner, using the route printed by this same native executable.
    let entry = json!({
        "version": card.version,
        "provider_id": card.route.provider_id,
        "model_id": card.route.model_id,
        "catalog_digest": card.route.catalog_digest,
        "capability_digest": card.route.capability_digest,
        "provenance": card.provenance,
        "issued_at_unix_secs": card.issued_at_unix_secs,
        "expires_at_unix_secs": card.expires_at_unix_secs,
        "rates": card.rates,
        "signer_id": signed.signer_id,
        "rate_card_digest": signed.rate_card_digest,
        "signature": signed.signature,
        "key_env": KEY_ENV,
    });
    let path = scratch.home().join(".iteron/config.json");
    let mut config: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    config["rate_cards"] = json!([entry]);
    fs::write(path, serde_json::to_vec(&config).unwrap()).unwrap();
    scratch.signed_pricing = true;
}

// This offline command opens no rollout, invokes no tools and dispatches no provider request:
// the route uses the already declared local synthetic catalog. Own and reap its direct child
// across timeout/assertion paths, and retain only independently bounded pipe captures.
struct OwnedPricing(Child);
impl Drop for OwnedPricing {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn bounded_pipe(source: impl Read + Send + 'static) -> thread::JoinHandle<Vec<u8>> {
    thread::spawn(move || {
        let mut bytes = Vec::new();
        source
            .take(OUTPUT_BOUND + 1)
            .read_to_end(&mut bytes)
            .unwrap();
        bytes
    })
}

fn route_document(scratch: &Scratch) -> Vec<u8> {
    let server = core_command(scratch);
    let mut command = Command::new(server.get_program());
    command
        .env_clear()
        .envs(
            server
                .get_envs()
                .map(|(name, value)| (name, value.unwrap())),
        )
        .current_dir(scratch.repo())
        .arg("--repo")
        .arg(scratch.repo())
        .args(["--provider", super::PROVIDER_ID, "--model", super::MODEL_ID])
        .args(["pricing", "print-digests"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = OwnedPricing(command.spawn().unwrap());
    let stdout = bounded_pipe(child.0.stdout.take().unwrap());
    let stderr = bounded_pipe(child.0.stderr.take().unwrap());
    let deadline = Instant::now() + timeout();
    let status = loop {
        if let Some(status) = child.0.try_wait().unwrap() {
            break status;
        }
        if Instant::now() >= deadline {
            child.0.kill().unwrap();
            child.0.wait().unwrap();
            let _ = stdout.join();
            let _ = stderr.join();
            panic!("offline synthetic pricing route command exceeded its finite deadline");
        }
        thread::sleep(Duration::from_millis(10));
    };
    let stdout = stdout.join().unwrap();
    let stderr = stderr.join().unwrap();
    assert!(stdout.len() as u64 <= OUTPUT_BOUND);
    assert!(stderr.len() as u64 <= OUTPUT_BOUND);
    assert!(status.success(), "offline synthetic route command failed");
    stdout
}
