//! The five W1 ABI contracts, bound to the frozen fixtures the compatibility gate reads.
//!
//! `core-xtask schema-compat` checks the fixtures against the *manifest*: it asserts that
//! `governance/schema-compat/fixtures/abi/*.json` carries exactly the fields
//! `governance/schema-compatibility.json` declares, and that those bytes never move again. What it
//! cannot check is the other half — that the declared shape is still the shape the Rust type
//! actually serialises. The managed families (`protocol.*`, `record.*`, `cli.machine-*`) get that
//! from a source binding in xtask; the `abi.` surfaces deliberately have none, because binding them
//! to `PROTOCOL_VERSION` would make every future wire bump mint five new frozen fixtures for
//! contracts whose shapes did not change.
//!
//! This file is the missing half, in the place that can express it: each fixture is decoded into
//! its contract type and re-encoded, and the bytes must come back identical. A field added to,
//! removed from or renamed on any of the five types fails here.

use core_protocol::artifact::ArtifactRef;
use core_protocol::context::ContextRequest;
use core_protocol::effect::EffectProposal;
use core_protocol::intent::ToolIntent;
use core_protocol::task::TaskEnvelope;
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::Value;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("repository root exists")
}

/// The one fixture the named surface pins at its current version, plus the fields it declares.
fn surface(id: &str) -> (String, BTreeSet<String>) {
    let contract: Value = serde_json::from_slice(
        &std::fs::read(root().join("governance/schema-compatibility.json"))
            .expect("compatibility contract is readable"),
    )
    .expect("compatibility contract is JSON");
    let surface = contract["surfaces"]
        .as_array()
        .expect("surfaces is an array")
        .iter()
        .find(|surface| surface["id"] == id)
        .unwrap_or_else(|| panic!("schema surface `{id}` is declared"));
    let current = surface["current_version"]
        .as_u64()
        .expect("surface current version");
    let path = surface["fixtures"]
        .as_array()
        .expect("fixtures is an array")
        .iter()
        .find(|fixture| fixture["schema_version"].as_u64() == Some(current))
        .expect("a surface pins a fixture at its current version")["path"]
        .as_str()
        .expect("fixture path is a string")
        .to_owned();
    let fields = surface["fields"]
        .as_array()
        .expect("fields is an array")
        .iter()
        .map(|field| field["name"].as_str().expect("field name").to_owned())
        .collect();
    (path, fields)
}

/// Decode the surface's current fixture as `T`, re-encode it, and require byte equality.
///
/// Byte equality rather than `Value` equality on purpose. A `skip_serializing_if` that starts
/// firing, or an `Option` that starts being omitted, changes the bytes a downstream reader parses
/// while leaving the decoded value equal; any field appended after the freeze carries exactly that
/// attribute pair, so only the bytes catch the drift.
fn round_trips<T: Serialize + DeserializeOwned>(id: &str) {
    let (relative, declared) = surface(id);
    let bytes = std::fs::read(root().join(&relative))
        .unwrap_or_else(|_| panic!("frozen fixture `{relative}` is readable"));
    let text = std::str::from_utf8(&bytes).expect("fixture is UTF-8");

    let decoded: T = serde_json::from_str(text)
        .unwrap_or_else(|error| panic!("`{relative}` no longer decodes as its contract: {error}"));
    let reencoded = serde_json::to_string(&decoded).expect("contract re-serialises");
    assert_eq!(
        reencoded,
        text.trim_end_matches('\n'),
        "`{relative}` is frozen; the contract type must still produce exactly these bytes"
    );

    let observed: BTreeSet<String> = serde_json::from_str::<Value>(text)
        .expect("fixture is JSON")
        .as_object()
        .expect("fixture is a JSON object")
        .keys()
        .cloned()
        .collect();
    assert_eq!(
        observed, declared,
        "`{id}` declares fields the fixture does not carry, or the reverse"
    );
}

#[test]
fn the_task_envelope_contract_matches_its_frozen_fixture() {
    round_trips::<TaskEnvelope>("abi.task-envelope");
}

#[test]
fn the_context_request_contract_matches_its_frozen_fixture() {
    round_trips::<ContextRequest>("abi.context-request");
}

#[test]
fn the_tool_intent_contract_matches_its_frozen_fixture() {
    round_trips::<ToolIntent>("abi.tool-intent");
}

#[test]
fn the_effect_proposal_contract_matches_its_frozen_fixture() {
    round_trips::<EffectProposal>("abi.effect-proposal");
}

#[test]
fn the_artifact_ref_contract_matches_its_frozen_fixture() {
    round_trips::<ArtifactRef>("abi.artifact-ref");
}
