//! Real signed packages and physical hook effects exercise the management owner's current authority.
use super::{RuntimePlugins, dispatch::hook_key};
use crate::runtime::hooks::{HookDecision, HookEvent, Hooks};
use base64::Engine as _;
use ed25519_dalek::{Signer as _, SigningKey};
use iteron_marketplace::{Contribution, Manifest, PluginStore, Version};
use iteron_protocol::{
    Capability, RunId, SessionId, capability_set::CapabilitySet,
    extension_dispatch::ExtensionSurfaceV1, plugin_control::PluginControlV1,
};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(0);
fn temporary() -> PathBuf {
    let root = std::env::temp_dir().join(format!(
        "iteron-plugin-management-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir(&root).unwrap();
    root
}
fn ceiling() -> CapabilitySet {
    CapabilitySet::from_iter_capabilities([Capability::ReadOnly, Capability::CodeExecuting])
}
fn signed(root: &Path, name: &str, version: Version, command: &str, key: &SigningKey) -> PathBuf {
    let package = root.join(format!("{name}-{version}"));
    fs::create_dir_all(package.join("skills/review")).unwrap();
    fs::write(
        package.join("skills/review/SKILL.md"),
        "# Review\nCheck actual changes.",
    )
    .unwrap();
    let manifest = Manifest::new(name, 0)
        .at_version(version)
        .with_capabilities(ceiling())
        .with(Contribution::Skill {
            name: "review".into(),
            description: "review".into(),
        })
        .with(Contribution::Hook {
            event: "PreToolUse".into(),
            action: command.into(),
        });
    fs::write(
        package.join("manifest.json"),
        serde_json::to_vec_pretty(&manifest).unwrap(),
    )
    .unwrap();
    // Signing fixture only. The production PluginStore independently verifies this actual tree.
    let mut files = vec!["manifest.json", "skills/review/SKILL.md"];
    files.sort();
    let mut tree = Sha256::new();
    for relative in files {
        let body = fs::read(package.join(relative)).unwrap();
        tree.update((relative.len() as u64).to_be_bytes());
        tree.update(relative.as_bytes());
        tree.update((body.len() as u64).to_be_bytes());
        tree.update(body);
    }
    let mut message = b"plantcore.core.plugin-package.v1\0".to_vec();
    message.extend_from_slice(&tree.finalize());
    fs::write(package.join("signature.json"),serde_json::to_vec(&serde_json::json!({"key_id":"publisher","signature":base64::engine::general_purpose::STANDARD.encode(key.sign(&message).to_bytes())})).unwrap()).unwrap();
    package
}
fn selection(plugin: &str, enabled: bool) -> PluginControlV1 {
    PluginControlV1::SetEnabled {
        thread_id: SessionId("thread".into()),
        run_id: RunId("run".into()),
        plugin_id: plugin.into(),
        enabled,
    }
}

pub(crate) fn installed_fixture() -> (PathBuf, RuntimePlugins) {
    let root = temporary();
    let store = PluginStore::new(root.join("store"));
    let key = SigningKey::from_bytes(&[34; 32]);
    store
        .trust_key("publisher", key.verifying_key().as_bytes())
        .unwrap();
    store
        .install(&signed(&root, "verified", Version(1, 0, 0), "true", &key))
        .unwrap();
    let runtime = RuntimePlugins::load(Some(store.root()), ceiling(), None).unwrap();
    (root, runtime)
}

#[tokio::test]
async fn real_signed_disable_is_current_monotone_even_after_enable_and_new_bootstrap_is_distinct() {
    let root = temporary();
    let store = PluginStore::new(root.join("store"));
    let key = SigningKey::from_bytes(&[31; 32]);
    store
        .trust_key("publisher", key.verifying_key().as_bytes())
        .unwrap();
    let marker = root.join("executed");
    let command = format!(
        "printf actual > '{}'",
        marker.to_string_lossy().replace('\'', "'\"'\"'")
    );
    let source = signed(&root, "verified", Version(1, 0, 0), &command, &key);
    store.install(&source).unwrap();
    let mut runtime = RuntimePlugins::load(Some(store.root()), ceiling(), None).unwrap();
    let owner = runtime.management_port().unwrap().unwrap();
    let policy = owner.dispatch_policy();
    let mut hooks = Hooks::from_user_config(Some(&runtime.hooks));
    let identity = hooks.catalog_identity();
    hooks
        .install_extension_dispatch_policy(policy.clone())
        .unwrap();
    assert!(matches!(
        hooks.run(HookEvent::PreToolUse, "{}").await,
        HookDecision::Allow
    ));
    assert_eq!(fs::read(&marker).unwrap(), b"actual");
    fs::remove_file(&marker).unwrap();
    let result = owner.execute(selection("verified", false)).await.unwrap();
    assert_eq!(result["change_confirmed"], true);
    assert!(!policy.admits(ExtensionSurfaceV1::Hook, &hook_key("PreToolUse", &command)));
    assert!(!policy.admits(ExtensionSurfaceV1::Skill, "review"));
    assert!(matches!(
        hooks.run(HookEvent::PreToolUse, "{}").await,
        HookDecision::Deny(_)
    ));
    assert!(!marker.exists());
    assert_eq!(hooks.catalog_identity(), identity);
    assert_eq!(
        owner.execute(selection("verified", true)).await.unwrap()["change_confirmed"],
        true
    );
    assert!(matches!(
        hooks.run(HookEvent::PreToolUse, "{}").await,
        HookDecision::Deny(_)
    ));
    assert!(!marker.exists());
    let restarted = RuntimePlugins::load(Some(store.root()), ceiling(), None).unwrap();
    let mut new_hooks = Hooks::from_user_config(Some(&restarted.hooks));
    new_hooks
        .install_extension_dispatch_policy(restarted.dispatch_policy().unwrap())
        .unwrap();
    assert!(matches!(
        new_hooks.run(HookEvent::PreToolUse, "{}").await,
        HookDecision::Allow
    ));
    assert_eq!(fs::read(&marker).unwrap(), b"actual");
    fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn actual_conflict_rank_rollback_and_prepared_install_keep_bootstrap_identity_truthful() {
    let root = temporary();
    let store = PluginStore::new(root.join("store"));
    let key = SigningKey::from_bytes(&[32; 32]);
    store
        .trust_key("publisher", key.verifying_key().as_bytes())
        .unwrap();
    for (name, version) in [
        ("alpha", Version(1, 0, 0)),
        ("alpha", Version(2, 0, 0)),
        ("beta", Version(1, 0, 0)),
    ] {
        store
            .install(&signed(&root, name, version, "true", &key))
            .unwrap();
    }
    store.set_precedence("beta", 5).unwrap();
    let mut runtime = RuntimePlugins::load(Some(store.root()), ceiling(), None).unwrap();
    let source = signed(&root, "gamma", Version(1, 0, 0), "true", &key);
    let receipt = runtime.prepare_package_install(&source).unwrap();
    let owner = runtime.management_port().unwrap().unwrap();
    let original = owner.snapshot();
    assert_eq!(
        original["bootstrap_composition"]["conflicts"]["items"][0]["winner"],
        "beta"
    );
    let original_digest =
        original["current_generation"]["items"][0]["manifest_digest_sha256"].clone();
    assert_eq!(
        owner
            .execute(PluginControlV1::Rollback {
                thread_id: SessionId("thread".into()),
                run_id: RunId("run".into()),
                plugin_id: "alpha".into()
            })
            .await
            .unwrap()["change_confirmed"],
        true
    );
    assert_eq!(
        store
            .list()
            .unwrap()
            .iter()
            .find(|(name, _)| name == "alpha")
            .unwrap()
            .1
            .current
            .version,
        Version(1, 0, 0)
    );
    assert_eq!(
        owner.snapshot()["current_generation"]["items"][0]["manifest_digest_sha256"],
        original_digest,
        "current loaded implementation is not forged into rollback target"
    );
    assert_eq!(
        owner
            .execute(PluginControlV1::Install {
                thread_id: SessionId("thread".into()),
                run_id: RunId("run".into()),
                receipt_id: receipt
            })
            .await
            .unwrap()["change_confirmed"],
        true
    );
    assert!(
        store
            .list()
            .unwrap()
            .iter()
            .any(|(name, _)| name == "gamma")
    );
    assert_eq!(
        owner.snapshot()["current_generation"]["total"],
        2,
        "install pending does not invent live bindings"
    );
    let metadata = owner.snapshot().to_string();
    assert!(!metadata.contains(&source.to_string_lossy().to_string()));
    assert!(!metadata.contains("signature\""));
    assert!(metadata.contains("next_bootstrap_pending"));
    fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn registry_publication_refusal_retains_actual_current_revocation_without_confirming_persistence()
 {
    let root = temporary();
    let store = PluginStore::new(root.join("store"));
    let key = SigningKey::from_bytes(&[33; 32]);
    store
        .trust_key("publisher", key.verifying_key().as_bytes())
        .unwrap();
    store
        .install(&signed(&root, "verified", Version(1, 0, 0), "true", &key))
        .unwrap();
    let mut runtime = RuntimePlugins::load(Some(store.root()), ceiling(), None).unwrap();
    let owner = runtime.management_port().unwrap().unwrap();
    // Occupy the exact next immutable generation. The real writer cannot overwrite it.
    fs::write(
        store.root().join("state/registry-0000000000000002.json"),
        b"unavailable state",
    )
    .unwrap();
    let reply = owner.execute(selection("verified", false)).await.unwrap();
    assert_eq!(reply["change_confirmed"], false);
    assert_eq!(reply["reason_code"], "persistent_change_unconfirmed");
    assert!(
        !owner
            .dispatch_policy()
            .admits(ExtensionSurfaceV1::Skill, "review")
    );
    assert_eq!(
        owner.snapshot()["current_generation"]["items"][0]["future_dispatch_revoked"],
        true
    );
    fs::remove_dir_all(root).unwrap();
}
