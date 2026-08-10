//! Provider-free CLI for the signed plugin store.

use std::io::Read as _;
use std::path::{Path, PathBuf};

use base64::Engine as _;
use clap::Subcommand;
use iteron_marketplace::{PluginStore, RuntimeScope, compose_governed};
use iteron_protocol::Capability;
use iteron_protocol::capability_set::CapabilitySet;

const MAX_PUBLIC_KEY_FILE_BYTES: usize = 1024;

#[derive(Debug, Clone, PartialEq, Eq, Subcommand)]
pub(crate) enum Action {
    /// List installed versions, enablement, rollback availability, and publisher identity.
    List,
    /// Add an immutable trusted Ed25519 publisher key from a raw-32-byte or base64 file.
    Trust {
        key_id: String,
        #[arg(value_name = "PUBLIC_KEY_FILE")]
        public_key: PathBuf,
    },
    /// Verify and install a local signed package directory.
    Install {
        #[arg(value_name = "PACKAGE_DIR")]
        package: PathBuf,
        /// Operator-owned conflict rank; package manifests cannot rank themselves.
        #[arg(long)]
        precedence: Option<u32>,
    },
    /// Verify and update from a newer local signed package directory.
    Update {
        #[arg(value_name = "PACKAGE_DIR")]
        package: PathBuf,
        /// Replace the current operator-owned conflict rank while updating.
        #[arg(long)]
        precedence: Option<u32>,
    },
    /// Enable an installed plugin for future runtime composition.
    Enable { name: String },
    /// Disable an installed plugin while retaining its offline cache.
    Disable { name: String },
    /// Change the operator-owned conflict rank without reinstalling.
    Rank { name: String, precedence: u32 },
    /// Remove a plugin from runtime composition while retaining cached artifacts.
    Uninstall { name: String },
    /// Atomically return to the one retained, re-verified prior artifact.
    Rollback { name: String },
    /// Re-verify every enabled cache entry and explain composition refusals/conflicts.
    Doctor,
}

pub(crate) fn run(action: &Action, root: &Path) -> anyhow::Result<u8> {
    let store = PluginStore::new(root);
    match action {
        Action::List => {
            let installed = store.list()?;
            if installed.is_empty() {
                println!("No plugins installed.");
            }
            for (name, entry) in installed {
                println!(
                    "{name} {}  {}  rank={}  key={}{}",
                    entry.current.version,
                    if entry.enabled { "enabled" } else { "disabled" },
                    entry.precedence,
                    entry.current.key_id,
                    if entry.previous.is_some() {
                        "  rollback=available"
                    } else {
                        ""
                    }
                );
            }
        }
        Action::Trust { key_id, public_key } => {
            let bytes = read_public_key(public_key)?;
            store.trust_key(key_id, &bytes)?;
            println!("Trusted publisher key {key_id}.");
        }
        Action::Install {
            package,
            precedence,
        }
        | Action::Update {
            package,
            precedence,
        } => {
            let artifact = store.install_with_precedence(package, *precedence)?;
            println!(
                "Installed {} (sha256:{}, key={}).",
                artifact.version, artifact.digest, artifact.key_id
            );
        }
        Action::Enable { name } => {
            store.set_enabled(name, true)?;
            println!("Enabled {name}.");
        }
        Action::Disable { name } => {
            store.set_enabled(name, false)?;
            println!("Disabled {name}; cached artifacts were retained for offline recovery.");
        }
        Action::Rank { name, precedence } => {
            store.set_precedence(name, *precedence)?;
            println!("Ranked {name} at precedence {precedence}.");
        }
        Action::Uninstall { name } => {
            store.uninstall(name)?;
            println!("Uninstalled {name}; cached artifacts were retained for offline recovery.");
        }
        Action::Rollback { name } => {
            let artifact = store.rollback(name)?;
            println!(
                "Rolled {name} back to {} (sha256:{}).",
                artifact.version, artifact.digest
            );
        }
        Action::Doctor => doctor(&store)?,
    }
    Ok(crate::output::EXIT_SUCCESS)
}

fn doctor(store: &PluginStore) -> anyhow::Result<()> {
    let trusted = store.trusted_keys()?;
    let packages = store.runtime_packages()?;
    let manifests = packages
        .active
        .iter()
        .map(|plugin| plugin.manifest.clone())
        .collect::<Vec<_>>();
    let composition = compose_governed(
        &manifests,
        RuntimeScope::Workspace,
        CapabilitySet::from_iter_capabilities([
            Capability::ReadOnly,
            Capability::ReversibleLocal,
            Capability::CodeExecuting,
            Capability::TrustMutating,
            Capability::IrreversibleExternal,
        ]),
    );
    println!("plugin store: {}", store.root().display());
    println!("trusted publishers: {}", trusted.len());
    println!("verified enabled plugins: {}", packages.active.len());
    println!("runtime bindings: {}", composition.wiring.slots().len());
    for quarantine in packages.quarantined {
        println!("quarantined: {quarantine}");
    }
    for refusal in composition.report.refusals() {
        println!("refused: {refusal}");
    }
    for contest in composition.report.contests() {
        println!(
            "conflict: {} -> {} (shadowed: {})",
            contest.slot,
            contest.winner,
            contest.shadowed.join(", ")
        );
    }
    Ok(())
}

fn read_public_key(path: &Path) -> anyhow::Result<[u8; 32]> {
    let mut file = std::fs::File::open(path)
        .map_err(|error| anyhow::anyhow!("public key {}: {error}", path.display()))?;
    let mut bytes = Vec::new();
    file.by_ref()
        .take((MAX_PUBLIC_KEY_FILE_BYTES + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() > MAX_PUBLIC_KEY_FILE_BYTES {
        anyhow::bail!("public key file exceeds {MAX_PUBLIC_KEY_FILE_BYTES} bytes");
    }
    if let Ok(raw) = <[u8; 32]>::try_from(bytes.as_slice()) {
        return Ok(raw);
    }
    let text = std::str::from_utf8(&bytes)
        .map(str::trim)
        .map_err(|_| anyhow::anyhow!("public key must be raw 32-byte Ed25519 or base64 text"))?;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(text)
        .map_err(|_| anyhow::anyhow!("public key is not valid base64"))?;
    decoded
        .try_into()
        .map_err(|_| anyhow::anyhow!("decoded Ed25519 public key must be exactly 32 bytes"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT: AtomicU64 = AtomicU64::new(0);

    #[test]
    fn public_key_reader_accepts_raw_and_base64_but_not_wrong_lengths() {
        let root = std::env::temp_dir().join(format!(
            "core-plugin-key-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&root).unwrap();
        let raw = root.join("raw");
        let encoded = root.join("encoded");
        let bad = root.join("bad");
        std::fs::write(&raw, [3; 32]).unwrap();
        std::fs::write(
            &encoded,
            base64::engine::general_purpose::STANDARD.encode([4; 32]),
        )
        .unwrap();
        std::fs::write(&bad, b"short").unwrap();
        assert_eq!(read_public_key(&raw).unwrap(), [3; 32]);
        assert_eq!(read_public_key(&encoded).unwrap(), [4; 32]);
        assert!(read_public_key(&bad).is_err());
        std::fs::remove_dir_all(root).unwrap();
    }
}
