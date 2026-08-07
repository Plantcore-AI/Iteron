//! Signed plugin packages and the durable, offline-capable local store.
//!
//! A package is a directory containing `manifest.json`, `signature.json`, and the declared
//! artifacts. The signature covers a domain-separated SHA-256 digest of every regular file except
//! `signature.json`, including each relative path and length. Symlinks and non-UTF-8 paths are
//! refused. Installation copies into a content-addressed cache, re-hashes the copy, and only then
//! appends a new immutable registry generation. Startup repeats both digest and signature checks;
//! a modified cache entry is quarantined from composition instead of becoming trusted by location.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::{Manifest, Version, valid_name};

mod verification;
use verification::*;

const MAX_REGISTRY_BYTES: usize = 4 * 1024 * 1024;
const MAX_REGISTRY_GENERATIONS: usize = 4096;
const RETAINED_REGISTRY_GENERATIONS: usize = 32;

#[derive(Debug, thiserror::Error)]
pub enum PackageError {
    #[error("plugin store I/O: {0}")]
    Io(#[from] std::io::Error),
    #[error("plugin package {path}: {reason}")]
    InvalidPackage { path: PathBuf, reason: String },
    #[error("plugin package signature is missing or malformed")]
    MalformedSignature,
    #[error("plugin package is signed by untrusted key {0:?}")]
    UnknownKey(String),
    #[error("plugin package signature from {0:?} did not verify")]
    BadSignature(String),
    #[error("trusted key {0:?} is malformed")]
    MalformedKey(String),
    #[error("trusted key {0:?} already exists with different bytes")]
    KeyConflict(String),
    #[error("plugin {0:?} is not installed")]
    NotInstalled(String),
    #[error("plugin {name:?} is already at {version}")]
    AlreadyCurrent { name: String, version: Version },
    #[error("plugin {name:?} cannot move backwards from {installed} to {candidate}")]
    Downgrade {
        name: String,
        installed: Version,
        candidate: Version,
    },
    #[error("plugin {name:?} publisher changed from {installed_key:?} to {candidate_key:?}")]
    PublisherChanged {
        name: String,
        installed_key: String,
        candidate_key: String,
    },
    #[error("plugin {name:?} requires {dependency:?} >= {minimum}, which is unavailable")]
    MissingDependency {
        name: String,
        dependency: String,
        minimum: Version,
    },
    #[error("plugin {0:?} has no retained rollback artifact")]
    NoRollback(String),
    #[error("plugin registry is malformed or exceeds its bound")]
    MalformedRegistry,
    #[error("plugin registry exhausted its {MAX_REGISTRY_GENERATIONS} durable generations")]
    RegistryGenerationLimit,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactRef {
    pub version: Version,
    pub digest: String,
    pub key_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstalledPackage {
    pub enabled: bool,
    /// Operator-owned arbitration rank. The signed manifest cannot rank itself above neighbours.
    #[serde(default)]
    pub precedence: u32,
    pub current: ArtifactRef,
    pub previous: Option<ArtifactRef>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct RegistryState {
    schema: u32,
    generation: u64,
    plugins: BTreeMap<String, InstalledPackage>,
}

impl Default for RegistryState {
    fn default() -> Self {
        Self {
            schema: 1,
            generation: 0,
            plugins: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ActivePlugin {
    pub manifest: Manifest,
    pub artifact_root: PathBuf,
}

#[derive(Debug, Clone, Default)]
pub struct RuntimePackages {
    pub active: Vec<ActivePlugin>,
    pub quarantined: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct PluginStore {
    root: PathBuf,
}

impl PluginStore {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Trust one named publisher key. Existing identities are immutable: rotation uses a new id.
    pub fn trust_key(&self, key_id: &str, public_key: &[u8]) -> Result<(), PackageError> {
        if !valid_name(key_id) || public_key.len() != 32 {
            return Err(PackageError::MalformedKey(key_id.to_owned()));
        }
        let dir = self.root.join("trusted-keys");
        fs::create_dir_all(&dir)?;
        let path = dir.join(format!("{key_id}.pub"));
        if let Ok(existing) = read_bounded(&path, 64) {
            return if existing == public_key {
                Ok(())
            } else {
                Err(PackageError::KeyConflict(key_id.to_owned()))
            };
        }
        write_new_private(&path, public_key)
    }

    pub fn trusted_keys(&self) -> Result<Vec<String>, PackageError> {
        let dir = self.root.join("trusted-keys");
        let Ok(entries) = fs::read_dir(dir) else {
            return Ok(Vec::new());
        };
        let mut keys = Vec::new();
        for entry in entries.take(MAX_PACKAGE_FILES) {
            let entry = entry?;
            if entry.file_type()?.is_file()
                && let Some(name) = entry.file_name().to_str()
                && let Some(key) = name.strip_suffix(".pub")
                && valid_name(key)
            {
                keys.push(key.to_owned());
            }
        }
        keys.sort();
        Ok(keys)
    }

    pub fn list(&self) -> Result<Vec<(String, InstalledPackage)>, PackageError> {
        Ok(self.load_state()?.plugins.into_iter().collect())
    }

    pub fn install(&self, package: &Path) -> Result<ArtifactRef, PackageError> {
        self.install_with_precedence(package, None)
    }

    /// Install with an operator-owned rank. Updates preserve the existing rank unless explicitly
    /// changed; the package manifest's `precedence` field is never authoritative.
    pub fn install_with_precedence(
        &self,
        package: &Path,
        precedence: Option<u32>,
    ) -> Result<ArtifactRef, PackageError> {
        let verified = self.verify_source(package)?;
        let mut state = self.load_state()?;
        for requirement in &verified.manifest.requires {
            let available = state
                .plugins
                .get(&requirement.plugin)
                .filter(|entry| entry.enabled)
                .map(|entry| entry.current.version);
            if available.is_none_or(|version| version < requirement.minimum) {
                return Err(PackageError::MissingDependency {
                    name: verified.manifest.plugin.clone(),
                    dependency: requirement.plugin.clone(),
                    minimum: requirement.minimum,
                });
            }
        }

        if let Some(installed) = state.plugins.get(&verified.manifest.plugin) {
            if verified.manifest.version < installed.current.version {
                return Err(PackageError::Downgrade {
                    name: verified.manifest.plugin.clone(),
                    installed: installed.current.version,
                    candidate: verified.manifest.version,
                });
            }
            if verified.manifest.version == installed.current.version {
                return Err(PackageError::AlreadyCurrent {
                    name: verified.manifest.plugin.clone(),
                    version: installed.current.version,
                });
            }
            if verified.key_id != installed.current.key_id {
                return Err(PackageError::PublisherChanged {
                    name: verified.manifest.plugin.clone(),
                    installed_key: installed.current.key_id.clone(),
                    candidate_key: verified.key_id,
                });
            }
        }

        let artifact = ArtifactRef {
            version: verified.manifest.version,
            digest: verified.digest.clone(),
            key_id: verified.key_id,
        };
        self.cache_verified(package, &verified.manifest.plugin, &artifact)?;
        let old = state.plugins.get(&verified.manifest.plugin).cloned();
        state.plugins.insert(
            verified.manifest.plugin,
            InstalledPackage {
                enabled: old.as_ref().is_none_or(|entry| entry.enabled),
                precedence: precedence
                    .or_else(|| old.as_ref().map(|entry| entry.precedence))
                    .unwrap_or_default(),
                previous: old.map(|entry| entry.current),
                current: artifact.clone(),
            },
        );
        self.commit_state(state)?;
        Ok(artifact)
    }

    pub fn set_enabled(&self, name: &str, enabled: bool) -> Result<(), PackageError> {
        let mut state = self.load_state()?;
        let plugin = state
            .plugins
            .get_mut(name)
            .ok_or_else(|| PackageError::NotInstalled(name.to_owned()))?;
        plugin.enabled = enabled;
        self.commit_state(state)
    }

    pub fn set_precedence(&self, name: &str, precedence: u32) -> Result<(), PackageError> {
        let mut state = self.load_state()?;
        let plugin = state
            .plugins
            .get_mut(name)
            .ok_or_else(|| PackageError::NotInstalled(name.to_owned()))?;
        plugin.precedence = precedence;
        self.commit_state(state)
    }

    pub fn uninstall(&self, name: &str) -> Result<(), PackageError> {
        let mut state = self.load_state()?;
        state
            .plugins
            .remove(name)
            .ok_or_else(|| PackageError::NotInstalled(name.to_owned()))?;
        // Content-addressed artifacts deliberately remain as an offline cache. No executable is
        // reachable after the registry generation stops naming it.
        self.commit_state(state)
    }

    pub fn rollback(&self, name: &str) -> Result<ArtifactRef, PackageError> {
        let mut state = self.load_state()?;
        let installed = state
            .plugins
            .get_mut(name)
            .ok_or_else(|| PackageError::NotInstalled(name.to_owned()))?;
        let target = installed
            .previous
            .take()
            .ok_or_else(|| PackageError::NoRollback(name.to_owned()))?;
        self.verify_cached(name, &target)?;
        installed.current = target.clone();
        self.commit_state(state)?;
        Ok(target)
    }

    /// Load enabled packages for runtime composition, re-verifying cache bytes and signatures.
    pub fn runtime_packages(&self) -> Result<RuntimePackages, PackageError> {
        let state = self.load_state()?;
        let mut runtime = RuntimePackages::default();
        for (name, installed) in state.plugins {
            if !installed.enabled {
                continue;
            }
            match self.verify_cached(&name, &installed.current) {
                Ok(mut verified) if verified.manifest.plugin == name => {
                    verified.manifest.precedence = installed.precedence;
                    runtime.active.push(ActivePlugin {
                        manifest: verified.manifest,
                        artifact_root: self.cache_path(&name, &installed.current),
                    });
                }
                Ok(_) => runtime
                    .quarantined
                    .push(format!("{name}: cached manifest identity changed")),
                Err(error) => runtime.quarantined.push(format!("{name}: {error}")),
            }
        }
        runtime
            .active
            .sort_by(|a, b| a.manifest.plugin.cmp(&b.manifest.plugin));
        runtime.quarantined.sort();
        Ok(runtime)
    }

    fn verify_source(&self, source: &Path) -> Result<VerifiedPackage, PackageError> {
        verify_package(source, |key_id| self.read_key(key_id))
    }

    fn verify_cached(
        &self,
        name: &str,
        artifact: &ArtifactRef,
    ) -> Result<VerifiedPackage, PackageError> {
        let path = self.cache_path(name, artifact);
        let verified = verify_package(&path, |key_id| self.read_key(key_id))?;
        if verified.digest != artifact.digest
            || verified.manifest.version != artifact.version
            || verified.key_id != artifact.key_id
        {
            return Err(PackageError::InvalidPackage {
                path,
                reason: "cached identity does not match the registry".into(),
            });
        }
        Ok(verified)
    }

    fn read_key(&self, key_id: &str) -> Result<[u8; 32], PackageError> {
        if !valid_name(key_id) {
            return Err(PackageError::MalformedKey(key_id.to_owned()));
        }
        let bytes = read_bounded(
            &self.root.join("trusted-keys").join(format!("{key_id}.pub")),
            64,
        )
        .map_err(|_| PackageError::UnknownKey(key_id.to_owned()))?;
        bytes
            .try_into()
            .map_err(|_| PackageError::MalformedKey(key_id.to_owned()))
    }

    fn cache_verified(
        &self,
        source: &Path,
        name: &str,
        artifact: &ArtifactRef,
    ) -> Result<(), PackageError> {
        let destination = self.cache_path(name, artifact);
        if destination.exists() {
            self.verify_cached(name, artifact)?;
            return Ok(());
        }
        let parent = destination.parent().expect("cache path has parent");
        fs::create_dir_all(parent)?;
        let temp = parent.join(format!(
            ".install-{}-{}",
            std::process::id(),
            artifact.digest
        ));
        if temp.exists() {
            return Err(PackageError::InvalidPackage {
                path: temp,
                reason: "stale private installation directory exists".into(),
            });
        }
        fs::create_dir(&temp)?;
        copy_tree(source, &temp)?;
        let copied = verify_package(&temp, |key_id| self.read_key(key_id))?;
        if copied.digest != artifact.digest {
            return Err(PackageError::InvalidPackage {
                path: temp,
                reason: "package changed while it was being installed".into(),
            });
        }
        fs::rename(&temp, &destination)?;
        sync_dir(parent)?;
        Ok(())
    }

    fn cache_path(&self, name: &str, artifact: &ArtifactRef) -> PathBuf {
        self.root
            .join("cache")
            .join(name)
            .join(format!("{}-{}", artifact.version, artifact.digest))
    }

    fn load_state(&self) -> Result<RegistryState, PackageError> {
        let dir = self.root.join("state");
        let Ok(entries) = fs::read_dir(&dir) else {
            return Ok(RegistryState::default());
        };
        let mut candidates = Vec::new();
        for entry in entries.take(MAX_REGISTRY_GENERATIONS + 1) {
            let entry = entry?;
            let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
                continue;
            };
            if entry.file_type()?.is_file()
                && name.starts_with("registry-")
                && name.ends_with(".json")
            {
                candidates.push(entry.path());
            }
        }
        if candidates.len() > MAX_REGISTRY_GENERATIONS {
            return Err(PackageError::RegistryGenerationLimit);
        }
        candidates.sort();
        let Some(path) = candidates.last() else {
            return Ok(RegistryState::default());
        };
        let bytes =
            read_bounded(path, MAX_REGISTRY_BYTES).map_err(|_| PackageError::MalformedRegistry)?;
        let state: RegistryState =
            serde_json::from_slice(&bytes).map_err(|_| PackageError::MalformedRegistry)?;
        if state.schema != 1 {
            return Err(PackageError::MalformedRegistry);
        }
        Ok(state)
    }

    fn commit_state(&self, mut state: RegistryState) -> Result<(), PackageError> {
        state.generation = state
            .generation
            .checked_add(1)
            .ok_or(PackageError::RegistryGenerationLimit)?;
        let bytes =
            serde_json::to_vec_pretty(&state).map_err(|_| PackageError::MalformedRegistry)?;
        if bytes.len() > MAX_REGISTRY_BYTES {
            return Err(PackageError::MalformedRegistry);
        }
        let dir = self.root.join("state");
        fs::create_dir_all(&dir)?;
        let path = dir.join(format!("registry-{:016}.json", state.generation));
        write_new_private(&path, &bytes)?;
        sync_dir(&dir)?;
        self.prune_registry_generations(&dir)?;
        sync_dir(&dir)
    }

    /// Keep enough immutable generations for diagnosis and recovery without eventually making an
    /// otherwise healthy long-lived installation unable to update its own registry.
    fn prune_registry_generations(&self, dir: &Path) -> Result<(), PackageError> {
        let mut generations = Vec::new();
        for entry in fs::read_dir(dir)?.take(MAX_REGISTRY_GENERATIONS + 1) {
            let entry = entry?;
            let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
                continue;
            };
            if entry.file_type()?.is_file()
                && name.starts_with("registry-")
                && name.ends_with(".json")
            {
                generations.push(entry.path());
            }
        }
        if generations.len() > MAX_REGISTRY_GENERATIONS {
            return Err(PackageError::RegistryGenerationLimit);
        }
        generations.sort();
        let obsolete = generations
            .len()
            .saturating_sub(RETAINED_REGISTRY_GENERATIONS);
        for path in generations.into_iter().take(obsolete) {
            fs::remove_file(path)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;
    use ed25519_dalek::{Signer as _, SigningKey};
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT: AtomicU64 = AtomicU64::new(0);

    fn temp(label: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "core-marketplace-{label}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        path
    }

    fn package(root: &Path, name: &str, version: Version, key: &SigningKey) -> PathBuf {
        let path = root.join(format!("{name}-{}", version));
        fs::create_dir(&path).unwrap();
        let manifest =
            Manifest::new(name, 1)
                .at_version(version)
                .with(crate::Contribution::Skill {
                    name: "review".into(),
                    description: "Review carefully".into(),
                });
        fs::write(
            path.join(MANIFEST_FILE),
            serde_json::to_vec_pretty(&manifest).unwrap(),
        )
        .unwrap();
        fs::create_dir(path.join("skills")).unwrap();
        fs::write(path.join("skills/review.md"), b"review body").unwrap();
        let digest = tree_digest(&path).unwrap();
        let mut message = DOMAIN.to_vec();
        message.extend_from_slice(&digest);
        let signature = key.sign(&message);
        fs::write(
            path.join(SIGNATURE_FILE),
            serde_json::to_vec_pretty(&SignatureEnvelope {
                key_id: "publisher".into(),
                signature: base64::engine::general_purpose::STANDARD.encode(signature.to_bytes()),
            })
            .unwrap(),
        )
        .unwrap();
        path
    }

    #[test]
    fn signed_install_update_disable_and_offline_rollback_are_durable() {
        let root = temp("lifecycle");
        let store = PluginStore::new(root.join("store"));
        let key = SigningKey::from_bytes(&[7; 32]);
        store
            .trust_key("publisher", key.verifying_key().as_bytes())
            .unwrap();
        let v1 = package(&root, "fmt", Version(1, 0, 0), &key);
        let v2 = package(&root, "fmt", Version(1, 1, 0), &key);
        store.install(&v1).unwrap();
        store.install(&v2).unwrap();
        store.set_enabled("fmt", false).unwrap();
        assert!(store.runtime_packages().unwrap().active.is_empty());
        store.set_enabled("fmt", true).unwrap();
        assert_eq!(store.rollback("fmt").unwrap().version, Version(1, 0, 0));
        assert_eq!(
            store.runtime_packages().unwrap().active[0].manifest.version,
            Version(1, 0, 0)
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn registry_generations_are_pruned_without_exhausting_the_logical_counter() {
        let root = temp("registry-retention");
        let store = PluginStore::new(root.join("store"));
        let key = SigningKey::from_bytes(&[8; 32]);
        store
            .trust_key("publisher", key.verifying_key().as_bytes())
            .unwrap();
        let source = package(&root, "fmt", Version(1, 0, 0), &key);
        store.install(&source).unwrap();
        for enabled in (0..(RETAINED_REGISTRY_GENERATIONS * 3)).map(|index| index % 2 == 0) {
            store.set_enabled("fmt", enabled).unwrap();
        }
        let generations = fs::read_dir(store.root().join("state"))
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| {
                entry
                    .file_name()
                    .to_str()
                    .is_some_and(|name| name.starts_with("registry-") && name.ends_with(".json"))
            })
            .count();
        assert_eq!(generations, RETAINED_REGISTRY_GENERATIONS);
        assert!(!store.list().unwrap()[0].1.enabled);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn operator_rank_overrides_the_signed_manifests_self_assigned_precedence() {
        let root = temp("operator-precedence");
        let store = PluginStore::new(root.join("store"));
        let key = SigningKey::from_bytes(&[12; 32]);
        store
            .trust_key("publisher", key.verifying_key().as_bytes())
            .unwrap();
        let source = package(&root, "fmt", Version(1, 0, 0), &key);
        let mut manifest: Manifest =
            serde_json::from_slice(&fs::read(source.join(MANIFEST_FILE)).unwrap()).unwrap();
        manifest.precedence = u32::MAX;
        fs::write(
            source.join(MANIFEST_FILE),
            serde_json::to_vec_pretty(&manifest).unwrap(),
        )
        .unwrap();
        let digest = tree_digest(&source).unwrap();
        let mut message = DOMAIN.to_vec();
        message.extend_from_slice(&digest);
        let signature = key.sign(&message);
        fs::write(
            source.join(SIGNATURE_FILE),
            serde_json::to_vec_pretty(&SignatureEnvelope {
                key_id: "publisher".into(),
                signature: base64::engine::general_purpose::STANDARD.encode(signature.to_bytes()),
            })
            .unwrap(),
        )
        .unwrap();

        store.install_with_precedence(&source, Some(7)).unwrap();
        assert_eq!(
            store.runtime_packages().unwrap().active[0]
                .manifest
                .precedence,
            7
        );
        store.set_precedence("fmt", 19).unwrap();
        assert_eq!(
            store.runtime_packages().unwrap().active[0]
                .manifest
                .precedence,
            19
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn cache_tampering_is_quarantined_on_every_runtime_load() {
        let root = temp("tamper");
        let store = PluginStore::new(root.join("store"));
        let key = SigningKey::from_bytes(&[9; 32]);
        store
            .trust_key("publisher", key.verifying_key().as_bytes())
            .unwrap();
        let source = package(&root, "fmt", Version(1, 0, 0), &key);
        let artifact = store.install(&source).unwrap();
        let cached = store.cache_path("fmt", &artifact).join("skills/review.md");
        fs::write(cached, b"attacker changed this").unwrap();
        let runtime = store.runtime_packages().unwrap();
        assert!(runtime.active.is_empty());
        assert_eq!(runtime.quarantined.len(), 1);
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_payload_is_refused_before_registry_mutation() {
        use std::os::unix::fs::symlink;

        let root = temp("symlink");
        let store = PluginStore::new(root.join("store"));
        let key = SigningKey::from_bytes(&[11; 32]);
        store
            .trust_key("publisher", key.verifying_key().as_bytes())
            .unwrap();
        let source = package(&root, "fmt", Version(1, 0, 0), &key);
        symlink("manifest.json", source.join("alias")).unwrap();
        assert!(matches!(
            store.install(&source),
            Err(PackageError::InvalidPackage { .. })
        ));
        assert!(store.list().unwrap().is_empty());
        fs::remove_dir_all(root).unwrap();
    }
}
