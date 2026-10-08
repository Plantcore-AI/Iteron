//! Physical read owner of one explicitly confined memory tier. Source paths, metadata index
//! and retained body cache remain private; recall receives read methods and immutable evidence.
use super::{
    FactRef, MAX_FACT_BYTES, MAX_MEMORY_FILES, MAX_MEMORY_SOURCE_BYTES, MemTier, is_safe_slug,
    suspicious_unicode,
};
use crate::ContextSourceClass;
use crate::context_provenance::{
    ContextMaterialRootV1, ContextMaterialUnavailableV1, MaterialSource,
};
use crate::source::{
    SourceEntryKind, SourceError, SourceScope, list_directory_bounded, read_bounded_utf8,
};
use iteron_protocol::trust::Trust;
use std::collections::{HashMap, VecDeque};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

/// Map a tier plus its trust-on-first-use approval to a `Trust` tier. This is Risk 5 made concrete:
/// trust keys on provenance (the tier) **and** authorship (whether the operator has approved
/// tree-discovered content), not on store location alone. `User` is Trusted without approval
/// because the operator authored it; `Project`/`Local` are Untrusted until approved, then Workspace;
/// `Dependency` is always Untrusted (and stripped before injection).
pub(super) fn trust_for(tier: MemTier, approved: bool) -> Trust {
    match tier {
        MemTier::User => Trust::Trusted,
        MemTier::Project | MemTier::Local => {
            if approved {
                Trust::Workspace
            } else {
                Trust::Untrusted
            }
        }
        MemTier::Dependency => Trust::Untrusted,
    }
}

/// One memory store: a directory with an optional `MEMORY.md` index and `<slug>.md` fact files.
/// A `Project`/`Local` store additionally carries the repo root, where `CLAUDE.md`/`AGENTS.md`
/// are discovered and folded into the segment (§1.4).
#[derive(Debug, Clone)]
pub struct MemStore {
    root: PathBuf,
    /// Confinement boundary. Project/local constructors set this to the repository root; a
    /// generic store treats its own root as the explicitly supplied boundary.
    source_root: PathBuf,
    tier: MemTier,
    trust: Trust,
    /// The directory under which repo instruction files (`AGENTS.md`/`CLAUDE.md`/
    /// `.iteron/instructions.md`) are discovered, when this store carries them.
    instr_root: Option<PathBuf>,
    recall_workspace: Option<PathBuf>,
    resource_index: Arc<crate::ResourceMetadataIndex>,
    body_cache: Arc<Mutex<MemoryBodyCache>>,
}

#[derive(Debug, Default)]
struct MemoryBodyCache {
    entries: HashMap<PathBuf, ([u8; 32], String, MaterialSource)>,
    retained_source_bytes: usize,
    order: VecDeque<PathBuf>,
}

impl MemStore {
    /// Build a store whose trust is derived from its tier and approval (§1.4, Risk 5).
    pub fn new(root: PathBuf, tier: MemTier, approved: bool) -> Self {
        let trust = trust_for(tier, approved);
        // Existing kernel/tool callers construct project stores from `<repo>/.iteron/memory`
        // directly. Infer that repository boundary so `.core` or `memory` cannot redirect the
        // read through a symlink; unusual explicit roots remain their own caller-selected anchor.
        let source_root = match tier {
            MemTier::Project | MemTier::Local => root
                .parent()
                .filter(|parent| {
                    parent
                        .file_name()
                        .and_then(|name| name.to_str())
                        .is_some_and(iteron_protocol::home::is_home_dir)
                })
                .and_then(Path::parent)
                .map(Path::to_path_buf)
                .unwrap_or_else(|| root.clone()),
            MemTier::User | MemTier::Dependency => root.clone(),
        };
        let recall_workspace =
            matches!(tier, MemTier::Project | MemTier::Local).then(|| source_root.clone());
        MemStore {
            source_root,
            root,
            tier,
            trust,
            instr_root: None,
            recall_workspace,
            resource_index: Arc::new(crate::ResourceMetadataIndex::default()),
            body_cache: Arc::new(Mutex::new(MemoryBodyCache::default())),
        }
    }

    /// Attach the repo root for instruction discovery (`CLAUDE.md`/`AGENTS.md`).
    pub fn with_instructions(mut self, repo_root: PathBuf) -> Self {
        self.source_root = repo_root.clone();
        self.instr_root = Some(repo_root);
        self
    }

    /// Legacy user files have unknown private scope. Only versioned global facts are visible
    /// without an explicit current workspace supplied by the host.
    pub fn user(home: &Path) -> Self {
        let mut store = MemStore::new(
            iteron_protocol::home::path(home, "memory"),
            MemTier::User,
            true,
        );
        store.source_root = home.to_path_buf();
        store
    }

    pub fn with_recall_workspace(mut self, workspace: &Path) -> Self {
        self.recall_workspace = Some(workspace.to_path_buf());
        self
    }

    pub(super) fn record_root(&self) -> std::io::Result<PathBuf> {
        if self.source_root == self.root {
            let parent = self
                .root
                .parent()
                .ok_or_else(|| std::io::Error::other("memory root has no parent"))?;
            let name = self
                .root
                .file_name()
                .ok_or_else(|| std::io::Error::other("memory root has no name"))?;
            Ok(parent.canonicalize()?.join(name))
        } else {
            let relative = self
                .root
                .strip_prefix(&self.source_root)
                .map_err(|_| std::io::Error::other("memory root escapes source"))?;
            Ok(self.source_root.canonicalize()?.join(relative))
        }
    }

    /// The project store: `<repo>/.iteron/memory` plus repo-root instructions. `approved` reflects
    /// a recorded trust-on-first-use decision; unapproved it is Untrusted (framed, still injected).
    pub fn project(repo_root: &Path, approved: bool) -> Self {
        MemStore::new(
            iteron_protocol::home::path(repo_root, "memory"),
            MemTier::Project,
            approved,
        )
        .with_instructions(repo_root.to_path_buf())
    }

    /// The machine-local store: `<repo>/.iteron/memory.local`.
    pub fn local(repo_root: &Path, approved: bool) -> Self {
        let mut store = MemStore::new(
            iteron_protocol::home::path(repo_root, "memory.local"),
            MemTier::Local,
            approved,
        );
        store.source_root = repo_root.to_path_buf();
        store
    }

    pub fn root(&self) -> &Path {
        &self.root
    }
    pub fn tier(&self) -> MemTier {
        self.tier
    }
    pub fn trust(&self) -> Trust {
        self.trust
    }
    /// True for a `Dependency` store, whose content is stripped and never injected (ADR-007 §6).
    pub fn is_stripped(&self) -> bool {
        matches!(self.tier, MemTier::Dependency)
    }

    pub(super) fn source_root(&self) -> &Path {
        &self.source_root
    }
    pub(super) fn recall_workspace(&self) -> Option<&Path> {
        self.recall_workspace.as_deref()
    }
    pub(super) fn instruction_root(&self) -> Option<&Path> {
        self.instr_root.as_deref()
    }

    fn index_path(&self) -> PathBuf {
        self.root.join("MEMORY.md")
    }
    fn fact_path(&self, slug: &str) -> PathBuf {
        // Defense in depth: a traversal slug collapses to a harmless in-root path here even if a
        // caller forgot the `is_safe_slug` guard (security review — the `..`/absolute-slug escape).
        if !is_safe_slug(slug) {
            return self.root.join("__unsafe_slug__.md");
        }
        self.root.join(format!("{slug}.md"))
    }

    fn source_scope(&self) -> SourceScope {
        match self.tier {
            MemTier::User => SourceScope::UserContained,
            MemTier::Project | MemTier::Local | MemTier::Dependency => SourceScope::Repository,
        }
    }

    fn read_root(&self) -> &Path {
        // The operator home is the provenance anchor, not permission to read arbitrary home
        // files through a memory symlink. User links may resolve only inside this memory store.
        if self.tier == MemTier::User {
            &self.root
        } else {
            &self.source_root
        }
    }

    fn read_source(&self, path: &Path, max_bytes: usize) -> Result<Option<String>, SourceError> {
        if self.is_stripped() {
            return Ok(None);
        }
        read_bounded_utf8(self.read_root(), path, max_bytes, self.source_scope())
    }

    /// The store's index entries. When a `MEMORY.md` index is present it is parsed line by line
    /// (bidi-suspicious lines skipped); when it is absent the store degrades to listing every
    /// `.md` file — the seed `MemoryStore::load` behaviour — so the R5 model stays strictly
    /// additive (§1.3). Returned sorted by slug for a stable, reproducible order.
    pub fn index_entries(&self) -> Vec<FactRef> {
        self.index_entries_materialized().0
    }

    pub(super) fn material_root(&self) -> ContextMaterialRootV1 {
        match self.tier {
            MemTier::User => ContextMaterialRootV1::Operator,
            MemTier::Dependency => ContextMaterialRootV1::Dependency,
            MemTier::Project | MemTier::Local => ContextMaterialRootV1::Workspace,
        }
    }

    pub(super) fn index_entries_materialized(&self) -> (Vec<FactRef>, MaterialSource) {
        let mut material = MaterialSource::unavailable(
            ContextSourceClass::WorkspaceMemory,
            ContextMaterialUnavailableV1::SourceOwnerDidNotCapture,
        );
        let mut entries = match self.read_source(
            &self.index_path(),
            iteron_tunables::param_usize(
                "ctx.memory.max_memory_source_bytes",
                iteron_tunables::param_integer(
                    "ctx.memory.max_memory_source_bytes",
                    MAX_MEMORY_SOURCE_BYTES,
                ),
            ),
        ) {
            Ok(Some(text)) if !text.trim().is_empty() => {
                material = MaterialSource::file(
                    ContextSourceClass::WorkspaceMemory,
                    self.material_root(),
                    &self.source_root,
                    &self.index_path(),
                    &text,
                    false,
                );
                text.lines()
                    .filter(|line| !suspicious_unicode(line))
                    .filter_map(|line| parse_index_line(line, self.tier))
                    .collect::<Vec<_>>()
            }
            _ => Vec::new(),
        };
        if entries.is_empty() {
            entries = self.list_facts();
            // These are actual directory-discovered metadata, not the unread fact-file bytes.
            material = MaterialSource::gathered(
                ContextSourceClass::WorkspaceMemory,
                &entries.iter().map(FactRef::line).collect::<String>(),
            );
        }
        entries.sort_by(|a, b| a.slug.cmp(&b.slug));
        entries.dedup_by(|a, b| a.slug == b.slug);
        (entries, material)
    }

    /// Degrade path: one metadata-only `FactRef` per `.md` file (excluding the index itself).
    /// Without a `MEMORY.md` there is no trusted summary to rank, so the stable slug is the title
    /// and the body remains unopened until the shortlist selects it. Body Unicode validation still
    /// occurs in `read_body` before any selected bytes enter model context.
    fn list_facts(&self) -> Vec<FactRef> {
        let Ok(Some(listing)) = list_directory_bounded(
            self.read_root(),
            &self.root,
            iteron_tunables::param_usize("ctx.memory.max_memory_files", MAX_MEMORY_FILES),
            self.source_scope(),
        ) else {
            return Vec::new();
        };
        let mut out = Vec::new();
        for entry in listing.entries {
            let allowed_kind = entry.kind == SourceEntryKind::File
                || (self.tier == MemTier::User && entry.kind == SourceEntryKind::Symlink);
            if !allowed_kind {
                continue;
            }
            let path = entry.path;
            if path.extension().and_then(|e| e.to_str()) != Some("md") {
                continue;
            }
            let stem = match path.file_stem().and_then(|s| s.to_str()) {
                Some(s) if s != "MEMORY" => s.to_string(),
                _ => continue,
            };
            if !is_safe_slug(&stem) {
                continue;
            }
            out.push(FactRef {
                title: stem.replace(['-', '_'], " "),
                slug: stem,
                summary: String::new(),
                tier: self.tier,
            });
        }
        out
    }

    /// Read a fact body from disk, bidi-scanned and head-capped. `None` if the file is absent or
    /// suspicious (skipped, never injected).
    pub(super) fn read_body(&self, slug: &str) -> Option<String> {
        self.read_body_materialized(slug).map(|(body, _)| body)
    }

    pub(super) fn read_body_materialized(&self, slug: &str) -> Option<(String, MaterialSource)> {
        // Guard against a traversal slug from a tree-discovered MEMORY.md index (security review):
        // an index line like `[x](../../../secrets.md)` would otherwise escape the store root (an
        // absolute slug would escape entirely via `join`). read_fact already guards this; the
        // auto-recall path must too, and `fact_path` now guards all callers.
        if !is_safe_slug(slug) {
            return None;
        }
        let path = self.fact_path(slug);
        let indexed = self
            .cacheable_regular_path(&path)
            .then(|| self.resource_index.refresh_one(&path).ok().flatten())
            .flatten();
        if let Some(indexed) = &indexed
            && let Some((digest, body, material)) = self
                .body_cache
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .entries
                .get(&path)
            && digest == &indexed.sha256
        {
            return Some((body.clone(), material.clone()));
        }
        let raw = self
            .read_source(
                &path,
                iteron_tunables::param_usize(
                    "ctx.memory.max_memory_source_bytes",
                    iteron_tunables::param_integer(
                        "ctx.memory.max_memory_source_bytes",
                        MAX_MEMORY_SOURCE_BYTES,
                    ),
                ),
            )
            .ok()??;
        if suspicious_unicode(&raw) {
            return None;
        }
        let body = iteron_protocol::text::head(
            raw.trim(),
            iteron_tunables::param_usize("ctx.memory.max_fact_bytes", MAX_FACT_BYTES),
        );
        let mut material = MaterialSource::file(
            ContextSourceClass::WorkspaceMemory,
            self.material_root(),
            &self.source_root,
            &path,
            &raw,
            false,
        )
        .mark_truncated(body.len() < raw.trim().len());
        if let Some(indexed) = indexed {
            let mut cache = self
                .body_cache
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let limit =
                iteron_tunables::param_usize("ctx.memory.body_cache_entries", 256).clamp(1, 1_024);
            while cache.entries.len() >= limit && !cache.entries.contains_key(&path) {
                let Some(oldest) = cache.order.pop_front() else {
                    break;
                };
                if let Some((_, _, old)) = cache.entries.remove(&oldest) {
                    cache.retained_source_bytes = cache
                        .retained_source_bytes
                        .saturating_sub(old.retained_bytes());
                }
            }
            if !cache.entries.contains_key(&path) {
                cache.order.push_back(path.clone());
            }
            if let Some((_, _, old)) = cache.entries.remove(&path) {
                cache.retained_source_bytes = cache
                    .retained_source_bytes
                    .saturating_sub(old.retained_bytes());
            }
            if material.retained_bytes()
                > crate::context_provenance::MAX_CONTEXT_PROVENANCE_BYTES
                    .saturating_sub(cache.retained_source_bytes)
            {
                material = material.without_bytes();
            }
            cache.retained_source_bytes += material.retained_bytes();
            cache
                .entries
                .insert(path, (indexed.sha256, body.clone(), material.clone()));
        }
        Some((body, material))
    }

    fn cacheable_regular_path(&self, path: &Path) -> bool {
        let Ok(metadata) = fs::symlink_metadata(path) else {
            return false;
        };
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            return false;
        }
        match (self.read_root().canonicalize(), path.canonicalize()) {
            (Ok(root), Ok(resolved)) => resolved.starts_with(root),
            _ => false,
        }
    }

    pub(super) fn modified_unix_secs(&self, slug: &str) -> Option<u64> {
        let path = self.fact_path(slug);
        let metadata = fs::symlink_metadata(path).ok()?;
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            return None;
        }
        metadata
            .modified()
            .ok()?
            .duration_since(std::time::UNIX_EPOCH)
            .ok()
            .map(|duration| duration.as_secs())
    }

    pub(super) fn body_available(&self, slug: &str) -> bool {
        if !is_safe_slug(slug) {
            return false;
        }
        let path = self.fact_path(slug);
        fs::symlink_metadata(&path).is_ok_and(|metadata| {
            if metadata.file_type().is_symlink() {
                self.tier == MemTier::User
                    && fs::metadata(&path).is_ok_and(|target| target.is_file())
            } else {
                metadata.is_file()
            }
        })
    }
}

/// Parse one `MEMORY.md` line `- [Title](slug.md) — summary` into a `FactRef`. Accepts `-` or `*`
/// bullets and any dash separator before the summary. Returns `None` for a non-entry line.
pub(super) fn parse_index_line(line: &str, tier: MemTier) -> Option<FactRef> {
    let line = line.trim();
    let rest = line
        .strip_prefix("- ")
        .or_else(|| line.strip_prefix("* "))
        .or_else(|| line.strip_prefix("-\t"))?;
    let rest = rest.trim_start();
    let rest = rest.strip_prefix('[')?;
    let close = rest.find("](")?;
    let title = rest[..close].trim().to_string();
    let after = &rest[close + 2..];
    let paren = after.find(')')?;
    let target = after[..paren].trim();
    let slug = target.strip_suffix(".md").unwrap_or(target).trim();
    if title.is_empty() || !is_safe_slug(slug) {
        // Skip a hostile index line whose target escapes the store (security review): the index is
        // untrusted tree-discovered content, so a traversal/absolute slug never becomes a FactRef.
        return None;
    }
    let summary = after[paren + 1..]
        .trim_start_matches([' ', '\t', '—', '–', '-'])
        .trim()
        .to_string();
    Some(FactRef {
        slug: slug.to_string(),
        title,
        summary,
        tier,
    })
}
