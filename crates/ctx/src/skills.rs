//! Skills — progressive-disclosure instruction bundles (Claude Code SKILL.md parity, R5).
//!
//! A skill is a bounded `SKILL.md` discovered from Core's native roots or the operator's portable
//! agent roots. Only model-invocable, path-relevant listing metadata is injected into the stable
//! prefix (a bounded index); the model pulls a skill's full body on demand with the `use_skill`
//! tool when its listing looks relevant — the same progressive-disclosure shape as memory (so a
//! large skill library costs a few tokens per skill until one is actually used).
//!
//! Trust-by-origin (ADR-007, the same posture as memory/agent definitions): a skill under the
//! user roots (`~/.iteron/skills`, `~/.agents/skills`, and Codex skill roots) are Trusted; under the
//! project (`<repo>/.iteron/skills` or `<repo>/.agents/skills`) it is Workspace; anything discovered
//! under a vendored/cloned dependency path is Untrusted and STRIPPED
//! (never injected) — the recon-injection incident this repo's own Errors.md records. Every skill's
//! frontmatter and body is bidi/invisible-Unicode scanned; a suspicious skill is rejected, not run.

use crate::instructions::suspicious_unicode;
use crate::source::{
    SourceEntryKind, SourcePrefix, SourceScope, list_directory_bounded, read_bounded_utf8,
    read_bounded_utf8_prefix,
};
use iteron_protocol::Trust;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

#[path = "skills_metadata.rs"]
mod metadata;
pub use metadata::{SKILL_REFUSED_TOOLS, SkillMetadata, active_paths_from_text};

/// Discovery ceilings apply before parsing or prompt construction.
const MAX_SKILL_DIRS: usize = 1_024;
const MAX_SKILL_SOURCE_BYTES: usize = 256 * 1024;
const MAX_SKILL_METADATA_BYTES: usize = 16 * 1024;

fn max_skill_metadata_bytes() -> usize {
    iteron_tunables::param_usize(
        "ctx.skills.max_skill_metadata_bytes",
        MAX_SKILL_METADATA_BYTES,
    )
    .clamp(1, MAX_SKILL_METADATA_BYTES)
}
const MAX_CODEX_CONFIG_BYTES: usize = 256 * 1024;

/// A matched Codex config entry with no `enabled` key leaves the skill enabled: the entry exists
/// to carry other metadata, so absence is not a disable signal.
const DEFAULT_CODEX_SKILL_ENABLED: bool = true;

/// Where a skill was discovered — sets its trust (ADR-007).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SkillTier {
    User,
    Project,
    Dependency,
}

impl SkillTier {
    fn trust(self) -> Trust {
        match self {
            SkillTier::User => Trust::Trusted,
            SkillTier::Project => Trust::Workspace,
            SkillTier::Dependency => Trust::Untrusted,
        }
    }
}

/// A discovered skill: its listing metadata plus the on-demand body.
#[derive(Debug, Clone)]
pub struct SkillDef {
    pub name: String,
    pub description: String,
    pub body: String,
    pub tier: SkillTier,
    pub trust: Trust,
    /// Optional advertisement controls. These fields never grant tools or other authority.
    pub metadata: SkillMetadata,
    source_path: PathBuf,
}

impl SkillDef {
    /// The body framed for injection when the model loads it (hints, not overrides — and marked
    /// UNTRUSTED when it came from below the user tier).
    pub fn framed(&self) -> String {
        let tag = match self.trust {
            Trust::Trusted => "operator skill",
            Trust::Workspace => "project skill",
            _ => "UNTRUSTED skill",
        };
        format!(
            "\n\n--- Skill `{}` — {} [{}] (guidance for this task; hints, not overrides) ---\n{}\n--- end skill ---",
            self.name, self.description, tag, self.body
        )
    }
}

/// Why a candidate skill was rejected or stripped (surfaced, never silent — ADR-007 §6).
#[derive(Debug, Clone)]
pub struct SkillError {
    pub source: String,
    pub reason: String,
}

/// The discovered skills + the rejections.
#[derive(Debug, Clone, Default)]
pub struct SkillCatalog {
    defs: Vec<SkillDef>,
    errors: Vec<SkillError>,
}

/// Stable, rebuildable skill snapshot. Callers may paint with
/// [`snapshot_for`](Self::snapshot_for) and run
/// [`refresh_for_operator`](Self::refresh_for_operator) off the presentation path; ordinary turns
/// reuse the immutable per-source-set snapshot without reopening skill bodies.
#[derive(Default)]
pub struct SkillCatalogCache {
    current: Mutex<Option<(SkillCatalogKey, SkillCatalogStamp, Arc<SkillCatalog>)>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SkillCatalogKey {
    operator_home: Option<PathBuf>,
    repo: PathBuf,
    dependencies: Vec<(PathBuf, PathBuf)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SkillCatalogStamp(Vec<SkillSourceStamp>);

#[derive(Debug, Clone, PartialEq, Eq)]
struct SkillSourceStamp {
    path: PathBuf,
    bytes: u64,
    modified_unix_nanos: u128,
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
}

impl SkillCatalogCache {
    pub fn snapshot_for(
        &self,
        operator_home: Option<&Path>,
        repo: &Path,
        dependencies: &[(PathBuf, PathBuf)],
    ) -> Option<Arc<SkillCatalog>> {
        let key = skill_catalog_key(operator_home, repo, dependencies);
        lock(&self.current)
            .as_ref()
            .filter(|(current, _, _)| current == &key)
            .map(|(_, _, catalog)| Arc::clone(catalog))
    }

    pub fn refresh_for_operator(
        &self,
        operator_home: Option<&Path>,
        repo: &Path,
        dependencies: &[(PathBuf, PathBuf)],
    ) -> Result<Arc<SkillCatalog>, String> {
        let key = skill_catalog_key(operator_home, repo, dependencies);
        let paths = skill_source_paths(operator_home, repo, dependencies);
        let stamp = skill_catalog_stamp(&paths)
            .map_err(|error| format!("cannot refresh skill metadata index: {error}"))?;
        if let Some((current_key, current_stamp, catalog)) = lock(&self.current).as_ref()
            && current_key == &key
            && current_stamp == &stamp
        {
            return Ok(Arc::clone(catalog));
        }
        let catalog = Arc::new(
            SkillCatalog::discover_metadata_for_operator_with_dependencies(
                operator_home,
                repo,
                dependencies,
            ),
        );
        *lock(&self.current) = Some((key, stamp, Arc::clone(&catalog)));
        Ok(catalog)
    }
}

fn skill_catalog_key(
    operator_home: Option<&Path>,
    repo: &Path,
    dependencies: &[(PathBuf, PathBuf)],
) -> SkillCatalogKey {
    SkillCatalogKey {
        operator_home: operator_home.map(Path::to_path_buf),
        repo: repo.to_path_buf(),
        dependencies: dependencies.to_vec(),
    }
}

fn skill_catalog_stamp(paths: &[PathBuf]) -> std::io::Result<SkillCatalogStamp> {
    let mut stamp = Vec::with_capacity(paths.len());
    for path in paths {
        let metadata = std::fs::metadata(path)?;
        if !metadata.is_file() {
            continue;
        }
        #[cfg(unix)]
        use std::os::unix::fs::MetadataExt as _;
        stamp.push(SkillSourceStamp {
            path: path.clone(),
            bytes: metadata.len(),
            modified_unix_nanos: metadata
                .modified()
                .ok()
                .and_then(|value| value.duration_since(std::time::UNIX_EPOCH).ok())
                .map_or(0, |value| value.as_nanos()),
            #[cfg(unix)]
            device: metadata.dev(),
            #[cfg(unix)]
            inode: metadata.ino(),
        });
    }
    Ok(SkillCatalogStamp(stamp))
}

fn skill_source_paths(
    operator_home: Option<&Path>,
    repo: &Path,
    dependencies: &[(PathBuf, PathBuf)],
) -> Vec<PathBuf> {
    let mut roots = Vec::new();
    if let Some(home) = operator_home {
        roots.extend([
            home.join(".iteron/skills"),
            home.join(".agents/skills"),
            home.join(".codex/skills"),
            home.join(".codex/skills/.system"),
        ]);
    }
    roots.extend([
        iteron_protocol::home::path(repo, "skills"),
        repo.join(".agents/skills"),
    ]);
    roots.extend(dependencies.iter().map(|(_, directory)| directory.clone()));
    let limit = iteron_tunables::param_usize("ctx.skills.max_skill_dirs", MAX_SKILL_DIRS);
    let mut paths = Vec::new();
    for root in roots {
        let Ok(entries) = std::fs::read_dir(&root) else {
            continue;
        };
        for entry in entries.take(limit.saturating_sub(paths.len())) {
            let Ok(entry) = entry else { continue };
            let source = entry.path().join("SKILL.md");
            if std::fs::symlink_metadata(&source).is_ok_and(|metadata| metadata.is_file()) {
                paths.push(source);
            }
        }
        if paths.len() >= limit {
            break;
        }
    }
    if let Some(home) = operator_home {
        let config = home.join(".codex/config.toml");
        if config.is_file() && paths.len() < limit {
            paths.push(config);
        }
    }
    paths.sort();
    paths.dedup();
    paths
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

impl SkillCatalog {
    /// Discover all operator-portable skill roots plus Core's repository roots.
    ///
    /// Precedence is deterministic and user-controlled: native Core skills win name collisions,
    /// then the portable `~/.agents` root, then legacy Codex user skills, then Codex system skills.
    /// Codex `[[skills.config]]` path/name rules are applied in declaration order, including
    /// explicit disables. The same constructor is used for prompt listing and on-demand loading.
    pub fn discover_for_operator(operator_home: Option<&Path>, repo: &Path) -> Self {
        Self::discover_for_operator_with_dependencies(operator_home, repo, &[])
    }

    pub fn discover_for_operator_with_dependencies(
        operator_home: Option<&Path>,
        repo: &Path,
        dependencies: &[(PathBuf, PathBuf)],
    ) -> Self {
        let mut cat = SkillCatalog::default();
        if let Some(home) = operator_home {
            cat.scan(
                &home.join(".iteron/skills"),
                &home.join(".iteron/skills"),
                SkillTier::User,
            );
            cat.scan(
                &home.join(".agents/skills"),
                &home.join(".agents/skills"),
                SkillTier::User,
            );
            let codex_skills = home.join(".codex/skills");
            cat.scan(&codex_skills, &codex_skills, SkillTier::User);
            let codex_system = codex_skills.join(".system");
            cat.scan(&codex_system, &codex_system, SkillTier::User);
        }
        let core_project = iteron_protocol::home::path(repo, "skills");
        cat.scan(repo, &core_project, SkillTier::Project);
        let agents_project = repo.join(".agents/skills");
        cat.scan(repo, &agents_project, SkillTier::Project);
        for (root, directory) in dependencies {
            cat.scan(root, directory, SkillTier::Dependency);
        }
        if let Some(home) = operator_home {
            cat.apply_codex_config(home);
        }
        cat.sort_and_dedup();
        cat
    }

    /// Discover only the bounded frontmatter needed for prompt listing. Skill bodies remain on
    /// disk and are opened by [`Self::load_one_for_operator`] only after an explicit tool call.
    pub fn discover_metadata_for_operator_with_dependencies(
        operator_home: Option<&Path>,
        repo: &Path,
        dependencies: &[(PathBuf, PathBuf)],
    ) -> Self {
        let mut cat = SkillCatalog::default();
        if let Some(home) = operator_home {
            cat.scan_metadata(
                &home.join(".iteron/skills"),
                &home.join(".iteron/skills"),
                SkillTier::User,
            );
            cat.scan_metadata(
                &home.join(".agents/skills"),
                &home.join(".agents/skills"),
                SkillTier::User,
            );
            let codex_skills = home.join(".codex/skills");
            cat.scan_metadata(&codex_skills, &codex_skills, SkillTier::User);
            let codex_system = codex_skills.join(".system");
            cat.scan_metadata(&codex_system, &codex_system, SkillTier::User);
        }
        cat.scan_metadata(
            repo,
            &iteron_protocol::home::path(repo, "skills"),
            SkillTier::Project,
        );
        cat.scan_metadata(repo, &repo.join(".agents/skills"), SkillTier::Project);
        for (root, directory) in dependencies {
            cat.scan_metadata(root, directory, SkillTier::Dependency);
        }
        if let Some(home) = operator_home {
            cat.apply_codex_config(home);
        }
        cat.sort_and_dedup();
        cat
    }

    /// Discover skills under the user dir (Trusted) and the repo (Workspace). A skill directory
    /// found under a vendored dependency path is stripped (Untrusted, never injected). Sorted by
    /// name for a stable, reproducible listing.
    pub fn discover(user_skills_dir: &Path, repo: &Path) -> Self {
        Self::discover_with_user(Some(user_skills_dir), repo)
    }

    /// Discover with an explicitly optional user tier. `None` means the composition root did not
    /// supply a home directory; it must not be replaced with `.` and accidentally treated as
    /// trusted user material.
    pub fn discover_optional(user_skills_dir: Option<&Path>, repo: &Path) -> Self {
        Self::discover_with_dependencies(user_skills_dir, repo, &[])
    }

    /// Discover the ordinary tiers plus exact, already-admitted plugin skill directories.
    ///
    /// Each tuple is `(verified package root, exact skill directory)`. Plugin packages are still
    /// framed as dependency guidance: a publisher signature proves identity and integrity, not
    /// that model-facing instructions may override operator or workspace policy.
    pub fn discover_with_dependencies(
        user_skills_dir: Option<&Path>,
        repo: &Path,
        dependencies: &[(PathBuf, PathBuf)],
    ) -> Self {
        let mut cat = Self::discover_with_user(user_skills_dir, repo);
        for (root, directory) in dependencies {
            cat.scan(root, directory, SkillTier::Dependency);
        }
        cat.sort_and_dedup();
        cat
    }

    /// Discover repository skills when no validated operator home is available.
    pub fn discover_without_user(repo: &Path) -> Self {
        Self::discover_with_user(None, repo)
    }

    fn discover_with_user(user_skills_dir: Option<&Path>, repo: &Path) -> Self {
        let mut cat = SkillCatalog::default();
        // User tier: the supplied `.iteron/skills` directory only.
        if let Some(user_skills_dir) = user_skills_dir {
            cat.scan(user_skills_dir, user_skills_dir, SkillTier::User);
        }
        // Project tier: the repo's `.iteron/skills` directory only.
        let project_dir = iteron_protocol::home::path(repo, "skills");
        cat.scan(repo, &project_dir, SkillTier::Project);
        cat.sort_and_dedup();
        cat
    }

    fn sort_and_dedup(&mut self) {
        // Stable sort preserves source precedence for duplicate names.
        self.defs.sort_by(|a, b| a.name.cmp(&b.name));
        self.defs.dedup_by(|a, b| a.name == b.name);
    }

    fn apply_codex_config(&mut self, operator_home: &Path) {
        let config = operator_home.join(".codex/config.toml");
        let raw = match read_bounded_utf8(
            operator_home,
            &config,
            iteron_tunables::param_integer(
                "ctx.skills.max_codex_config_bytes",
                MAX_CODEX_CONFIG_BYTES,
            ),
            SourceScope::User,
        ) {
            Ok(Some(raw)) => raw,
            Ok(None) => return,
            Err(error) => {
                self.errors.push(SkillError {
                    source: config.display().to_string(),
                    reason: error.reason().to_string(),
                });
                return;
            }
        };
        let value = match toml::from_str::<toml::Value>(&raw) {
            Ok(value) => value,
            Err(error) => {
                self.errors.push(SkillError {
                    source: config.display().to_string(),
                    reason: format!("invalid Codex skills config: {error}"),
                });
                return;
            }
        };
        let Some(rules) = value
            .get("skills")
            .and_then(|skills| skills.get("config"))
            .and_then(toml::Value::as_array)
        else {
            return;
        };
        self.defs.retain(|definition| {
            let mut enabled = true;
            for rule in rules {
                let Some(table) = rule.as_table() else {
                    continue;
                };
                let matches_path = table
                    .get("path")
                    .and_then(toml::Value::as_str)
                    .map(Path::new)
                    .is_some_and(|path| same_skill_path(path, &definition.source_path));
                let matches_name = table
                    .get("name")
                    .and_then(toml::Value::as_str)
                    .is_some_and(|name| name.trim() == definition.name);
                if matches_path || matches_name {
                    enabled = table
                        .get("enabled")
                        .and_then(toml::Value::as_bool)
                        .unwrap_or(iteron_tunables::param_bool(
                            "ctx.skills.default_codex_skill_enabled",
                            DEFAULT_CODEX_SKILL_ENABLED,
                        ));
                }
            }
            enabled
        });
    }

    fn scan(&mut self, root: &Path, dir: &Path, tier: SkillTier) {
        self.scan_with_mode(root, dir, tier, false);
    }

    fn scan_metadata(&mut self, root: &Path, dir: &Path, tier: SkillTier) {
        self.scan_with_mode(root, dir, tier, true);
    }

    fn scan_with_mode(&mut self, root: &Path, dir: &Path, tier: SkillTier, metadata_only: bool) {
        let scope = if tier == SkillTier::User {
            SourceScope::User
        } else {
            SourceScope::Repository
        };
        let max_skill_dirs =
            iteron_tunables::param_usize("ctx.skills.max_skill_dirs", MAX_SKILL_DIRS);
        let listing = match list_directory_bounded(root, dir, max_skill_dirs, scope) {
            Ok(Some(listing)) => listing,
            Ok(None) => return,
            Err(error) => {
                self.errors.push(SkillError {
                    source: dir.display().to_string(),
                    reason: error.reason().to_string(),
                });
                return;
            }
        };
        if listing.truncated {
            self.errors.push(SkillError {
                source: dir.display().to_string(),
                reason: format!("skill discovery truncated at {max_skill_dirs} entries"),
            });
        }
        for entry in listing.entries {
            let p = entry.path;
            let is_directory = entry.kind == SourceEntryKind::Directory
                || (scope == SourceScope::User
                    && entry.kind == SourceEntryKind::Symlink
                    && std::fs::metadata(&p).is_ok_and(|metadata| metadata.is_dir()));
            if !is_directory {
                if scope == SourceScope::Repository && entry.kind == SourceEntryKind::Symlink {
                    self.errors.push(SkillError {
                        source: p.display().to_string(),
                        reason: "repository skill entry is a symlink — not followed".into(),
                    });
                }
                continue;
            }
            // A dependency/vendor path under the skills dir is stripped (defense in depth — the
            // skills dir itself is first-party, but a symlinked/nested vendor dir is not).
            if is_vendor_path(&p) {
                self.errors.push(SkillError {
                    source: p.display().to_string(),
                    reason: "under a dependency/vendor path — stripped".into(),
                });
                continue;
            }
            let skill_md = p.join("SKILL.md");
            let raw = if metadata_only {
                match read_bounded_utf8_prefix(root, &skill_md, max_skill_metadata_bytes(), scope) {
                    Ok(Some(prefix)) => match metadata_document(prefix) {
                        Ok(raw) => raw,
                        Err(reason) => {
                            self.errors.push(SkillError {
                                source: skill_md.display().to_string(),
                                reason,
                            });
                            continue;
                        }
                    },
                    Ok(None) => continue,
                    Err(error) => {
                        self.errors.push(SkillError {
                            source: skill_md.display().to_string(),
                            reason: error.reason().to_string(),
                        });
                        continue;
                    }
                }
            } else {
                match read_bounded_utf8(
                    root,
                    &skill_md,
                    iteron_tunables::param_usize(
                        "ctx.skills.max_skill_source_bytes",
                        iteron_tunables::param_integer(
                            "ctx.skills.max_skill_source_bytes",
                            MAX_SKILL_SOURCE_BYTES,
                        ),
                    ),
                    scope,
                ) {
                    Ok(Some(raw)) => raw,
                    Ok(None) => continue,
                    Err(error) => {
                        self.errors.push(SkillError {
                            source: skill_md.display().to_string(),
                            reason: error.reason().to_string(),
                        });
                        continue;
                    }
                }
            };
            match parse_skill(&raw, &p, tier) {
                Ok(mut def) => {
                    def.source_path = skill_md;
                    self.defs.push(def);
                }
                Err(reason) => self.errors.push(SkillError {
                    source: skill_md.display().to_string(),
                    reason,
                }),
            }
        }
    }

    pub fn get(&self, name: &str) -> Option<&SkillDef> {
        self.defs.iter().find(|d| d.name == name)
    }

    /// Load one exact skill without constructing the full catalog. At most the fixed native,
    /// portable, Codex, and project candidate paths are opened, in the same precedence order as
    /// [`discover_for_operator`].
    pub fn load_one_for_operator(
        operator_home: Option<&Path>,
        repo: &Path,
        name: &str,
    ) -> Result<Option<SkillDef>, String> {
        if !valid_skill_slug(name) {
            return Err("skill name is not a plain slug".into());
        }
        let mut candidates = Vec::new();
        if let Some(home) = operator_home {
            candidates.extend([
                (
                    home.to_path_buf(),
                    home.join(".iteron/skills"),
                    SkillTier::User,
                ),
                (
                    home.to_path_buf(),
                    home.join(".agents/skills"),
                    SkillTier::User,
                ),
                (
                    home.to_path_buf(),
                    home.join(".codex/skills"),
                    SkillTier::User,
                ),
                (
                    home.to_path_buf(),
                    home.join(".codex/skills/.system"),
                    SkillTier::User,
                ),
            ]);
        }
        candidates.extend([
            (
                repo.to_path_buf(),
                iteron_protocol::home::path(repo, "skills"),
                SkillTier::Project,
            ),
            (
                repo.to_path_buf(),
                repo.join(".agents/skills"),
                SkillTier::Project,
            ),
        ]);
        let mut first_error = None;
        for (root, directory, tier) in candidates {
            let skill_dir = directory.join(name);
            let path = skill_dir.join("SKILL.md");
            let scope = if tier == SkillTier::User {
                SourceScope::User
            } else {
                SourceScope::Repository
            };
            let raw = match read_bounded_utf8(
                &root,
                &path,
                iteron_tunables::param_usize(
                    "ctx.skills.max_skill_source_bytes",
                    MAX_SKILL_SOURCE_BYTES,
                ),
                scope,
            ) {
                Ok(Some(raw)) => raw,
                Ok(None) => continue,
                Err(error) => {
                    first_error.get_or_insert_with(|| error.reason().to_owned());
                    continue;
                }
            };
            let mut definition = match parse_skill(&raw, &skill_dir, tier) {
                Ok(definition) if definition.name == name => definition,
                Ok(_) => {
                    first_error.get_or_insert_with(|| {
                        "skill frontmatter name differs from the requested slug".to_owned()
                    });
                    continue;
                }
                Err(error) => {
                    first_error.get_or_insert(error);
                    continue;
                }
            };
            definition.source_path = path;
            if let Some(home) = operator_home {
                let mut catalog = SkillCatalog {
                    defs: vec![definition],
                    errors: Vec::new(),
                };
                catalog.apply_codex_config(home);
                return Ok(catalog.defs.pop());
            }
            return Ok(Some(definition));
        }
        match first_error {
            Some(error) => Err(error),
            None => Ok(None),
        }
    }
    pub fn defs(&self) -> &[SkillDef] {
        &self.defs
    }
    pub fn errors(&self) -> &[SkillError] {
        &self.errors
    }
    pub fn is_empty(&self) -> bool {
        self.defs.is_empty()
    }

    /// Trust of the metadata that enters the stable prefix. Empty is explicit so the caller can
    /// distinguish “no skill text was injected” from a lost provenance path.
    pub fn governing_trust(&self) -> Option<Trust> {
        Trust::governing(self.defs.iter().map(|definition| definition.trust))
    }

    /// The bounded model-facing index with no active path hints. Path-scoped and explicitly
    /// user-only skills remain available through `get`, but are not advertised to the model.
    pub fn listing(&self, budget_bytes: usize) -> String {
        self.listing_for_paths(budget_bytes, &[])
    }

    /// Build the model-facing index for a bounded set of repository-relative active paths.
    pub fn listing_for_paths(&self, budget_bytes: usize, active_paths: &[PathBuf]) -> String {
        self.listing_for_task(budget_bytes, "", active_paths)
    }

    /// Relevance-ranked listing. Exact path-scoped matches come first, followed by textual task
    /// relevance and then the stable name order. The default hard envelope is 6 KiB.
    pub fn listing_for_task(
        &self,
        budget_bytes: usize,
        task: &str,
        active_paths: &[PathBuf],
    ) -> String {
        let budget_bytes = budget_bytes.min(
            iteron_tunables::param_usize("ctx.skills.max_listing_bytes", 6_000)
                .clamp(512, 64 * 1024),
        );
        let query_terms = lexical_terms(task, 64);
        let task_is_present = !task.trim().is_empty();
        let candidates = self
            .defs
            .iter()
            .filter(|definition| definition.metadata.model_visible(active_paths))
            .map(|definition| {
                let searchable = format!(
                    "{} {} {}",
                    definition.name,
                    definition.description,
                    definition
                        .metadata
                        .when_to_use
                        .as_deref()
                        .unwrap_or_default()
                );
                (
                    !definition.metadata.paths.is_empty(),
                    lexical_terms(&definition.name, 32),
                    lexical_terms(&searchable, 256),
                    definition,
                )
            })
            .collect::<Vec<_>>();
        if candidates.is_empty() {
            return String::new();
        }

        // Relevance is derived from the current catalog rather than a provider-, language-, or
        // task-specific keyword table. Terms that occur in most candidate skills carry no
        // selection weight, while exact name terms receive a larger weight. Path-scoped skills
        // have already proved relevance through an active-path match and are retained regardless
        // of lexical score.
        let document_frequency = query_terms
            .iter()
            .map(|term| {
                candidates
                    .iter()
                    .filter(|(_, _, searchable, _)| lexical_match(searchable, term))
                    .count()
            })
            .collect::<Vec<_>>();
        let candidate_count = candidates.len();
        let mut visible = candidates
            .into_iter()
            .filter_map(|(path_match, name_terms, searchable, definition)| {
                let relevance = query_terms
                    .iter()
                    .zip(document_frequency.iter().copied())
                    .filter_map(|(term, frequency)| {
                        if frequency == 0 {
                            return None;
                        }
                        let name_match = lexical_match(&name_terms, term);
                        let text_match = lexical_match(&searchable, term);
                        if !name_match && !text_match {
                            return None;
                        }
                        if !name_match
                            && candidate_count > 2
                            && frequency.saturating_mul(2) > candidate_count
                        {
                            return None;
                        }
                        let rarity = candidate_count.saturating_div(frequency).clamp(1, 8);
                        Some(if name_match { rarity * 8 } else { rarity })
                    })
                    .sum::<usize>();
                (!task_is_present || path_match || relevance > 0)
                    .then_some((path_match, relevance, definition))
            })
            .collect::<Vec<_>>();
        if visible.is_empty() {
            return String::new();
        }
        visible.sort_by(|left, right| {
            right
                .0
                .cmp(&left.0)
                .then_with(|| right.1.cmp(&left.1))
                .then_with(|| left.2.name.cmp(&right.2.name))
        });
        let mut out = String::from(
            "\n\nAvailable skills (use the `use_skill` tool to load one when relevant):\n",
        );
        if out.len() > budget_bytes {
            return String::new();
        }
        let visible_len = visible.len();
        let omitted = iteron_tunables::param_str(
            "ctx.skills.omitted",
            "- … (more skills omitted; listing bounded)\n",
        );
        for (index, (_, _, d)) in visible.into_iter().enumerate() {
            let argument_hint = d
                .metadata
                .argument_hint
                .as_deref()
                .map(|hint| format!(" {}", one_line(hint, 80)))
                .unwrap_or_default();
            let when_to_use = d
                .metadata
                .when_to_use
                .as_deref()
                .map(|hint| format!(" (use when: {})", one_line(hint, 120)))
                .unwrap_or_default();
            let line = format!(
                "- {}{} — {}{}\n",
                d.name,
                argument_hint,
                one_line(&d.description, 120),
                when_to_use
            );
            let reserve = usize::from(index + 1 < visible_len).saturating_mul(omitted.len());
            if out.len() + line.len() + reserve > budget_bytes {
                if out.len() + omitted.len() <= budget_bytes {
                    out.push_str(omitted);
                }
                break;
            }
            out.push_str(&line);
        }
        out
    }
}

/// Produce a bounded, deterministic Unicode lexical view. Long non-ASCII runs also expose
/// adjacent character pairs: this supports scripts without whitespace word boundaries without a
/// language table or an unbounded tokenizer. The exact term remains present for precise matches.
fn lexical_terms(value: &str, limit: usize) -> Vec<String> {
    let mut terms = Vec::with_capacity(limit.min(64));
    for raw in value.split(|character: char| !character.is_alphanumeric()) {
        if terms.len() >= limit {
            break;
        }
        if raw.is_empty() {
            continue;
        }
        let normalized = raw.chars().take(256).collect::<String>().to_lowercase();
        terms.push(normalized.clone());
        if !normalized.is_ascii() {
            let characters = normalized.chars().collect::<Vec<_>>();
            for pair in characters.windows(2) {
                if terms.len() >= limit {
                    break;
                }
                terms.push(pair.iter().collect());
            }
        }
    }
    terms.sort_unstable();
    terms.dedup();
    terms.truncate(limit);
    terms
}

fn lexical_match(terms: &[String], query: &str) -> bool {
    terms.iter().any(|term| {
        term == query
            || (term.chars().count().min(query.chars().count()) >= 4
                && (term.contains(query) || query.contains(term)))
    })
}

/// A path is a vendor/dependency location whose skills must not be trusted or injected.
fn is_vendor_path(p: &Path) -> bool {
    p.components().any(|c| {
        matches!(
            c.as_os_str().to_str(),
            Some("node_modules")
                | Some("vendor")
                | Some("target")
                | Some(".git")
                | Some("site-packages")
                | Some("dist")
        )
    })
}

/// Parse a `SKILL.md`: bounded `---` frontmatter then the body. Unknown keys are tolerated for
/// forward compatibility; malformed known fields are surfaced. Rejects suspicious Unicode.
fn parse_skill(raw: &str, dir: &Path, tier: SkillTier) -> Result<SkillDef, String> {
    if let Some(cp) = suspicious_unicode(raw) {
        return Err(format!("suspicious Unicode U+{cp:04X}"));
    }
    let (front, body) = split_frontmatter(raw);
    let metadata = metadata::parse(front)?;
    let mut name = String::new();
    let mut description = String::new();
    for line in front.lines() {
        if let Some(v) = line.strip_prefix("name:") {
            name = v.trim().trim_matches(['"', '\'']).to_string();
        } else if let Some(v) = line.strip_prefix("description:") {
            description = v.trim().trim_matches(['"', '\'']).to_string();
        }
    }
    // Fall back to the directory name if frontmatter omits `name`.
    if name.is_empty() {
        name = dir
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_string();
    }
    if name.is_empty() {
        return Err("no skill name".into());
    }
    // A skill name must be a plain slug (it is echoed into the prompt + used as a tool arg).
    if !valid_skill_slug(&name) {
        return Err(format!("skill name `{name}` is not a plain slug"));
    }
    Ok(SkillDef {
        name,
        description: if description.is_empty() {
            "(no description)".into()
        } else {
            description
        },
        body: body.trim().to_string(),
        tier,
        trust: tier.trust(),
        metadata,
        source_path: dir.join("SKILL.md"),
    })
}

fn metadata_document(prefix: SourcePrefix) -> Result<String, String> {
    let text = prefix.text.trim_start();
    let Some(rest) = text.strip_prefix("---") else {
        // A body-only skill has no listing metadata beyond its stable directory slug. Its body is
        // intentionally not opened until `use_skill` selects that exact slug.
        return Ok(String::new());
    };
    let Some(end) = rest.find("\n---") else {
        return Err(if prefix.truncated {
            format!("skill frontmatter exceeds {MAX_SKILL_METADATA_BYTES} bytes")
        } else {
            "skill frontmatter is not terminated".into()
        });
    };
    let complete = 3_usize.saturating_add(end).saturating_add(4);
    Ok(text[..complete].to_owned())
}

fn valid_skill_slug(name: &str) -> bool {
    !name.is_empty()
        && name
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || matches!(character, '-' | '_'))
}

fn same_skill_path(configured: &Path, discovered: &Path) -> bool {
    if configured == discovered {
        return true;
    }
    matches!(
        (configured.canonicalize(), discovered.canonicalize()),
        (Ok(configured), Ok(discovered)) if configured == discovered
    )
}

/// Split a leading `---` fenced frontmatter block from the body. Returns (frontmatter, body).
fn split_frontmatter(raw: &str) -> (&str, &str) {
    let t = raw.trim_start();
    if let Some(rest) = t.strip_prefix("---")
        && let Some(end) = rest.find("\n---")
    {
        let front = &rest[..end];
        let body = &rest[end + 4..];
        return (front, body);
    }
    ("", raw)
}

fn one_line(s: &str, max: usize) -> String {
    let flat: String = s.split_whitespace().collect::<Vec<_>>().join(" ");
    if flat.chars().count() <= max {
        return flat;
    }
    let mut out: String = flat.chars().take(max.saturating_sub(1)).collect();
    out.push('…');
    out
}

/// The user skills dir `~/.iteron/skills`, if an absolute operator home is available.
pub fn user_skills_dir() -> Option<PathBuf> {
    iteron_protocol::home::operator().map(|home| iteron_protocol::home::path(&home, "skills"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("core-skills-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn write_skill(root: &Path, name: &str, front_body: &str) {
        let dir = root.join(".iteron").join("skills").join(name);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("SKILL.md"), front_body).unwrap();
    }

    fn write_skill_in(root: &Path, relative: &str, name: &str) -> PathBuf {
        let dir = root.join(relative).join(name);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("SKILL.md");
        std::fs::write(
            &path,
            format!("---\nname: {name}\ndescription: {name} helper\n---\n{name} body\n"),
        )
        .unwrap();
        path
    }

    #[test]
    fn operator_portable_roots_share_one_index_and_honor_codex_enablement() {
        let base = tmp("portable-operator-roots");
        let home = base.join("home");
        let repo = base.join("repo");
        std::fs::create_dir_all(&repo).unwrap();
        write_skill_in(&home, ".iteron/skills", "native");
        write_skill_in(&home, ".agents/skills", "portable");
        let legacy = write_skill_in(&home, ".codex/skills", "legacy");
        let system = write_skill_in(&home, ".codex/skills/.system", "system");
        write_skill_in(&repo, ".agents/skills", "project");
        std::fs::create_dir_all(home.join(".codex")).unwrap();
        let escaped = |path: &Path| path.display().to_string().replace('\\', "\\\\");
        std::fs::write(
            home.join(".codex/config.toml"),
            format!(
                "[[skills.config]]\npath = \"{}\"\nenabled = false\n\n[[skills.config]]\npath = \"{}\"\nenabled = true\n",
                escaped(&legacy),
                escaped(&system)
            ),
        )
        .unwrap();

        let catalog = SkillCatalog::discover_for_operator(Some(&home), &repo);
        let names = catalog
            .defs()
            .iter()
            .map(|definition| definition.name.as_str())
            .collect::<Vec<_>>();
        assert_eq!(
            names,
            vec!["native", "portable", "project", "system"],
            "errors={:?}",
            catalog.errors()
        );
        assert!(catalog.get("legacy").is_none());
        let listing = catalog.listing(4_000);
        for name in ["native", "portable", "project", "system"] {
            assert!(listing.contains(&format!("- {name}")), "{listing}");
        }
        let _ = std::fs::remove_dir_all(&base);
    }

    /// A skill may narrow the registry it runs against, and only narrow it.
    #[test]
    fn a_declared_tool_set_narrows_the_registry() {
        let root = tmp("skill-scoping-narrow");
        write_skill(
            &root,
            "reader",
            "---\nname: reader\ndescription: reads\ntools: [read_file, grep]\n---\nBody.\n",
        );
        let catalog = SkillCatalog::discover_optional(None, &root);
        assert!(catalog.errors().is_empty(), "{:?}", catalog.errors());
        let skill = catalog.get("reader").expect("the skill loaded");
        let registry: Vec<String> = ["read_file", "list_dir", "grep", "glob"]
            .iter()
            .map(|t| (*t).to_owned())
            .collect();
        assert_eq!(
            skill.metadata.narrow(&registry),
            vec!["read_file".to_owned(), "grep".to_owned()]
        );

        // A name the registry does not contain is dropped, never added: the declaration is a
        // filter over what the caller had, not a list the skill hands back.
        let narrower: Vec<String> = vec!["list_dir".to_owned()];
        assert!(skill.metadata.narrow(&narrower).is_empty());

        // Declaring nothing inherits whatever the caller already had.
        let silent = SkillMetadata::default();
        assert_eq!(silent.narrow(&registry), registry);
        let _ = std::fs::remove_dir_all(&root);
    }

    /// A skill that believes it was granted a writer is wrong about its own authority, and the
    /// catalog is the last cheap place to say so.
    #[test]
    fn declaring_a_write_tool_is_a_load_error_at_catalog_build() {
        let root = tmp("skill-scoping-refuse");
        write_skill(
            &root,
            "writer",
            "---\nname: writer\ndescription: writes\ntools: [read_file, write_file]\n---\nBody.\n",
        );
        let catalog = SkillCatalog::discover_optional(None, &root);
        assert!(
            catalog.get("writer").is_none(),
            "a skill naming a writer must not load"
        );
        let error = catalog
            .errors()
            .iter()
            .find(|error| error.reason.contains("write_file"))
            .expect("the refusal is surfaced, not silent");
        assert!(error.reason.contains("narrow"), "{}", error.reason);
        let _ = std::fs::remove_dir_all(&root);
    }

    /// Every refused name is refused, and an empty or malformed declaration is refused too.
    #[test]
    fn every_write_exec_dispatch_name_is_refused() {
        for refused in SKILL_REFUSED_TOOLS {
            let root = tmp(&format!("skill-scoping-{refused}"));
            write_skill(
                &root,
                "candidate",
                &format!("---\nname: candidate\ndescription: d\ntools: [{refused}]\n---\nBody.\n"),
            );
            let catalog = SkillCatalog::discover_optional(None, &root);
            assert!(
                catalog.get("candidate").is_none(),
                "`{refused}` must be refused"
            );
            let _ = std::fs::remove_dir_all(&root);
        }

        let root = tmp("skill-scoping-empty");
        write_skill(
            &root,
            "empty",
            "---\nname: empty\ndescription: d\ntools: []\n---\nBody.\n",
        );
        let catalog = SkillCatalog::discover_optional(None, &root);
        assert!(
            catalog.get("empty").is_none(),
            "an empty declaration is a refusal, not a silent grant of everything"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn discovers_parses_and_lists_a_project_skill() {
        let repo = tmp("basic");
        write_skill(
            &repo,
            "commit-style",
            "---\nname: commit-style\ndescription: How to write commits here\n---\nUse imperative mood.\n",
        );
        let cat = SkillCatalog::discover(Path::new("/nonexistent"), &repo);
        assert_eq!(cat.defs().len(), 1);
        let s = cat.get("commit-style").unwrap();
        assert_eq!(s.trust, Trust::Workspace);
        assert!(s.body.contains("imperative"));
        assert!(cat.listing(4000).contains("commit-style"));
        assert!(s.framed().contains("project skill"));
        assert_eq!(cat.governing_trust(), Some(Trust::Workspace));
        let _ = std::fs::remove_dir_all(&repo);
    }

    #[test]
    fn task_listing_exposes_only_lexically_relevant_unscoped_skills() {
        let repo = tmp("task-relevance");
        write_skill(
            &repo,
            "commit-style",
            "---\nname: commit-style\ndescription: Write concise source control commit messages\n---\nbody\n",
        );
        write_skill(
            &repo,
            "image-editor",
            "---\nname: image-editor\ndescription: Crop and transform raster photographs\n---\nbody\n",
        );
        write_skill(
            &repo,
            "release-notes",
            "---\nname: release-notes\ndescription: Summarize shipped changes for customers\n---\nbody\n",
        );
        let catalog = SkillCatalog::discover(Path::new("/nonexistent"), &repo);

        let relevant = catalog.listing_for_task(4_000, "write a commit message", &[]);
        assert!(relevant.contains("commit-style"), "{relevant}");
        assert!(!relevant.contains("image-editor"), "{relevant}");
        assert!(!relevant.contains("release-notes"), "{relevant}");

        let unrelated = catalog.listing_for_task(4_000, "explain available database models", &[]);
        assert!(unrelated.is_empty(), "{unrelated}");
        assert!(
            catalog.listing(4_000).contains("image-editor"),
            "an empty task preserves the complete operator-facing catalog"
        );
        let _ = std::fs::remove_dir_all(&repo);
    }

    #[test]
    fn active_path_match_survives_zero_lexical_relevance() {
        let repo = tmp("task-path-relevance");
        write_skill(
            &repo,
            "rust-review",
            "---\nname: rust-review\ndescription: Review Rust implementation safety\npaths: [src/**]\n---\nbody\n",
        );
        write_skill(
            &repo,
            "image-editor",
            "---\nname: image-editor\ndescription: Crop raster photographs\n---\nbody\n",
        );
        let catalog = SkillCatalog::discover(Path::new("/nonexistent"), &repo);
        let listing = catalog.listing_for_task(
            4_000,
            "translate a customer invoice",
            &[PathBuf::from("src/lib.rs")],
        );
        assert!(listing.contains("rust-review"), "{listing}");
        assert!(!listing.contains("image-editor"), "{listing}");
        let _ = std::fs::remove_dir_all(&repo);
    }

    #[test]
    fn task_relevance_supports_unicode_without_a_language_dictionary() {
        let repo = tmp("task-unicode-relevance");
        write_skill(
            &repo,
            "release-helper",
            "---\nname: release-helper\ndescription: 生成提交信息和发布说明\n---\nbody\n",
        );
        write_skill(
            &repo,
            "photo-helper",
            "---\nname: photo-helper\ndescription: 处理照片尺寸和颜色\n---\nbody\n",
        );
        let catalog = SkillCatalog::discover(Path::new("/nonexistent"), &repo);
        let listing = catalog.listing_for_task(4_000, "请帮我写提交信息", &[]);
        assert!(listing.contains("release-helper"), "{listing}");
        assert!(!listing.contains("photo-helper"), "{listing}");
        let _ = std::fs::remove_dir_all(&repo);
    }

    #[test]
    fn runtime_catalog_reads_frontmatter_without_opening_the_skill_body() {
        let root = tmp("metadata-only");
        let home = root.join("home");
        let repo = root.join("repo");
        let skill_dir = home.join(".iteron/skills/lazy-skill");
        std::fs::create_dir_all(&skill_dir).unwrap();
        std::fs::create_dir_all(&repo).unwrap();
        let mut bytes = b"---\nname: lazy-skill\ndescription: metadata stays hot\n---\n".to_vec();
        bytes.extend(std::iter::repeat_n(b'x', MAX_SKILL_SOURCE_BYTES + 1));
        std::fs::write(skill_dir.join("SKILL.md"), bytes).unwrap();

        let cache = SkillCatalogCache::default();
        let catalog = cache
            .refresh_for_operator(Some(&home), &repo, &[])
            .expect("frontmatter-only refresh accepts a cold oversized body");
        assert!(catalog.listing(4_000).contains("lazy-skill"));
        assert!(
            SkillCatalog::load_one_for_operator(Some(&home), &repo, "lazy-skill").is_err(),
            "explicit body loading retains the immutable source-byte ceiling"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn rejects_a_bidi_skill_and_a_bad_name() {
        let repo = tmp("reject");
        write_skill(
            &repo,
            "evil",
            "---\nname: evil\ndescription: x\n---\nnormal \u{202E}reversed\n",
        );
        write_skill(
            &repo,
            "badname",
            "---\nname: has spaces\ndescription: x\n---\nbody\n",
        );
        let cat = SkillCatalog::discover(Path::new("/nonexistent"), &repo);
        assert!(cat.get("evil").is_none(), "bidi skill must be rejected");
        assert!(
            cat.get("has spaces").is_none(),
            "non-slug name must be rejected"
        );
        assert!(cat.errors().len() >= 2);
        let _ = std::fs::remove_dir_all(&repo);
    }

    #[test]
    fn listing_is_bounded() {
        let repo = tmp("bounded");
        for i in 0..50 {
            write_skill(
                &repo,
                &format!("skill{i:02}"),
                &format!(
                    "---\nname: skill{i:02}\ndescription: {}\n---\nbody\n",
                    "x".repeat(200)
                ),
            );
        }
        let cat = SkillCatalog::discover(Path::new("/nonexistent"), &repo);
        let listing = cat.listing(500);
        assert!(listing.len() <= 600, "listing must respect the budget");
        assert!(listing.contains("omitted"), "truncation must be surfaced");
        let _ = std::fs::remove_dir_all(&repo);
    }

    #[test]
    fn rejects_an_oversized_project_skill() {
        let repo = tmp("oversized");
        let dir = repo.join(".iteron/skills/large");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("SKILL.md"), vec![b'x'; MAX_SKILL_SOURCE_BYTES + 1]).unwrap();
        let cat = SkillCatalog::discover(Path::new("/nonexistent"), &repo);
        assert!(cat.get("large").is_none());
        assert!(
            cat.errors()
                .iter()
                .any(|error| error.reason.contains("byte limit")),
            "oversize rejection must be surfaced: {:?}",
            cat.errors()
        );
        std::fs::remove_dir_all(repo).ok();
    }

    #[cfg(unix)]
    #[test]
    fn project_skill_symlink_escape_is_rejected_but_user_symlink_is_preserved() {
        let base = tmp("links");
        let repo = base.join("repo");
        let outside = base.join("outside");
        let user = base.join("user-skills");
        std::fs::create_dir_all(repo.join(".iteron/skills")).unwrap();
        std::fs::create_dir_all(&user).unwrap();
        std::fs::create_dir_all(outside.join("external")).unwrap();
        std::fs::write(
            outside.join("external/SKILL.md"),
            "---\nname: linked\ndescription: linked user skill\n---\nbody\n",
        )
        .unwrap();
        std::os::unix::fs::symlink(
            outside.join("external"),
            repo.join(".iteron/skills/escaped"),
        )
        .unwrap();
        std::os::unix::fs::symlink(outside.join("external"), user.join("linked")).unwrap();

        let cat = SkillCatalog::discover(&user, &repo);
        let linked = cat.get("linked").expect("intentional user symlink loads");
        assert_eq!(linked.tier, SkillTier::User);
        assert!(
            cat.errors()
                .iter()
                .any(|error| error.source.contains("escaped") && error.reason.contains("symlink")),
            "project symlink rejection must be surfaced: {:?}",
            cat.errors()
        );
        std::fs::remove_dir_all(base).ok();
    }
}
