//! Skills — progressive-disclosure instruction bundles (Claude Code SKILL.md parity, R5).
//!
//! A skill is `<root>/.core/skills/<name>/SKILL.md`: bounded frontmatter plus a body of
//! instructions. Only model-invocable, path-relevant listing metadata is injected into the stable
//! prefix (a bounded index); the model pulls a skill's full body on demand with the `use_skill`
//! tool when its listing looks relevant — the same progressive-disclosure shape as memory (so a
//! large skill library costs a few tokens per skill until one is actually used).
//!
//! Trust-by-origin (ADR-007, the same posture as memory/agent definitions): a skill under the
//! user dir (`~/.core/skills`) is Trusted; under the project (`<repo>/.core/skills`) it is
//! Workspace; anything discovered under a vendored/cloned dependency path is Untrusted and STRIPPED
//! (never injected) — the recon-injection incident this repo's own Errors.md records. Every skill's
//! frontmatter and body is bidi/invisible-Unicode scanned; a suspicious skill is rejected, not run.

use crate::instructions::suspicious_unicode;
use crate::source::{SourceEntryKind, SourceScope, list_directory_bounded, read_bounded_utf8};
use core_protocol::Trust;
use std::path::{Path, PathBuf};

#[path = "skills_metadata.rs"]
mod metadata;
pub use metadata::{SkillMetadata, active_paths_from_text};

/// Discovery ceilings apply before parsing or prompt construction.
const MAX_SKILL_DIRS: usize = 1_024;
const MAX_SKILL_SOURCE_BYTES: usize = 256 * 1024;

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

impl SkillCatalog {
    /// Discover skills under the user dir (Trusted) and the repo (Workspace). A skill directory
    /// found under a vendored dependency path is stripped (Untrusted, never injected). Sorted by
    /// name for a stable, reproducible listing.
    pub fn discover(user_skills_dir: &Path, repo: &Path) -> Self {
        let mut cat = SkillCatalog::default();
        // User tier: the supplied `.core/skills` directory only.
        cat.scan(user_skills_dir, user_skills_dir, SkillTier::User);
        // Project tier: the repo's `.core/skills` directory only.
        let project_dir = core_protocol::home::path(repo, "skills");
        cat.scan(repo, &project_dir, SkillTier::Project);
        cat.defs.sort_by(|a, b| a.name.cmp(&b.name));
        cat.defs.dedup_by(|a, b| a.name == b.name);
        cat
    }

    fn scan(&mut self, root: &Path, dir: &Path, tier: SkillTier) {
        let scope = if tier == SkillTier::User {
            SourceScope::User
        } else {
            SourceScope::Repository
        };
        let listing = match list_directory_bounded(root, dir, MAX_SKILL_DIRS, scope) {
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
                reason: format!("skill discovery truncated at {MAX_SKILL_DIRS} entries"),
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
            let raw = match read_bounded_utf8(root, &skill_md, MAX_SKILL_SOURCE_BYTES, scope) {
                Ok(Some(raw)) => raw,
                Ok(None) => continue,
                Err(error) => {
                    self.errors.push(SkillError {
                        source: skill_md.display().to_string(),
                        reason: error.reason().to_string(),
                    });
                    continue;
                }
            };
            match parse_skill(&raw, &p, tier) {
                Ok(def) => self.defs.push(def),
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
        if !self
            .defs
            .iter()
            .any(|definition| definition.metadata.model_visible(active_paths))
        {
            return String::new();
        }
        let mut out = String::from(
            "\n\nAvailable skills (use the `use_skill` tool to load one when relevant):\n",
        );
        for d in &self.defs {
            if !d.metadata.model_visible(active_paths) {
                continue;
            }
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
            if out.len() + line.len() > budget_bytes {
                out.push_str("- … (more skills omitted; listing bounded)\n");
                break;
            }
            out.push_str(&line);
        }
        out
    }
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
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_'))
    {
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
    })
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

/// The user skills dir `~/.core/skills`, if HOME is set.
pub fn user_skills_dir() -> Option<PathBuf> {
    std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".core").join("skills"))
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
        let dir = root.join(".core").join("skills").join(name);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("SKILL.md"), front_body).unwrap();
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
        let dir = repo.join(".core/skills/large");
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
        std::fs::create_dir_all(repo.join(".core/skills")).unwrap();
        std::fs::create_dir_all(&user).unwrap();
        std::fs::create_dir_all(outside.join("external")).unwrap();
        std::fs::write(
            outside.join("external/SKILL.md"),
            "---\nname: linked\ndescription: linked user skill\n---\nbody\n",
        )
        .unwrap();
        std::os::unix::fs::symlink(outside.join("external"), repo.join(".core/skills/escaped"))
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
