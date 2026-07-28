use crate::model::{Boundary, DependencyKinds, PathClaim, Registry};
use anyhow::{Context, Result, bail};
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::process::Command;

pub struct Report {
    pub files: usize,
    pub packages: usize,
}

pub fn validate(root: &Path, registry: &Registry) -> Result<Report> {
    validate_registry(registry)?;
    validate_protocol_boundary(root, registry)?;
    crate::schema_compat::validate_current(root)?;
    crate::conformance::validate(root)?;
    let files = public_files(root)?;
    validate_path_coverage(registry, &files)?;
    let packages = validate_cargo_policy(root, registry)?;
    Ok(Report {
        files: files.len(),
        packages,
    })
}

pub fn explain(registry: &Registry, path: &str) -> Result<()> {
    validate_repo_path(path)?;
    let boundary = boundary_for_path(registry, path)
        .with_context(|| format!("`{path}` has no primary boundary"))?;
    println!("boundary: {} — {}", boundary.id, boundary.title);
    println!("status: {} · risk: {}", boundary.status, boundary.risk);
    println!(
        "primary: {}",
        boundary
            .primary
            .as_deref()
            .unwrap_or("open (Owner fallback)")
    );
    if boundary.reviewers.is_empty() {
        println!("reviewers: none recorded");
    } else {
        println!("reviewers: {}", boundary.reviewers.join(", "));
    }
    let overlays: Vec<_> = registry
        .overlays
        .iter()
        .filter(|overlay| overlay.paths.iter().any(|claim| claim_matches(claim, path)))
        .map(|overlay| overlay.id.as_str())
        .collect();
    println!(
        "invariant overlays: {}",
        if overlays.is_empty() {
            "none".into()
        } else {
            overlays.join(", ")
        }
    );
    Ok(())
}

pub fn list(registry: &Registry, only_open: bool) {
    println!("BOUNDARY\tRISK\tSTATUS\tPRIMARY\tTITLE");
    for boundary in &registry.boundaries {
        if only_open && boundary.status != "open" {
            continue;
        }
        println!(
            "{}\t{}\t{}\t{}\t{}",
            boundary.id,
            boundary.risk,
            boundary.status,
            boundary.primary.as_deref().unwrap_or("Owner fallback"),
            boundary.title
        );
    }
}

pub fn readiness(registry: &Registry) -> Result<()> {
    let owner = registry
        .people
        .iter()
        .find(|person| person.id == registry.enforcement.project_owner);
    let mut blockers = Vec::new();
    if owner.and_then(|person| person.github.as_ref()).is_none() {
        blockers.push("record the Owner's explicit individual GitHub handle".to_string());
    }
    let critical: Vec<_> = registry
        .boundaries
        .iter()
        .filter(|boundary| boundary.risk == "critical" && boundary.status != "active")
        .map(|boundary| boundary.id.as_str())
        .collect();
    if !critical.is_empty() {
        blockers.push(format!(
            "assign primary and independent reviewer for critical boundaries: {}",
            critical.join(", ")
        ));
    }
    let overlays: Vec<_> = registry
        .overlays
        .iter()
        .filter(|overlay| overlay.requires_independent_review && overlay.status != "active")
        .map(|overlay| overlay.id.as_str())
        .collect();
    if !overlays.is_empty() {
        blockers.push(format!(
            "assign independent reviewers for invariant overlays: {}",
            overlays.join(", ")
        ));
    }
    if registry.enforcement.mode != "active" {
        blockers.push("switch enforcement.mode to `active` after assignments validate".into());
    }
    if blockers.is_empty() {
        println!("boundary ownership is ready for remote Ruleset activation");
        Ok(())
    } else {
        bail!(
            "remote activation is not ready:\n- {}",
            blockers.join("\n- ")
        )
    }
}

struct Impact {
    boundaries: BTreeMap<String, BTreeSet<String>>,
    overlays: BTreeSet<String>,
    responsible: BTreeSet<String>,
    review_groups: BTreeMap<String, BTreeSet<String>>,
}

pub fn affected(root: &Path, registry: &Registry, base: &str) -> Result<()> {
    let impact = calculate_impact(root, registry, base)?;
    println!("## Boundary impact");
    if impact.boundaries.is_empty() {
        println!("\nNo changed repository paths were found.");
        return Ok(());
    }
    println!("\nPrimary boundaries:");
    for (id, paths) in impact.boundaries {
        println!("- `{id}` — {} path(s)", paths.len());
    }
    println!("\nInvariant overlays:");
    if impact.overlays.is_empty() {
        println!("- none");
    } else {
        for id in impact.overlays {
            println!("- `{id}`");
        }
    }
    println!("\nEffective responsible maintainers:");
    if impact.responsible.is_empty() {
        println!("- unassigned");
    } else {
        for handle in &impact.responsible {
            println!("- `{handle}`");
        }
    }
    println!("\nRequired review groups:");
    if impact.review_groups.is_empty() {
        println!("- none");
    } else {
        for (group, handles) in &impact.review_groups {
            println!(
                "- `{group}` — {}",
                handles.iter().cloned().collect::<Vec<_>>().join(", ")
            );
        }
    }
    Ok(())
}

pub fn check_pr(root: &Path, registry: &Registry, base: &str, body: &str) -> Result<()> {
    if body.len() > 262_144 {
        bail!("pull request body is too large");
    }
    let impact = validate_candidate_against_base(root, registry, base)?;
    if registry.enforcement.mode == "bootstrap" {
        println!(
            "bootstrap pull request inspected: {} boundaries, {} overlays; responsibility enforcement is not active",
            impact.boundaries.len(),
            impact.overlays.len()
        );
        return Ok(());
    }
    validate_pr_contract(registry, &impact, body)?;
    println!(
        "pull request contract valid: {} boundaries, {} overlays",
        impact.boundaries.len(),
        impact.overlays.len()
    );
    Ok(())
}

/// Validate code/schema changes against the exact current base without requiring PR prose.
///
/// Merge queues synthesize a new candidate after earlier queued changes land. Re-running this
/// check against that merge-group base prevents two individually monotone protocol bumps from
/// collapsing to the same version when composed.
pub fn check_base(root: &Path, registry: &Registry, base: &str) -> Result<()> {
    let impact = validate_candidate_against_base(root, registry, base)?;
    println!(
        "candidate contract valid against immediate base: {} boundaries, {} overlays",
        impact.boundaries.len(),
        impact.overlays.len()
    );
    Ok(())
}

fn validate_candidate_against_base(root: &Path, registry: &Registry, base: &str) -> Result<Impact> {
    let impact = calculate_impact(root, registry, base)?;
    let wire_changed = impact.boundaries.contains_key("protocol-compat")
        && crate::schema_compat::wire_line_format_changed(root, base)?;
    validate_protocol_version_bump(root, base, wire_changed)?;
    crate::schema_compat::validate_against_base(root, base)?;
    Ok(impact)
}

pub(crate) const PROTOCOL_VERSION_SOURCE: &str = "crates/protocol/src/wire.rs";
const MAX_PROTOCOL_VERSION_SOURCE_BYTES: u64 = 64 * 1024;

fn validate_protocol_boundary(root: &Path, registry: &Registry) -> Result<()> {
    let boundary = registry
        .boundaries
        .iter()
        .find(|boundary| boundary.id == "protocol-compat")
        .context("boundary registry lacks protocol-compat")?;
    if !boundary
        .contracts
        .iter()
        .any(|contract| contract == "sqeq-version-lockstep")
    {
        bail!("protocol-compat must declare the sqeq-version-lockstep contract");
    }
    if !boundary
        .checks
        .iter()
        .any(|check| check == "core-xtask boundaries check-pr --base <rev>")
    {
        bail!("protocol-compat must declare the version-skew pull-request check");
    }
    if !boundary
        .checks
        .iter()
        .any(|check| check == "core-xtask boundaries check-base --base <rev>")
    {
        bail!("protocol-compat must declare the merge-group-safe immediate-base check");
    }
    let source = crate::schema_compat::read_candidate_file_bounded(
        root,
        PROTOCOL_VERSION_SOURCE,
        MAX_PROTOCOL_VERSION_SOURCE_BYTES,
    )
    .context("cannot read the SQ/EQ protocol version source")?;
    let version = protocol_version_from_source(&source)?;
    if version == 0 {
        bail!("PROTOCOL_VERSION must be positive");
    }
    Ok(())
}

fn validate_protocol_version_bump(root: &Path, base: &str, protocol_changed: bool) -> Result<()> {
    if !protocol_changed {
        return Ok(());
    }
    let base = resolve_base(root, base)?;
    let base_version = protocol_version_at_revision(root, &base)?;
    let candidate_source = crate::schema_compat::read_candidate_file_bounded(
        root,
        PROTOCOL_VERSION_SOURCE,
        MAX_PROTOCOL_VERSION_SOURCE_BYTES,
    )
    .context("cannot read candidate SQ/EQ protocol version source")?;
    let candidate_version = protocol_version_from_source(&candidate_source)?;
    if candidate_version <= base_version {
        bail!(
            "protocol-compat changed without a monotone PROTOCOL_VERSION bump (base {base_version}, candidate {candidate_version})"
        );
    }
    Ok(())
}

fn protocol_version_at_revision(root: &Path, revision: &str) -> Result<u32> {
    let Some(source) = crate::schema_compat::read_revision_file_bounded(
        root,
        revision,
        PROTOCOL_VERSION_SOURCE,
        MAX_PROTOCOL_VERSION_SOURCE_BYTES,
    )
    .context("cannot read base SQ/EQ protocol version")?
    else {
        // Version zero is the one-time pre-versioning baseline. Once wire.rs lands, deleting it
        // from a base revision is impossible without already tripping candidate validation.
        return Ok(0);
    };
    protocol_version_from_source(&source)
}

pub(crate) fn protocol_version_from_source(source: &[u8]) -> Result<u32> {
    if source.len() as u64 > MAX_PROTOCOL_VERSION_SOURCE_BYTES {
        bail!("SQ/EQ protocol version source exceeds 64 KiB");
    }
    crate::rust_source::public_decimal_const(source, "PROTOCOL_VERSION", "u32")
        .context("invalid SQ/EQ protocol version constant")
}

pub fn check_reviews(
    root: &Path,
    registry: &Registry,
    base: &str,
    author: &str,
    reviews_json: &[u8],
) -> Result<()> {
    if reviews_json.len() > 4 * 1024 * 1024 {
        bail!("GitHub review evidence exceeds the 4 MiB limit");
    }
    let impact = calculate_impact(root, registry, base)?;
    if registry.enforcement.mode == "bootstrap" {
        // Honest bootstrap keeps ordinary responsibility review non-enforcing so early
        // contributions are not falsely rejected. The ownership registry, however, is the
        // root of trust: `governance/boundaries.json` defines every boundary and the
        // enforcement mode itself. Leaving it under the non-enforcing pass lets a change
        // silently rewrite the boundary/enforcement definitions. Enforce the one bootstrap
        // floor the runbook already reserves — an ownership-registry change requires the
        // Owner's accountable authorship or a current-commit Owner approval — while every
        // other responsibility group stays advisory.
        let registry_floor: BTreeMap<String, BTreeSet<String>> = impact
            .review_groups
            .iter()
            .filter(|(group, _)| group.starts_with("owner:registry-"))
            .map(|(group, handles)| (group.clone(), handles.clone()))
            .collect();
        if !registry_floor.is_empty() {
            let head = resolve_base(root, "HEAD")?;
            let floor = Impact {
                boundaries: BTreeMap::new(),
                overlays: BTreeSet::new(),
                responsible: BTreeSet::new(),
                review_groups: registry_floor,
            };
            validate_review_contract(&floor, &head, author, reviews_json)
                .context("bootstrap ownership-registry floor")?;
            println!(
                "bootstrap review inspected: {} responsibility groups; ownership-registry change enforced against the Owner floor",
                impact.review_groups.len()
            );
            return Ok(());
        }
        println!(
            "bootstrap review inspected: {} responsibility groups; registered-human review enforcement is not active",
            impact.review_groups.len()
        );
        return Ok(());
    }
    let head = resolve_base(root, "HEAD")?;
    validate_review_contract(&impact, &head, author, reviews_json)?;
    println!(
        "required human reviews valid: {} responsibility groups",
        impact.review_groups.len()
    );
    Ok(())
}

#[derive(Deserialize)]
struct GithubReview {
    id: u64,
    user: Option<GithubReviewUser>,
    state: String,
    commit_id: String,
}

#[derive(Deserialize)]
struct GithubReviewUser {
    login: String,
}

fn validate_review_contract(
    impact: &Impact,
    head: &str,
    author: &str,
    reviews_json: &[u8],
) -> Result<()> {
    let evidence: serde_json::Value =
        serde_json::from_slice(reviews_json).context("GitHub review evidence is invalid JSON")?;
    let mut reviews = Vec::new();
    flatten_reviews(&evidence, &mut reviews)?;
    let mut latest = BTreeMap::new();
    for review in &reviews {
        if !matches!(
            review.state.as_str(),
            "APPROVED" | "CHANGES_REQUESTED" | "DISMISSED"
        ) {
            continue;
        }
        let Some(user) = &review.user else {
            continue;
        };
        let login = format!("@{}", user.login.to_ascii_lowercase());
        let replace = latest
            .get(&login)
            .is_none_or(|previous: &&GithubReview| review.id > previous.id);
        if replace {
            latest.insert(login, review);
        }
    }

    let author = format!("@{}", author.trim_start_matches('@').to_ascii_lowercase());
    let mut missing = Vec::new();
    for (group, eligible) in &impact.review_groups {
        let authored_authority = (group.starts_with("primary:") || group.starts_with("owner:"))
            && eligible.contains(&author);
        let review_eligible: Vec<_> = eligible
            .iter()
            .filter(|handle| *handle != &author)
            .collect();
        let approved = review_eligible.iter().any(|handle| {
            latest.get(handle.as_str()).is_some_and(|review| {
                review.state == "APPROVED" && review.commit_id.eq_ignore_ascii_case(head)
            })
        });
        if !authored_authority && !approved {
            let candidates = review_eligible
                .iter()
                .map(|handle| handle.as_str())
                .collect::<Vec<_>>()
                .join(", ");
            missing.push(if candidates.is_empty() {
                format!("{group} (no registered reviewer other than the pull request author)")
            } else {
                format!("{group} (one of {candidates})")
            });
        }
    }
    if missing.is_empty() {
        Ok(())
    } else {
        bail!(
            "required current-commit reviews are missing:\n- {}",
            missing.join("\n- ")
        )
    }
}

fn flatten_reviews(value: &serde_json::Value, reviews: &mut Vec<GithubReview>) -> Result<()> {
    let entries = value
        .as_array()
        .context("GitHub review evidence must be a JSON array")?;
    for entry in entries {
        if entry.is_array() {
            flatten_reviews(entry, reviews)?;
        } else {
            reviews.push(
                serde_json::from_value(entry.clone())
                    .context("GitHub review evidence contains an invalid review")?,
            );
        }
    }
    Ok(())
}

fn validate_pr_contract(registry: &Registry, impact: &Impact, body: &str) -> Result<()> {
    if registry.enforcement.mode != "active" {
        bail!("pull request enforcement is unavailable while the registry is in bootstrap mode");
    }
    let mut allowed_boundaries: BTreeSet<_> = registry
        .boundaries
        .iter()
        .map(|boundary| boundary.id.as_str())
        .collect();
    allowed_boundaries.extend(impact.boundaries.keys().map(String::as_str));
    let mut allowed_overlays: BTreeSet<_> = registry
        .overlays
        .iter()
        .map(|overlay| overlay.id.as_str())
        .collect();
    allowed_overlays.extend(impact.overlays.iter().map(String::as_str));
    let declared_boundaries = parse_id_field(
        pr_field(body, "Affected-Boundaries")?,
        "Affected-Boundaries",
        &allowed_boundaries,
    )?;
    let declared_overlays = parse_id_field(
        pr_field(body, "Invariant-Overlays")?,
        "Invariant-Overlays",
        &allowed_overlays,
    )?;
    let actual_boundaries: BTreeSet<_> = impact.boundaries.keys().cloned().collect();
    if declared_boundaries != actual_boundaries {
        bail!(
            "Affected-Boundaries does not match the diff; expected `{}`",
            display_ids(&actual_boundaries)
        );
    }
    if declared_overlays != impact.overlays {
        bail!(
            "Invariant-Overlays does not match the diff; expected `{}`",
            display_ids(&impact.overlays)
        );
    }

    let tracking = pr_field(body, "Tracking-Issue")?;
    if !valid_issue_or_na(tracking) {
        bail!("Tracking-Issue must be `#<positive number>` or `not-applicable`");
    }
    let ownership = pr_field(body, "Ownership-Claim")?;
    if !valid_issue_or_na(ownership) {
        bail!("Ownership-Claim must be `#<positive number>` or `not-applicable`");
    }
    let registry_changed = impact
        .boundaries
        .values()
        .any(|paths| paths.contains("governance/boundaries.json"));
    if registry_changed && !valid_issue_ref(ownership) {
        bail!("a boundary registry change must reference an ownership claim issue");
    }
    let responsible = parse_handle_field(
        pr_field(body, "Responsible-Maintainers")?,
        "Responsible-Maintainers",
    )?;
    if responsible != impact.responsible {
        bail!(
            "Responsible-Maintainers does not match effective ownership; expected `{}`",
            display_ids(&impact.responsible)
        );
    }
    let agreement = pr_field(body, "Cross-Boundary-Agreement")?;
    if actual_boundaries.len() > 1 && !valid_issue_ref(agreement) {
        bail!("a multi-boundary change must reference its human agreement as `#<positive number>`");
    }
    if actual_boundaries.len() <= 1 && !valid_issue_or_na(agreement) {
        bail!("Cross-Boundary-Agreement must be an issue reference or `not-applicable`");
    }
    let contract = pr_field(body, "Contract-Impact")?;
    if contract.len() < 4 {
        bail!("Contract-Impact must state `none` or give a meaningful summary");
    }
    let rollback = pr_field(body, "Rollback")?;
    if rollback.len() < 8 || rollback.eq_ignore_ascii_case("none") {
        bail!("Rollback must give a concrete bounded rollback or revert plan");
    }
    Ok(())
}

fn calculate_impact(root: &Path, registry: &Registry, base: &str) -> Result<Impact> {
    let base = resolve_base(root, base)?;
    require_current_base(root, &base)?;
    let base_registry = registry_at_revision(root, &base)?;
    validate_registry(&base_registry).context("base boundary registry is invalid")?;
    validate_enforcement_transition(registry, &base_registry)?;
    let range = format!("{base}...HEAD");
    let output = Command::new("git")
        .args([
            "diff",
            "--no-ext-diff",
            "--no-textconv",
            "--name-status",
            "-z",
            "-M",
            &range,
            "--",
        ])
        .current_dir(root)
        .output()
        .context("cannot inspect changed paths")?;
    if !output.status.success() {
        bail!(
            "git diff failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    impact_from_name_status(registry, &base_registry, &output.stdout)
}

fn require_current_base(root: &Path, base: &str) -> Result<()> {
    let status = Command::new("git")
        .args(["merge-base", "--is-ancestor", base, "HEAD"])
        .current_dir(root)
        .status()
        .context("cannot compare the pull request head with its base")?;
    match status.code() {
        Some(0) => Ok(()),
        Some(1) => bail!(
            "pull request head does not contain the current base commit; update the branch before responsibility review"
        ),
        _ => bail!("git merge-base failed while checking the current base"),
    }
}

fn validate_enforcement_transition(head: &Registry, base: &Registry) -> Result<()> {
    if base.enforcement.mode == "active" && head.enforcement.mode != "active" {
        bail!("active ownership enforcement cannot be downgraded to bootstrap by a pull request");
    }
    Ok(())
}

fn resolve_base(root: &Path, base: &str) -> Result<String> {
    if base.is_empty() || base.starts_with('-') || base.chars().any(char::is_control) {
        bail!("invalid base revision");
    }
    let revision = format!("{base}^{{commit}}");
    let output = Command::new("git")
        .args(["rev-parse", "--verify", "--end-of-options", &revision])
        .current_dir(root)
        .output()
        .context("cannot resolve base revision")?;
    if !output.status.success() {
        bail!(
            "cannot resolve base revision: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    let resolved = std::str::from_utf8(&output.stdout)
        .context("base object ID is not UTF-8")?
        .trim();
    if !matches!(resolved.len(), 40 | 64) || !resolved.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        bail!("git returned an invalid base object ID");
    }
    Ok(resolved.to_ascii_lowercase())
}

fn registry_at_revision(root: &Path, revision: &str) -> Result<Registry> {
    let object = format!("{revision}:governance/boundaries.json");
    let output = Command::new("git")
        .args(["show", "--no-textconv", &object])
        .current_dir(root)
        .output()
        .context("cannot read base boundary registry")?;
    if !output.status.success() {
        bail!(
            "cannot read base boundary registry: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    if output.stdout.len() > 2 * 1024 * 1024 {
        bail!("base boundary registry exceeds the 2 MiB limit");
    }
    serde_json::from_slice(&output.stdout).context("base boundary registry is invalid JSON")
}

fn impact_from_name_status(head: &Registry, base: &Registry, bytes: &[u8]) -> Result<Impact> {
    let fields = nul_paths(bytes)?;
    let mut index = 0;
    let mut impact = Impact {
        boundaries: BTreeMap::new(),
        overlays: BTreeSet::new(),
        responsible: BTreeSet::new(),
        review_groups: BTreeMap::new(),
    };
    while index < fields.len() {
        let status = &fields[index];
        index += 1;
        match status.as_str() {
            "A" => {
                let path = next_diff_path(&fields, &mut index, status)?;
                add_impact(&mut impact, head, path, "added")?;
            }
            "D" => {
                let path = next_diff_path(&fields, &mut index, status)?;
                add_impact(&mut impact, base, path, "deleted")?;
            }
            "M" | "T" => {
                let path = next_diff_path(&fields, &mut index, status)?;
                add_impact(&mut impact, base, path, "previous")?;
                add_impact(&mut impact, head, path, "current")?;
            }
            status
                if status.len() > 1
                    && matches!(status.as_bytes()[0], b'R' | b'C')
                    && status[1..].bytes().all(|byte| byte.is_ascii_digit()) =>
            {
                let old_path = next_diff_path(&fields, &mut index, status)?;
                let new_path = next_diff_path(&fields, &mut index, status)?;
                add_impact(&mut impact, base, old_path, "renamed source")?;
                add_impact(&mut impact, head, new_path, "renamed destination")?;
            }
            _ => bail!("unsupported git diff status `{status}`"),
        }
    }
    Ok(impact)
}

fn next_diff_path<'a>(fields: &'a [String], index: &mut usize, status: &str) -> Result<&'a str> {
    let path = fields
        .get(*index)
        .with_context(|| format!("git diff status `{status}` is missing a path"))?;
    *index += 1;
    validate_repo_path(path).with_context(|| format!("git diff emitted invalid path `{path}`"))?;
    Ok(path)
}

fn add_impact(impact: &mut Impact, registry: &Registry, path: &str, side: &str) -> Result<()> {
    let boundary = boundary_for_path(registry, path)
        .with_context(|| format!("{side} path `{path}` has no primary boundary"))?;
    impact
        .boundaries
        .entry(boundary.id.clone())
        .or_default()
        .insert(path.to_string());
    let responsible_id = boundary
        .primary
        .as_deref()
        .unwrap_or(&registry.enforcement.project_owner);
    let phase = impact_phase(side);
    if let Some(handle) = person_handle(registry, responsible_id) {
        let handle = handle.to_ascii_lowercase();
        impact.responsible.insert(handle.clone());
        impact
            .review_groups
            .entry(format!("primary:{}:{handle}", boundary.id))
            .or_default()
            .insert(handle);
    }
    if !boundary.reviewers.is_empty() {
        let group = impact
            .review_groups
            .entry(format!("boundary:{}:{phase}:independent", boundary.id))
            .or_default();
        for reviewer in &boundary.reviewers {
            if let Some(handle) = person_handle(registry, reviewer) {
                group.insert(handle.to_ascii_lowercase());
            }
        }
    }
    if path == "governance/boundaries.json"
        && let Some(handle) = person_handle(registry, &registry.enforcement.project_owner)
    {
        impact
            .review_groups
            .entry(format!("owner:registry-{phase}"))
            .or_default()
            .insert(handle.to_ascii_lowercase());
    }
    for overlay in &registry.overlays {
        if overlay.paths.iter().any(|claim| claim_matches(claim, path)) {
            impact.overlays.insert(overlay.id.clone());
            if !overlay.reviewers.is_empty() {
                let group = impact
                    .review_groups
                    .entry(format!("overlay:{}:{phase}:{}", overlay.id, boundary.id))
                    .or_default();
                for reviewer in &overlay.reviewers {
                    if reviewer != responsible_id
                        && let Some(handle) = person_handle(registry, reviewer)
                    {
                        group.insert(handle.to_ascii_lowercase());
                    }
                }
            }
        }
    }
    Ok(())
}

fn impact_phase(side: &str) -> &'static str {
    if matches!(side, "previous" | "deleted" | "renamed source") {
        "base"
    } else {
        "candidate"
    }
}

fn person_handle<'a>(registry: &'a Registry, id: &str) -> Option<&'a str> {
    registry
        .people
        .iter()
        .find(|person| person.id == id)
        .and_then(|person| person.github.as_deref())
}

fn pr_field<'a>(body: &'a str, name: &str) -> Result<&'a str> {
    let section = responsibility_section(body)?;
    let prefix = format!("{name}:");
    let mut matches = section
        .lines()
        .filter_map(|line| line.strip_prefix(&prefix));
    let value = matches
        .next()
        .with_context(|| format!("pull request body is missing `{name}:`"))?
        .trim();
    if matches.next().is_some() {
        bail!("pull request body repeats `{name}:`");
    }
    if value.is_empty() || value.starts_with("<!--") {
        bail!("pull request field `{name}` is not filled in");
    }
    Ok(value)
}

fn responsibility_section(body: &str) -> Result<&str> {
    let marker = "## Responsibility contract";
    let (_, remainder) = body
        .split_once(marker)
        .context("pull request body is missing the Responsibility contract section")?;
    if remainder.contains(marker) {
        bail!("pull request body repeats the Responsibility contract section");
    }
    let section = remainder
        .split_once("\n## ")
        .map_or(remainder, |(section, _)| section);
    if section.contains("```") {
        bail!("responsibility fields cannot be placed in a code fence");
    }
    Ok(section)
}

fn parse_id_field(value: &str, name: &str, allowed: &BTreeSet<&str>) -> Result<BTreeSet<String>> {
    if value.eq_ignore_ascii_case("none") {
        return Ok(BTreeSet::new());
    }
    let mut parsed = BTreeSet::new();
    for item in value.split(',') {
        let id = item.trim();
        if id.is_empty() || !allowed.contains(id) {
            bail!("pull request field `{name}` contains unknown ID `{id}`");
        }
        if !parsed.insert(id.to_string()) {
            bail!("pull request field `{name}` repeats ID `{id}`");
        }
    }
    Ok(parsed)
}

fn display_ids(ids: &BTreeSet<String>) -> String {
    if ids.is_empty() {
        "none".into()
    } else {
        ids.iter().cloned().collect::<Vec<_>>().join(", ")
    }
}

fn parse_handle_field(value: &str, name: &str) -> Result<BTreeSet<String>> {
    let mut handles = BTreeSet::new();
    for item in value.split(',') {
        let handle = item.trim();
        if !valid_individual_handle(handle) {
            bail!("pull request field `{name}` contains invalid human handle `{handle}`");
        }
        if !handles.insert(handle.to_ascii_lowercase()) {
            bail!("pull request field `{name}` repeats handle `{handle}`");
        }
    }
    Ok(handles)
}

fn valid_issue_ref(value: &str) -> bool {
    value
        .strip_prefix('#')
        .and_then(|number| number.parse::<u64>().ok())
        .is_some_and(|number| number > 0)
}

fn valid_issue_or_na(value: &str) -> bool {
    value.eq_ignore_ascii_case("not-applicable") || valid_issue_ref(value)
}

fn valid_individual_handle(value: &str) -> bool {
    let Some(handle) = value.strip_prefix('@') else {
        return false;
    };
    !handle.is_empty()
        && handle.len() <= 39
        && !handle.starts_with('-')
        && !handle.ends_with('-')
        && !handle.contains("--")
        && handle
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
}

pub fn claim_matches(claim: &PathClaim, path: &str) -> bool {
    match claim.kind.as_str() {
        "file" => path == claim.path,
        "tree" => path.starts_with(&format!("{}/", claim.path)),
        _ => false,
    }
}

fn boundary_for_path<'a>(registry: &'a Registry, path: &str) -> Option<&'a Boundary> {
    let mut matches = registry.boundaries.iter().filter(|boundary| {
        boundary
            .paths
            .iter()
            .any(|claim| claim_matches(claim, path))
    });
    let first = matches.next()?;
    matches.next().is_none().then_some(first)
}

fn validate_registry(registry: &Registry) -> Result<()> {
    let mut errors = Vec::new();
    if registry.schema_version != 1 {
        errors.push(format!(
            "unsupported boundary schema {}; expected 1",
            registry.schema_version
        ));
    }
    if !matches!(registry.enforcement.mode.as_str(), "bootstrap" | "active") {
        errors.push("enforcement.mode must be `bootstrap` or `active`".into());
    }
    if registry.cargo_policy.mode != "exact" {
        errors.push("cargo_policy.mode must be `exact`".into());
    }

    let mut people = BTreeMap::new();
    let mut github = BTreeSet::new();
    for person in &registry.people {
        if !valid_id(&person.id) {
            errors.push(format!("invalid person id `{}`", person.id));
        }
        if person.kind != "human" {
            errors.push(format!("person `{}` must have kind `human`", person.id));
        }
        if !matches!(person.role.as_str(), "owner" | "maintainer" | "reviewer") {
            errors.push(format!("person `{}` has invalid role", person.id));
        }
        validate_text("person display", &person.display, &mut errors);
        if people.insert(person.id.as_str(), person).is_some() {
            errors.push(format!("duplicate person id `{}`", person.id));
        }
        if let Some(handle) = &person.github {
            if !valid_individual_handle(handle) {
                errors.push(format!("person `{}` has invalid GitHub handle", person.id));
            } else if !github.insert(handle.to_ascii_lowercase()) {
                errors.push(format!("duplicate GitHub handle `{handle}`"));
            }
        }
    }

    let Some(owner) = people.get(registry.enforcement.project_owner.as_str()) else {
        errors.push("enforcement.project_owner does not name a registered human".into());
        return finish_errors(errors);
    };
    if owner.role != "owner" {
        errors.push("enforcement.project_owner must have role `owner`".into());
    }
    if registry
        .people
        .iter()
        .filter(|person| person.role == "owner")
        .count()
        != 1
    {
        errors.push("the registry must contain exactly one project Owner".into());
    }
    if registry.enforcement.mode == "active" && owner.github.is_none() {
        errors.push("active enforcement requires the Owner's explicit GitHub handle".into());
    }

    let mut ids = BTreeSet::new();
    let mut primary_claims: Vec<(&str, &PathClaim)> = Vec::new();
    for boundary in &registry.boundaries {
        if !valid_id(&boundary.id) || !ids.insert(&boundary.id) {
            errors.push(format!(
                "invalid or duplicate boundary id `{}`",
                boundary.id
            ));
        }
        validate_text("boundary title", &boundary.title, &mut errors);
        validate_text("boundary summary", &boundary.summary, &mut errors);
        if !matches!(boundary.status.as_str(), "open" | "active") {
            errors.push(format!("boundary `{}` has invalid status", boundary.id));
        }
        if !matches!(boundary.risk.as_str(), "standard" | "elevated" | "critical") {
            errors.push(format!("boundary `{}` has invalid risk", boundary.id));
        }
        if registry.enforcement.mode == "active"
            && boundary.risk == "critical"
            && boundary.status != "active"
        {
            errors.push(format!(
                "active enforcement requires critical boundary `{}` to be active",
                boundary.id
            ));
        }
        if boundary.paths.is_empty() {
            errors.push(format!("boundary `{}` has no paths", boundary.id));
        }
        if boundary.checks.is_empty() {
            errors.push(format!(
                "boundary `{}` has no verification checks",
                boundary.id
            ));
        }
        for contract in &boundary.contracts {
            validate_text("boundary contract", contract, &mut errors);
        }
        for check in &boundary.checks {
            validate_text("boundary check", check, &mut errors);
        }
        validate_assignment(
            &boundary.id,
            &boundary.status,
            boundary.risk == "critical",
            boundary.primary.as_deref(),
            &boundary.reviewers,
            &people,
            registry.enforcement.mode == "active",
            &mut errors,
        );
        for claim in &boundary.paths {
            validate_claim(&boundary.id, claim, &mut errors);
            primary_claims.push((&boundary.id, claim));
        }
    }
    for left in 0..primary_claims.len() {
        for right in (left + 1)..primary_claims.len() {
            let (left_id, left_claim) = primary_claims[left];
            let (right_id, right_claim) = primary_claims[right];
            if claims_overlap(left_claim, right_claim) {
                errors.push(format!(
                    "primary path claims overlap: `{left_id}` {} and `{right_id}` {}",
                    left_claim.path, right_claim.path
                ));
            }
        }
    }

    for overlay in &registry.overlays {
        if !valid_id(&overlay.id) || !ids.insert(&overlay.id) {
            errors.push(format!("invalid or duplicate overlay id `{}`", overlay.id));
        }
        validate_text("overlay title", &overlay.title, &mut errors);
        validate_text("overlay summary", &overlay.summary, &mut errors);
        if !matches!(overlay.status.as_str(), "open" | "active") {
            errors.push(format!("overlay `{}` has invalid status", overlay.id));
        }
        if overlay.paths.is_empty() {
            errors.push(format!("overlay `{}` has no paths", overlay.id));
        }
        if registry.enforcement.mode == "active"
            && overlay.requires_independent_review
            && overlay.status != "active"
        {
            errors.push(format!(
                "active enforcement requires independent overlay `{}` to be active",
                overlay.id
            ));
        }
        if overlay.status == "open" && !overlay.reviewers.is_empty() {
            errors.push(format!(
                "open overlay `{}` cannot name reviewers",
                overlay.id
            ));
        }
        if overlay.status == "active"
            && overlay.requires_independent_review
            && overlay.reviewers.is_empty()
        {
            errors.push(format!("active overlay `{}` needs a reviewer", overlay.id));
        }
        let mut seen_reviewers = BTreeSet::new();
        for reviewer in &overlay.reviewers {
            if !seen_reviewers.insert(reviewer.as_str()) {
                errors.push(format!(
                    "overlay `{}` repeats reviewer `{reviewer}`",
                    overlay.id
                ));
            }
            validate_person_reference(
                reviewer,
                &format!("overlay `{}` reviewer", overlay.id),
                &people,
                registry.enforcement.mode == "active",
                &mut errors,
            );
        }
        for claim in &overlay.paths {
            validate_claim(&overlay.id, claim, &mut errors);
        }
        for left in 0..overlay.paths.len() {
            for right in (left + 1)..overlay.paths.len() {
                if claims_overlap(&overlay.paths[left], &overlay.paths[right]) {
                    errors.push(format!(
                        "overlay `{}` repeats or overlaps path claims `{}` and `{}`",
                        overlay.id, overlay.paths[left].path, overlay.paths[right].path
                    ));
                }
            }
        }
        if overlay.status == "active" && overlay.requires_independent_review {
            for boundary in &registry.boundaries {
                let overlaps = overlay.paths.iter().any(|overlay_claim| {
                    boundary
                        .paths
                        .iter()
                        .any(|boundary_claim| claims_overlap(overlay_claim, boundary_claim))
                });
                let effective_primary = boundary
                    .primary
                    .as_deref()
                    .unwrap_or(&registry.enforcement.project_owner);
                if overlaps
                    && !overlay
                        .reviewers
                        .iter()
                        .any(|reviewer| reviewer != effective_primary)
                {
                    errors.push(format!(
                        "overlay `{}` has no reviewer independent from boundary `{}` effective primary `{effective_primary}`",
                        overlay.id, boundary.id,
                    ));
                }
            }
        }
    }

    for path in [
        registry.generated.ownership.as_str(),
        registry.generated.codeowners.as_str(),
    ] {
        if let Err(error) = validate_repo_path(path) {
            errors.push(format!("invalid generated path `{path}`: {error}"));
        }
    }
    if registry.generated.ownership != "OWNERSHIP.md" {
        errors.push("generated.ownership must be exactly `OWNERSHIP.md`".into());
    }
    if registry.generated.codeowners != ".github/CODEOWNERS" {
        errors.push("generated.codeowners must be exactly `.github/CODEOWNERS`".into());
    }
    for (package, dependencies) in &registry.cargo_policy.packages {
        validate_text("Cargo package", package, &mut errors);
        let mut seen = BTreeMap::new();
        for (kind, names) in [
            ("normal", &dependencies.normal),
            ("dev", &dependencies.dev),
            ("build", &dependencies.build),
        ] {
            for dependency in names {
                if !registry.cargo_policy.packages.contains_key(dependency) {
                    errors.push(format!(
                        "Cargo package `{package}` names unknown internal dependency `{dependency}`"
                    ));
                }
                if dependency == package {
                    errors.push(format!("Cargo package `{package}` cannot depend on itself"));
                }
                if let Some(previous_kind) = seen.insert(dependency.as_str(), kind) {
                    errors.push(format!(
                        "Cargo package `{package}` repeats dependency `{dependency}` in `{previous_kind}` and `{kind}`"
                    ));
                }
            }
        }
    }
    finish_errors(errors)
}

#[allow(clippy::too_many_arguments)]
fn validate_assignment(
    id: &str,
    status: &str,
    critical: bool,
    primary: Option<&str>,
    reviewers: &[String],
    people: &BTreeMap<&str, &crate::model::Person>,
    require_github: bool,
    errors: &mut Vec<String>,
) {
    if status == "open" {
        if primary.is_some() || !reviewers.is_empty() {
            errors.push(format!(
                "open boundary `{id}` cannot name owners or reviewers"
            ));
        }
        return;
    }
    let Some(primary) = primary else {
        errors.push(format!("active boundary `{id}` needs a primary human"));
        return;
    };
    validate_person_reference(
        primary,
        &format!("boundary `{id}` primary"),
        people,
        require_github,
        errors,
    );
    if let Some(person) = people.get(primary)
        && person.role == "reviewer"
    {
        errors.push(format!(
            "boundary `{id}` primary `{primary}` must be an Owner or maintainer"
        ));
    }
    let mut seen = BTreeSet::new();
    for reviewer in reviewers {
        if reviewer == primary {
            errors.push(format!("boundary `{id}` primary cannot review itself"));
        }
        if !seen.insert(reviewer) {
            errors.push(format!("boundary `{id}` repeats reviewer `{reviewer}`"));
        }
        validate_person_reference(
            reviewer,
            &format!("boundary `{id}` reviewer"),
            people,
            require_github,
            errors,
        );
    }
    if critical && reviewers.is_empty() {
        errors.push(format!(
            "critical active boundary `{id}` needs an independent reviewer"
        ));
    }
}

fn validate_person_reference(
    id: &str,
    label: &str,
    people: &BTreeMap<&str, &crate::model::Person>,
    require_github: bool,
    errors: &mut Vec<String>,
) {
    match people.get(id) {
        None => errors.push(format!("{label} names unknown human `{id}`")),
        Some(person) if require_github && person.github.is_none() => {
            errors.push(format!("{label} `{id}` has no explicit GitHub handle"));
        }
        Some(_) => {}
    }
}

fn validate_claim(id: &str, claim: &PathClaim, errors: &mut Vec<String>) {
    if !matches!(claim.kind.as_str(), "file" | "tree") {
        errors.push(format!("`{id}` path `{}` has invalid kind", claim.path));
    }
    if let Err(error) = validate_repo_path(&claim.path) {
        errors.push(format!("`{id}` path `{}` is invalid: {error}", claim.path));
    }
}

fn validate_repo_path(path: &str) -> Result<()> {
    if path.is_empty()
        || path.starts_with('/')
        || path.ends_with('/')
        || path.contains('\\')
        || path.contains(['*', '?', '[', ']', '#', '!'])
        || path
            .chars()
            .any(|character| character.is_control() || character.is_whitespace())
        || path
            .split('/')
            .any(|part| part.is_empty() || matches!(part, "." | ".."))
    {
        bail!("expected a normalized, whitespace- and glob-free repository-relative path");
    }
    Ok(())
}

fn claims_overlap(left: &PathClaim, right: &PathClaim) -> bool {
    left.path == right.path
        || claim_matches(left, &right.path)
        || claim_matches(right, &left.path)
        || (left.kind == "tree"
            && right.kind == "tree"
            && (left.path.starts_with(&format!("{}/", right.path))
                || right.path.starts_with(&format!("{}/", left.path))))
}

fn validate_text(label: &str, text: &str, errors: &mut Vec<String>) {
    if text.trim().is_empty() || text.contains(['\n', '\r', '|']) {
        errors.push(format!(
            "{label} must be non-empty single-line text without `|`"
        ));
    }
}

fn valid_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 64
        && id
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        && !id.starts_with('-')
        && !id.ends_with('-')
        && !id.contains("--")
}

fn finish_errors(errors: Vec<String>) -> Result<()> {
    if errors.is_empty() {
        Ok(())
    } else {
        bail!("boundary registry is invalid:\n- {}", errors.join("\n- "))
    }
}

fn public_files(root: &Path) -> Result<Vec<String>> {
    let output = Command::new("git")
        .args([
            "ls-files",
            "--cached",
            "--others",
            "--exclude-standard",
            "-z",
        ])
        .current_dir(root)
        .output()
        .context("cannot enumerate public repository files")?;
    if !output.status.success() {
        bail!(
            "git ls-files failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    nul_paths(&output.stdout)
}

fn nul_paths(bytes: &[u8]) -> Result<Vec<String>> {
    bytes
        .split(|byte| *byte == 0)
        .filter(|part| !part.is_empty())
        .map(|part| {
            std::str::from_utf8(part)
                .context("repository path is not UTF-8")
                .map(str::to_owned)
        })
        .collect()
}

fn validate_path_coverage(registry: &Registry, files: &[String]) -> Result<()> {
    let mut errors = Vec::new();
    for file in files {
        let matches: Vec<_> = registry
            .boundaries
            .iter()
            .filter(|boundary| {
                boundary
                    .paths
                    .iter()
                    .any(|claim| claim_matches(claim, file))
            })
            .map(|boundary| boundary.id.as_str())
            .collect();
        match matches.as_slice() {
            [] => errors.push(format!("public path `{file}` has no primary boundary")),
            [_] => {}
            _ => errors.push(format!(
                "public path `{file}` has multiple primary boundaries: {}",
                matches.join(", ")
            )),
        }
    }
    for boundary in &registry.boundaries {
        for claim in &boundary.paths {
            if !files.iter().any(|file| claim_matches(claim, file)) {
                errors.push(format!(
                    "boundary `{}` has dead path claim `{}`",
                    boundary.id, claim.path
                ));
            }
        }
    }
    for overlay in &registry.overlays {
        for claim in &overlay.paths {
            if !files.iter().any(|file| claim_matches(claim, file)) {
                errors.push(format!(
                    "overlay `{}` has dead path claim `{}`",
                    overlay.id, claim.path
                ));
            }
        }
    }
    finish_errors(errors)
}

#[derive(Deserialize)]
struct Metadata {
    packages: Vec<MetadataPackage>,
    workspace_members: Vec<String>,
}

#[derive(Deserialize)]
struct MetadataPackage {
    id: String,
    name: String,
    manifest_path: String,
    dependencies: Vec<MetadataDependency>,
}

#[derive(Deserialize)]
struct MetadataDependency {
    name: String,
    kind: Option<String>,
    path: Option<String>,
}

fn validate_cargo_policy(root: &Path, registry: &Registry) -> Result<usize> {
    let output = Command::new("cargo")
        .args([
            "metadata",
            "--format-version",
            "1",
            "--no-deps",
            "--locked",
            "--offline",
        ])
        .current_dir(root)
        .output()
        .context("cannot inspect Cargo dependency graph")?;
    if !output.status.success() {
        bail!(
            "cargo metadata failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    let metadata: Metadata =
        serde_json::from_slice(&output.stdout).context("cargo metadata returned invalid JSON")?;
    let workspace_ids: BTreeSet<_> = metadata.workspace_members.into_iter().collect();
    let workspace_packages: Vec<_> = metadata
        .packages
        .iter()
        .filter(|package| workspace_ids.contains(&package.id))
        .collect();
    let internal_names: BTreeSet<_> = workspace_packages
        .iter()
        .map(|package| package.name.as_str())
        .collect();
    let internal_paths: BTreeMap<_, _> = workspace_packages
        .iter()
        .map(|package| {
            let manifest = Path::new(&package.manifest_path);
            let directory = manifest.parent().unwrap_or(manifest);
            (package.name.as_str(), directory)
        })
        .collect();
    let mut actual = BTreeMap::new();
    for package in &workspace_packages {
        let mut kinds = DependencyKinds::default();
        for dependency in &package.dependencies {
            if !internal_names.contains(dependency.name.as_str()) {
                continue;
            }
            let expected_path = internal_paths
                .get(dependency.name.as_str())
                .context("workspace package path is missing")?;
            let actual_path = dependency.path.as_deref().map(Path::new);
            if actual_path != Some(*expected_path) {
                bail!(
                    "package `{}` dependency `{}` does not resolve to the workspace member path",
                    package.name,
                    dependency.name
                );
            }
            match dependency.kind.as_deref() {
                None | Some("normal") => kinds.normal.push(dependency.name.clone()),
                Some("dev") => kinds.dev.push(dependency.name.clone()),
                Some("build") => kinds.build.push(dependency.name.clone()),
                Some(other) => bail!("unknown Cargo dependency kind `{other}`"),
            }
        }
        normalize_dependencies(&mut kinds);
        actual.insert(package.name.clone(), kinds);
    }

    let mut expected = registry.cargo_policy.packages.clone();
    for dependencies in expected.values_mut() {
        normalize_dependencies(dependencies);
    }
    if actual != expected {
        let actual_json = serde_json::to_string_pretty(&actual).unwrap_or_default();
        let expected_json = serde_json::to_string_pretty(&expected).unwrap_or_default();
        bail!(
            "Cargo dependency contract drifted\nexpected:\n{expected_json}\nactual:\n{actual_json}"
        );
    }
    Ok(workspace_packages.len())
}

fn normalize_dependencies(kinds: &mut DependencyKinds) {
    for dependencies in [&mut kinds.normal, &mut kinds.dev, &mut kinds.build] {
        dependencies.sort();
        dependencies.dedup();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    struct GitFixture {
        root: PathBuf,
    }

    impl GitFixture {
        fn new() -> Self {
            let nonce = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let root = std::env::temp_dir()
                .join(format!("core-boundary-test-{}-{nonce}", std::process::id()));
            std::fs::create_dir_all(root.join("governance")).unwrap();
            let fixture = Self { root };
            fixture.git(&["init", "--initial-branch=main"]);
            fixture.git(&["config", "user.name", "Core Test"]);
            fixture.git(&["config", "user.email", "core-test@example.invalid"]);
            fixture
        }

        fn git(&self, args: &[&str]) -> String {
            let output = Command::new("git")
                .args(["-c", "core.hooksPath=/dev/null"])
                .args(args)
                .current_dir(&self.root)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "git {args:?} failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            String::from_utf8(output.stdout).unwrap().trim().to_string()
        }
    }

    impl Drop for GitFixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    fn claim(kind: &str, path: &str) -> PathClaim {
        PathClaim {
            kind: kind.into(),
            path: path.into(),
        }
    }

    fn add_test_person(registry: &mut Registry, id: &str, handle: &str) {
        registry.people.push(crate::model::Person {
            id: id.into(),
            kind: "human".into(),
            role: "maintainer".into(),
            display: id.into(),
            github: Some(handle.into()),
        });
    }

    #[test]
    fn d1_02_protocol_surface_change_requires_a_monotone_version_bump() {
        let fixture = GitFixture::new();
        let protocol = fixture.root.join("crates/protocol/src");
        std::fs::create_dir_all(&protocol).unwrap();
        std::fs::write(
            protocol.join("wire.rs"),
            "pub const PROTOCOL_VERSION: u32 = 1;\n",
        )
        .unwrap();
        std::fs::write(protocol.join("lib.rs"), "pub enum Op { Interrupt }\n").unwrap();
        fixture.git(&[
            "add",
            "--",
            "crates/protocol/src/wire.rs",
            "crates/protocol/src/lib.rs",
        ]);
        fixture.git(&["commit", "--no-gpg-sign", "-m", "versioned protocol base"]);
        let base = fixture.git(&["rev-parse", "HEAD"]);

        std::fs::write(
            protocol.join("lib.rs"),
            "pub enum Op { Interrupt, Future }\n",
        )
        .unwrap();
        assert!(validate_protocol_version_bump(&fixture.root, &base, true).is_err());

        std::fs::write(
            protocol.join("wire.rs"),
            "pub const PROTOCOL_VERSION: u32 = 2;\n",
        )
        .unwrap();
        assert!(validate_protocol_version_bump(&fixture.root, &base, true).is_ok());
        assert!(validate_protocol_version_bump(&fixture.root, &base, false).is_ok());
    }

    #[test]
    fn d13_14_protocol_version_rejects_a_commented_decoy_with_include() {
        let spoof = br#"/*
pub const PROTOCOL_VERSION: u32 = 9;
*/
include!("protocol-version.rs");
"#;
        let error = protocol_version_from_source(spoof)
            .expect_err("a lexical decoy cannot provide the authoritative protocol version");
        assert!(
            format!("{error:#}").contains("public Rust constant 'PROTOCOL_VERSION' is missing")
        );

        assert_eq!(
            protocol_version_from_source(
                b"/// Wire schema revision.\npub const PROTOCOL_VERSION: u32 = 9;\n"
            )
            .unwrap(),
            9
        );
    }

    #[cfg(unix)]
    #[test]
    fn d13_14_protocol_version_rejects_a_candidate_symlink() {
        use std::os::unix::fs::symlink;

        let fixture = GitFixture::new();
        let protocol = fixture.root.join("crates/protocol/src");
        std::fs::create_dir_all(&protocol).unwrap();
        let wire = protocol.join("wire.rs");
        std::fs::write(&wire, "pub const PROTOCOL_VERSION: u32 = 1;\n").unwrap();
        fixture.git(&["add", "--", PROTOCOL_VERSION_SOURCE]);
        fixture.git(&["commit", "--no-gpg-sign", "-m", "protocol base"]);
        let base = fixture.git(&["rev-parse", "HEAD"]);

        std::fs::remove_file(&wire).unwrap();
        std::fs::write(
            protocol.join("protocol-version.rs"),
            "pub const PROTOCOL_VERSION: u32 = 2;\n",
        )
        .unwrap();
        symlink("protocol-version.rs", &wire).unwrap();

        let error = validate_protocol_version_bump(&fixture.root, &base, true)
            .expect_err("candidate protocol source symlinks must fail closed");
        assert!(format!("{error:#}").contains("contains a symbolic link"));
    }

    #[test]
    fn d13_14_protocol_version_rejects_an_oversized_candidate_source() {
        let fixture = GitFixture::new();
        let protocol = fixture.root.join("crates/protocol/src");
        std::fs::create_dir_all(&protocol).unwrap();
        let wire = protocol.join("wire.rs");
        std::fs::write(&wire, "pub const PROTOCOL_VERSION: u32 = 1;\n").unwrap();
        fixture.git(&["add", "--", PROTOCOL_VERSION_SOURCE]);
        fixture.git(&["commit", "--no-gpg-sign", "-m", "protocol base"]);
        let base = fixture.git(&["rev-parse", "HEAD"]);

        std::fs::write(
            &wire,
            vec![b' '; MAX_PROTOCOL_VERSION_SOURCE_BYTES as usize + 1],
        )
        .unwrap();
        let error = validate_protocol_version_bump(&fixture.root, &base, true)
            .expect_err("oversized candidate protocol source must fail before parsing");
        assert!(format!("{error:#}").contains("not a regular file within its byte limit"));
    }

    #[test]
    fn d13_14_protocol_version_sizes_the_base_blob_before_reading_it() {
        let fixture = GitFixture::new();
        let protocol = fixture.root.join("crates/protocol/src");
        std::fs::create_dir_all(&protocol).unwrap();
        let wire = protocol.join("wire.rs");
        std::fs::write(
            &wire,
            vec![b' '; MAX_PROTOCOL_VERSION_SOURCE_BYTES as usize + 1],
        )
        .unwrap();
        fixture.git(&["add", "--", PROTOCOL_VERSION_SOURCE]);
        fixture.git(&["commit", "--no-gpg-sign", "-m", "oversized protocol base"]);
        let base = fixture.git(&["rev-parse", "HEAD"]);

        std::fs::write(&wire, "pub const PROTOCOL_VERSION: u32 = 2;\n").unwrap();
        let error = validate_protocol_version_bump(&fixture.root, &base, true)
            .expect_err("oversized base blobs must fail at the Git object size boundary");
        assert!(format!("{error:#}").contains("exceeds its byte limit"));
    }

    #[test]
    fn d13_14_immediate_base_check_rejects_merge_queue_protocol_version_skew() {
        let fixture = GitFixture::new();
        let protocol = fixture.root.join("crates/protocol/src");
        std::fs::create_dir_all(&protocol).unwrap();
        std::fs::write(
            protocol.join("wire.rs"),
            "pub const PROTOCOL_VERSION: u32 = 2;\n",
        )
        .unwrap();
        std::fs::write(protocol.join("lib.rs"), "pub enum Op { Interrupt }\n").unwrap();
        std::fs::write(
            fixture.root.join("governance/boundaries.json"),
            include_bytes!("../../governance/boundaries.json"),
        )
        .unwrap();
        fixture.git(&[
            "add",
            "--",
            "crates/protocol/src/wire.rs",
            "crates/protocol/src/lib.rs",
            "governance/boundaries.json",
        ]);
        fixture.git(&["commit", "--no-gpg-sign", "-m", "merge queue base at v2"]);
        let base = fixture.git(&["rev-parse", "HEAD"]);

        std::fs::write(
            protocol.join("lib.rs"),
            "pub enum Op { Interrupt, Future }\n",
        )
        .unwrap();
        fixture.git(&["add", "--", "crates/protocol/src/lib.rs"]);
        fixture.git(&[
            "commit",
            "--no-gpg-sign",
            "-m",
            "stale candidate also at v2",
        ]);

        let registry: Registry =
            serde_json::from_str(include_str!("../../governance/boundaries.json")).unwrap();
        assert!(check_base(&fixture.root, &registry, &base).is_err());

        std::fs::write(
            protocol.join("wire.rs"),
            "pub const PROTOCOL_VERSION: u32 = 3;\n",
        )
        .unwrap();
        assert!(check_base(&fixture.root, &registry, &base).is_ok());
    }

    #[test]
    fn file_and_tree_matching_are_exact() {
        assert!(claim_matches(&claim("file", "Cargo.toml"), "Cargo.toml"));
        assert!(!claim_matches(&claim("file", "Cargo.toml"), "x/Cargo.toml"));
        assert!(claim_matches(
            &claim("tree", "crates/protocol"),
            "crates/protocol/src/lib.rs"
        ));
        assert!(!claim_matches(
            &claim("tree", "crates/protocol"),
            "crates/protocol"
        ));
        assert!(!claim_matches(
            &claim("tree", "crates/protocol"),
            "crates/protocol-old/lib.rs"
        ));
    }

    #[test]
    fn overlapping_claims_are_detected() {
        assert!(claims_overlap(
            &claim("tree", "crates/cli"),
            &claim("file", "crates/cli/src/main.rs")
        ));
        assert!(!claims_overlap(
            &claim("tree", "crates/cli"),
            &claim("tree", "crates/kernel")
        ));
    }

    #[test]
    fn ids_and_handles_are_bounded() {
        assert!(valid_id("provider-core"));
        assert!(!valid_id("Provider_Core"));
        assert!(valid_individual_handle("@maintainer-name"));
        assert!(!valid_individual_handle("maintainer"));
        assert!(!valid_individual_handle("@plantcore-ai/core-runtime"));
    }

    #[test]
    fn repository_paths_reject_ambiguous_forms() {
        assert!(validate_repo_path("crates/kernel/src/lib.rs").is_ok());
        for path in [
            "/tmp/x",
            "../x",
            "a/../b",
            "a b",
            "a\\b",
            "a//b",
            "src/*.rs",
            "docs/[ab].md",
            "#comment",
        ] {
            assert!(validate_repo_path(path).is_err(), "accepted {path:?}");
        }
    }

    #[test]
    fn pull_request_fields_are_unique_and_explicit() {
        let body = "## Responsibility contract\nAffected-Boundaries: cli-tui, cli-render\nInvariant-Overlays: none\n\n## Evidence\n";
        assert_eq!(
            pr_field(body, "Affected-Boundaries").unwrap(),
            "cli-tui, cli-render"
        );
        assert!(pr_field(body, "Missing").is_err());
        assert!(pr_field("## Responsibility contract\nRollback: \n", "Rollback").is_err());
        assert!(
            pr_field(
                "## Responsibility contract\nRollback: <!-- fill -->\n",
                "Rollback"
            )
            .is_err()
        );
        assert!(
            pr_field(
                "## Responsibility contract\nRollback: one\nRollback: two\n",
                "Rollback"
            )
            .is_err()
        );
    }

    #[test]
    fn pull_request_ids_and_human_handle_are_bounded() {
        let allowed = BTreeSet::from(["cli-render", "cli-tui"]);
        assert_eq!(
            parse_id_field("cli-tui, cli-render", "test", &allowed)
                .unwrap()
                .len(),
            2
        );
        assert!(parse_id_field("none", "test", &allowed).unwrap().is_empty());
        assert!(parse_id_field("unknown", "test", &allowed).is_err());
        assert!(valid_individual_handle("@maintainer-name"));
        assert!(!valid_individual_handle("@org/team"));
        assert!(!valid_individual_handle("agent"));
    }

    #[test]
    fn pull_request_contract_matches_computed_impact() {
        let mut registry: Registry =
            serde_json::from_str(include_str!("../../governance/boundaries.json")).unwrap();
        registry.enforcement.mode = "active".into();
        registry.people[0].github = Some("@core-owner".into());
        let impact = Impact {
            boundaries: BTreeMap::from([(
                "community-entry".into(),
                BTreeSet::from(["README.md".into()]),
            )]),
            overlays: BTreeSet::from(["public-truth".into()]),
            responsible: BTreeSet::from(["@core-owner".into()]),
            review_groups: BTreeMap::new(),
        };
        let body = "## Responsibility contract\n\
Affected-Boundaries: community-entry\n\
Invariant-Overlays: public-truth\n\
Tracking-Issue: #1\n\
Responsible-Maintainers: @core-owner\n\
Cross-Boundary-Agreement: not-applicable\n\
Ownership-Claim: not-applicable\n\
Contract-Impact: none\n\
Rollback: revert the commit\n\
\n## Evidence\n";
        assert!(validate_pr_contract(&registry, &impact, body).is_ok());
        assert!(
            validate_pr_contract(
                &registry,
                &impact,
                &body.replace("community-entry", "project-governance")
            )
            .is_err()
        );
    }

    #[test]
    fn review_contract_requires_current_commit_and_latest_decisive_state() {
        let impact = Impact {
            boundaries: BTreeMap::new(),
            overlays: BTreeSet::new(),
            responsible: BTreeSet::from(["@core-owner".into()]),
            review_groups: BTreeMap::from([
                (
                    "primary:community-entry:@core-owner".into(),
                    BTreeSet::from(["@core-owner".into()]),
                ),
                (
                    "overlay:public-truth".into(),
                    BTreeSet::from(["@reviewer-one".into(), "@reviewer-two".into()]),
                ),
            ]),
        };
        let approved = br#"[[{"id":1,"user":{"login":"Reviewer-One"},"state":"APPROVED","commit_id":"abc123"}]]"#;
        assert!(validate_review_contract(&impact, "abc123", "core-owner", approved).is_ok());
        assert!(validate_review_contract(&impact, "new-head", "core-owner", approved).is_err());

        let changed = br#"[
          {"id":1,"user":{"login":"reviewer-one"},"state":"APPROVED","commit_id":"abc123"},
          {"id":2,"user":{"login":"reviewer-one"},"state":"CHANGES_REQUESTED","commit_id":"abc123"}
        ]"#;
        assert!(validate_review_contract(&impact, "abc123", "core-owner", changed).is_err());
    }

    #[test]
    fn registry_changes_require_owner_confirmation_or_owner_authorship() {
        let impact = Impact {
            boundaries: BTreeMap::new(),
            overlays: BTreeSet::new(),
            responsible: BTreeSet::new(),
            review_groups: BTreeMap::from([(
                "owner:registry-base".into(),
                BTreeSet::from(["@core-owner".into()]),
            )]),
        };
        assert!(validate_review_contract(&impact, "abc123", "core-owner", b"[]").is_ok());
        assert!(validate_review_contract(&impact, "abc123", "contributor", b"[]").is_err());

        let approved =
            br#"[{"id":1,"user":{"login":"core-owner"},"state":"APPROVED","commit_id":"abc123"}]"#;
        assert!(validate_review_contract(&impact, "abc123", "contributor", approved).is_ok());

        let mut registry: Registry =
            serde_json::from_str(include_str!("../../governance/boundaries.json")).unwrap();
        registry.people[0].github = Some("@core-owner".into());
        let registry_impact =
            impact_from_name_status(&registry, &registry, b"M\0governance/boundaries.json\0")
                .unwrap();
        assert_eq!(
            registry_impact
                .review_groups
                .get("owner:registry-base")
                .unwrap(),
            &BTreeSet::from(["@core-owner".into()])
        );
        assert_eq!(
            registry_impact
                .review_groups
                .get("owner:registry-candidate")
                .unwrap(),
            &BTreeSet::from(["@core-owner".into()])
        );
    }

    #[test]
    fn overlay_reviews_are_independent_per_boundary() {
        let mut registry: Registry =
            serde_json::from_str(include_str!("../../governance/boundaries.json")).unwrap();
        registry.people[0].github = Some("@owner-a".into());
        add_test_person(&mut registry, "maintainer-b", "@maintainer-b");
        add_test_person(&mut registry, "reviewer-c", "@reviewer-c");
        let community = registry
            .boundaries
            .iter_mut()
            .find(|boundary| boundary.id == "community-entry")
            .unwrap();
        community.primary = Some("core-owner".into());
        let security = registry
            .boundaries
            .iter_mut()
            .find(|boundary| boundary.id == "security-policy")
            .unwrap();
        security.primary = Some("maintainer-b".into());
        let public_truth = registry
            .overlays
            .iter_mut()
            .find(|overlay| overlay.id == "public-truth")
            .unwrap();
        public_truth.reviewers = vec![
            "core-owner".into(),
            "maintainer-b".into(),
            "reviewer-c".into(),
        ];

        let impact =
            impact_from_name_status(&registry, &registry, b"M\0README.md\0M\0SECURITY.md\0")
                .unwrap();
        for phase in ["base", "candidate"] {
            assert_eq!(
                impact
                    .review_groups
                    .get(&format!("overlay:public-truth:{phase}:community-entry"))
                    .unwrap(),
                &BTreeSet::from(["@maintainer-b".into(), "@reviewer-c".into()])
            );
            assert_eq!(
                impact
                    .review_groups
                    .get(&format!("overlay:public-truth:{phase}:security-policy"))
                    .unwrap(),
                &BTreeSet::from(["@owner-a".into(), "@reviewer-c".into()])
            );
        }

        let only_b = br#"[{"id":1,"user":{"login":"maintainer-b"},"state":"APPROVED","commit_id":"abc123"}]"#;
        assert!(validate_review_contract(&impact, "abc123", "owner-a", only_b).is_err());
        let b_and_c = br#"[
          {"id":1,"user":{"login":"maintainer-b"},"state":"APPROVED","commit_id":"abc123"},
          {"id":2,"user":{"login":"reviewer-c"},"state":"APPROVED","commit_id":"abc123"}
        ]"#;
        assert!(validate_review_contract(&impact, "abc123", "owner-a", b_and_c).is_ok());
    }

    #[test]
    fn base_and_candidate_reviewer_sets_are_both_required() {
        let mut base: Registry =
            serde_json::from_str(include_str!("../../governance/boundaries.json")).unwrap();
        let mut head: Registry =
            serde_json::from_str(include_str!("../../governance/boundaries.json")).unwrap();
        for registry in [&mut base, &mut head] {
            registry.people[0].github = Some("@owner-a".into());
            add_test_person(registry, "reviewer-b", "@reviewer-b");
            add_test_person(registry, "reviewer-c", "@reviewer-c");
            registry
                .boundaries
                .iter_mut()
                .find(|boundary| boundary.id == "community-entry")
                .unwrap()
                .primary = Some("core-owner".into());
        }
        base.overlays
            .iter_mut()
            .find(|overlay| overlay.id == "public-truth")
            .unwrap()
            .reviewers = vec!["reviewer-b".into()];
        head.overlays
            .iter_mut()
            .find(|overlay| overlay.id == "public-truth")
            .unwrap()
            .reviewers = vec!["reviewer-c".into()];

        let impact = impact_from_name_status(&head, &base, b"M\0README.md\0").unwrap();
        let only_b =
            br#"[{"id":1,"user":{"login":"reviewer-b"},"state":"APPROVED","commit_id":"abc123"}]"#;
        assert!(validate_review_contract(&impact, "abc123", "owner-a", only_b).is_err());
        let b_and_c = br#"[
          {"id":1,"user":{"login":"reviewer-b"},"state":"APPROVED","commit_id":"abc123"},
          {"id":2,"user":{"login":"reviewer-c"},"state":"APPROVED","commit_id":"abc123"}
        ]"#;
        assert!(validate_review_contract(&impact, "abc123", "owner-a", b_and_c).is_ok());
    }

    #[test]
    fn pull_requests_cannot_downgrade_active_enforcement() {
        let mut base: Registry =
            serde_json::from_str(include_str!("../../governance/boundaries.json")).unwrap();
        let mut head: Registry =
            serde_json::from_str(include_str!("../../governance/boundaries.json")).unwrap();
        base.enforcement.mode = "active".into();
        assert!(validate_enforcement_transition(&head, &base).is_err());

        head.enforcement.mode = "active".into();
        assert!(validate_enforcement_transition(&head, &base).is_ok());
        base.enforcement.mode = "bootstrap".into();
        assert!(validate_enforcement_transition(&head, &base).is_ok());
    }

    #[test]
    fn rename_impact_unions_old_and_new_registry_ownership() {
        let registry: Registry =
            serde_json::from_str(include_str!("../../governance/boundaries.json")).unwrap();
        let impact = impact_from_name_status(
            &registry,
            &registry,
            b"R100\0README.md\0docs/getting-started/renamed.md\0",
        )
        .unwrap();
        assert_eq!(
            impact.boundaries.keys().cloned().collect::<Vec<_>>(),
            vec!["community-entry", "documentation-site"]
        );
        assert!(impact.overlays.contains("public-truth"));
    }

    #[test]
    fn real_git_history_uses_base_for_rename_source_and_head_for_destination() {
        let fixture = GitFixture::new();
        std::fs::write(fixture.root.join("README.md"), "base\n").unwrap();
        std::fs::write(
            fixture.root.join("governance/boundaries.json"),
            include_bytes!("../../governance/boundaries.json"),
        )
        .unwrap();
        fixture.git(&["add", "--", "README.md", "governance/boundaries.json"]);
        fixture.git(&["commit", "--no-gpg-sign", "-m", "base"]);
        let base = fixture.git(&["rev-parse", "HEAD"]);
        std::fs::create_dir_all(fixture.root.join("docs/getting-started")).unwrap();
        fixture.git(&["mv", "README.md", "docs/getting-started/renamed.md"]);
        fixture.git(&["commit", "--no-gpg-sign", "-m", "rename"]);

        let registry: Registry =
            serde_json::from_str(include_str!("../../governance/boundaries.json")).unwrap();
        let impact = calculate_impact(&fixture.root, &registry, &base).unwrap();
        assert_eq!(
            impact.boundaries.keys().cloned().collect::<Vec<_>>(),
            vec!["community-entry", "documentation-site"]
        );
    }

    #[test]
    fn responsibility_review_requires_head_to_contain_current_base() {
        let fixture = GitFixture::new();
        std::fs::write(fixture.root.join("README.md"), "base\n").unwrap();
        std::fs::write(
            fixture.root.join("governance/boundaries.json"),
            include_bytes!("../../governance/boundaries.json"),
        )
        .unwrap();
        fixture.git(&["add", "--", "README.md", "governance/boundaries.json"]);
        fixture.git(&["commit", "--no-gpg-sign", "-m", "common base"]);
        fixture.git(&["checkout", "-b", "candidate"]);
        std::fs::write(fixture.root.join("README.md"), "candidate\n").unwrap();
        fixture.git(&["add", "--", "README.md"]);
        fixture.git(&["commit", "--no-gpg-sign", "-m", "candidate"]);
        fixture.git(&["checkout", "main"]);
        std::fs::write(fixture.root.join("SECURITY.md"), "base advanced\n").unwrap();
        fixture.git(&["add", "--", "SECURITY.md"]);
        fixture.git(&["commit", "--no-gpg-sign", "-m", "advance base"]);
        let current_base = fixture.git(&["rev-parse", "HEAD"]);
        fixture.git(&["checkout", "candidate"]);

        let registry: Registry =
            serde_json::from_str(include_str!("../../governance/boundaries.json")).unwrap();
        assert!(calculate_impact(&fixture.root, &registry, &current_base).is_err());
    }

    #[test]
    fn bootstrap_pull_requests_are_inspected_without_false_enforcement() {
        let fixture = GitFixture::new();
        std::fs::write(fixture.root.join("README.md"), "base\n").unwrap();
        std::fs::write(
            fixture.root.join("governance/boundaries.json"),
            include_bytes!("../../governance/boundaries.json"),
        )
        .unwrap();
        fixture.git(&["add", "--", "README.md", "governance/boundaries.json"]);
        fixture.git(&["commit", "--no-gpg-sign", "-m", "base"]);
        let base = fixture.git(&["rev-parse", "HEAD"]);
        std::fs::write(fixture.root.join("README.md"), "candidate\n").unwrap();
        fixture.git(&["add", "--", "README.md"]);
        fixture.git(&["commit", "--no-gpg-sign", "-m", "candidate"]);

        let registry: Registry =
            serde_json::from_str(include_str!("../../governance/boundaries.json")).unwrap();
        assert!(check_pr(&fixture.root, &registry, &base, "").is_ok());
        assert!(check_reviews(&fixture.root, &registry, &base, "contributor", b"[]").is_ok());
    }

    #[test]
    fn active_enforcement_requires_critical_owners_and_independent_overlays() {
        let mut registry: Registry =
            serde_json::from_str(include_str!("../../governance/boundaries.json")).unwrap();
        registry.enforcement.mode = "active".into();
        registry.people[0].github = Some("@core-owner".into());
        assert!(validate_registry(&registry).is_err());
        assert!(readiness(&registry).is_err());

        registry.people.push(crate::model::Person {
            id: "independent-reviewer".into(),
            kind: "human".into(),
            role: "reviewer".into(),
            display: "Independent Reviewer".into(),
            github: Some("@independent-reviewer".into()),
        });
        for boundary in &mut registry.boundaries {
            if boundary.risk == "critical" {
                boundary.status = "active".into();
                boundary.primary = Some("core-owner".into());
                boundary.reviewers = vec!["independent-reviewer".into()];
            }
        }
        for overlay in &mut registry.overlays {
            if overlay.requires_independent_review {
                overlay.status = "active".into();
                overlay.reviewers = vec!["independent-reviewer".into()];
            }
        }
        assert!(validate_registry(&registry).is_ok());
        assert!(readiness(&registry).is_ok());
    }

    #[test]
    fn generated_paths_and_casefolded_human_ids_cannot_be_redirected() {
        let mut registry: Registry =
            serde_json::from_str(include_str!("../../governance/boundaries.json")).unwrap();
        registry.generated.codeowners = "docs/not-codeowners.md".into();
        assert!(validate_registry(&registry).is_err());

        registry.generated.codeowners = ".github/CODEOWNERS".into();
        registry.people[0].github = Some("@core-owner".into());
        registry.people.push(crate::model::Person {
            id: "duplicate-owner-login".into(),
            kind: "human".into(),
            role: "reviewer".into(),
            display: "Duplicate Login".into(),
            github: Some("@CORE-OWNER".into()),
        });
        assert!(validate_registry(&registry).is_err());
    }
}
