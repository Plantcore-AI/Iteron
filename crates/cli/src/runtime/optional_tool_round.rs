//! Explicit optional workflow adapter for one completed tool round. Ordinary coding has no
//! tracker, candidate path scan, localization set, repair receipt or completion gate here.
//! This owner holds only proposal classifications; it cannot admit or execute a tool.

use super::investigation_convergence::{
    CandidateDiffState, ConvergenceRequest, InvestigationConvergence,
};
use super::tool_turn::ToolTurnOwner;
use iteron_protocol::{ToolResult, ToolUse};
use iteron_tools::Registry;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

static EMPTY_INDICES: BTreeSet<usize> = BTreeSet::new();

#[derive(Default)]
pub(super) struct OptionalToolRound {
    tracked: Option<TrackedRound>,
}

#[derive(Default)]
struct TrackedRound {
    changes: BTreeSet<usize>,
    paths: BTreeSet<PathBuf>,
    unauthorized: BTreeSet<usize>,
    owner_evidence_blocked: BTreeSet<usize>,
    repair_evidence: BTreeSet<usize>,
    targeted: BTreeSet<usize>,
    localization: BTreeSet<usize>,
    // Actual immutable native arguments for an admitted SDK projection, never a name guess.
    projected: BTreeMap<usize, ToolUse>,
}

pub(super) struct OptionalRoundSettlement {
    pub(super) completed_change: bool,
    pub(super) request: Option<ConvergenceRequest>,
}

impl OptionalToolRound {
    pub(super) fn prepare(
        policy: &InvestigationConvergence,
        explicit_verification: bool,
        registry: &Registry,
        workspace: &Path,
        tools: &ToolTurnOwner,
        returned: &[ToolUse],
    ) -> Self {
        if !policy.enabled() && !explicit_verification {
            return Self::default();
        }
        let mut tracked = TrackedRound::default();
        if policy.enabled() {
            for (index, tool) in returned.iter().enumerate() {
                if let Ok(Some(physical)) = registry.ordinary_call_projection(tool) {
                    tracked.projected.insert(index, physical);
                }
                if registry.is_repair_evidence_submission(tool, workspace) {
                    tracked.repair_evidence.insert(index);
                }
                if registry.is_workspace_targeted_observation(tool, workspace) {
                    tracked.targeted.insert(index);
                }
                if registry.is_workspace_localization_observation(tool, workspace) {
                    tracked.localization.insert(index);
                }
            }
        }
        let owner_evidence_required = policy.candidate_owner_evidence_required();
        let mutation_authorized = policy.candidate_change_allowed()
            && !owner_evidence_required
            && tracked.repair_evidence.is_empty();
        let path_restricted = !policy.authorized_repair_paths().is_empty();
        let authorized_paths = policy
            .authorized_repair_paths()
            .iter()
            .filter_map(|path| workspace.join(path).canonicalize().ok())
            .collect::<BTreeSet<_>>();
        for (index, tool, _) in tools.deferred() {
            if !registry.is_candidate_change_tool(&tool.name) {
                continue;
            }
            let candidate_paths = registry.workspace_candidate_paths(tool, workspace);
            if !policy.enabled() {
                // The existing explicit --verify observes changes without imposing ticket rules.
                tracked.changes.insert(*index);
                if let Some(paths) = candidate_paths {
                    tracked.paths.extend(paths);
                }
                continue;
            }
            let Some(paths) = candidate_paths else {
                tracked.unauthorized.insert(*index);
                continue;
            };
            if paths.is_empty()
                || !mutation_authorized
                || path_restricted && !paths.iter().all(|path| authorized_paths.contains(path))
            {
                tracked.unauthorized.insert(*index);
                if owner_evidence_required {
                    tracked.owner_evidence_blocked.insert(*index);
                }
            } else {
                tracked.changes.insert(*index);
                tracked.paths.extend(paths);
            }
        }
        Self {
            tracked: Some(tracked),
        }
    }

    pub(super) fn tracked(&self) -> bool {
        self.tracked.is_some()
    }
    pub(super) fn paths(&self) -> impl Iterator<Item = &Path> {
        self.tracked
            .iter()
            .flat_map(|round| round.paths.iter().map(PathBuf::as_path))
    }
    pub(super) fn excluded(&self) -> &BTreeSet<usize> {
        self.tracked
            .as_ref()
            .map_or(&EMPTY_INDICES, |round| &round.unauthorized)
    }
    pub(super) fn refusal(&self, index: usize) -> Option<&'static str> {
        let round = self.tracked.as_ref()?;
        if !round.unauthorized.contains(&index) {
            return None;
        }
        Some(if round.owner_evidence_blocked.contains(&index) {
            "refused: candidate revision requires one bounded stable-key owner search before another mutation"
        } else {
            "refused: candidate mutation is outside the exact path authorized by the typed RepairIntent receipt"
        })
    }
    pub(super) fn requires_diff(&self, review_active: bool, total_tools: usize) -> bool {
        self.tracked
            .as_ref()
            .is_some_and(|round| !round.changes.is_empty() || review_active && total_tools > 0)
    }

    pub(super) fn settle(
        self,
        policy: &mut InvestigationConvergence,
        returned: &[ToolUse],
        results: &[Option<ToolResult>],
        any_error: bool,
        diff: Option<CandidateDiffState>,
    ) -> OptionalRoundSettlement {
        let Some(round) = self.tracked else {
            return OptionalRoundSettlement {
                completed_change: false,
                request: None,
            };
        };
        let successful = |index: &usize| {
            results
                .get(*index)
                .and_then(Option::as_ref)
                .is_some_and(|result| !result.is_error)
        };
        let attempted_change = !round.changes.is_empty();
        let completed_change = round.changes.iter().any(successful);
        if !policy.enabled() {
            return OptionalRoundSettlement {
                completed_change,
                request: None,
            };
        }
        let mutation_failure = round
            .changes
            .iter()
            .filter_map(|index| {
                let result = results.get(*index)?.as_ref()?;
                if !result.is_error {
                    return None;
                }
                let tool = returned.get(*index)?;
                Some(InvestigationConvergence::mutation_failure_signature(
                    &tool.name,
                    &result.content,
                ))
            })
            .next_back();
        let targeted = round.targeted.iter().any(successful);
        let scopes = round
            .localization
            .iter()
            .filter(|index| successful(index))
            .filter_map(|index| round.projected.get(index).or_else(|| returned.get(*index)))
            .filter_map(|tool| {
                InvestigationConvergence::localization_scope(&tool.name, &tool.input)
            })
            .collect::<Vec<_>>();
        let repair_evidence = round
            .repair_evidence
            .iter()
            .filter_map(|index| results.get(*index).and_then(Option::as_ref))
            .filter_map(iteron_tools::tool_result_repair_evidence)
            .next_back();
        let exact_read = scopes.iter().any(|scope| scope.starts_with("read_file:"));
        let stable_key_search = round
            .localization
            .iter()
            .filter_map(|index| {
                let tool = round
                    .projected
                    .get(index)
                    .or_else(|| returned.get(*index))?;
                let result = results.get(*index)?.as_ref()?;
                (!result.is_error).then_some((tool, result))
            })
            .any(|(tool, result)| {
                tool.name == "grep"
                    && tool
                        .input
                        .get("pattern")
                        .and_then(serde_json::Value::as_str)
                        .is_some_and(|pattern| {
                            InvestigationConvergence::stable_key_search_supports_owner(
                                pattern,
                                iteron_tools::tool_result_workspace_evidence(result),
                            )
                        })
            });
        let localization_request = if repair_evidence.is_none() {
            policy.observe_localization_scopes_for_round(scopes, !any_error && !attempted_change)
        } else {
            None
        };
        let candidate_request = diff.and_then(|diff| {
            policy.observe_candidate_round(
                diff,
                attempted_change,
                mutation_failure,
                exact_read,
                stable_key_search,
            )
        });
        let request = candidate_request
            .or_else(|| policy.observe_round(None, targeted, repair_evidence, !returned.is_empty()))
            .or(localization_request);
        OptionalRoundSettlement {
            completed_change,
            request,
        }
    }
}
