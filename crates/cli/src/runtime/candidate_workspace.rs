//! Filesystem identities for verification of actual candidate changes.
//! This owner is independent of optional ticket strategy.

use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

const MAX_BASELINE_PATHS: usize = 1_024;

/// Pre-change identities for exactly the paths named by structured candidate tools. Capturing is
/// lazy (the first candidate write pays for it), bounded by the same transaction ceiling as the
/// tools, and preserves identities across later revisions. Any unavailable identity fails open to
/// continued review: without an exact pre-image the controller must not claim a revert.
#[derive(Debug, Default)]
pub(super) struct CandidateWorkspaceBaseline {
    paths: BTreeMap<PathBuf, iteron_tools::WorkspaceCandidatePathIdentity>,
    incomplete: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum CandidateDiffState {
    Unavailable,
    Empty,
    Changed([u8; 32]),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum VerificationCandidateGuard {
    Verify,
    #[cfg(any(feature = "ticket-investigation", test))]
    RequireTransition(&'static str),
    #[cfg(any(feature = "ticket-investigation", test))]
    Stop(&'static str),
}

impl CandidateWorkspaceBaseline {
    pub(super) async fn capture_before<'a>(&mut self, paths: impl IntoIterator<Item = &'a Path>) {
        for (index, path) in paths.into_iter().enumerate() {
            if index >= MAX_BASELINE_PATHS {
                self.incomplete = true;
                break;
            }
            if self.paths.contains_key(path) {
                continue;
            }
            if self.paths.len() >= MAX_BASELINE_PATHS {
                self.incomplete = true;
                break;
            }
            match iteron_tools::workspace_candidate_path_identity(path).await {
                Ok(identity) => {
                    self.paths.insert(path.to_owned(), identity);
                }
                Err(_) => self.incomplete = true,
            }
        }
    }

    pub(super) async fn diff_state(&self) -> CandidateDiffState {
        if self.incomplete || self.paths.is_empty() {
            return CandidateDiffState::Unavailable;
        }
        let mut changed = false;
        let mut digest = Sha256::new();
        for (path, baseline) in &self.paths {
            match iteron_tools::workspace_candidate_path_identity(path).await {
                Ok(current) if current == *baseline => {}
                Ok(current) => {
                    changed = true;
                    digest.update(path.as_os_str().as_encoded_bytes());
                    digest.update([0]);
                    for identity in [*baseline, current] {
                        match identity {
                            iteron_tools::WorkspaceCandidatePathIdentity::Missing => {
                                digest.update([0])
                            }
                            iteron_tools::WorkspaceCandidatePathIdentity::File(bytes) => {
                                digest.update([1]);
                                digest.update(bytes);
                            }
                        }
                    }
                }
                Err(_) => return CandidateDiffState::Unavailable,
            }
        }
        if changed {
            CandidateDiffState::Changed(digest.finalize().into())
        } else {
            CandidateDiffState::Empty
        }
    }
}
