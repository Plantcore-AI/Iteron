//! Host-only direct child identity. A model cannot replace its namespace, attribution or deadline.
use iteron_kernel::diagnostics::DiagnosticEmitter;
use iteron_protocol::{Effort, RunId};
use std::{path::PathBuf, time::Instant};

pub(super) struct DirectChildIdentity {
    pub(super) run: RunId,
    pub(super) directory: PathBuf,
    pub(super) depth: usize,
    pub(super) effort: Effort,
    pub(super) deadline: Instant,
    pub(super) diagnostics: DiagnosticEmitter,
}
