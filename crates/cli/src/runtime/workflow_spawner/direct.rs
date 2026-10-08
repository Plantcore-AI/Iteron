//! Host-only direct child identity. A model cannot replace its namespace, attribution or deadline.
use iteron_kernel::diagnostics::DiagnosticEmitter;
use iteron_protocol::{Effort, RunId};
use std::{path::PathBuf, time::Instant};

pub(in crate::runtime) struct DirectChildIdentity {
    pub(in crate::runtime) run: RunId,
    pub(in crate::runtime) directory: PathBuf,
    pub(in crate::runtime) depth: u8,
    pub(in crate::runtime) effort: Effort,
    pub(in crate::runtime) deadline: Instant,
    pub(in crate::runtime) diagnostics: DiagnosticEmitter,
}
