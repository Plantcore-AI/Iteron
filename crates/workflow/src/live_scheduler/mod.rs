//! Versioned live planning, separate from persistent agent identity and execution.
//!
//! The scheduler is the only writer of its dependency graph. A controller port owns agent
//! lifecycle, contexts, permissions and processes; a journal port owns durable publication. A
//! revision updates future work, never silently restarts completed work or an unknown effect.

pub mod file_journal;
mod owner;
pub mod ports;
pub mod types;
mod validation;

pub use owner::WorkflowScheduler;
pub use ports::{WorkflowControllerPort, WorkflowPlanJournal};
pub use types::*;
