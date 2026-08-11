//! Iteron's frozen microkernel.
//!
//! This crate is the trusted control plane: pure reduction, bounded driving, versioned injected
//! ports, the universal effect broker, canonical diagnostics, and no concrete world strategy.
//! Provider clients, context selection, prompt construction, tool registries, schedulers,
//! verification executors, sandboxes, workflow engines, process spawning, and UI rendering are
//! composed by `iteron-cli`; none is a kernel dependency.

pub mod admission;
pub mod diagnostics;
pub mod driver;
pub mod effect_admission;
pub mod effect_class;
pub mod effect_journal;
pub mod effects;
pub mod ports;
pub mod reducer;
pub mod turn_action;
pub mod turn_command;
pub mod turn_protocol;
pub mod turn_state;

#[cfg(test)]
#[path = "driver_tests.rs"]
mod driver_tests;

#[cfg(test)]
#[path = "effect_boundary_tests.rs"]
mod effect_boundary_tests;

#[cfg(test)]
#[path = "reducer_tests.rs"]
mod reducer_tests;
