//! Terminal command and presentation adapters around the shared host assembly.
pub(crate) use iteron_host::cli_entry::*;
pub(crate) mod frontend;
pub(crate) mod local_commands;
mod workflow_command;
pub(crate) use workflow_command::run_workflow_command;
