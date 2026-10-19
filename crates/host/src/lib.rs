//! Shared session assembly, runtime ownership and authenticated AppServer transports.
//!
//! This crate has no terminal renderer or terminal event-loop dependency. Frontends share the
//! same Agent and AppServer; only their input/output adapters differ.

pub mod app_server;
pub mod artifacts;
pub mod bundle_adapter;
pub mod cli_entry;
pub mod client_effects;
pub mod client_event;
pub mod client_inventory;
pub mod config;
pub mod effective_config;
pub mod environment;
pub mod external_editor;
pub mod file_input;
pub mod image_input;
pub mod keymap;
pub mod keyword_trigger;
pub mod launch;
pub mod machine_contract;
pub mod machine_projection;
pub mod maintenance;
pub mod mcp;
pub mod model_route;
pub mod output;
pub mod plugin;
pub mod plugin_runtime;
pub mod pricing;
pub mod prompt_history;
pub mod providers;
pub mod queue_policy;
#[cfg(feature = "legacy-plantcore")]
pub mod recording_provider;
#[cfg(not(feature = "legacy-plantcore"))]
#[path = "recording_provider_disabled.rs"]
pub mod recording_provider;
pub mod resident_service;
pub mod route;
pub mod runtime;
pub mod runtime_tunables;
pub mod semantic_text;
pub mod server;
pub mod session_isolation;
pub mod session_transcript;
pub mod session_view;
pub mod setup;
pub mod startup;
pub mod transport;
pub mod tunables;
pub mod workflow;
pub mod workspace_review;
