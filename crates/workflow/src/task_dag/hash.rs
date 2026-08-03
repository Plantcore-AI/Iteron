use serde::Serialize;
use sha2::{Digest as _, Sha256};

use super::DagError;
use super::reducer::LogEntry;
use super::types::{Command, CommandId, Config};

const LOG_VERSION: u32 = 1;

pub(crate) fn config_digest(config: &Config) -> Result<String, DagError> {
    #[derive(Serialize)]
    struct Genesis<'a> {
        version: u32,
        config: &'a Config,
    }
    digest_json(&Genesis {
        version: LOG_VERSION,
        config,
    })
}

pub(super) fn entry_digest(entry: &LogEntry) -> Result<String, DagError> {
    #[derive(Serialize)]
    struct Material<'a> {
        version: u32,
        graph_id: &'a str,
        sequence: u64,
        previous_digest: &'a str,
        command_id: CommandId,
        command_digest: &'a str,
        command: &'a Command,
    }
    digest_json(&Material {
        version: entry.version,
        graph_id: &entry.graph_id,
        sequence: entry.sequence,
        previous_digest: &entry.previous_digest,
        command_id: entry.command_id,
        command_digest: &entry.command_digest,
        command: &entry.command,
    })
}

pub(super) fn digest_json(value: &impl Serialize) -> Result<String, DagError> {
    let bytes = serde_json::to_vec(value)?;
    Ok(hex::encode(Sha256::digest(bytes)))
}
