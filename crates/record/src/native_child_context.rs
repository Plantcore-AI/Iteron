//! Select one bounded native-context record through the canonical physical hash chain.
//! Filesystem capability and caller/native deadlines are owned by the host's retained reader.
use super::{ChainLine, RecordError, ZERO_HASH, hash_line, validate_event_bounds};
use iteron_protocol::native_child_context::{NativeChildContextRefV1, NativeChildContextV1};
use iteron_protocol::{Event, EventKind, Seq};
const MAX_BYTES: usize = 8 * 1024 * 1024;
const MAX_LINE: usize = 1024 * 1024;
pub fn read_reference(
    bytes: &[u8],
    reference: &NativeChildContextRefV1,
) -> Result<NativeChildContextV1, RecordError> {
    super::require_strict_replay_policy()?;
    reference.validate().map_err(|reason| {
        RecordError::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, reason))
    })?;
    if bytes.len() > MAX_BYTES {
        return invalid("native context archive exceeds bound");
    }
    let mut previous = ZERO_HASH.to_owned();
    let mut expected = 0u64;
    for line in bytes.split_inclusive(|byte| *byte == b'\n') {
        if line.last() != Some(&b'\n') {
            break;
        } // no torn-tail evidence
        if line.len() > MAX_LINE {
            return invalid("native context archive line exceeds bound");
        }
        let row: ChainLine = serde_json::from_slice(line)?;
        if row.seq != expected
            || row.tenant != reference.tenant
            || row.prev != previous
            || row.hash != hash_line(&previous, row.seq, &row.payload)
        {
            return invalid("native context physical chain differs");
        }
        previous = row.hash;
        expected = expected.checked_add(1).ok_or_else(|| {
            RecordError::Io(std::io::Error::other("native context sequence overflow"))
        })?;
        if row.seq == reference.sequence {
            // This event is intentionally inline config evidence; it never has content-store
            // reconstruction indirection or client-provided raw payload fields.
            let mut event: Event = serde_json::from_value(row.payload)?;
            event.seq = Seq(row.seq);
            validate_event_bounds(&event)?;
            if let EventKind::NativeChildContextCapturedV1 { context } = event.kind
                && context.generation_sha256 == reference.generation_sha256
                && context.tenant == reference.tenant
                && context.run == reference.run
                && context.publication_sequence == row.seq
            {
                context.validate().map_err(|reason| {
                    RecordError::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, reason))
                })?;
                return Ok(context);
            }
            return invalid("native context reference does not name its exact publication");
        }
    }
    invalid("native context publication is unavailable")
}
fn invalid<T>(reason: &'static str) -> Result<T, RecordError> {
    Err(RecordError::Io(std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        reason,
    )))
}

#[cfg(test)]
#[path = "native_child_context/tests.rs"]
mod tests;
