//! Caller-visible preimages authorize a deliberate whole-file replacement. The native writer
//! compares against its retained byte snapshot, then keeps its original identity/commit guard.
use super::{ExistingTarget, TargetSnapshot};

#[derive(Clone, Copy)]
pub(crate) enum WritePreimage {
    CreateOnly,
    ExistingSha256([u8; 32]),
    // Native transaction race tests exercise their already captured snapshot directly. This
    // variant does not exist in a production helper or model tool dispatcher.
    #[cfg(test)]
    CurrentSnapshot,
}

impl WritePreimage {
    pub(crate) fn from_input(input: &serde_json::Value) -> Result<Self, String> {
        let Some(value) = input.get("expected_sha256") else {
            return Ok(Self::CreateOnly);
        };
        let Some(text) = value.as_str().filter(|text| {
            text.len() == 64
                && text
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        }) else {
            return Err(
                "write_file: expected_sha256 must be a 64-character lowercase SHA-256".into(),
            );
        };
        let mut digest = [0_u8; 32];
        for (index, pair) in text.as_bytes().chunks_exact(2).enumerate() {
            let nibble = |byte: u8| {
                if byte <= b'9' {
                    byte - b'0'
                } else {
                    byte - b'a' + 10
                }
            };
            digest[index] = nibble(pair[0]) * 16 + nibble(pair[1]);
        }
        Ok(Self::ExistingSha256(digest))
    }

    pub(super) fn validate(self, actual: &TargetSnapshot, path: &str) -> Result<(), String> {
        let kind = match (self, actual) {
            (Self::CreateOnly, TargetSnapshot::Missing) => return Ok(()),
            (
                Self::ExistingSha256(expected),
                TargetSnapshot::Existing(ExistingTarget { digest, .. }),
            ) if expected == *digest => return Ok(()),
            #[cfg(test)]
            (Self::CurrentSnapshot, _) => return Ok(()),
            (Self::CreateOnly, TargetSnapshot::Existing(_)) => "preimage_required",
            (Self::ExistingSha256(_), _) => "preimage_changed",
        };
        Err(serde_json::json!({
            "error": "write_file_failed",
            "kind": kind,
            "phase": "planning",
            "path": path,
            "message": "Existing files require a deliberate replacement preimage. Read the current file with include_sha256=true, preserve its user changes, then pass expected_sha256; use edit/apply_patch for a targeted change. No file was replaced."
        }).to_string())
    }
}
