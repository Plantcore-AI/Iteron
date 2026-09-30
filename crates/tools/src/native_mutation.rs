//! Sealed evidence of native guarded commits. Model/external JSON cannot mint these receipts.

#[cfg(any(target_os = "linux", test))]
use base64::Engine;
#[cfg(any(target_os = "linux", test))]
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

pub const MAX_NATIVE_CAPTURE_FILE_BYTES: usize = 8 * 1024 * 1024;
const MAX_FILES: usize = 64;
const MAX_TOTAL_BYTES: usize = 32 * 1024 * 1024;

#[derive(Clone)]
pub struct NativeFileChange {
    path: PathBuf,
    before: Option<Vec<u8>>,
    after: Vec<u8>,
}
impl NativeFileChange {
    pub fn path(&self) -> &Path {
        &self.path
    }
    pub fn before(&self) -> Option<&[u8]> {
        self.before.as_deref()
    }
    pub fn after(&self) -> &[u8] {
        &self.after
    }
    /// Called only after the actual executor's guarded commit has returned success.
    pub(crate) fn committed(path: PathBuf, before: Option<Vec<u8>>, after: Vec<u8>) -> Self {
        Self {
            path,
            before,
            after,
        }
    }
}
impl std::fmt::Debug for NativeFileChange {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NativeFileChange")
            .field("before_bytes", &self.before.as_ref().map(Vec::len))
            .field("after_bytes", &self.after.len())
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Debug)]
pub struct NativeMutationReceipt {
    tool_use_id: String,
    tool_name: String,
    files: Vec<NativeFileChange>,
}
impl NativeMutationReceipt {
    pub fn tool_use_id(&self) -> &str {
        &self.tool_use_id
    }
    pub fn tool_name(&self) -> &str {
        &self.tool_name
    }
    pub fn files(&self) -> &[NativeFileChange] {
        &self.files
    }
    pub(crate) fn committed(
        id: String,
        name: String,
        files: Vec<NativeFileChange>,
    ) -> Result<Self, &'static str> {
        if id.is_empty()
            || id.len() > 512
            || !matches!(name.as_str(), "write_file" | "edit" | "apply_patch")
            || files.is_empty()
            || files.len() > MAX_FILES
        {
            return Err("native mutation capture unavailable");
        }
        let mut total = 0usize;
        for file in &files {
            if !file.path.is_absolute()
                || file.path.as_os_str().as_encoded_bytes().len() > 16384
                || file.after.len() > MAX_NATIVE_CAPTURE_FILE_BYTES
                || file
                    .before
                    .as_ref()
                    .is_some_and(|b| b.len() > MAX_NATIVE_CAPTURE_FILE_BYTES)
            {
                return Err("native mutation capture exceeds its file envelope");
            }
            total = total
                .checked_add(file.after.len())
                .and_then(|v| v.checked_add(file.before.as_ref().map_or(0, Vec::len)))
                .ok_or("native mutation capture exceeds its aggregate envelope")?;
        }
        if total > MAX_TOTAL_BYTES {
            return Err("native mutation capture exceeds its aggregate envelope");
        }
        Ok(Self {
            tool_use_id: id,
            tool_name: name,
            files,
        })
    }
    pub(crate) fn matches(&self, id: &str, name: &str) -> bool {
        self.tool_use_id == id && self.tool_name == name
    }
    #[cfg(any(target_os = "linux", test))]
    pub(crate) fn wire(&self) -> NativeReceiptWire {
        NativeReceiptWire {
            tool_use_id: self.tool_use_id.clone(),
            tool_name: self.tool_name.clone(),
            files: self
                .files
                .iter()
                .map(|file| NativeFileWire {
                    path: file.path.clone(),
                    before: file
                        .before
                        .as_ref()
                        .map(|v| base64::engine::general_purpose::STANDARD.encode(v)),
                    after: base64::engine::general_purpose::STANDARD.encode(&file.after),
                })
                .collect(),
        }
    }
}

// Only the owned private helper response admits this wire type. The public receipt deliberately
// has no Deserialize implementation; neither ToolResult nor model arguments contain this field.
#[cfg(any(target_os = "linux", test))]
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NativeReceiptWire {
    tool_use_id: String,
    tool_name: String,
    files: Vec<NativeFileWire>,
}
#[cfg(any(target_os = "linux", test))]
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct NativeFileWire {
    path: PathBuf,
    before: Option<String>,
    after: String,
}
#[cfg(any(target_os = "linux", test))]
impl NativeReceiptWire {
    pub(crate) fn seal(self, id: &str, name: &str) -> Result<NativeMutationReceipt, &'static str> {
        if self.tool_use_id != id || self.tool_name != name || self.files.len() > MAX_FILES {
            return Err("native helper capture identity mismatch");
        }
        // Reject the aggregate encoded envelope before allocating decoded file buffers.
        let max_encoded = MAX_TOTAL_BYTES.div_ceil(3) * 4 + MAX_FILES * 8;
        let encoded_total = self.files.iter().try_fold(0usize, |total, file| {
            total
                .checked_add(file.after.len())?
                .checked_add(file.before.as_ref().map_or(0, String::len))
        });
        if encoded_total.is_none_or(|total| total > max_encoded) {
            return Err("native helper capture exceeds its aggregate envelope");
        }
        let decode = |value: String| {
            if value.len() > MAX_NATIVE_CAPTURE_FILE_BYTES.div_ceil(3) * 4 {
                return Err("native helper capture exceeds its file envelope");
            }
            base64::engine::general_purpose::STANDARD
                .decode(value)
                .map_err(|_| "native helper capture encoding unavailable")
        };
        let files = self
            .files
            .into_iter()
            .map(|file| {
                Ok(NativeFileChange {
                    path: file.path,
                    before: file.before.map(&decode).transpose()?,
                    after: decode(file.after)?,
                })
            })
            .collect::<Result<Vec<_>, &'static str>>()?;
        NativeMutationReceipt::committed(self.tool_use_id, self.tool_name, files)
    }
}

#[cfg(test)]
#[path = "native_mutation_tests.rs"]
mod tests;
