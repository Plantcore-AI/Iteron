//! Existing operator default-model storage. Host captures the target; clients supply no path.
use super::{
    ConfigLock, FILE_CONFIG_SCHEMA_VERSION, MAX_CONFIG_BYTES, apply_setting,
    read_user_config_for_write,
};
use std::path::PathBuf;
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum PreferenceWriteStatus {
    Pending,
    NotInstalled,
    Installed,
    InstallationUnknown,
}
pub(crate) struct UserPreferenceTarget(PathBuf);
impl UserPreferenceTarget {
    #[cfg(test)]
    pub(crate) fn fixture(path: PathBuf) -> Self {
        Self(path)
    }
    pub(crate) fn capture() -> Option<Self> {
        super::user_config_path().map(Self)
    }
    pub(crate) fn write_selected_model(self, provider: &str, model: &str) -> PreferenceWriteStatus {
        // Read/lock/validation refusal precedes the configuration file write stage. An empty
        // parent directory or the existing writer lock is not a successful preference install.
        let prepared = (|| -> anyhow::Result<(ConfigLock, Vec<u8>)> {
            let parent = self
                .0
                .parent()
                .ok_or_else(|| anyhow::anyhow!("config has no parent"))?;
            std::fs::create_dir_all(parent)?;
            let lock = ConfigLock::acquire(&self.0)?;
            let mut config = read_user_config_for_write(&self.0)?;
            apply_setting(&mut config, "provider", provider).map_err(anyhow::Error::msg)?;
            apply_setting(&mut config, "model", model).map_err(anyhow::Error::msg)?;
            config.schema_version = FILE_CONFIG_SCHEMA_VERSION;
            config.validate().map_err(anyhow::Error::msg)?;
            let mut value = serde_json::to_value(config)?;
            if let Some(object) = value.as_object_mut() {
                object.retain(|_, value| !value.is_null());
            }
            let mut bytes = serde_json::to_vec_pretty(&value)?;
            bytes.push(b'\n');
            if bytes.len() > MAX_CONFIG_BYTES {
                anyhow::bail!("serialized preferences exceed config bound");
            }
            Ok((lock, bytes))
        })();
        let Ok((_lock, bytes)) = prepared else {
            return PreferenceWriteStatus::NotInstalled;
        };
        // Retain the real global config lock across the one existing native installation and its
        // directory barrier. Any uncertainty here remains explicit; never undo the selected route.
        if super::write_private_atomic(&self.0, &bytes).is_err() {
            return PreferenceWriteStatus::InstallationUnknown;
        }
        let Some(parent) = self.0.parent() else {
            return PreferenceWriteStatus::InstallationUnknown;
        };
        #[cfg(unix)]
        let barrier = std::fs::File::open(parent)
            .and_then(|file| file.sync_all())
            .is_ok();
        #[cfg(windows)]
        let barrier =
            iteron_support::durable_windows_state::sync_directory_namespace(parent).is_ok();
        #[cfg(not(any(unix, windows)))]
        let barrier = false;
        if barrier {
            PreferenceWriteStatus::Installed
        } else {
            PreferenceWriteStatus::InstallationUnknown
        }
    }
}

#[cfg(test)]
mod tests;
