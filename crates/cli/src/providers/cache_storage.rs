//! Installation-local secret scope key and private namespace byte publication. Key bytes have
//! no formatting/serialization port; stores receive only credential-bound scope digests.
use super::{
    CACHE_TEMP_TIMESTAMP_ON_UNUSABLE_CLOCK, CATALOG_CACHE_FILE, CATALOG_CACHE_SCOPE_KEY_BYTES,
    CATALOG_CACHE_SCOPE_KEY_FILE, CATALOG_CACHE_SCOPE_PREFIX, CATALOG_CACHE_VERSION,
};
use iteron_provider::ProviderInstance;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};
use std::time::{SystemTime, UNIX_EPOCH};
static CACHE_TEMP_NONCE: AtomicU64 = AtomicU64::new(0);
/// Installation-local HMAC key used only to bind credential-visible inventory to the credential
/// that produced it. The key has no serde/debug surface and is kept in a separate fixed-size file;
/// Unix additionally enforces exact owner/0600 metadata, while Windows rejects reparse paths and
/// inherits the operator cache directory's ACL.
#[derive(Clone)]
pub(super) struct CatalogCacheScopeKey([u8; CATALOG_CACHE_SCOPE_KEY_BYTES]);

pub(super) fn credential_scope(
    instance: &ProviderInstance,
    scope_key: &CatalogCacheScopeKey,
) -> Option<String> {
    let scope = instance.catalog_cache_credential_scope(&scope_key.0)?;
    let mut encoded = String::with_capacity(CATALOG_CACHE_SCOPE_PREFIX.len() + scope.len() * 2);
    encoded.push_str(CATALOG_CACHE_SCOPE_PREFIX);
    for byte in scope {
        use std::fmt::Write as _;
        let _ = write!(encoded, "{byte:02x}");
    }
    Some(encoded)
}

pub(super) fn valid_credential_scope(value: &str) -> bool {
    let Some(hex) = value.strip_prefix(CATALOG_CACHE_SCOPE_PREFIX) else {
        return false;
    };
    hex.len() == CATALOG_CACHE_SCOPE_KEY_BYTES * 2
        && hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

/// Publish `bytes` at `path` through a 0600 temporary file and a rename, inside a directory whose
/// identity and permissions were verified first. Shared by both operator caches so a second cache
/// cannot quietly acquire weaker durability or weaker permissions than the first.
pub(super) fn write_private_file_atomic(
    path: &Path,
    bytes: &[u8],
    fallback_name: &str,
) -> io::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "cache path has no parent"))?;
    let directory = prepare_private_cache_directory(parent)?;
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(fallback_name);
    let mut temporary = None;
    let nonce = CACHE_TEMP_NONCE.fetch_add(1, AtomicOrdering::Relaxed);
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(iteron_tunables::param_integer(
            "cli.providers.cache_temp_timestamp_on_unusable_clock",
            CACHE_TEMP_TIMESTAMP_ON_UNUSABLE_CLOCK,
        ));
    for attempt in 0..16u8 {
        let candidate = parent.join(format!(
            ".{file_name}.tmp-{}-{timestamp:x}-{nonce:x}-{attempt}",
            std::process::id()
        ));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        match options.open(&candidate) {
            Ok(file) => {
                temporary = Some((candidate, file));
                break;
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error),
        }
    }
    let Some((temporary_path, mut file)) = temporary else {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "could not reserve an atomic provider-cache temporary file",
        ));
    };
    let result = (|| {
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&temporary_path, path)?;
        // Persist the rename itself where the platform supports directory fsync.
        if let Some(directory) = directory {
            let _ = directory.sync_all();
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary_path);
    }
    if result.is_ok() && file_name == CATALOG_CACHE_FILE {
        // A cache-format bump renames the file, so every earlier generation just stayed in
        // `~/.iteron/cache/providers` forever — a full stale catalog nobody reads and nothing
        // deletes. Reclaim them once the current generation is durable on disk.
        for superseded in 1..CATALOG_CACHE_VERSION {
            let _ = fs::remove_file(parent.join(format!("catalogs-v{superseded}.json")));
        }
    }
    result
}

impl CatalogCacheScopeKey {
    #[cfg(any(unix, windows))]
    pub(super) fn load_or_create(cache_path: &Path) -> io::Result<Self> {
        Self::load_or_create_with_rng(cache_path, fill_scope_key_from_os)
    }

    #[cfg(any(unix, windows))]
    pub(super) fn load_or_create_with_rng(
        cache_path: &Path,
        fill_random: impl FnOnce(&mut [u8]) -> io::Result<()>,
    ) -> io::Result<Self> {
        let parent = cache_path.parent().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "cache path has no parent")
        })?;
        let directory = prepare_private_cache_directory(parent)?;
        let key_path = parent.join(CATALOG_CACHE_SCOPE_KEY_FILE);
        match load_existing_scope_key(&key_path) {
            Ok(key) => return Ok(key),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }

        let mut bytes = [0_u8; CATALOG_CACHE_SCOPE_KEY_BYTES];
        fill_random(&mut bytes)?;
        if bytes.iter().all(|byte| *byte == 0) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "operating-system randomness returned an invalid cache key",
            ));
        }

        let nonce = CACHE_TEMP_NONCE.fetch_add(1, AtomicOrdering::Relaxed);
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or(iteron_tunables::param_integer(
                "cli.providers.cache_temp_timestamp_on_unusable_clock",
                CACHE_TEMP_TIMESTAMP_ON_UNUSABLE_CLOCK,
            ));
        let mut temporary = None;
        for attempt in 0..16u8 {
            let candidate = parent.join(format!(
                ".{CATALOG_CACHE_SCOPE_KEY_FILE}.tmp-{}-{timestamp:x}-{nonce:x}-{attempt}",
                std::process::id()
            ));
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            match options.open(&candidate) {
                Ok(file) => {
                    temporary = Some((candidate, file));
                    break;
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(error),
            }
        }
        let Some((temporary_path, mut file)) = temporary else {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "could not reserve an atomic provider-cache key temporary file",
            ));
        };

        let result = (|| {
            file.write_all(&bytes)?;
            file.sync_all()?;
            drop(file);
            match fs::hard_link(&temporary_path, &key_path) {
                Ok(()) => {
                    fs::remove_file(&temporary_path)?;
                    if let Some(directory) = &directory {
                        let _ = directory.sync_all();
                    }
                    load_existing_scope_key(&key_path)
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                    fs::remove_file(&temporary_path)?;
                    load_existing_scope_key(&key_path)
                }
                Err(error) => Err(error),
            }
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temporary_path);
        }
        result
    }

    /// Targets outside the explicitly admitted Unix/Windows OS-RNG set stay disabled. Silently
    /// deriving a key from time/process state would turn the HMAC into a naked hash.
    #[cfg(not(any(unix, windows)))]
    pub(super) fn load_or_create(_cache_path: &Path) -> io::Result<Self> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "persistent provider catalog cache requires a trusted OS RNG",
        ))
    }
}

#[cfg(any(unix, windows))]
fn fill_scope_key_from_os(destination: &mut [u8]) -> io::Result<()> {
    getrandom::fill(destination).map_err(|error| {
        let kind = if error == getrandom::Error::UNSUPPORTED {
            io::ErrorKind::Unsupported
        } else {
            io::ErrorKind::Other
        };
        io::Error::new(kind, "operating-system randomness is unavailable")
    })
}

pub(super) fn prepare_private_cache_directory(path: &Path) -> io::Result<Option<File>> {
    fs::create_dir_all(path)?;
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "provider cache parent is not a real directory",
        ));
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "provider cache parent must not be a Windows reparse point",
            ));
        }
    }
    #[cfg(unix)]
    fs::set_permissions(path, {
        use std::os::unix::fs::PermissionsExt;
        fs::Permissions::from_mode(0o700)
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let directory = File::open(path)?;
        let opened_metadata = directory.metadata()?;
        if metadata.dev() != opened_metadata.dev()
            || metadata.ino() != opened_metadata.ino()
            || opened_metadata.mode() & 0o777 != 0o700
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "provider cache directory identity or permissions changed",
            ));
        }
        Ok(Some(directory))
    }
    #[cfg(not(unix))]
    {
        Ok(None)
    }
}

#[cfg(any(unix, windows))]
fn load_existing_scope_key(path: &Path) -> io::Result<CatalogCacheScopeKey> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() != CATALOG_CACHE_SCOPE_KEY_BYTES as u64
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "provider cache scope key is not a regular fixed-size file",
        ));
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "provider cache scope key must not be a Windows reparse point",
            ));
        }
    }
    let file = File::open(path)?;
    let opened_metadata = file.metadata()?;
    if !opened_metadata.is_file() || opened_metadata.len() != CATALOG_CACHE_SCOPE_KEY_BYTES as u64 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "opened provider cache scope key is not a regular fixed-size file",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let parent_metadata = fs::symlink_metadata(path.parent().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "cache key path has no parent")
        })?)?;
        if metadata.dev() != opened_metadata.dev()
            || metadata.ino() != opened_metadata.ino()
            || opened_metadata.mode() & 0o777 != 0o600
            || opened_metadata.nlink() != 1
            || opened_metadata.uid() != parent_metadata.uid()
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "provider cache scope key identity, owner, or permissions are unsafe",
            ));
        }
    }
    let mut bytes = Vec::with_capacity(CATALOG_CACHE_SCOPE_KEY_BYTES + 1);
    file.take((CATALOG_CACHE_SCOPE_KEY_BYTES + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() != CATALOG_CACHE_SCOPE_KEY_BYTES || bytes.iter().all(|byte| *byte == 0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "provider cache scope key has invalid content",
        ));
    }
    let mut key = [0_u8; CATALOG_CACHE_SCOPE_KEY_BYTES];
    key.copy_from_slice(&bytes);
    Ok(CatalogCacheScopeKey(key))
}
