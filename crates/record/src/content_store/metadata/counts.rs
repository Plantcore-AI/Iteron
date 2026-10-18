//! Rebuildable run and digest membership counts under the same OS lease as the reference index.
//! New references update scalar counts without enumerating either growing reference directory.

use super::*;
use std::collections::BTreeSet;

const MAX_CACHED_REFERENCE_COUNTS: usize = 128;

#[derive(PartialEq, Eq)]
struct LegacyStamp {
    length: u64,
    modified: std::time::SystemTime,
    #[cfg(unix)]
    identity: (u64, u64, i64, i64),
}

pub(super) struct ReferenceCount {
    members: usize,
    legacy: Option<LegacyStamp>,
}

#[cfg(test)]
std::thread_local! {
    pub(super) static REBUILDS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

fn legacy_stamp(path: &Path) -> io::Result<Option<LegacyStamp>> {
    let metadata = match std::fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    if !metadata.is_dir() {
        return Err(invalid(
            "private content reference directory is not a directory",
        ));
    }
    Ok(Some(LegacyStamp {
        length: metadata.len(),
        modified: metadata.modified()?,
        #[cfg(unix)]
        identity: {
            use std::os::unix::fs::MetadataExt;
            (
                metadata.dev(),
                metadata.ino(),
                metadata.ctime(),
                metadata.ctime_nsec(),
            )
        },
    }))
}

impl Index {
    fn count_reference_members(&mut self, path: &Path, relative: &str) -> io::Result<usize> {
        // Modern writers mutate logical members only through committed frames. The stamp also
        // catches physical legacy deletion/replacement, including migration cleanup by peers.
        let legacy = if self.write_lease && self.lease_directories.get(relative) == Some(&true) {
            None
        } else {
            let legacy = legacy_stamp(path)?;
            self.remember_legacy_directory(relative, legacy.is_none());
            legacy
        };
        if let Some(count) = self.reference_counts.get(relative)
            && count.legacy == legacy
        {
            return bounded_count(count.members);
        }
        #[cfg(test)]
        REBUILDS.with(|count| count.set(count.get() + 1));
        let mut names = BTreeSet::new();
        if legacy.is_some() {
            for entry in std::fs::read_dir(path)?.take(MAX_DIRECTORY_ENTRIES + 1) {
                names.insert(entry?.file_name());
                bounded_count(names.len())?;
            }
        }
        let prefix = format!("{relative}/");
        for (key, value) in self.entries.range(prefix.clone()..) {
            let Some(name) = key.strip_prefix(&prefix) else {
                break;
            };
            // Validated log members have exactly family/owner/member components.
            if value.is_some() {
                names.insert(OsString::from(name));
            } else {
                names.remove(&OsString::from(name));
            }
            bounded_count(names.len())?;
        }
        let members = names.len();
        // This optimization is bounded independently of the authoritative index. Cache pressure
        // only causes a later rebuild; it cannot reject a valid reference or relax its quota.
        if self.reference_counts.len() >= MAX_CACHED_REFERENCE_COUNTS
            && !self.reference_counts.contains_key(relative)
        {
            self.reference_counts.clear();
        }
        self.reference_counts
            .insert(relative.to_owned(), ReferenceCount { members, legacy });
        Ok(members)
    }

    pub(super) fn update_reference_count(&mut self, scope: &Path, path: &str, present: bool) {
        let Some((directory, _)) = path.rsplit_once('/') else {
            return;
        };
        let Some(count) = self.reference_counts.get(directory) else {
            return;
        };
        let previous = match self.entries.get(path) {
            Some(value) => value.is_some(),
            None if count.legacy.is_none() => false,
            None => match std::fs::symlink_metadata(scope.join(path)) {
                Ok(_) => true,
                Err(error) if error.kind() == io::ErrorKind::NotFound => false,
                Err(_) => {
                    // The committed frame still applies. Never let an optional count cache
                    // introduce a new failure after publication or guess legacy membership.
                    self.reference_counts.remove(directory);
                    return;
                }
            },
        };
        let count = self
            .reference_counts
            .get_mut(directory)
            .expect("cached reference count");
        let members = match (previous, present) {
            (false, true) => count.members.checked_add(1),
            (true, false) => count.members.checked_sub(1),
            _ => Some(count.members),
        };
        if let Some(members) = members {
            count.members = members;
        } else {
            // A changed physical baseline must trigger a recount, never a clamped quota.
            self.reference_counts.remove(directory);
        }
    }
}

fn bounded_count(count: usize) -> io::Result<usize> {
    if count > MAX_DIRECTORY_ENTRIES {
        Err(invalid("metadata directory exceeds its bound"))
    } else {
        Ok(count)
    }
}

pub(in crate::content_store) fn reference_count(path: &Path) -> io::Result<Option<usize>> {
    let Some((scope, relative)) = location(path) else {
        return Ok(None);
    };
    let Some(owner) = relative
        .strip_prefix("run-refs/")
        .or_else(|| relative.strip_prefix("refs/"))
    else {
        return Ok(None);
    };
    if owner.contains('/') {
        return Ok(None);
    }
    validate_relative(&format!("{relative}/count"))?;
    with_index(&scope, |index| {
        index.count_reference_members(path, &relative)
    })
    .map(Some)
}

#[cfg(test)]
pub(super) fn count_with_local_index(index: &mut Index, path: &Path) -> io::Result<usize> {
    // Parallel tests may legitimately evict any unleased global cache entry. Keep the cache
    // under test local while exercising the same real log refresh and membership methods.
    let (scope, relative) = location(path).ok_or_else(missing)?;
    index.refresh(&scope, false)?;
    index.count_reference_members(path, &relative)
}
