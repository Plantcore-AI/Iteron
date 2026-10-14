//! Bounded, no-follow actual-object enumeration for permission installation and retirement.
//! Setup pins last only through the ACL transaction; they do not prohibit live atomic edits.
use super::acl::BoundObject;
use std::collections::BTreeSet;
use std::fs::File;
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::path::PathBuf;

const MAX_SCOPE_OBJECTS: usize = 65_536;
const MAX_SCOPE_DEPTH: usize = 128;
const MAX_SCOPE_PATH_UNITS: usize = 32 * 1024 * 1024;

pub(super) struct Snapshot {
    pub(super) objects: Vec<BoundObject>,
    // All directory/object names remain pinned until the actual transaction finishes. Retained
    // grant handles use delete sharing afterward so the agent can rename/remove ordinary files.
    pub(super) _pins: Vec<File>,
}

pub(super) fn snapshot(roots: &[&BoundObject], retiring: bool) -> io::Result<Snapshot> {
    let mut pending = Vec::<(File, PathBuf, usize)>::new();
    let mut seen = BTreeSet::new();
    for root in roots {
        root.validate()?;
        if !root.is_directory() || !seen.insert(root.key()) {
            continue;
        }
        pending.push((root.file().try_clone()?, root.path().to_path_buf(), 0));
    }
    let mut objects = Vec::new();
    let mut pins = Vec::new();
    let mut path_units = 0_usize;
    let mut visited = 0_usize;
    while let Some((parent, directory, depth)) = pending.pop() {
        let remaining = MAX_SCOPE_OBJECTS.saturating_sub(visited);
        if remaining == 0 {
            return Err(bound_refusal());
        }
        let (entries, omitted) =
            crate::durable_windows_state::workspace_directory_read::list_permission_scope(
                &parent, remaining,
            )
            .map_err(|_| {
                io::Error::other("Windows sandbox actual directory enumeration refused")
            })?;
        if omitted {
            return Err(bound_refusal());
        }
        for (name, is_directory) in entries {
            visited = visited
                .checked_add(1)
                .filter(|count| *count <= MAX_SCOPE_OBJECTS)
                .ok_or_else(bound_refusal)?;
            let path = directory.join(&name);
            path_units = path_units
                .checked_add(path.as_os_str().encode_wide().count())
                .filter(|count| *count <= MAX_SCOPE_PATH_UNITS)
                .ok_or_else(bound_refusal)?;
            let (object, pin, descend) =
                BoundObject::open_descendant(&parent, &name, &path, is_directory, retiring)?;
            if !seen.insert(object.key()) {
                continue;
            }
            if descend {
                let next_depth = depth
                    .checked_add(1)
                    .filter(|depth| *depth <= MAX_SCOPE_DEPTH)
                    .ok_or_else(bound_refusal)?;
                pending.push((pin.try_clone()?, path, next_depth));
            }
            pins.push(pin);
            objects.push(object);
        }
    }
    Ok(Snapshot {
        objects,
        _pins: pins,
    })
}

fn bound_refusal() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "Windows sandbox permission scope exceeds its finite object/depth/path envelope",
    )
}
