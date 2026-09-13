//! Fixed PlantCore PreToolUse workspace Hook gate.

use serde::Deserialize;
use serde_json::{Value, json};
use std::io::{self, Read};
use std::path::{Component, Path, PathBuf};

const MAX_INPUT_BYTES: u64 = 1_048_576;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Posture {
    ReadOnly,
    ReadWrite,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    event: String,
    tool: String,
    input: Value,
    posture: String,
    workspace: WorkspaceRoots,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkspaceRoots {
    input: String,
    work: String,
    output: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Access {
    Read,
    Write,
    WriteOutput,
}

pub(crate) fn invoked_as_workspace_hook() -> bool {
    std::env::current_exe()
        .ok()
        .as_deref()
        .and_then(Path::file_stem)
        .and_then(std::ffi::OsStr::to_str)
        == Some("iteron-workspace-hook")
}

pub(crate) fn main() -> std::process::ExitCode {
    let decision = run();
    match decision {
        Ok(()) => {
            println!(
                "{}",
                json!({"decision":"allow","reason":"workspace_path_allowed"})
            );
            std::process::ExitCode::SUCCESS
        }
        Err(reason) => {
            println!("{}", json!({"decision":"deny","reason":reason}));
            eprintln!("{reason}");
            std::process::ExitCode::from(2)
        }
    }
}

fn run() -> Result<(), &'static str> {
    let posture = parse_posture(std::env::args().skip(1))?;
    let mut bytes = Vec::new();
    io::stdin()
        .take(MAX_INPUT_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "input_unreadable")?;
    if bytes.len() as u64 > MAX_INPUT_BYTES {
        return Err("input_too_large");
    }
    let request: Request = serde_json::from_slice(&bytes).map_err(|_| "input_invalid")?;
    if request.event != "PreToolUse"
        || !request.input.is_object()
        || request.posture != posture.label()
        || request.workspace.input != "/workspace/input"
        || request.workspace.work != "/workspace/work"
        || request.workspace.output != "/workspace/output"
    {
        return Err("input_invalid");
    }
    if let Some(decision) = admit_fixed_gateway_proxy(&request.tool, &request.input) {
        return decision;
    }
    let paths = tool_paths(&request.tool, &request.input)?;
    if paths.is_empty() {
        return Err("path_not_proven");
    }
    for (access, path) in paths {
        admit_path(posture, access, &path)?;
    }
    Ok(())
}

fn admit_fixed_gateway_proxy(tool: &str, input: &Value) -> Option<Result<(), &'static str>> {
    let object = input.as_object()?;
    let decision = match tool {
        "plantcore-run-gateway__tool_search" => {
            if !object
                .keys()
                .all(|key| matches!(key.as_str(), "query" | "limit"))
                || object.get("query").and_then(Value::as_str).is_none()
                || object
                    .get("limit")
                    .is_some_and(|value| value.as_u64().is_none())
            {
                Err("input_invalid")
            } else {
                Ok(())
            }
        }
        "plantcore-run-gateway__tool_call" => {
            if object.len() != 2
                || !object.contains_key("handle")
                || !object.contains_key("arguments")
                || object
                    .get("handle")
                    .and_then(Value::as_str)
                    .is_none_or(str::is_empty)
                || !object.get("arguments").is_some_and(Value::is_object)
            {
                Err("input_invalid")
            } else {
                Ok(())
            }
        }
        _ => return None,
    };
    Some(decision)
}

impl Posture {
    fn label(self) -> &'static str {
        match self {
            Self::ReadOnly => "read-only",
            Self::ReadWrite => "read-write",
        }
    }
}

fn parse_posture(mut args: impl Iterator<Item = String>) -> Result<Posture, &'static str> {
    if args.next().as_deref() != Some("--posture") {
        return Err("posture_invalid");
    }
    let posture = match args.next().as_deref() {
        Some("read-only") => Posture::ReadOnly,
        Some("read-write") => Posture::ReadWrite,
        _ => return Err("posture_invalid"),
    };
    if args.next().is_some() {
        return Err("posture_invalid");
    }
    Ok(posture)
}

fn tool_paths(tool: &str, input: &Value) -> Result<Vec<(Access, PathBuf)>, &'static str> {
    let only = |fields: &[&str]| {
        let object = input.as_object().ok_or("input_invalid")?;
        if object.keys().all(|key| fields.contains(&key.as_str())) {
            Ok(())
        } else {
            Err("input_invalid")
        }
    };
    let one = |field: &str, access| {
        input
            .get(field)
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .map(|path| vec![(access, PathBuf::from(path))])
            .ok_or("path_not_proven")
    };
    match tool {
        "read_file" => {
            only(&["path", "offset", "limit"])?;
            one("path", Access::Read)
        }
        "list_dir" => {
            only(&["path", "depth"])?;
            Ok(vec![(
                Access::Read,
                PathBuf::from(input.get("path").and_then(Value::as_str).unwrap_or(".")),
            )])
        }
        "glob" => {
            only(&["pattern", "path"])?;
            Ok(vec![(
                Access::Read,
                PathBuf::from(input.get("path").and_then(Value::as_str).unwrap_or(".")),
            )])
        }
        "grep" => {
            only(&[
                "pattern",
                "path",
                "regex",
                "context_lines",
                "max_results",
                "related_terms",
                "proximity_lines",
            ])?;
            Ok(vec![(
                Access::Read,
                PathBuf::from(input.get("path").and_then(Value::as_str).unwrap_or(".")),
            )])
        }
        "git_diff" => {
            only(&["stat", "path"])?;
            Ok(vec![(
                Access::Read,
                PathBuf::from(input.get("path").and_then(Value::as_str).unwrap_or(".")),
            )])
        }
        "lsp_query" => {
            only(&[
                "query",
                "path",
                "line",
                "character",
                "limit",
                "include_declaration",
            ])?;
            one("path", Access::Read)
        }
        "git_status" => {
            only(&[])?;
            Ok(vec![(Access::Read, PathBuf::from("/workspace/work"))])
        }
        "git_log" => {
            only(&["max_count"])?;
            Ok(vec![(Access::Read, PathBuf::from("/workspace/work"))])
        }
        "repo_map" => {
            only(&["query"])?;
            Ok(vec![(Access::Read, PathBuf::from("/workspace/work"))])
        }
        "edit" => {
            only(&["path", "old", "new"])?;
            one("path", Access::Write)
        }
        "write_file" => {
            only(&["path", "content"])?;
            one("path", Access::Write)
        }
        "publish_artifact" => {
            only(&["logical_name", "relative_path", "media_type"])?;
            let path = input
                .get("relative_path")
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty())
                .ok_or("path_not_proven")?;
            Ok(vec![(
                Access::WriteOutput,
                Path::new("/workspace/output").join(path),
            )])
        }
        "apply_patch" => {
            only(&["files"])?;
            let files = input
                .get("files")
                .and_then(Value::as_array)
                .filter(|files| !files.is_empty())
                .ok_or("path_not_proven")?;
            files
                .iter()
                .map(|file| {
                    let object = file.as_object().ok_or("input_invalid")?;
                    if !object
                        .keys()
                        .all(|key| matches!(key.as_str(), "path" | "hunks"))
                    {
                        return Err("input_invalid");
                    }
                    let hunks = object
                        .get("hunks")
                        .and_then(Value::as_array)
                        .filter(|hunks| !hunks.is_empty())
                        .ok_or("input_invalid")?;
                    if hunks.iter().any(|hunk| {
                        hunk.as_object().is_none_or(|object| {
                            !object
                                .keys()
                                .all(|key| matches!(key.as_str(), "old" | "new"))
                        })
                    }) {
                        return Err("input_invalid");
                    }
                    file.get("path")
                        .and_then(Value::as_str)
                        .filter(|value| !value.is_empty())
                        .map(|path| (Access::Write, PathBuf::from(path)))
                        .ok_or("path_not_proven")
                })
                .collect()
        }
        // Shell/process/Git mutations can hide arbitrarily many paths. No partial parser can
        // establish beneath/no-follow for the complete operation, so the entire call is denied.
        "bash"
        | "process_start"
        | "process_list"
        | "process_poll"
        | "process_write"
        | "process_stop"
        | "process_resize"
        | "read_memory"
        | "use_skill"
        | "web_fetch"
        | "web_search"
        | "dispatch_agent"
        | "Workflow"
        | "tool_search"
        | "submit_repair_evidence"
        | "request_user_input" => Err("path_not_proven"),
        _ => Err("unknown_tool"),
    }
}

fn admit_path(posture: Posture, access: Access, supplied: &Path) -> Result<(), &'static str> {
    let (root, relative) = authorize_path(posture, access, supplied)?;
    verify_beneath(root, &relative, access)
}

fn authorize_path(
    posture: Posture,
    access: Access,
    supplied: &Path,
) -> Result<(&'static Path, PathBuf), &'static str> {
    if supplied
        .components()
        .any(|component| matches!(component, Component::ParentDir))
    {
        return Err("path_escape");
    }
    if supplied
        .components()
        .any(|component| component.as_os_str() == ".plantcore-staging")
    {
        return Err("staging_forbidden");
    }
    let absolute = if supplied.is_absolute() {
        supplied.to_path_buf()
    } else {
        Path::new("/workspace/work").join(supplied)
    };
    let (root, relative) = workspace_root(&absolute).ok_or("path_outside_workspace")?;
    match access {
        Access::Read => {}
        Access::WriteOutput if root != Path::new("/workspace/output") => {
            return Err("output_write_outside_output");
        }
        Access::WriteOutput => {}
        Access::Write if posture == Posture::ReadOnly => return Err("read_only_write"),
        Access::Write if root == Path::new("/workspace/input") => {
            return Err("input_write_forbidden");
        }
        Access::Write => {}
    }
    Ok((root, relative.to_path_buf()))
}

fn workspace_root(path: &Path) -> Option<(&'static Path, &Path)> {
    for root in [
        Path::new("/workspace/input"),
        Path::new("/workspace/work"),
        Path::new("/workspace/output"),
    ] {
        if let Ok(relative) = path.strip_prefix(root) {
            return Some((root, relative));
        }
    }
    None
}

#[cfg(target_os = "linux")]
fn verify_beneath(root: &Path, relative: &Path, access: Access) -> Result<(), &'static str> {
    use std::ffi::{CString, OsStr};
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::ffi::OsStrExt;

    #[repr(C)]
    struct OpenHow {
        flags: u64,
        mode: u64,
        resolve: u64,
    }

    const RESOLVE_NO_XDEV: u64 = 0x01;
    const RESOLVE_NO_MAGICLINKS: u64 = 0x02;
    const RESOLVE_NO_SYMLINKS: u64 = 0x04;
    const RESOLVE_BENEATH: u64 = 0x08;

    fn c(value: &OsStr) -> Result<CString, &'static str> {
        CString::new(value.as_bytes()).map_err(|_| "path_invalid")
    }

    fn open_beneath(parent: i32, path: &Path, directory: bool) -> Result<std::fs::File, i32> {
        let path = c(path.as_os_str()).map_err(|_| libc::EINVAL)?;
        let mut flags = libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK;
        if directory {
            flags |= libc::O_DIRECTORY;
        }
        let how = OpenHow {
            flags: flags as u64,
            mode: 0,
            resolve: RESOLVE_BENEATH
                | RESOLVE_NO_SYMLINKS
                | RESOLVE_NO_MAGICLINKS
                | RESOLVE_NO_XDEV,
        };
        // SAFETY: `path` and `how` remain live for the syscall and successful return owns one fd.
        let fd = unsafe {
            libc::syscall(
                libc::SYS_openat2,
                parent,
                path.as_ptr(),
                &how,
                std::mem::size_of::<OpenHow>(),
            ) as i32
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error()
                .raw_os_error()
                .unwrap_or(libc::EIO));
        }
        // SAFETY: successful openat2 returns one owned descriptor.
        Ok(unsafe { std::fs::File::from_raw_fd(fd) })
    }

    let root_name = c(root.as_os_str())?;
    // SAFETY: root_name is NUL terminated and the result is checked.
    let root_fd = unsafe {
        libc::open(
            root_name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if root_fd < 0 {
        return Err("path_unresolvable");
    }
    // SAFETY: successful open returns one owned descriptor.
    let root_file = unsafe { std::fs::File::from_raw_fd(root_fd) };
    if relative.as_os_str().is_empty() {
        return Ok(());
    }
    match open_beneath(root_file.as_raw_fd(), relative, false) {
        Ok(_) => Ok(()),
        Err(libc::ENOENT) if access == Access::Write => {
            let leaf = relative.file_name().ok_or("path_unresolvable")?;
            let parent = relative.parent().ok_or("path_unresolvable")?;
            // Only a genuinely absent final component is writable. A dangling symlink returns
            // ELOOP under RESOLVE_NO_SYMLINKS and never reaches this branch.
            let leaf = c(leaf)?;
            let parent_file = if parent.as_os_str().is_empty() {
                None
            } else {
                Some(
                    open_beneath(root_file.as_raw_fd(), parent, true)
                        .map_err(|_| "path_unresolvable")?,
                )
            };
            let parent_fd = parent_file
                .as_ref()
                .map_or(root_file.as_raw_fd(), AsRawFd::as_raw_fd);
            let mut metadata = std::mem::MaybeUninit::<libc::stat>::uninit();
            // SAFETY: parent_fd and leaf are valid and metadata points to writable storage.
            let status = unsafe {
                libc::fstatat(
                    parent_fd,
                    leaf.as_ptr(),
                    metadata.as_mut_ptr(),
                    libc::AT_SYMLINK_NOFOLLOW,
                )
            };
            if status == 0 {
                return Err("path_unresolvable");
            }
            if std::io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT) {
                Ok(())
            } else {
                Err("path_unresolvable")
            }
        }
        Err(_) => Err("path_unresolvable"),
    }
}

#[cfg(all(unix, not(target_os = "linux")))]
fn verify_beneath(root: &Path, relative: &Path, access: Access) -> Result<(), &'static str> {
    use std::ffi::{CString, OsStr};
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::MetadataExt;

    fn c(value: &OsStr) -> Result<CString, &'static str> {
        CString::new(value.as_bytes()).map_err(|_| "path_invalid")
    }
    fn open_at(parent: i32, name: &OsStr, directory: bool) -> Result<std::fs::File, i32> {
        let name = c(name).map_err(|_| libc::EINVAL)?;
        let mut flags = libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK;
        if directory {
            flags |= libc::O_DIRECTORY;
        }
        // SAFETY: parent is a held directory descriptor and name is NUL terminated.
        let fd = unsafe { libc::openat(parent, name.as_ptr(), flags) };
        if fd < 0 {
            return Err(std::io::Error::last_os_error()
                .raw_os_error()
                .unwrap_or(libc::EIO));
        }
        // SAFETY: successful openat returns one owned descriptor.
        Ok(unsafe { std::fs::File::from_raw_fd(fd) })
    }

    let root_name = c(root.as_os_str())?;
    // SAFETY: root_name is NUL terminated and the result is checked.
    let root_fd = unsafe {
        libc::open(
            root_name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if root_fd < 0 {
        return Err("path_unresolvable");
    }
    // SAFETY: successful open returns one owned descriptor.
    let root_file = unsafe { std::fs::File::from_raw_fd(root_fd) };
    let device = root_file.metadata().map_err(|_| "path_unresolvable")?.dev();
    let components: Vec<_> = relative.components().collect();
    if components.is_empty() {
        return Ok(());
    }
    let mut parent = root_file;
    for (index, component) in components.iter().enumerate() {
        let Component::Normal(name) = component else {
            return Err("path_escape");
        };
        let leaf = index + 1 == components.len();
        match open_at(parent.as_raw_fd(), name, !leaf) {
            Ok(opened) => {
                let metadata = opened.metadata().map_err(|_| "path_unresolvable")?;
                if metadata.dev() != device {
                    return Err("mount_escape");
                }
                if leaf {
                    return Ok(());
                }
                parent = opened;
            }
            Err(libc::ENOENT) if leaf && access == Access::Write => return Ok(()),
            Err(_) => return Err("path_unresolvable"),
        }
    }
    Ok(())
}

#[cfg(not(unix))]
fn verify_beneath(_root: &Path, _relative: &Path, _access: Access) -> Result<(), &'static str> {
    Err("platform_unsupported")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn published_requests_include_fixed_posture_and_workspace_roots() {
        let schema: Value = serde_json::from_str(include_str!(
            "../../../contracts/plantcore/workspace-hook-v1.schema.json"
        ))
        .unwrap();
        let validator = jsonschema::options()
            .with_draft(jsonschema::Draft::Draft202012)
            .build(&schema)
            .unwrap();
        for bytes in [
            include_bytes!("../../../contracts/plantcore/examples/workspace-hook-allow.json")
                .as_slice(),
            include_bytes!("../../../contracts/plantcore/examples/workspace-hook-deny.json")
                .as_slice(),
        ] {
            let value: Value = serde_json::from_slice(bytes).unwrap();
            assert!(validator.validate(&value).is_ok());
            assert!(serde_json::from_value::<Request>(value).is_ok());
        }
        let missing_roots = json!({
            "event": "PreToolUse",
            "tool": "read_file",
            "input": {"path": "/workspace/input/context.txt"},
            "posture": "read-only",
        });
        assert!(validator.validate(&missing_roots).is_err());
        assert!(serde_json::from_value::<Request>(missing_roots).is_err());
    }

    #[test]
    fn fixed_table_covers_every_model_visible_builtin_and_gateway_proxy() {
        let mut registry = iteron_tools::Registry::coding_agent("/workspace/work").unwrap();
        registry.register_plantcore_tools().unwrap();
        let registered = registry
            .specs()
            .into_iter()
            .map(|spec| spec.name)
            .collect::<std::collections::BTreeSet<_>>();
        let table: Value = serde_json::from_str(include_str!(
            "../../../contracts/plantcore/workspace-tools-v1.json"
        ))
        .unwrap();
        let declared = table["tools"]
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect::<std::collections::BTreeSet<_>>();
        assert!(registered.is_subset(&declared));
        assert_eq!(declared.len(), registered.len() + 2);
        assert!(declared.contains("plantcore-run-gateway__tool_search"));
        assert!(declared.contains("plantcore-run-gateway__tool_call"));
    }

    #[test]
    fn fixed_gateway_proxy_is_pathless_but_strictly_shaped() {
        assert_eq!(
            admit_fixed_gateway_proxy(
                "plantcore-run-gateway__tool_search",
                &json!({"query":"customer", "limit":8})
            ),
            Some(Ok(()))
        );
        assert_eq!(
            admit_fixed_gateway_proxy(
                "plantcore-run-gateway__tool_call",
                &json!({"handle":"read_customer", "arguments":{"customer_id":"1"}})
            ),
            Some(Ok(()))
        );
        assert_eq!(
            admit_fixed_gateway_proxy(
                "plantcore-run-gateway__tool_call",
                &json!({"handle":"read_customer", "arguments":{}, "path":"/etc/passwd"})
            ),
            Some(Err("input_invalid"))
        );
        assert_eq!(
            admit_fixed_gateway_proxy("future-server__tool_call", &json!({})),
            None
        );
    }

    #[test]
    fn unknown_and_shell_tools_fail_closed() {
        assert_eq!(tool_paths("future_tool", &json!({})), Err("unknown_tool"));
        assert_eq!(
            tool_paths("bash", &json!({"command":"pwd"})),
            Err("path_not_proven")
        );
        assert_eq!(
            tool_paths("process_poll", &json!({"job_id":"job-1"})),
            Err("path_not_proven")
        );
        assert_eq!(
            tool_paths("Workflow", &json!({"name":"run"})),
            Err("path_not_proven")
        );
        assert_eq!(
            tool_paths(
                "read_file",
                &json!({"path":"README.md","fallback_path":"/etc/passwd"})
            ),
            Err("input_invalid")
        );
    }

    #[test]
    fn fixed_repository_observers_are_read_only_under_the_work_root() {
        for (tool, input) in [
            ("git_status", serde_json::json!({})),
            ("git_log", serde_json::json!({"max_count": 5})),
            ("repo_map", serde_json::json!({"query": "PlantCore"})),
        ] {
            assert_eq!(
                tool_paths(tool, &input),
                Ok(vec![(Access::Read, PathBuf::from("/workspace/work"))])
            );
        }
        assert_eq!(
            tool_paths("git_status", &serde_json::json!({"path": "/tmp"})),
            Err("input_invalid")
        );
    }

    #[test]
    fn traversal_and_staging_are_rejected_before_io() {
        assert_eq!(
            admit_path(Posture::ReadWrite, Access::Write, Path::new("../input/a")),
            Err("path_escape")
        );
        assert_eq!(
            admit_path(
                Posture::ReadWrite,
                Access::Write,
                Path::new("/workspace/output/.plantcore-staging/x")
            ),
            Err("staging_forbidden")
        );
    }

    #[test]
    fn posture_matrix_is_exact_before_descriptor_resolution() {
        assert_eq!(
            authorize_path(
                Posture::ReadOnly,
                Access::Write,
                Path::new("/workspace/work/new.txt")
            ),
            Err("read_only_write")
        );
        assert_eq!(
            authorize_path(
                Posture::ReadWrite,
                Access::Write,
                Path::new("/workspace/input/new.txt")
            ),
            Err("input_write_forbidden")
        );
        assert_eq!(
            authorize_path(
                Posture::ReadWrite,
                Access::Read,
                Path::new("/workspace/input/context.txt")
            ),
            Ok((Path::new("/workspace/input"), PathBuf::from("context.txt")))
        );
        assert_eq!(
            authorize_path(Posture::ReadWrite, Access::Write, Path::new("output.txt")),
            Ok((Path::new("/workspace/work"), PathBuf::from("output.txt")))
        );
        assert_eq!(
            authorize_path(Posture::ReadWrite, Access::Read, Path::new("/etc/passwd")),
            Err("path_outside_workspace")
        );
        assert_eq!(
            authorize_path(
                Posture::ReadOnly,
                Access::WriteOutput,
                Path::new("/workspace/output/report.txt")
            ),
            Ok((Path::new("/workspace/output"), PathBuf::from("report.txt")))
        );
        assert_eq!(
            authorize_path(
                Posture::ReadOnly,
                Access::WriteOutput,
                Path::new("/workspace/work/report.txt")
            ),
            Err("output_write_outside_output")
        );
    }

    #[cfg(unix)]
    #[test]
    fn descriptor_walk_rejects_symlinks_and_distinguishes_missing_read_from_write() {
        use std::os::unix::fs::symlink;

        let root =
            std::env::temp_dir().join(format!("iteron-workspace-hook-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir(&root).unwrap();
        std::fs::write(root.join("inside.txt"), b"inside").unwrap();
        symlink(root.join("inside.txt"), root.join("link.txt")).unwrap();

        assert_eq!(
            verify_beneath(&root, Path::new("inside.txt"), Access::Read),
            Ok(())
        );
        assert_eq!(
            verify_beneath(&root, Path::new("link.txt"), Access::Read),
            Err("path_unresolvable")
        );
        assert_eq!(
            verify_beneath(&root, Path::new("link.txt"), Access::Write),
            Err("path_unresolvable")
        );
        assert_eq!(
            verify_beneath(&root, Path::new("missing.txt"), Access::Read),
            Err("path_unresolvable")
        );
        assert_eq!(
            verify_beneath(&root, Path::new("missing.txt"), Access::Write),
            Ok(())
        );
        assert_eq!(
            verify_beneath(&root, Path::new("missing.txt"), Access::WriteOutput),
            Err("path_unresolvable")
        );
        let _ = std::fs::remove_dir_all(root);
    }
}
