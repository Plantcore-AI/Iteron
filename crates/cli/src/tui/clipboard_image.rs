//! Bounded platform clipboard process and sanitized helper environment owner.

use super::{CLIPBOARD_CAPTURE_TIMEOUT, OsString, Stdio};
#[cfg(windows)]
use std::path::Component;
#[cfg(any(windows, test))]
use std::path::Path;
use tokio::io::AsyncReadExt as _;

#[derive(Clone)]
pub(super) struct ClipboardCommand {
    pub(super) program: OsString,
    pub(super) args: Vec<String>,
}

#[cfg(target_os = "macos")]
pub(super) fn clipboard_commands(_environment: &[(OsString, OsString)]) -> Vec<ClipboardCommand> {
    vec![ClipboardCommand {
        program: "pngpaste".into(),
        args: vec!["-".into()],
    }]
}

#[cfg(all(unix, not(target_os = "macos")))]
pub(super) fn clipboard_commands(_environment: &[(OsString, OsString)]) -> Vec<ClipboardCommand> {
    vec![
        ClipboardCommand {
            program: "wl-paste".into(),
            args: vec!["--no-newline".into(), "--type".into(), "image/png".into()],
        },
        ClipboardCommand {
            program: "xclip".into(),
            args: vec![
                "-selection".into(),
                "clipboard".into(),
                "-t".into(),
                "image/png".into(),
                "-o".into(),
            ],
        },
    ]
}

#[cfg(windows)]
pub(super) fn clipboard_commands(environment: &[(OsString, OsString)]) -> Vec<ClipboardCommand> {
    const SCRIPT: &str = "Add-Type -AssemblyName System.Windows.Forms; Add-Type -AssemblyName \
        System.Drawing; $i=[System.Windows.Forms.Clipboard]::GetImage(); if($null -eq $i){exit 3}; \
        $m=New-Object System.IO.MemoryStream; \
        $i.Save($m,[System.Drawing.Imaging.ImageFormat]::Png); $b=$m.ToArray(); \
        [Console]::OpenStandardOutput().Write($b,0,$b.Length)";
    windows_clipboard_powershell_program(environment)
        .map(|program| {
            vec![ClipboardCommand {
                program,
                args: vec![
                    "-NoProfile".into(),
                    "-NonInteractive".into(),
                    "-Sta".into(),
                    "-Command".into(),
                    iteron_tunables::param_str("cli.tui.script", SCRIPT).into(),
                ],
            }]
        })
        .unwrap_or_default()
}

#[cfg(not(any(unix, windows)))]
pub(super) fn clipboard_commands(_environment: &[(OsString, OsString)]) -> Vec<ClipboardCommand> {
    Vec::new()
}

const MAX_CLIPBOARD_ENV_BYTES: usize = 4 * 1024;
#[cfg(any(windows, test))]
const MAX_WINDOWS_SYSTEM_ROOT_BYTES: usize = 1_024;

pub(super) fn bounded_clipboard_environment_value(value: OsString) -> Option<OsString> {
    if value.as_encoded_bytes().len()
        > iteron_tunables::param_integer("cli.tui.max_clipboard_env_bytes", MAX_CLIPBOARD_ENV_BYTES)
        || value
            .to_str()
            .is_some_and(|text| text.chars().any(char::is_control))
    {
        None
    } else {
        Some(value)
    }
}

pub(super) fn clipboard_child_environment_with(
    mut source: impl FnMut(&str) -> Option<OsString>,
) -> Vec<(OsString, OsString)> {
    let mut environment = Vec::new();
    #[cfg(target_os = "macos")]
    environment.push((
        "PATH".into(),
        "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin".into(),
    ));
    #[cfg(all(unix, not(target_os = "macos")))]
    environment.push(("PATH".into(), "/usr/local/bin:/usr/bin:/bin".into()));
    #[cfg(unix)]
    {
        environment.push(("LANG".into(), "C.UTF-8".into()));
        environment.push(("LC_ALL".into(), "C.UTF-8".into()));
        for name in [
            "WAYLAND_DISPLAY",
            "XDG_RUNTIME_DIR",
            "DISPLAY",
            "XAUTHORITY",
        ] {
            if let Some(value) = source(name).and_then(bounded_clipboard_environment_value) {
                environment.push((name.into(), value));
            }
        }
    }
    #[cfg(windows)]
    {
        environment.extend(windows_clipboard_environment_with(
            trusted_windows_directory(),
            |name| source(name),
            native_windows_clipboard_root,
        ));
    }
    environment
}

#[cfg(any(windows, test))]
pub(super) fn windows_clipboard_environment_with(
    trusted_root: Option<OsString>,
    mut source: impl FnMut(&str) -> Option<OsString>,
    admissible_root: impl Fn(&Path) -> bool,
) -> Vec<(OsString, OsString)> {
    let Some(root) = trusted_root
        .and_then(bounded_clipboard_environment_value)
        .filter(|value| value.as_encoded_bytes().len() <= MAX_WINDOWS_SYSTEM_ROOT_BYTES)
        .filter(|value| {
            value
                .to_str()
                .is_some_and(|text| !text.contains(';') && !text.contains('"'))
        })
        .filter(|value| admissible_root(Path::new(value)))
    else {
        return Vec::new();
    };

    let powershell_dir = append_windows_subpath(&root, r"System32\WindowsPowerShell\v1.0");
    let system32 = append_windows_subpath(&root, "System32");
    let wbem = append_windows_subpath(&root, r"System32\Wbem");
    let mut path = OsString::new();
    for directory in [&powershell_dir, &system32, &root, &wbem] {
        if !path.is_empty() {
            path.push(";");
        }
        path.push(directory);
    }
    let Some(path) = bounded_clipboard_environment_value(path) else {
        return Vec::new();
    };

    let mut environment = vec![
        ("PATH".into(), path),
        ("SystemRoot".into(), root.clone()),
        ("WINDIR".into(), root),
    ];
    for name in ["TEMP", "TMP"] {
        if let Some(value) = source(name).and_then(bounded_clipboard_environment_value) {
            environment.push((name.into(), value));
        }
    }
    environment
}

#[cfg(any(windows, test))]
pub(super) fn append_windows_subpath(root: &std::ffi::OsStr, subpath: &str) -> OsString {
    let mut path = root.to_os_string();
    if !root
        .to_string_lossy()
        .as_bytes()
        .last()
        .is_some_and(|byte| matches!(byte, b'\\' | b'/'))
    {
        path.push("\\");
    }
    path.push(subpath);
    path
}

#[cfg(any(windows, test))]
pub(super) fn windows_clipboard_powershell_program(
    environment: &[(OsString, OsString)],
) -> Option<OsString> {
    let root = environment
        .iter()
        .find_map(|(name, value)| (name == "SystemRoot").then_some(value))?;
    Some(append_windows_subpath(
        root,
        r"System32\WindowsPowerShell\v1.0\powershell.exe",
    ))
}

#[cfg(windows)]
pub(super) fn native_windows_clipboard_root(path: &Path) -> bool {
    use std::path::Prefix;

    if !path.is_absolute() {
        return false;
    }
    matches!(
        path.components().next(),
        Some(Component::Prefix(prefix))
            if matches!(prefix.kind(), Prefix::Disk(_) | Prefix::UNC(_, _))
    )
}

#[cfg(windows)]
pub(super) fn trusted_windows_directory() -> Option<OsString> {
    use std::os::windows::ffi::OsStringExt;
    use windows_sys::Win32::System::SystemInformation::GetWindowsDirectoryW;

    // The OS, not an inherited environment variable, selects the executable trust root. Refuse an
    // unexpectedly large path instead of allocating from an unbounded native return value.
    let mut buffer = vec![
        0_u16;
        iteron_tunables::param_integer(
            "cli.tui.max_windows_system_root_bytes",
            MAX_WINDOWS_SYSTEM_ROOT_BYTES
        ) + 1
    ];
    // SAFETY: `buffer` is writable for its declared length and retained until the call returns.
    let length = unsafe { GetWindowsDirectoryW(buffer.as_mut_ptr(), buffer.len() as u32) } as usize;
    if length == 0 || length >= buffer.len() {
        return None;
    }
    Some(OsString::from_wide(&buffer[..length]))
}

/// Read a clipboard image through a fixed platform adapter. The subprocess has no shell, stderr is
/// discarded, stdout is capped before retention, the environment is an explicit display-only
/// allowlist, and the whole operation has a short timeout.
pub(super) async fn clipboard_image_bytes() -> Result<Option<Vec<u8>>, &'static str> {
    let environment = clipboard_child_environment_with(|name| std::env::var_os(name));
    for specification in clipboard_commands(&environment) {
        let mut command = tokio::process::Command::new(&specification.program);
        command
            .env_clear()
            .envs(environment.iter().cloned())
            .args(specification.args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true);
        let mut child = match command.spawn() {
            Ok(child) => child,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(_) => continue,
        };
        let Some(mut stdout) = child.stdout.take() else {
            let _ = child.kill().await;
            continue;
        };
        let capture = async {
            let mut bytes = Vec::new();
            let mut chunk = [0_u8; 16 * 1024];
            loop {
                let read = stdout
                    .read(&mut chunk)
                    .await
                    .map_err(|_| "could not read the clipboard image")?;
                if read == 0 {
                    break;
                }
                if bytes.len().saturating_add(read) > image_input::MAX_IMAGE_FILE_BYTES {
                    return Err("clipboard image exceeds the per-file limit");
                }
                bytes.extend_from_slice(&chunk[..read]);
            }
            let status = child
                .wait()
                .await
                .map_err(|_| "could not finish clipboard image capture")?;
            Ok::<_, &'static str>((status.success(), bytes))
        };
        match tokio::time::timeout(
            iteron_tunables::param_duration(
                "cli.tui.clipboard_capture_timeout",
                CLIPBOARD_CAPTURE_TIMEOUT,
            ),
            capture,
        )
        .await
        {
            Ok(Ok((true, bytes))) if !bytes.is_empty() => return Ok(Some(bytes)),
            Ok(Ok(_)) => continue,
            Ok(Err(error)) => {
                let _ = child.kill().await;
                let _ = child.wait().await;
                return Err(error);
            }
            Err(_) => {
                let _ = child.kill().await;
                let _ = child.wait().await;
                return Err("clipboard image capture timed out");
            }
        }
    }
    Ok(None)
}
