//! Core's single on-disk home directory and operator-home resolution.
//!
//! This is an intentionally breaking contract: runtime state, configuration, skills, agents and
//! memory are read from and written to `.iteron/` only. Discovery does not union historical product
//! directories and no compatibility fallback exists. Unix keeps `HOME` authority. Windows
//! preserves that precedence for shells that deliberately set it, then uses `USERPROFILE` and
//! finally the native `HOMEDRIVE` + `HOMEPATH` pair.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

/// The only product home-directory name understood by Core.
pub const HOME_DIR: &str = ".iteron";

#[derive(Clone, Copy)]
enum Platform {
    UnixLike,
    Windows,
}

/// Resolve the operator-owned home directory from the current process environment.
///
/// Every admitted value is absolute. Windows device-namespace paths are rejected because they
/// bypass ordinary path normalization. A malformed higher-precedence value falls through on
/// Windows instead of redirecting trusted user state relative to the repository. Unix deliberately
/// has no native fallback: an absent or relative `HOME` makes user-level sources unavailable.
pub fn operator() -> Option<PathBuf> {
    resolve_with(
        |name| std::env::var_os(name),
        if cfg!(windows) {
            Platform::Windows
        } else {
            Platform::UnixLike
        },
        native_operator_path,
    )
}

/// Build `<base>/.iteron/<sub>` deterministically.
pub fn path(base: &Path, sub: &str) -> PathBuf {
    base.join(HOME_DIR).join(sub)
}

/// True only for the current Core home-directory component.
pub fn is_home_dir(name: &str) -> bool {
    name == HOME_DIR
}

fn resolve_with(
    mut value: impl FnMut(&str) -> Option<OsString>,
    platform: Platform,
    admissible: impl Fn(&Path) -> bool,
) -> Option<PathBuf> {
    let mut absolute = |name| {
        value(name)
            .map(PathBuf::from)
            .filter(|path| admissible(path))
    };

    if let Some(home) = absolute("HOME") {
        return Some(home);
    }
    if matches!(platform, Platform::UnixLike) {
        return None;
    }
    if let Some(profile) = absolute("USERPROFILE") {
        return Some(profile);
    }

    let drive = value("HOMEDRIVE")?;
    let home_path = value("HOMEPATH")?;
    if drive.is_empty() || home_path.is_empty() {
        return None;
    }
    let mut combined = drive;
    combined.push(&home_path);
    let combined = PathBuf::from(combined);
    admissible(&combined).then_some(combined)
}

fn native_operator_path(path: &Path) -> bool {
    if !path.is_absolute() {
        return false;
    }
    #[cfg(windows)]
    {
        use std::path::{Component, Prefix};

        matches!(
            path.components().next(),
            Some(Component::Prefix(prefix))
                if matches!(prefix.kind(), Prefix::Disk(_) | Prefix::UNC(_, _))
        )
    }
    #[cfg(not(windows))]
    {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn source<'a>(values: &'a [(&'a str, &'a str)]) -> impl FnMut(&str) -> Option<OsString> + 'a {
        let values = values
            .iter()
            .map(|(name, value)| ((*name).to_owned(), OsString::from(value)))
            .collect::<BTreeMap<_, _>>();
        move |name| values.get(name).cloned()
    }

    fn simulated_windows_absolute(path: &Path) -> bool {
        let text = path.to_string_lossy();
        if text.starts_with("\\\\?\\") || text.starts_with("\\\\.\\") {
            return false;
        }
        let bytes = text.as_bytes();
        (bytes.len() >= 3
            && bytes[0].is_ascii_alphabetic()
            && bytes[1] == b':'
            && matches!(bytes[2], b'\\' | b'/'))
            || text.starts_with(r"\\")
    }

    fn simulated_unix_absolute(path: &Path) -> bool {
        path.to_string_lossy().starts_with('/')
    }

    #[test]
    fn path_has_one_unambiguous_home() {
        assert_eq!(
            path(Path::new("/repo"), "skills"),
            PathBuf::from("/repo/.iteron/skills")
        );
        assert!(is_home_dir(".iteron"));
        assert!(!is_home_dir(".git"));
        assert!(!is_home_dir("iteron"));
    }

    #[test]
    fn unix_preserves_absolute_home_precedence_and_ignores_windows_fallbacks() {
        assert_eq!(
            resolve_with(
                source(&[("HOME", "/operator"), ("USERPROFILE", "/windows-profile")]),
                Platform::UnixLike,
                simulated_unix_absolute,
            ),
            Some(PathBuf::from("/operator"))
        );
        assert_eq!(
            resolve_with(
                source(&[("HOME", "relative"), ("USERPROFILE", "/windows-profile")]),
                Platform::UnixLike,
                simulated_unix_absolute,
            ),
            None
        );
    }

    #[test]
    fn windows_falls_through_invalid_home_to_userprofile() {
        assert_eq!(
            resolve_with(
                source(&[
                    ("HOME", "relative"),
                    ("USERPROFILE", r"C:\Users\operator"),
                    ("HOMEDRIVE", "D:"),
                    ("HOMEPATH", r"\Fallback"),
                ]),
                Platform::Windows,
                simulated_windows_absolute,
            ),
            Some(PathBuf::from(r"C:\Users\operator"))
        );
        assert_eq!(
            resolve_with(
                source(&[
                    ("HOME", r"D:\ShellHome"),
                    ("USERPROFILE", r"C:\Users\operator"),
                ]),
                Platform::Windows,
                simulated_windows_absolute,
            ),
            Some(PathBuf::from(r"D:\ShellHome"))
        );
    }

    #[test]
    fn windows_combines_only_an_absolute_homedrive_homepath_pair() {
        assert_eq!(
            resolve_with(
                source(&[
                    ("USERPROFILE", "relative"),
                    ("HOMEDRIVE", "C:"),
                    ("HOMEPATH", r"\Users\operator"),
                ]),
                Platform::Windows,
                simulated_windows_absolute,
            ),
            Some(PathBuf::from(r"C:\Users\operator"))
        );
        assert_eq!(
            resolve_with(
                source(&[("HOMEDRIVE", "C:"), ("HOMEPATH", "relative")]),
                Platform::Windows,
                simulated_windows_absolute,
            ),
            None
        );
    }

    #[test]
    fn windows_rejects_device_namespaces_but_accepts_a_normal_unc_home() {
        for device in [r"\\?\C:\Users\operator", r"\\.\C:\Users\operator"] {
            assert_eq!(
                resolve_with(
                    source(&[("USERPROFILE", device)]),
                    Platform::Windows,
                    simulated_windows_absolute,
                ),
                None
            );
        }
        assert_eq!(
            resolve_with(
                source(&[("USERPROFILE", r"\\server\share\operator")]),
                Platform::Windows,
                simulated_windows_absolute,
            ),
            Some(PathBuf::from(r"\\server\share\operator"))
        );
    }
}
