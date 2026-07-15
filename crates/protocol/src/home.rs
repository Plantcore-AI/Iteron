//! Core's single on-disk home directory.
//!
//! This is an intentionally breaking contract: runtime state, configuration, skills, agents and
//! memory are read from and written to `.core/` only. Discovery does not union historical product
//! directories and no compatibility fallback exists.

use std::path::{Path, PathBuf};

/// The only product home-directory name understood by Core.
pub const HOME_DIR: &str = ".core";

/// Build `<base>/.core/<sub>` deterministically.
pub fn path(base: &Path, sub: &str) -> PathBuf {
    base.join(HOME_DIR).join(sub)
}

/// True only for the current Core home-directory component.
pub fn is_home_dir(name: &str) -> bool {
    name == HOME_DIR
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_has_one_unambiguous_home() {
        assert_eq!(
            path(Path::new("/repo"), "skills"),
            PathBuf::from("/repo/.core/skills")
        );
        assert!(is_home_dir(".core"));
        assert!(!is_home_dir(".git"));
        assert!(!is_home_dir("core"));
    }
}
