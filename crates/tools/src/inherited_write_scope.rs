//! Host-only literal write authority. Private helper envelopes carry this value separately from
//! model ToolUse input; native descriptors retain it through commit and rollback boundaries.
use iteron_protocol::ToolUse;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct InheritedWriteScope {
    paths: Vec<String>,
}
impl InheritedWriteScope {
    pub(crate) fn validate_tool(
        &self,
        call: &ToolUse,
        capability: iteron_protocol::Capability,
    ) -> Result<(), String> {
        if capability != iteron_protocol::Capability::ReadOnly
            && !matches!(call.name.as_str(), "write_file" | "edit" | "apply_patch")
        {
            return Err(
                "inherited writer authority admits only native scoped file mutations".into(),
            );
        }
        Ok(())
    }
    pub(crate) fn new(paths: Vec<String>) -> Result<Self, String> {
        iteron_protocol::agent_control::validate_write_paths(&paths).map_err(str::to_owned)?;
        Ok(Self { paths })
    }
    pub(crate) fn validate(&self) -> Result<(), String> {
        iteron_protocol::agent_control::validate_write_paths(&self.paths).map_err(str::to_owned)
    }
    pub(crate) fn allows_relative(&self, path: &Path) -> bool {
        !path.as_os_str().is_empty()
            && !path.components().any(|part| match part {
                std::path::Component::Normal(name) => name.to_str().is_none_or(|name| {
                    matches!(
                        name.to_ascii_lowercase().as_str(),
                        ".git"
                            | ".gitconfig"
                            | ".gitattributes"
                            | ".gitmodules"
                            | ".github"
                            | ".iteron"
                            | ".claude"
                            | ".agents"
                            | ".codex"
                            | ".mcp.json"
                            | "agents.md"
                            | "claude.md"
                            | "skill.md"
                    )
                }),
                _ => true,
            })
            && path
                .components()
                .all(|part| matches!(part, std::path::Component::Normal(_)))
            && self
                .paths
                .iter()
                .any(|allowed| path == Path::new(allowed) || path.starts_with(allowed))
    }
    pub(crate) fn validate_target(&self, root: &Path, target: &Path) -> Result<(), String> {
        self.validate()?;
        let root = root
            .canonicalize()
            .map_err(|_| "inherited write root is unavailable")?;
        let relative = target
            .strip_prefix(&root)
            .map_err(|_| "write resolves outside inherited workspace")?;
        if !self.allows_relative(relative) {
            return Err("write target exceeds inherited literal paths".into());
        }
        let target =
            crate::resolve_in_root(&root, target.to_str().ok_or("non-UTF-8 scoped target")?)?;
        let relative = target
            .strip_prefix(&root)
            .map_err(|_| "write resolves outside inherited workspace")?;
        if !self.allows_relative(relative) {
            return Err("canonical target exceeds inherited literal paths".into());
        }
        Ok(())
    }
    pub(crate) fn validate_call(&self, root: &Path, call: &ToolUse) -> Result<(), String> {
        self.validate()?;
        let paths: Vec<&str> = if call.name == "apply_patch" {
            let files = call
                .input
                .get("files")
                .and_then(serde_json::Value::as_array)
                .ok_or("scoped patch needs files")?;
            if files.len() > 64 {
                return Err("scoped patch has too many targets".into());
            }
            files
                .iter()
                .map(|file| {
                    file.get("path")
                        .and_then(serde_json::Value::as_str)
                        .ok_or("scoped patch path is invalid")
                })
                .collect::<Result<_, _>>()?
        } else if matches!(call.name.as_str(), "edit" | "write_file") {
            vec![
                call.input
                    .get("path")
                    .and_then(serde_json::Value::as_str)
                    .ok_or("scoped write path is invalid")?,
            ]
        } else {
            return Ok(());
        };
        if paths.is_empty() {
            return Err("scoped write has no targets".into());
        }
        let root = root
            .canonicalize()
            .map_err(|_| "scoped workspace is unavailable")?;
        for requested in paths {
            let logical = PathBuf::from(requested);
            if !self.allows_relative(&logical) {
                return Err("logical write target exceeds inherited literal paths".into());
            }
            let target = crate::resolve_in_root(&root, requested)?;
            self.validate_target(&root, &target)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use iteron_protocol::ToolUse;
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(1);
    struct Root(PathBuf);
    impl Root {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "iteron-inherited-scope-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir_all(path.join("allowed")).unwrap();
            std::fs::create_dir_all(path.join("other")).unwrap();
            Self(path)
        }
    }
    impl Drop for Root {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    fn call(path: &str) -> ToolUse {
        ToolUse {
            id: "scoped".into(),
            name: "write_file".into(),
            input: serde_json::json!({"path":path,"content":"after"}),
        }
    }
    #[test]
    fn empty_scope_and_model_input_cannot_authorize_a_destination() {
        let root = Root::new();
        let empty = InheritedWriteScope::new(vec![]).unwrap();
        assert!(empty.validate_call(&root.0, &call("allowed/file")).is_err());
        let scope = InheritedWriteScope::new(vec!["allowed".into()]).unwrap();
        let mut forged = call("other/file");
        forged.input["scope"] = serde_json::json!({"paths":["other"]});
        assert!(scope.validate_call(&root.0, &forged).is_err());
        assert!(scope.validate_call(&root.0, &call("allowed/file")).is_ok());
        for path in [
            "allowed/.gitattributes",
            "allowed/.gitmodules",
            "allowed/.gitconfig",
            "allowed/.agents/config",
            "allowed/SKILL.md",
        ] {
            assert!(scope.validate_call(&root.0, &call(path)).is_err());
        }
        assert!(
            scope
                .validate_call(&root.0, &call("allowed/../other/file"))
                .is_err()
        );
        assert!(
            scope
                .validate_call(&root.0, &call("allowed-neighbor/file"))
                .is_err()
        );
    }
    #[cfg(unix)]
    #[test]
    fn logical_alias_and_canonical_destination_both_need_scope() {
        let root = Root::new();
        std::os::unix::fs::symlink(root.0.join("other"), root.0.join("allowed/link")).unwrap();
        let scope = InheritedWriteScope::new(vec!["allowed".into()]).unwrap();
        assert!(
            scope
                .validate_call(&root.0, &call("allowed/link/file"))
                .is_err()
        );
        std::os::unix::fs::symlink(root.0.join("allowed"), root.0.join("alias")).unwrap();
        assert!(scope.validate_call(&root.0, &call("alias/file")).is_err());
    }
    #[cfg(unix)]
    #[tokio::test]
    async fn descriptor_commit_refuses_directory_retarget_inside_workspace() {
        let root = Root::new();
        std::fs::write(root.0.join("allowed/file"), "before").unwrap();
        std::fs::write(root.0.join("other/file"), "protected").unwrap();
        let scope = InheritedWriteScope::new(vec!["allowed".into()]).unwrap();
        let result = crate::write_file::write_workspace_file_with_scope(
            &root.0,
            "allowed/file",
            "after",
            true,
            Some(&scope),
            |_| {
                std::fs::rename(root.0.join("allowed"), root.0.join("old")).unwrap();
                std::os::unix::fs::symlink(root.0.join("other"), root.0.join("allowed")).unwrap();
            },
        )
        .await;
        assert!(result.is_err());
        assert_eq!(
            std::fs::read_to_string(root.0.join("old/file")).unwrap(),
            "before"
        );
        assert_eq!(
            std::fs::read_to_string(root.0.join("other/file")).unwrap(),
            "protected"
        );
    }
    #[cfg(unix)]
    #[tokio::test]
    async fn patch_refuses_one_outside_member_before_any_replace() {
        let root = Root::new();
        std::fs::write(root.0.join("allowed/file"), "before").unwrap();
        std::fs::write(root.0.join("other/file"), "protected").unwrap();
        let scope = InheritedWriteScope::new(vec!["allowed".into()]).unwrap();
        let call = ToolUse {
            id: "batch".into(),
            name: "apply_patch".into(),
            input: serde_json::json!({"files":[{"path":"allowed/file","hunks":[{"old":"before","new":"after"}]},{"path":"other/file","hunks":[{"old":"protected","new":"changed"}]}]}),
        };
        assert!(scope.validate_call(&root.0, &call).is_err());
        let result =
            crate::multi_file_patch::apply_patch_scoped(&root.0, &call.input, Some(&scope)).await;
        assert!(result.is_err());
        assert_eq!(
            std::fs::read_to_string(root.0.join("allowed/file")).unwrap(),
            "before"
        );
        assert_eq!(
            std::fs::read_to_string(root.0.join("other/file")).unwrap(),
            "protected"
        );
    }
}
