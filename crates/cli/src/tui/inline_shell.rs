//! Pure TUI compatibility adapter for an ordinary host-owned shell receipt.

#[cfg(test)]
pub(super) async fn run_bash_inline(
    repo: &std::path::Path,
    command: &str,
    _: &[String],
    mode: iteron_protocol::PermissionMode,
    rules: &iteron_protocol::PermissionRules,
    cancelled: &mut tokio::sync::watch::Receiver<bool>,
) -> ShellCompletion {
    crate::client_effects::shell::run_fixture(repo, command, mode, rules, cancelled).await
}
