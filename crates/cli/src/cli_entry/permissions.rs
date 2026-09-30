//! Pure launch authority admission and posture selection.

use super::options::Cli;
pub(crate) const DEFAULT_ALLOW_CODE: bool = true;

/// The trusted (pre-project-tightening) code-execution grant. Code starts enabled in the ordinary
/// session; a trusted user setting or repository `allow_code:false` may tighten its rule, and
/// `--mode plan` disables execution. A cloned repository cannot turn execution back on.
pub(crate) fn trusted_allow_code(cli_flag: bool, user_config: Option<bool>) -> bool {
    cli_flag || user_config.unwrap_or(DEFAULT_ALLOW_CODE)
}

/// The mode is separate from bypass authority. `--ask-permissions` selects stricter mode and
/// disables bypass for a fresh session; checkpoint authority is checked separately on resume.
pub(crate) fn default_permission_mode(ask_permissions: bool) -> iteron_protocol::PermissionMode {
    if ask_permissions {
        iteron_protocol::PermissionMode::Default
    } else {
        iteron_protocol::PermissionMode::AcceptEdits
    }
}

pub(crate) fn confined_execution(
    dangerously_bypass_permissions: bool,
    force_confine: bool,
) -> bool {
    !dangerously_bypass_permissions || force_confine
}

pub(crate) fn fresh_permission_bypass(
    dangerous_flag: bool,
    ask_permissions: bool,
    explicit_mode: Option<iteron_protocol::PermissionMode>,
) -> bool {
    use iteron_protocol::PermissionMode;
    if ask_permissions || explicit_mode == Some(PermissionMode::Plan) {
        false
    } else {
        dangerous_flag
            || !matches!(
                explicit_mode,
                Some(PermissionMode::Default | PermissionMode::AcceptEdits)
            )
    }
}

pub(crate) fn requested_permission_bypass(
    resuming: bool,
    dangerous_flag: bool,
    ask_permissions: bool,
    explicit_mode: Option<iteron_protocol::PermissionMode>,
) -> Option<bool> {
    if !resuming {
        Some(fresh_permission_bypass(
            dangerous_flag,
            ask_permissions,
            explicit_mode,
        ))
    } else if ask_permissions {
        Some(false)
    } else if dangerous_flag {
        Some(true)
    } else if matches!(
        explicit_mode,
        Some(
            iteron_protocol::PermissionMode::Default | iteron_protocol::PermissionMode::AcceptEdits
        )
    ) {
        Some(false)
    } else {
        None
    }
}

/// An absent CLI override preserves the checkpoint, including an older gated default. There is
/// no durable bypass transition, so explicit conflicting authority requests fail rather than
/// silently upgrading or downgrading a resumed run. Confinement may still be tightened.
pub(crate) fn admitted_execution_posture(
    pinned_bypass: bool,
    requested_bypass: Option<bool>,
    force_confine: bool,
) -> anyhow::Result<bool> {
    if requested_bypass.is_some_and(|requested| requested != pinned_bypass) {
        anyhow::bail!(
            "recorded permission bypass ({pinned_bypass}) disagrees with the explicit permission request; omit that override to preserve recorded authority, or start a new run. Iteron will not change a checkpoint's bypass silently"
        );
    }
    Ok(confined_execution(pinned_bypass, force_confine))
}

pub(crate) fn dangerous_bypass_notice() -> &'static str {
    "WARNING: DANGEROUS BYPASS active (the fresh-session default): tools may act without approval. Without --confine, code has host authority. Use --ask-permissions for a new gated session or --mode plan for read-only; explicit denies and authority ceilings still apply."
}

/// The session rules a fresh run starts with. Only the operator's code-execution grant is seeded;
/// everything else is left to the mode×capability table, which is what
/// `docs/using/permissions-and-sandbox.md` documents. Seeding `web_fetch`/`web_search` as `Auto`
/// here used to pre-approve egress on every install — an exact-tool rule outranks the table, so the
/// `irreversible_external` "always asks" row was unreachable and no default install ever prompted
/// before reaching the network.
pub(crate) fn initial_permission_rules(allow_code: bool) -> iteron_protocol::PermissionRules {
    let mut rules = iteron_protocol::PermissionRules::new();
    if allow_code {
        rules.allow_cap(iteron_protocol::Capability::CodeExecuting);
    }
    rules
}
