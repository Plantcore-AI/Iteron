use super::*;

pub(super) fn model_picker_items(
    directory: &ProviderDirectory,
    current_provider: &str,
    current_model: &str,
) -> Vec<PickItem> {
    let mut items = Vec::new();
    let mut current_provider_seen = false;

    for entry in directory.entries() {
        let is_current_provider = entry.id() == current_provider;
        current_provider_seen |= is_current_provider;
        let provider_reason = directory.blocked_reason(entry);
        let provider_index = items.len();
        items.push(PickItem {
            label: entry.display_name().to_owned(),
            hint: directory.status_label(entry),
            is_current: is_current_provider,
            action: PickAction::Info,
            parent: None,
            depth: 0,
            expandable: true,
            expanded: is_current_provider,
            enabled: provider_reason.is_none(),
            disabled_reason: provider_reason.clone(),
        });

        let mut current_model_seen = false;
        if let Some(catalog) = &entry.catalog {
            for family in &catalog.families {
                let family_has_current = is_current_provider
                    && family
                        .models
                        .iter()
                        .any(|model| model.raw.id == current_model);
                current_model_seen |= family_has_current;
                let family_index = items.len();
                items.push(PickItem {
                    label: family.display_name.clone(),
                    hint: format!("{} models", family.models.len()),
                    is_current: false,
                    action: PickAction::Info,
                    parent: Some(provider_index),
                    depth: 1,
                    expandable: true,
                    expanded: family_has_current,
                    enabled: provider_reason.is_none(),
                    disabled_reason: provider_reason.clone(),
                });
                for model in &family.models {
                    let model_reason = provider_reason
                        .clone()
                        .or_else(|| directory.model_blocked_reason(entry.id(), &model.raw.id))
                        .or_else(|| match model.selectability {
                            core_provider::Selectability::Selectable => None,
                            core_provider::Selectability::Disabled { reason } => {
                                Some(reason.into())
                            }
                        });
                    let label = model
                        .raw
                        .display_name
                        .as_deref()
                        .filter(|name| *name != model.raw.id)
                        .map(|name| format!("{} · {name}", model.raw.id))
                        .unwrap_or_else(|| model.raw.id.clone());
                    let hint = model
                        .raw
                        .owned_by
                        .as_deref()
                        .map(|owner| format!("owned by {owner}"))
                        .unwrap_or_default();
                    items.push(PickItem {
                        label,
                        hint,
                        is_current: is_current_provider && model.raw.id == current_model,
                        action: PickAction::SetModel(ModelSelection {
                            provider_id: entry.id().to_owned(),
                            model_id: model.raw.id.clone(),
                        }),
                        parent: Some(family_index),
                        depth: 2,
                        expandable: false,
                        expanded: false,
                        enabled: model_reason.is_none(),
                        disabled_reason: model_reason,
                    });
                }
            }
        }

        // Keep the active pair visible even if a refresh no longer returns it. It is disabled when
        // the provider promised a catalog, and selectable only for an operator-declared
        // catalog-disabled gateway.
        if is_current_provider && !current_model.is_empty() && !current_model_seen {
            let family_index = items.len();
            items.push(PickItem {
                label: "Current / unverified".into(),
                hint: "pinned from this session".into(),
                is_current: false,
                action: PickAction::Info,
                parent: Some(provider_index),
                depth: 1,
                expandable: true,
                expanded: true,
                enabled: provider_reason.is_none() && !entry.catalog_enabled,
                disabled_reason: provider_reason.clone(),
            });
            let reason = provider_reason.clone().or_else(|| {
                entry
                    .catalog_enabled
                    .then(|| "not present in the current provider catalog".into())
            });
            items.push(PickItem {
                label: current_model.to_owned(),
                hint: "current selection".into(),
                is_current: true,
                action: PickAction::SetModel(ModelSelection {
                    provider_id: entry.id().to_owned(),
                    model_id: current_model.to_owned(),
                }),
                parent: Some(family_index),
                depth: 2,
                expandable: false,
                expanded: false,
                enabled: reason.is_none(),
                disabled_reason: reason,
            });
        } else if entry.catalog.is_none() {
            let reason = provider_reason
                .clone()
                .or_else(|| entry.catalog_error.clone())
                .unwrap_or_else(|| "no dynamic catalog loaded".into());
            items.push(PickItem {
                label: "Models unavailable".into(),
                hint: String::new(),
                is_current: false,
                action: PickAction::Info,
                parent: Some(provider_index),
                depth: 1,
                expandable: false,
                expanded: false,
                enabled: false,
                disabled_reason: Some(reason),
            });
        }
    }

    if !current_provider_seen && (!current_provider.is_empty() || !current_model.is_empty()) {
        let provider_index = items.len();
        items.push(PickItem {
            label: if current_provider.is_empty() {
                "Unresolved provider".into()
            } else {
                current_provider.to_owned()
            },
            hint: "current provider is not configured".into(),
            is_current: true,
            action: PickAction::Info,
            parent: None,
            depth: 0,
            expandable: true,
            expanded: true,
            enabled: false,
            disabled_reason: Some("provider is not configured".into()),
        });
        if !current_model.is_empty() {
            items.push(PickItem {
                label: current_model.to_owned(),
                hint: "current selection".into(),
                is_current: true,
                action: PickAction::Info,
                parent: Some(provider_index),
                depth: 1,
                expandable: false,
                expanded: false,
                enabled: false,
                disabled_reason: Some("provider is not configured".into()),
            });
        }
    }
    items
}

/// Build the `/mode` picker. The code clause is *derived* from the same gate the runtime consults,
/// never asserted: a session rule (`--allow-code`, `/permissions allow code_executing`) outranks the
/// mode table, so a hard-coded "code still gated" mislabels every session that carries such a grant.
pub(super) fn mode_picker_items(current: PermissionMode, rules: &PermissionRules) -> Vec<PickItem> {
    let code_clause = |mode: PermissionMode| match core_protocol::gate(
        mode,
        rules,
        "bash",
        Capability::CodeExecuting,
    ) {
        Verdict::Auto => "code auto",
        Verdict::Deny => "code denied",
        Verdict::Ask => "code still gated",
    };
    let modes = [
        (
            PermissionMode::Default,
            format!(
                "edits prompt live; {}",
                code_clause(PermissionMode::Default)
            ),
        ),
        (
            PermissionMode::AcceptEdits,
            format!("edits auto; {}", code_clause(PermissionMode::AcceptEdits)),
        ),
        (
            PermissionMode::Plan,
            "read-only; propose a plan first".to_string(),
        ),
        (
            PermissionMode::Yolo,
            "auto-approve (still asks for trust-mutating + egress)".to_string(),
        ),
    ];
    modes
        .into_iter()
        .map(|(mode, hint)| {
            PickItem::flat(
                mode.label(),
                hint,
                mode == current,
                PickAction::SetMode(mode),
            )
        })
        .collect()
}

/// The mode label as an operator should read it. Under the default bypass the mode still exists —
/// it is what `--ask-permissions` falls back to, and `plan` still hard-denies — but on its own the
/// label reads as a promise to prompt, which is false. Say both rather than either.
pub(super) fn permission_mode_row_value(session: &Session) -> String {
    let label = session.permission_mode().label().to_string();
    if session.bypass_permissions() {
        format!("{label} (bypassed: every tool auto-approves)")
    } else {
        label
    }
}

pub(super) fn permission_picker_items(rules: &PermissionRules, bypass: bool) -> Vec<PickItem> {
    let caps = [
        (Capability::ReversibleLocal, "Reversible edits"),
        (Capability::CodeExecuting, "Code execution"),
        (Capability::TrustMutating, "Trust and policy changes"),
        (
            Capability::IrreversibleExternal,
            "External actions and network access",
        ),
    ];
    let verdicts = [
        (Verdict::Auto, "allow automatically"),
        (Verdict::Ask, "ask every time"),
        (Verdict::Deny, "deny"),
    ];
    let mut items = Vec::new();
    if bypass {
        items.push(PickItem {
            label: "Permission gate → BYPASSED for this session".into(),
            hint: "every tool auto-approves; the rows below take effect only under \
                   --ask-permissions, except an explicit deny, which still applies"
                .into(),
            is_current: false,
            action: PickAction::Info,
            parent: None,
            depth: 0,
            expandable: false,
            expanded: false,
            enabled: false,
            disabled_reason: Some(
                "started with the default bypass; re-run with --ask-permissions to restore the gate"
                    .into(),
            ),
        });
    }
    items.push(PickItem {
        label: "Read-only operations → always allow".into(),
        hint: "viewing files and metadata does not prompt".into(),
        is_current: false,
        action: PickAction::Info,
        parent: None,
        depth: 0,
        expandable: false,
        expanded: false,
        enabled: false,
        disabled_reason: Some(
            "read-only operations are always allowed and are not configurable".into(),
        ),
    });

    for (capability, capability_label) in caps {
        for (verdict, verdict_label) in verdicts {
            let forbidden_auto = verdict == Verdict::Auto
                && matches!(
                    capability,
                    Capability::TrustMutating | Capability::IrreversibleExternal
                );
            items.push(PickItem {
                label: format!("{capability_label} → {verdict_label}"),
                hint: String::new(),
                is_current: rules.cap_rule(capability) == Some(verdict),
                action: PickAction::SetCap(capability, verdict),
                parent: None,
                depth: 0,
                expandable: false,
                expanded: false,
                enabled: !forbidden_auto,
                disabled_reason: forbidden_auto
                    .then(|| "non-negotiable: this capability always requires approval".into()),
            });
        }
    }
    items
}
