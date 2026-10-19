//! Shared local fixtures for host and terminal adapter conformance tests.
use super::*;
pub(super) fn pin_test_tunables(
    agent: &mut Agent,
    orchestrated: bool,
    provider_id: &str,
    model_id: &str,
) {
    pin_test_tunables_with_hooks(agent, orchestrated, provider_id, model_id, None);
}

pub(super) fn pin_test_tunables_with_hooks(
    agent: &mut Agent,
    orchestrated: bool,
    provider_id: &str,
    model_id: &str,
    hooks: Option<&crate::runtime::hooks::Hooks>,
) {
    const FIXED_ARTIFACT_FAMILIES: &[&str] = &[
        "hooks_map",
        "operator_prompt_stream",
        "instruction_bundle",
        "memory_corpus",
        "skill_catalog",
        "provider_model_capability_catalog",
        "mcp_topology_tool_catalog",
        "mcp_transport_selection",
        "oauth_auth_lifecycle_policy",
        "web_search_backend_catalog",
    ];
    let hooks_identity = hooks
        .filter(|hooks| !hooks.is_empty())
        .map(|hooks| hooks.catalog_identity());
    let mut input = iteron_record::resolved_fixture::input();
    let retained = |family: &str| {
        !FIXED_ARTIFACT_FAMILIES.contains(&family)
            || (family == "hooks_map" && hooks_identity.is_some())
    };
    input
        .declared_values
        .retain(|value| retained(&value.family));
    input
        .constraint_evidence
        .retain(|value| retained(&value.family));
    if let Some(identity) = hooks_identity {
        let value = iteron_tunables::ResolutionValue::CatalogRef {
            catalog_id: "iteron://tunables/catalogs/hooks_map-v1".into(),
            digest_sha256: identity.digest_sha256,
            entry_count: u64::try_from(identity.entry_count).unwrap(),
            canonical_bytes: u64::try_from(identity.canonical_bytes).unwrap(),
        };
        input
            .declared_values
            .iter_mut()
            .find(|entry| entry.family == "hooks_map")
            .unwrap()
            .value = value.clone();
        for evidence in input
            .constraint_evidence
            .iter_mut()
            .filter(|entry| entry.family == "hooks_map")
        {
            let iteron_tunables::ConstraintValue::Domain {
                allowed_values,
                preferred,
                ..
            } = &mut evidence.value
            else {
                panic!("hook identity must retain its operator-attested domain")
            };
            *allowed_values = Some([value.clone()].into_iter().collect());
            if preferred.is_some() {
                *preferred = Some(value.clone());
            }
        }
    }

    let context_window = iteron_tunables::ResolutionValue::Integer { value: 120_000 };
    let window = input
        .declared_values
        .iter_mut()
        .find(|value| value.family == "context_window_override_reserve")
        .expect("context-window fixture value");
    let iteron_tunables::ResolutionValue::Object { fields } = &mut window.value else {
        panic!("context-window fixture stopped being an object")
    };
    fields.insert("model_window_tokens".into(), context_window.clone());
    fields.insert(
        "tool_schema_budget_tokens".into(),
        iteron_tunables::ResolutionValue::Integer { value: 20_000 },
    );
    let ceiling = input
        .constraint_evidence
        .iter_mut()
        .find(|evidence| {
            evidence.family == "context_window_override_reserve"
                && evidence.field == "model_window_tokens"
                && evidence.ceiling == iteron_tunables::ExternalCeiling::ProviderCapability
        })
        .expect("context-window provider ceiling");
    ceiling.value = iteron_tunables::ConstraintValue::Domain {
        minimum: None,
        maximum: None,
        allowed_values: Some(
            [context_window.clone()]
                .into_iter()
                .collect::<std::collections::BTreeSet<_>>(),
        ),
        required_values: None,
        preferred: Some(context_window),
    };
    let context_ceiling = input
        .constraint_evidence
        .iter_mut()
        .find(|evidence| {
            evidence.family == "context_window_override_reserve"
                && evidence.field == "model_window_tokens"
                && evidence.ceiling == iteron_tunables::ExternalCeiling::ContextWindow
        })
        .expect("context-window local ceiling");
    context_ceiling.value = iteron_tunables::ConstraintValue::UpperBound {
        value: iteron_tunables::ResolutionValue::Integer { value: 120_000 },
    };

    let graph = iteron_workflow::workflow_graph_runtime_identity();
    let workflow_graph = iteron_tunables::ResolutionValue::CatalogRef {
        catalog_id: "iteron://tunables/catalogs/workflow_graph-v1".into(),
        digest_sha256: graph.digest_sha256,
        entry_count: u64::try_from(graph.entry_count).unwrap(),
        canonical_bytes: u64::try_from(graph.canonical_bytes).unwrap(),
    };
    let environment = iteron_protocol::EnvironmentSnapshotIdentity::from_optional(None);
    let environment_value = iteron_tunables::ResolutionValue::Object {
        fields: [
            (
                "present".into(),
                iteron_tunables::ResolutionValue::Boolean {
                    value: environment.present,
                },
            ),
            (
                "digest_sha256".into(),
                iteron_tunables::ResolutionValue::Text {
                    value: environment.digest_sha256,
                },
            ),
            (
                "canonical_bytes".into(),
                iteron_tunables::ResolutionValue::Integer {
                    value: i64::try_from(environment.canonical_bytes).unwrap(),
                },
            ),
            (
                "trust".into(),
                iteron_tunables::ResolutionValue::Enum {
                    value: "trusted".into(),
                },
            ),
        ]
        .into_iter()
        .collect(),
    };
    let live_catalog = agent.agent_catalog_snapshot();
    let catalog = live_catalog.runtime_identity();
    let agent_catalog = iteron_tunables::ResolutionValue::CatalogRef {
        catalog_id: "iteron://tunables/catalogs/agent_catalog-v1".into(),
        digest_sha256: catalog.digest_sha256,
        entry_count: u64::try_from(catalog.entry_count).unwrap(),
        canonical_bytes: u64::try_from(catalog.canonical_bytes).unwrap(),
    };
    for (family, value) in [
        ("workflow_graph", workflow_graph),
        ("environment_snapshot", environment_value),
        ("agent_catalog", agent_catalog),
    ] {
        input
            .declared_values
            .iter_mut()
            .find(|candidate| candidate.family == family)
            .unwrap_or_else(|| panic!("resolved fixture omitted {family}"))
            .value = value.clone();
        for evidence in input
            .constraint_evidence
            .iter_mut()
            .filter(|evidence| evidence.family == family)
        {
            if let iteron_tunables::ConstraintValue::Domain { allowed_values, .. } =
                &mut evidence.value
            {
                *allowed_values = Some([value.clone()].into_iter().collect());
            }
        }
    }
    let admitted_role_routes =
        crate::runtime_tunables::execution_policy::admitted_role_model_routes(
            live_catalog.as_ref(),
            provider_id,
            model_id,
        )
        .expect("the live test catalog must resolve role-specific routes");
    let selected_route = format!("{provider_id}:{model_id}");
    let role_specific_models = iteron_tunables::ResolutionValue::Map {
        entries: admitted_role_routes
            .iter()
            .map(|(role, route)| {
                (
                    role.clone(),
                    iteron_tunables::ResolutionValue::Enum {
                        value: route.clone(),
                    },
                )
            })
            .collect(),
    };
    for (catalog_id, values) in [
        (
            "iteron://tunables/catalogs/agent-roles-v1",
            live_catalog
                .defs()
                .iter()
                .map(|definition| definition.name.clone())
                .collect::<std::collections::BTreeSet<_>>(),
        ),
        (
            "iteron://tunables/catalogs/model-routes-v1",
            admitted_role_routes
                .values()
                .cloned()
                .chain(std::iter::once(selected_route.clone()))
                .collect::<std::collections::BTreeSet<_>>(),
        ),
    ] {
        let snapshot = iteron_tunables::runtime_catalog_snapshot(catalog_id, values)
            .expect("test catalog owner must publish bounded route values");
        *input
            .runtime
            .catalogs
            .iter_mut()
            .find(|catalog| catalog.catalog_id == catalog_id)
            .unwrap_or_else(|| panic!("resolved fixture omitted {catalog_id}")) = snapshot;
    }
    for (family, value) in [
        ("role_specific_model_map", role_specific_models.clone()),
        (
            "per_agent_model",
            iteron_tunables::ResolutionValue::Enum {
                value: selected_route.clone(),
            },
        ),
    ] {
        input
            .declared_values
            .iter_mut()
            .find(|declared| declared.family == family)
            .unwrap_or_else(|| panic!("resolved fixture omitted {family}"))
            .value = value;
    }
    for evidence in &mut input.constraint_evidence {
        match evidence.family.as_str() {
            "role_specific_model_map" => {
                let iteron_tunables::ConstraintValue::Domain { allowed_values, .. } =
                    &mut evidence.value
                else {
                    panic!("role-specific model ceiling stopped being a domain")
                };
                *allowed_values = Some([role_specific_models.clone()].into_iter().collect());
            }
            "per_agent_model" => {
                let iteron_tunables::ConstraintValue::Domain {
                    allowed_values,
                    preferred,
                    ..
                } = &mut evidence.value
                else {
                    panic!("per-agent model ceiling stopped being a domain")
                };
                let selected = iteron_tunables::ResolutionValue::Enum {
                    value: selected_route.clone(),
                };
                *allowed_values = Some([selected.clone()].into_iter().collect());
                if evidence.ceiling == iteron_tunables::ExternalCeiling::ProviderCapability {
                    *preferred = Some(selected);
                }
            }
            _ => {}
        }
    }
    if orchestrated {
        let route_topology = iteron_tunables::ResolutionValue::Enum {
            value: "orchestrated".into(),
        };
        input
            .declared_values
            .iter_mut()
            .find(|declared| declared.family == "route_topology")
            .expect("route-topology fixture value")
            .value = route_topology.clone();
        for evidence in input
            .constraint_evidence
            .iter_mut()
            .filter(|evidence| evidence.family == "route_topology")
        {
            match &mut evidence.value {
                iteron_tunables::ConstraintValue::Domain {
                    allowed_values,
                    preferred,
                    ..
                } => {
                    *allowed_values = Some([route_topology.clone()].into_iter().collect());
                    if preferred.is_some() {
                        *preferred = Some(route_topology.clone());
                    }
                }
                iteron_tunables::ConstraintValue::Exact { value } => {
                    *value = route_topology.clone();
                }
                iteron_tunables::ConstraintValue::UpperBound { .. } => {
                    panic!("route topology cannot have an upper-bound constraint")
                }
            }
        }
    }
    let resolved = iteron_tunables::resolve(input)
        .expect("the production-compatible app-server fixture must resolve");
    let resolved = iteron_tunables::with_synthetic_fixed_authority_attestations_for_test(resolved)
        .expect("the resolver-only fixture must bind every effective fixed authority");
    agent
        .pin_resolved_tunables(Arc::new(resolved))
        .expect("the canonical resolved fixture must install before app-server execution");
    let effective = crate::runtime_tunables::effective_runtime::decode_checkpoint(
        agent.tunables_checkpoint().unwrap(),
        None,
    )
    .expect("the canonical checkpoint must have an executable runtime projection")
    .core;
    agent.model_context_window = effective.model_context_window;
    agent.model_max_output_tokens = effective.request_output_cap;
    if orchestrated {
        agent
            .set_provider_controls(effective.provider_governor.controls)
            .expect("the fixture provider must attest the checkpoint-derived controls");
        agent
            .install_provider_governor(
                effective.provider_governor.policy,
                [format!("{provider_id}:{model_id}")],
            )
            .expect("the fixture must install one provider-governor owner before execution");
    }
}

pub fn navigation_agent(workspace: &std::path::Path) -> Agent {
    use sha2::Digest;
    use std::collections::BTreeMap;
    let credential = workspace.join("fixture-credential");
    std::fs::write(&credential, "test-only-navigation-token\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&credential, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let config = crate::config::ProviderConfig {
        id: "fixture-navigation".into(),
        display_name: Some("Navigation fixture".into()),
        adapter: "openai_chat".into(),
        error_profile: Some("openai".into()),
        api_root: "http://127.0.0.1:9/v1".into(),
        key_env: None,
        credential: Some(crate::config::ProviderCredential::File {
            path: credential.display().to_string(),
        }),
        enabled: true,
        catalog: false,
        models: vec!["m".into()],
        model_capabilities: BTreeMap::new(),
    };
    let config_digest = format!(
        "sha256:{}",
        hex::encode(sha2::Sha256::digest(serde_json::to_vec(&config).unwrap()))
    );
    let directory = crate::providers::ProviderDirectory::inspect_local(&[config]).unwrap();
    let selection = crate::providers::ModelSelection {
        provider_id: "fixture-navigation".into(),
        model_id: "m".into(),
    };
    let rollout = iteron_record::Rollout::open(
        &workspace.join(".iteron/runs"),
        &RunId("navigation-origin".into()),
        iteron_protocol::TenantId::default(),
    )
    .unwrap();
    let mut agent = Agent::new(
        directory.build(&selection).unwrap(),
        iteron_tools::Registry::coding_agent(workspace).unwrap(),
        rollout,
        "m".into(),
        "system".into(),
        iteron_protocol::Budget {
            max_turns: 4,
            max_usd: None,
            max_tokens: None,
            max_wall_secs: 30,
            max_consecutive_tool_errors: 3,
        },
    );
    agent.workspace = workspace.to_path_buf();
    pin_test_tunables(
        &mut agent,
        false,
        &selection.provider_id,
        &selection.model_id,
    );
    agent
        .record_genesis_with_tunables(workspace.display().to_string(), 1, config_digest, None)
        .unwrap();
    agent
        .install_client_inventory(
            crate::client_inventory::ClientInventoryOwner::capture(
                &directory,
                &crate::plugin_runtime::RuntimePlugins::default(),
                &selection,
            )
            .unwrap(),
        )
        .unwrap();
    agent
}
