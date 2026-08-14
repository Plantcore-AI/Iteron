use crate::{
    IMPLEMENTATION_PROTOCOL, IMPLEMENTATION_PROTOCOL_V1, ImplementationObservationEnvelope,
    ImplementationProtocolError, ImplementationRequest, ImplementationRequestEnvelope,
    ImplementationResponse, ImplementationResponseEnvelope, ImplementationState,
};
use iteron_protocol::{Capability, capability_set::CapabilitySet};
use iteron_tunables::{ModuleId, capability_seam_graph};

fn digest(byte: char) -> String {
    format!("sha256:{}", byte.to_string().repeat(64))
}

fn load_request() -> ImplementationRequestEnvelope {
    let node = capability_seam_graph()
        .nodes
        .into_iter()
        .find(|node| node.module == ModuleId::ProviderRouting)
        .unwrap();
    ImplementationRequestEnvelope {
        protocol: IMPLEMENTATION_PROTOCOL.into(),
        request_id: "request-1".into(),
        implementation_id: "provider.route.fast".into(),
        module: node.module,
        payload: ImplementationRequest::Load {
            lifecycle_contract: node.lifecycle.load,
            definition_contract: node.definition_contract,
            provider_contract: node.provider_contract,
            consumer_contract: node.consumer_contract,
            observation_schema: node.observation_schema,
            artifact_sha256: digest('a'),
            admitted_capabilities: CapabilitySet::only(Capability::ReadOnly),
        },
    }
}

#[test]
fn exact_seam_contract_and_response_correlation_are_required() {
    let request = load_request();
    request.validate().unwrap();
    let node = capability_seam_graph()
        .nodes
        .into_iter()
        .find(|node| node.module == request.module)
        .unwrap();
    let response = ImplementationResponseEnvelope {
        protocol: IMPLEMENTATION_PROTOCOL.into(),
        request_id: request.request_id.clone(),
        implementation_id: request.implementation_id.clone(),
        module: request.module,
        payload: ImplementationResponse::Loaded {
            provider_contract: node.provider_contract,
            observation_schema: node.observation_schema,
        },
    };
    response.validate_for(&request).unwrap();

    let mut rebound = response;
    rebound.request_id = "other-request".into();
    assert_eq!(
        rebound.validate_for(&request),
        Err(ImplementationProtocolError::Correlation)
    );
}

#[test]
fn wrong_module_contract_and_observation_schema_fail_closed() {
    let mut request = load_request();
    let wrong = capability_seam_graph()
        .nodes
        .into_iter()
        .find(|node| node.module == ModuleId::PromptSystem)
        .unwrap();
    let ImplementationRequest::Load {
        definition_contract,
        ..
    } = &mut request.payload
    else {
        unreachable!()
    };
    *definition_contract = wrong.definition_contract;
    assert_eq!(
        request.validate(),
        Err(ImplementationProtocolError::Contract)
    );

    let observation = ImplementationObservationEnvelope {
        protocol: IMPLEMENTATION_PROTOCOL.into(),
        implementation_id: "provider.route.fast".into(),
        module: ModuleId::ProviderRouting,
        run_id: "run-1".into(),
        sequence: 0,
        schema: wrong.observation_schema,
        terminal: false,
        observation: serde_json::json!({"route": "fast"}),
    };
    assert_eq!(
        observation.validate(),
        Err(ImplementationProtocolError::Contract)
    );
}

#[test]
fn protocol_parser_is_closed_and_size_bounded() {
    let mut value = serde_json::to_value(load_request()).unwrap();
    value["unexpected"] = serde_json::json!(true);
    let bytes = serde_json::to_vec(&value).unwrap();
    assert!(matches!(
        crate::parse_implementation_request(&bytes),
        Err(ImplementationProtocolError::MalformedJson(_))
    ));

    let oversized = vec![b' '; crate::MAX_IMPLEMENTATION_MESSAGE_BYTES + 1];
    assert!(matches!(
        crate::parse_implementation_request(&oversized),
        Err(ImplementationProtocolError::TooLarge { .. })
    ));
}

#[test]
fn v1_remains_compatible_only_for_stateless_operations() {
    let mut request = load_request();
    request.protocol = IMPLEMENTATION_PROTOCOL_V1.into();
    request.validate().expect("v1 load remains compatible");

    let node = capability_seam_graph()
        .nodes
        .into_iter()
        .find(|node| node.module == request.module)
        .unwrap();
    request.payload = ImplementationRequest::Snapshot {
        lifecycle_contract: node.lifecycle.snapshot.clone(),
        run_id: "run-1".into(),
        generation: 1,
        state_schema: node.lifecycle.snapshot,
        deadline_ms: 100,
    };
    assert_eq!(
        request.validate(),
        Err(ImplementationProtocolError::Operation)
    );
}

#[test]
fn v2_state_is_bounded_content_addressed_and_correlated() {
    let node = capability_seam_graph()
        .nodes
        .into_iter()
        .find(|node| node.module == ModuleId::ProviderRouting)
        .unwrap();
    let state = ImplementationState::new(
        ModuleId::ProviderRouting,
        "provider.route.fast",
        "run-1",
        7,
        node.lifecycle.snapshot.clone(),
        serde_json::json!({"counter": 42}),
    )
    .unwrap();
    let request = ImplementationRequestEnvelope {
        protocol: IMPLEMENTATION_PROTOCOL.into(),
        request_id: "request-state".into(),
        implementation_id: "provider.route.fast".into(),
        module: node.module,
        payload: ImplementationRequest::Snapshot {
            lifecycle_contract: node.lifecycle.snapshot.clone(),
            run_id: state.run_id.clone(),
            generation: state.generation,
            state_schema: state.state_schema.clone(),
            deadline_ms: 100,
        },
    };
    let response = ImplementationResponseEnvelope {
        protocol: IMPLEMENTATION_PROTOCOL.into(),
        request_id: request.request_id.clone(),
        implementation_id: request.implementation_id.clone(),
        module: request.module,
        payload: ImplementationResponse::Snapshotted {
            state: state.clone(),
        },
    };
    response.validate_for(&request).unwrap();

    let mut rebound = response;
    let ImplementationResponse::Snapshotted { state } = &mut rebound.payload else {
        unreachable!()
    };
    state.state = serde_json::json!({"counter": 43});
    assert_eq!(
        rebound.validate_for(&request),
        Err(ImplementationProtocolError::Field("state_sha256"))
    );

    let oversized = serde_json::Value::String("x".repeat(crate::MAX_IMPLEMENTATION_STATE_BYTES));
    assert!(matches!(
        ImplementationState::new(
            ModuleId::ProviderRouting,
            "provider.route.fast",
            "run-1",
            1,
            node.lifecycle.snapshot,
            oversized,
        ),
        Err(ImplementationProtocolError::TooLarge { .. })
    ));
}

#[test]
fn duplicate_json_keys_are_rejected_before_deserialization() {
    let serialized = serde_json::to_string(&load_request()).unwrap();
    let duplicate = format!(
        "{{\"protocol\":\"{IMPLEMENTATION_PROTOCOL}\",{}",
        &serialized[1..]
    );
    assert_eq!(
        crate::parse_implementation_request(duplicate.as_bytes()),
        Err(ImplementationProtocolError::DuplicateJsonKey)
    );
}
