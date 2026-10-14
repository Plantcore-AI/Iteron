use super::physical_input_ceiling;
use crate::{Anthropic, ApiRoot, OpenAiCompat, Provider, StaticProviderMetadata};
use std::sync::Arc;

#[test]
fn injected_planning_metadata_cannot_shrink_the_literal_physical_baseline() {
    let mut document: serde_json::Value =
        serde_json::from_str(include_str!("../static-provider-metadata-v1.json")).unwrap();
    for (route, family) in [
        ("openai_responses", "gpt-5.6"),
        ("anthropic_messages", "claude-opus-4-7"),
    ] {
        document["model_capabilities"][route]["families"][family]["context_window_tokens"] =
            serde_json::json!(1024);
        document["model_capabilities"][route]["families"][family]["max_output_tokens"] =
            serde_json::json!(512);
    }
    StaticProviderMetadata::stamp_content_versions(&mut document).unwrap();
    let configured = Arc::new(
        StaticProviderMetadata::from_slice(&serde_json::to_vec(&document).unwrap()).unwrap(),
    );
    let chat = OpenAiCompat::with_root(
        "fixture".into(),
        ApiRoot::parse("https://api.openai.com/v1").unwrap(),
    )
    .unwrap()
    .with_static_metadata(configured.clone());
    let messages = Anthropic::new("fixture".into(), None)
        .unwrap()
        .with_static_metadata(configured.clone());
    for (provider, root, model) in [
        (
            &chat as &dyn Provider,
            "https://api.openai.com/v1",
            "gpt-5.6",
        ),
        (
            &messages as &dyn Provider,
            "https://api.anthropic.com/v1",
            "claude-opus-4-7",
        ),
    ] {
        assert_eq!(
            configured
                .route_model_capabilities(root, model)
                .unwrap()
                .context_window_tokens,
            Some(1024)
        );
        let baseline = StaticProviderMetadata::shipped_physical_input_ceiling(root, model).unwrap();
        assert!(baseline > 1024);
        assert_eq!(provider.physical_input_token_ceiling(model), Some(baseline));
    }
    // Bigger current native capability must increase the bound, not be capped at old shipped data.
    document["model_capabilities"]["openai_responses"]["families"]["gpt-5.6"]["context_window_tokens"] =
        serde_json::json!(2_000_000);
    StaticProviderMetadata::stamp_content_versions(&mut document).unwrap();
    let bigger =
        StaticProviderMetadata::from_slice(&serde_json::to_vec(&document).unwrap()).unwrap();
    assert_eq!(
        physical_input_ceiling(&bigger, "https://api.openai.com/v1", "gpt-5.6"),
        Some(2_000_000)
    );
}

#[test]
fn configured_lookalike_route_cannot_mint_a_new_physical_baseline() {
    let mut document: serde_json::Value =
        serde_json::from_str(include_str!("../static-provider-metadata-v1.json")).unwrap();
    document["model_capabilities"]["openai_responses"]["api_root"] =
        serde_json::json!("https://gateway.invalid/v1");
    StaticProviderMetadata::stamp_content_versions(&mut document).unwrap();
    let configured =
        StaticProviderMetadata::from_slice(&serde_json::to_vec(&document).unwrap()).unwrap();
    assert!(
        configured
            .route_model_capabilities("https://gateway.invalid/v1", "gpt-5.6")
            .is_some()
    );
    assert_eq!(
        physical_input_ceiling(&configured, "https://gateway.invalid/v1", "gpt-5.6"),
        None
    );
    assert_eq!(
        StaticProviderMetadata::shipped_physical_input_ceiling(
            "https://gateway.invalid/v1",
            "gpt-5.6"
        ),
        None
    );
}
