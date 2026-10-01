use super::*;
use crate::providers::ProviderDirectory;
use std::collections::BTreeMap;

fn view(digest: &str) -> ProviderCatalogView {
    let config = crate::config::ProviderConfig {
        id: "ui-provider".into(),
        display_name: Some("UI provider".into()),
        adapter: "openai_chat".into(),
        error_profile: Some("openai".into()),
        api_root: "http://127.0.0.1:9/v1".into(),
        key_env: Some("ITERON_UI_CATALOG_ABSENT_FIXTURE_KEY".into()),
        credential: None,
        enabled: true,
        catalog: false,
        models: vec!["m".into()],
        model_capabilities: BTreeMap::new(),
    };
    let directory = ProviderDirectory::inspect_local(&[config]).unwrap();
    ProviderCatalogView::capture(
        &directory,
        &ModelSelection {
            provider_id: "ui-provider".into(),
            model_id: "m".into(),
        },
        digest.into(),
        false,
    )
    .unwrap()
}
fn session() -> (Session, mpsc::Receiver<ControlRequest>) {
    let (submissions, _received) = mpsc::channel(4);
    let mut session = Session::for_test(submissions);
    let (sender, received) = mpsc::channel(4);
    session.control = sender;
    (session, received)
}

#[tokio::test]
async fn real_retry_receipt_precedes_selection_with_new_host_digest() {
    let (session, mut host) = session();
    let mut directory = view(&"1".repeat(64));
    let mut app = App::new();
    let mut effects = transcript_effect::Supervisor::default();
    let interrupt = Arc::new(AtomicBool::new(false));
    queue_retry(
        &mut app,
        &session,
        &directory,
        &mut effects,
        &interrupt,
        ModelSelection {
            provider_id: "ui-provider".into(),
            model_id: "m".into(),
        },
    );
    let request = host.recv().await.unwrap();
    assert!(matches!(
        request.control,
        Control::ProviderCatalog(ProviderCatalogControl::Retry(_))
    ));
    assert!(
        host.try_recv().is_err(),
        "selection cannot precede actual retry receipt"
    );
    request
        .reply
        .send(ControlReply::ProviderCatalog(Box::new(view(
            &"2".repeat(64),
        ))))
        .unwrap();
    let effect = effects.recv().await.unwrap();
    assert!(
        complete_retry(
            &mut app,
            &session,
            &mut directory,
            &mut effects,
            &interrupt,
            effect
        )
        .is_none()
    );
    let selected = host.recv().await.unwrap();
    match selected.control {
        Control::SelectModelV1(request) => {
            assert_eq!(request.inventory_digest_sha256, "2".repeat(64));
            assert_eq!(request.provider_id, "ui-provider");
            assert_eq!(request.model_id, "m");
        }
        _ => panic!("expected ordinary host model-selection request"),
    }
    selected
        .reply
        .send(ControlReply::Refused(
            "fixture ends at the actual selection boundary".into(),
        ))
        .unwrap();
    assert!(effects.recv().await.is_some());
}

#[tokio::test]
async fn cancelled_health_retry_does_not_dispatch_a_model_change() {
    let (session, mut host) = session();
    let mut directory = view(&"1".repeat(64));
    let mut app = App::new();
    let mut effects = transcript_effect::Supervisor::default();
    let interrupt = Arc::new(AtomicBool::new(false));
    queue_retry(
        &mut app,
        &session,
        &directory,
        &mut effects,
        &interrupt,
        ModelSelection {
            provider_id: "ui-provider".into(),
            model_id: "m".into(),
        },
    );
    let request = host.recv().await.unwrap();
    assert!(effects.cancel());
    request
        .reply
        .send(ControlReply::ProviderCatalog(Box::new(view(
            &"2".repeat(64),
        ))))
        .unwrap();
    let effect = effects.recv().await.unwrap();
    assert!(
        complete_retry(
            &mut app,
            &session,
            &mut directory,
            &mut effects,
            &interrupt,
            effect
        )
        .is_none()
    );
    assert!(host.try_recv().is_err());
    assert!(!effects.is_active());
}

#[tokio::test]
async fn first_frame_is_only_an_observed_typed_host_control() {
    let (sender, mut host) = mpsc::channel(1);
    let observed = first_frame(sender);
    let request = host.recv().await.unwrap();
    assert!(matches!(
        request.control,
        Control::ProviderCatalog(ProviderCatalogControl::FirstFrame)
    ));
    request
        .reply
        .send(ControlReply::ProviderCatalog(Box::new(view(
            &"1".repeat(64),
        ))))
        .unwrap();
    assert!(observed.await.unwrap().is_ok());
}

#[test]
fn selection_identity_comes_from_current_dto_and_unknown_route_refuses() {
    let directory = view(&"2".repeat(64));
    let selection = ModelSelection {
        provider_id: "ui-provider".into(),
        model_id: "m".into(),
    };
    assert_eq!(
        selection_request(&directory, &selection)
            .unwrap()
            .inventory_digest_sha256,
        "2".repeat(64)
    );
    assert!(
        selection_request(
            &directory,
            &ModelSelection {
                provider_id: "unknown".into(),
                model_id: "missing".into()
            }
        )
        .is_err()
    );
}

#[test]
fn native_immutable_catalog_renders_picker_without_provider_execution_authority() {
    let (session, _host) = session();
    let directory = view(&"2".repeat(64));
    let mut app = App::new();
    crate::tui::command_surfaces::open_picker(&mut app, &session, &directory, "model");
    let screen = crate::tui::tests::render_text(&mut app, 100, 28);
    assert!(screen.contains("UI provider"), "{screen}");
    assert!(screen.contains("Model"), "{screen}");
}
