use super::Fixture;
use crate::artifacts::{ArtifactSchema, storage};
use base64::Engine as _;
use iteron_protocol::ToolUse;
use iteron_tools::CapturedToolImage;

fn image() -> CapturedToolImage {
    // A generated single red RGBA pixel, with actual PNG compression and chunk checksums.
    let bytes = base64::engine::general_purpose::STANDARD
        .decode("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR4nGP4z8DwHwAFAAH/iZk9HQAAAABJRU5ErkJggg==")
        .unwrap();
    CapturedToolImage::png(bytes)
        .unwrap()
        .with_browser_observation("https://example.com/?token=private-source".into(), 123456)
        .unwrap()
}
fn call() -> ToolUse {
    ToolUse {
        id: "screenshot".into(),
        name: "computer".into(),
        input: serde_json::json!({}),
    }
}

#[test]
fn exact_png_and_separate_source_metadata_survive_owner_restart_and_revocation() {
    let fixture = Fixture::new();
    let image = image();
    let descriptor = fixture
        .store()
        .publish_tool_image(2, &call(), &image)
        .unwrap();
    let reopened = fixture.store();
    let metadata_chunk = fixture.read(&reopened, &descriptor.artifact_id, 0, 65536);
    let metadata = base64::engine::general_purpose::STANDARD
        .decode(metadata_chunk["content_base64"].as_str().unwrap())
        .unwrap();
    let observation: serde_json::Value = serde_json::from_slice(&metadata).unwrap();
    assert_eq!(observation["observed_unix_ms"], 123456);
    assert_eq!(observation["source_event_seq"], 2);
    assert_eq!(observation["binary_redaction"], "not_applied");
    assert!(
        !String::from_utf8(metadata)
            .unwrap()
            .contains("private-source")
    );
    let png_id = observation["retained_image"]["artifact_id"]
        .as_str()
        .unwrap();
    assert_eq!(png_id, image.sha256());
    assert_eq!(observation["retained_image"]["mime_type"], "image/png");
    let download = fixture.read(&reopened, png_id, 0, 65536);
    assert_eq!(
        base64::engine::general_purpose::STANDARD
            .decode(download["content_base64"].as_str().unwrap())
            .unwrap(),
        image.bytes()
    );

    let catalog = storage::ManifestFile::acquire(&reopened, false)
        .unwrap()
        .unwrap();
    let manifest = catalog.read().unwrap().unwrap();
    let png = manifest
        .entries
        .iter()
        .find(|entry| entry.descriptor.artifact_id == png_id)
        .unwrap();
    reopened
        .private(ArtifactSchema::ViewportImage)
        .unwrap()
        .release(
            iteron_protocol::Seq(png.content.sequence),
            &png.content.handle.digest,
        )
        .unwrap();
    // Revoking the real private source prevents serving the dependent observation.
    assert!(
        reopened
            .bytes(
                manifest
                    .entries
                    .iter()
                    .find(|entry| entry.descriptor.artifact_id == descriptor.artifact_id)
                    .unwrap()
            )
            .is_err()
    );
}

#[test]
fn uncaptured_source_and_text_png_projection_are_refused() {
    let fixture = Fixture::new();
    let plain = CapturedToolImage::png(image().bytes().to_vec()).unwrap();
    assert!(
        fixture
            .store()
            .publish_tool_image(2, &call(), &plain)
            .is_err()
    );
    assert!(
        fixture
            .store()
            .publish_text(2, ArtifactSchema::ViewportImage, "not PNG", &[])
            .is_err()
    );
}
