use super::{
    Content, Display, MAX_ARTIFACT_BYTES, MAX_ARTIFACT_DOWNLOAD_CHUNK_BYTES, MAX_IMAGE_DIMENSION,
    TEXT_PAGE_BYTES, Transfer, Viewer, decode_png, page_end, previous_page, render,
};
use base64::Engine as _;
use crossterm::event::KeyCode;
use iteron_protocol::{Capability, RunId, SessionId, client_artifact::ClientArtifactDescriptorV1};
use ratatui::{Terminal, backend::TestBackend, style::Color};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

fn descriptor(bytes: &[u8], mime: &str) -> ClientArtifactDescriptorV1 {
    ClientArtifactDescriptorV1 {
        artifact_id: hex::encode(Sha256::digest(bytes)),
        schema: "iteron.fixture.v1".into(),
        mime_type: mime.into(),
        bytes: bytes.len() as u64,
        complete: true,
        required_capability: Capability::ReadOnly,
        source_event_seq: 17,
    }
}
fn transfer(descriptor: &ClientArtifactDescriptorV1) -> Transfer {
    Transfer::select(
        SessionId("thread".into()),
        &descriptor.artifact_id[..12],
        &json!({"type":"artifacts_v1","contract_version":1,"artifacts":[descriptor]}),
    )
    .unwrap()
}
fn chunk(descriptor: &ClientArtifactDescriptorV1, bytes: &[u8], offset: usize) -> Value {
    json!({"type":"artifact_chunk_v1","contract_version":1,"artifact":descriptor,
        "offset":offset,"next_offset":offset+bytes.len(),"eof":offset+bytes.len()==descriptor.bytes as usize,
        "content_base64":base64::engine::general_purpose::STANDARD.encode(bytes)})
}
fn deliver(bytes: &[u8], mime: &str) -> Content {
    let descriptor = descriptor(bytes, mime);
    let mut transfer = transfer(&descriptor);
    for (index, bytes) in bytes.chunks(MAX_ARTIFACT_DOWNLOAD_CHUNK_BYTES).enumerate() {
        transfer
            .accept(&chunk(
                &descriptor,
                bytes,
                index * MAX_ARTIFACT_DOWNLOAD_CHUNK_BYTES,
            ))
            .unwrap();
    }
    if bytes.is_empty() {
        transfer.accept(&chunk(&descriptor, bytes, 0)).unwrap();
    }
    transfer.into_content().unwrap()
}
fn screen(viewer: &Viewer, width: u16, height: u16) -> (String, ratatui::buffer::Buffer) {
    let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
    terminal.draw(|frame| render(frame, viewer)).unwrap();
    let buffer = terminal.backend().buffer().clone();
    let mut text = String::new();
    for y in 0..height {
        for x in 0..width {
            text.push_str(buffer[(x, y)].symbol());
        }
        text.push('\n');
    }
    (text, buffer)
}
#[test]
fn all_served_text_pages_retain_the_tail_and_validate_the_actual_full_hash() {
    let text = format!("{}\nLAST-SOURCE-BYTES", "é".repeat(80_000));
    let mut viewer = Viewer {
        open: true,
        content: Some(deliver(text.as_bytes(), "text/plain")),
        ..Default::default()
    };
    let first = screen(&viewer, 110, 8).0;
    assert!(first.contains("160018 bytes"));
    assert!(first.contains("SHA-256 verified"));
    assert!(!first.contains("LAST-SOURCE-BYTES"));
    let mut covered = 0;
    while covered < text.len() {
        assert_eq!(viewer.page, covered);
        covered = page_end(&text, covered);
        viewer.key(KeyCode::Right);
    }
    viewer.key(KeyCode::Left);
    assert!(screen(&viewer, 110, 110).0.contains("LAST-SOURCE-BYTES"));
    let Content {
        descriptor,
        display: Display::Text(actual),
    } = viewer.content.as_ref().unwrap()
    else {
        panic!("text view expected")
    };
    assert_eq!(actual.as_bytes(), text.as_bytes());
    assert_eq!(
        descriptor.artifact_id,
        hex::encode(Sha256::digest(actual.as_bytes()))
    );
}
#[test]
fn descriptors_offsets_completion_and_full_hash_cannot_be_forged() {
    let bytes = b"actual source";
    let descriptor = descriptor(bytes, "text/plain");
    let valid = chunk(&descriptor, bytes, 0);
    for key in [
        "source_event_seq",
        "bytes",
        "schema",
        "mime_type",
        "required_capability",
        "complete",
        "artifact_id",
    ] {
        let mut forged = valid.clone();
        forged["artifact"][key] = match key {
            "source_event_seq" => json!(18),
            "bytes" => json!(12),
            "complete" => json!(false),
            "schema" => json!("other"),
            "mime_type" => json!("application/json"),
            "required_capability" => json!("code_executing"),
            _ => json!("b".repeat(64)),
        };
        assert!(
            transfer(&descriptor).accept(&forged).is_err(),
            "forged {key}"
        );
    }
    for key in ["offset", "next_offset", "eof", "content_base64"] {
        let mut forged = valid.clone();
        forged[key] = match key {
            "offset" => json!(1),
            "next_offset" => json!(14),
            "eof" => json!(false),
            _ => json!(base64::engine::general_purpose::STANDARD.encode(b"forged source")),
        };
        assert!(
            transfer(&descriptor).accept(&forged).is_err(),
            "forged {key}"
        );
    }
    let mut oversized = descriptor.clone();
    oversized.bytes = MAX_ARTIFACT_BYTES as u64 + 1;
    assert!(
        Transfer::select(
            SessionId("thread".into()),
            &oversized.artifact_id,
            &json!({"type":"artifacts_v1","contract_version":1,"artifacts":[oversized]})
        )
        .is_err()
    );
    let mut partial = transfer(&descriptor);
    assert!(partial.accept(&chunk(&descriptor, &[], 0)).is_err());
    assert!(partial.into_content().is_err());
    let duplicate =
        json!({"type":"artifacts_v1","contract_version":1,"artifacts":[descriptor,descriptor]});
    assert!(
        Transfer::select(
            SessionId("thread".into()),
            &descriptor.artifact_id[..12],
            &duplicate
        )
        .is_err()
    );
}
fn png(width: u32, height: u32, color: png::ColorType, pixels: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::new();
    {
        let mut encoder = png::Encoder::new(&mut bytes, width, height);
        encoder.set_color(color);
        encoder.set_depth(png::BitDepth::Eight);
        let mut writer = encoder.write_header().unwrap();
        writer.write_image_data(pixels).unwrap();
    }
    bytes
}
#[test]
fn actual_png_bytes_render_colored_pixels_and_never_pass_through_utf8() {
    let bytes = png(
        2,
        2,
        png::ColorType::Rgb,
        &[255, 0, 0, 0, 255, 0, 0, 0, 255, 255, 255, 255],
    );
    assert!(String::from_utf8(bytes.clone()).is_err());
    let viewer = Viewer {
        open: true,
        content: Some(deliver(&bytes, "image/png")),
        ..Default::default()
    };
    let (text, pixels) = screen(&viewer, 90, 8);
    assert!(text.contains("PNG 2×2"));
    assert!(text.contains("SHA-256 verified"));
    assert_eq!(pixels[(1, 2)].symbol(), "▀");
    assert_eq!(pixels[(1, 2)].fg, Color::Rgb(255, 0, 0));
    assert_eq!(pixels[(1, 2)].bg, Color::Rgb(0, 0, 255));
    assert_eq!(pixels[(2, 2)].fg, Color::Rgb(0, 255, 0));
    assert_eq!(pixels[(2, 2)].bg, Color::Rgb(255, 255, 255));
    for size in [(1, 1), (2, 2), (3, 3)] {
        let _ = screen(&viewer, size.0, size.1);
    }
    let rgba = decode_png(&png(1, 1, png::ColorType::Rgba, &[255, 0, 0, 0])).unwrap();
    assert_eq!(rgba.rgb(0, 0), Color::Rgb(32, 32, 32));
    assert!(decode_png(b"not a png").is_err());
    let wide = png(
        MAX_IMAGE_DIMENSION + 1,
        1,
        png::ColorType::Grayscale,
        &vec![0; MAX_IMAGE_DIMENSION as usize + 1],
    );
    assert!(decode_png(&wide).is_err());
    let invalid_text = descriptor(&bytes, "text/plain");
    let mut transfer = transfer(&invalid_text);
    transfer.accept(&chunk(&invalid_text, &bytes, 0)).unwrap();
    assert!(transfer.into_content().is_err());
}
#[test]
fn utf8_pages_and_host_source_truncation_are_explicit() {
    let text = format!("{}éZ", "a".repeat(TEXT_PAGE_BYTES - 1));
    let end = page_end(&text, 0);
    assert_eq!(end, TEXT_PAGE_BYTES - 1);
    assert!(text.is_char_boundary(previous_page(&text, text.len())));
    let mut content = deliver(text.as_bytes(), "text/plain");
    content.descriptor.complete = false;
    let viewer = Viewer {
        open: true,
        content: Some(content),
        ..Default::default()
    };
    assert!(
        screen(&viewer, 100, 6)
            .0
            .contains("source truncated by host")
    );
}
#[tokio::test]
async fn cancellation_and_run_adoption_discard_only_presentation_not_physical_slot() {
    let semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(1));
    let permit = semaphore.clone().try_acquire_owned().unwrap();
    let (resume, wait) = std::sync::mpsc::channel();
    let (send, receive) = tokio::sync::oneshot::channel();
    let worker = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        wait.recv_timeout(std::time::Duration::from_secs(3))
            .unwrap();
        let _ = send.send(Ok(deliver(b"old source", "text/plain")));
    });
    let mut viewer = Viewer {
        open: true,
        generation: 7,
        capacity: Some(semaphore.clone()),
        pending: Some(super::Pending {
            generation: 7,
            run: RunId("old".into()),
            receive,
        }),
        ..Default::default()
    };
    viewer.close();
    assert!(semaphore.clone().try_acquire_owned().is_err());
    assert!(viewer.pending.is_some());
    viewer.begin_remote();
    assert!(
        viewer
            .finish_remote(
                transfer(&descriptor(b"", "text/plain")),
                RunId("new".into())
            )
            .is_err()
    );
    resume.send(()).unwrap();
    worker.await.unwrap();
    assert!(!viewer.poll(&RunId("new".into())));
    assert!(viewer.content.is_none());
    assert!(viewer.pending.is_none());
    assert!(semaphore.try_acquire_owned().is_ok());
}
