#[path = "../src/image_input.rs"]
mod image_input;

use base64::Engine as _;
use core_protocol::input::ImageMediaType;
use image_input::{
    ImageAttachments, ImageInputErrorKind, ImageLoadLimits, parse_explicit_image_path,
    parse_image_mentions,
};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

struct TempTree(PathBuf);

impl TempTree {
    fn new(label: &str) -> Self {
        let serial = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "core-image-input-{label}-{}-{serial}",
            std::process::id()
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }

    fn write(&self, name: &str, bytes: &[u8]) -> PathBuf {
        let path = self.0.join(name);
        fs::write(&path, bytes).unwrap();
        path
    }
}

impl Drop for TempTree {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn png() -> Vec<u8> {
    base64::engine::general_purpose::STANDARD
        .decode(
            "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=",
        )
        .unwrap()
}

fn jpeg() -> Vec<u8> {
    base64::engine::general_purpose::STANDARD
        .decode(
            "/9j/4AAQSkZJRgABAQAAAQABAAD/2wBDAAgGBgcGBQgHBwcJCQgKDBQNDAsLDBkSEw8UHRofHh0aHBwgJC4nICIsIxwcKDcpLDAxNDQ0Hyc5PTgyPC4zNDL/2wBDAQkJCQwLDBgNDRgyIRwhMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjL/wAARCAABAAEDASIAAhEBAxEB/8QAHwAAAQUBAQEBAQEAAAAAAAAAAAECAwQFBgcICQoL/8QAtRAAAgEDAwIEAwUFBAQAAAF9AQIDAAQRBRIhMUEGE1FhByJxFDKBkaEII0KxwRVS0fAkM2JyggkKFhcYGRolJicoKSo0NTY3ODk6Q0RFRkdISUpTVFVWV1hZWmNkZWZnaGlqc3R1dnd4eXqDhIWGh4iJipKTlJWWl5iZmqKjpKWmp6ipqrKztLW2t7i5usLDxMXGx8jJytLT1NXW19jZ2uHi4+Tl5ufo6erx8vP09fb3+Pn6/8QAHwEAAwEBAQEBAQEBAQAAAAAAAAECAwQFBgcICQoL/8QAtREAAgECBAQDBAcFBAQAAQJ3AAECAxEEBSExBhJBUQdhcRMiMoEIFEKRobHBCSMzUvAVYnLRChYkNOEl8RcYGRomJygpKjU2Nzg5OkNERUZHSElKU1RVVldYWVpjZGVmZ2hpanN0dXZ3eHl6goOEhYaHiImKkpOUlZaXmJmaoqOkpaanqKmqsrO0tba3uLm6wsPExcbHyMnK0tPU1dbX2Nna4uPk5ebn6Onq8vP09fb3+Pn6/9oADAMBAAIRAxEAPwD3+iiigD//2Q==",
        )
        .unwrap()
}

fn gif() -> Vec<u8> {
    b"GIF89a\x01\0\x01\0\x80\0\0\0\0\0\xff\xff\xff!\xf9\x04\x01\0\0\0\0,\0\0\0\0\x01\0\x01\0\0\x02\x02D\x01\0;".to_vec()
}

fn webp() -> Vec<u8> {
    base64::engine::general_purpose::STANDARD
        .decode("UklGRh4AAABXRUJQVlA4TBEAAAAvAAAAAAfQ//73v/+BiOh/AAA=")
        .unwrap()
}

fn png_chunk(kind: &[u8; 4], data: &[u8]) -> Vec<u8> {
    let mut chunk = Vec::with_capacity(12 + data.len());
    chunk.extend_from_slice(&(data.len() as u32).to_be_bytes());
    chunk.extend_from_slice(kind);
    chunk.extend_from_slice(data);
    let mut crc = u32::MAX;
    for byte in kind.iter().chain(data) {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            let mask = 0u32.wrapping_sub(crc & 1);
            crc = (crc >> 1) ^ (0xedb8_8320 & mask);
        }
    }
    chunk.extend_from_slice(&(!crc).to_be_bytes());
    chunk
}

fn crc_valid_png_with_truncated_idat() -> Vec<u8> {
    let mut bytes = b"\x89PNG\r\n\x1a\n".to_vec();
    bytes.extend(png_chunk(b"IHDR", &[0, 0, 0, 1, 0, 0, 0, 1, 8, 6, 0, 0, 0]));
    bytes.extend(png_chunk(b"IDAT", &[0x78]));
    bytes.extend(png_chunk(b"IEND", &[]));
    bytes
}

fn png_with_legal_empty_idat() -> Vec<u8> {
    let mut bytes = png();
    let kind_offset = bytes
        .windows(4)
        .position(|window| window == b"IDAT")
        .expect("fixture contains IDAT");
    let chunk_offset = kind_offset
        .checked_sub(4)
        .expect("IDAT type follows its length");
    bytes.splice(chunk_offset..chunk_offset, png_chunk(b"IDAT", &[]));
    bytes
}

fn png_with_dimensions(width: u32, height: u32) -> Vec<u8> {
    let mut header = Vec::with_capacity(13);
    header.extend_from_slice(&width.to_be_bytes());
    header.extend_from_slice(&height.to_be_bytes());
    header.extend_from_slice(&[8, 6, 0, 0, 0]);
    let mut bytes = b"\x89PNG\r\n\x1a\n".to_vec();
    bytes.extend(png_chunk(b"IHDR", &header));
    bytes.extend(png_chunk(b"IDAT", &[0x78]));
    bytes.extend(png_chunk(b"IEND", &[]));
    bytes
}

fn webp_with_header_only_vp8() -> Vec<u8> {
    let mut bytes = b"RIFF".to_vec();
    bytes.extend_from_slice(&22u32.to_le_bytes());
    bytes.extend_from_slice(b"WEBPVP8 ");
    bytes.extend_from_slice(&10u32.to_le_bytes());
    bytes.extend_from_slice(&[0, 0, 0, 0x9d, 0x01, 0x2a, 1, 0, 1, 0]);
    bytes
}

fn gif_with_invalid_lzw_payload() -> Vec<u8> {
    b"GIF89a\x01\0\x01\0\x80\0\0\0\0\0\xff\xff\xff,\0\0\0\0\x01\0\x01\0\0\x02\x01\0\0;".to_vec()
}

fn jpeg_with_no_entropy_data() -> Vec<u8> {
    vec![
        0xff, 0xd8, // SOI
        0xff, 0xc0, 0, 11, // SOF0
        8, 0, 1, 0, 1, 1, 1, 0x11, 0, // 1x1, one component
        0xff, 0xda, 0, 8, // SOS
        1, 1, 0, 0, 63, 0, // one scan component
        0xff, 0xd9, // EOI without entropy-coded bytes
    ]
}

fn limits(
    count: usize,
    per_file: usize,
    aggregate: usize,
    per_encoded: usize,
    aggregate_encoded: usize,
) -> ImageLoadLimits {
    ImageLoadLimits::new(count, per_file, aggregate, per_encoded, aggregate_encoded).unwrap()
}

#[test]
fn loads_all_supported_magic_and_builds_neutral_segments() {
    let temp = TempTree::new("formats");
    let fixtures = [
        ("one.png", png(), ImageMediaType::Png),
        ("two.jpg", jpeg(), ImageMediaType::Jpeg),
        ("three.gif", gif(), ImageMediaType::Gif),
        ("four.webp", webp(), ImageMediaType::Webp),
    ];
    let mut attachments = ImageAttachments::default();

    for (name, bytes, media_type) in &fixtures {
        let path = temp.write(name, bytes);
        let attachment = attachments.attach_path(&path).unwrap();
        assert_eq!(attachment.media_type(), *media_type);
        assert_eq!(attachment.file_bytes(), bytes.len());
        assert_eq!(
            base64::engine::general_purpose::STANDARD
                .decode(attachment.encoded())
                .unwrap(),
            *bytes
        );
    }

    let segments = attachments
        .to_content_segments("compare these".into())
        .unwrap();
    assert_eq!(attachments.len(), fixtures.len());
    assert_eq!(segments.text(), "compare these");
    assert_eq!(segments.images().count(), fixtures.len());
    let consumed = attachments
        .clone()
        .into_content_segments("consume these".into())
        .unwrap();
    assert_eq!(consumed.images().count(), fixtures.len());
}

#[test]
fn spoofed_non_image_and_truncated_files_are_rejected_without_mutation() {
    let temp = TempTree::new("reject");
    let valid_png = png();
    let png_without_pixels = [
        &valid_png[..33],
        &valid_png[valid_png.len().saturating_sub(12)..],
    ]
    .concat();
    let mut webp_without_pixels = b"RIFF".to_vec();
    webp_without_pixels.extend_from_slice(&22u32.to_le_bytes());
    webp_without_pixels.extend_from_slice(b"WEBPVP8X");
    webp_without_pixels.extend_from_slice(&10u32.to_le_bytes());
    webp_without_pixels.extend_from_slice(&[0; 10]);
    let cases = vec![
        ("spoof.png", jpeg(), ImageInputErrorKind::ExtensionMismatch),
        (
            "plain.png",
            b"not an image".to_vec(),
            ImageInputErrorKind::InvalidImage,
        ),
        (
            "short.png",
            b"\x89PNG\r\n\x1a\n".to_vec(),
            ImageInputErrorKind::TruncatedImage,
        ),
        (
            "short.jpg",
            vec![0xff, 0xd8, 0xff, 0xe0],
            ImageInputErrorKind::TruncatedImage,
        ),
        (
            "short.gif",
            b"GIF89a\x01\0\x01\0\0\0\0".to_vec(),
            ImageInputErrorKind::TruncatedImage,
        ),
        (
            "short.webp",
            b"RIFF".to_vec(),
            ImageInputErrorKind::TruncatedImage,
        ),
        (
            "wrapper.png",
            png_without_pixels,
            ImageInputErrorKind::InvalidImage,
        ),
        (
            "wrapper.jpg",
            vec![0xff, 0xd8, 0xff, 0xe0, 0, 2, 0xff, 0xd9],
            ImageInputErrorKind::InvalidImage,
        ),
        (
            "wrapper.gif",
            b"GIF89a\x01\0\x01\0\0\0\0;".to_vec(),
            ImageInputErrorKind::InvalidImage,
        ),
        (
            "wrapper.webp",
            webp_without_pixels,
            ImageInputErrorKind::InvalidImage,
        ),
    ];
    let mut attachments = ImageAttachments::default();
    for (name, bytes, expected) in cases {
        let path = temp.write(name, &bytes);
        let error = attachments.attach_path(&path).unwrap_err();
        assert_eq!(error.kind(), expected, "{name}");
        assert!(attachments.is_empty(), "{name} mutated the attachment set");
    }
}

#[test]
fn legal_zero_length_png_idat_is_decoded_as_part_of_the_aggregate_stream() {
    let bytes = png_with_legal_empty_idat();
    let mut attachments = ImageAttachments::default();
    let attachment = attachments
        .attach_bytes("empty-idat.png", &bytes)
        .expect("an empty IDAT preceding valid compressed data is legal PNG");

    assert_eq!(attachment.media_type(), ImageMediaType::Png);
    assert_eq!(
        base64::engine::general_purpose::STANDARD
            .decode(attachment.encoded())
            .expect("canonical base64"),
        bytes
    );
}

#[test]
fn structurally_wrapped_but_undecodable_pixel_streams_are_rejected() {
    let temp = TempTree::new("decode-reject");
    let cases = [
        ("bad-pixels.png", crc_valid_png_with_truncated_idat()),
        ("bad-pixels.jpg", jpeg_with_no_entropy_data()),
        ("bad-pixels.gif", gif_with_invalid_lzw_payload()),
        ("bad-pixels.webp", webp_with_header_only_vp8()),
    ];
    let mut attachments = ImageAttachments::default();
    for (name, bytes) in cases {
        let path = temp.write(name, &bytes);
        assert_eq!(
            attachments.attach_path(&path).unwrap_err().kind(),
            ImageInputErrorKind::InvalidImage,
            "{name} reached the attachment set without a full pixel decode"
        );
        assert!(attachments.is_empty(), "{name} mutated the attachment set");
    }
}

#[test]
fn oversized_declared_dimensions_are_rejected_before_pixel_decode() {
    let mut attachments = ImageAttachments::default();
    let oversized = png_with_dimensions(8 * 1024 + 1, 1);
    assert_eq!(
        attachments
            .attach_bytes("dimension-bomb.png", &oversized)
            .unwrap_err()
            .kind(),
        ImageInputErrorKind::DecodeLimitExceeded
    );
    assert!(attachments.is_empty());
}

#[test]
fn count_file_aggregate_and_encoded_limits_are_independent_and_recoverable() {
    let temp = TempTree::new("limits");
    let image = png();
    let first = temp.write("first.png", &image);
    let second = temp.write("second.png", &image);

    let mut file_limited =
        ImageAttachments::new(limits(2, image.len() - 1, image.len() * 2, 1_000, 2_000));
    assert_eq!(
        file_limited.attach_path(&first).unwrap_err().kind(),
        ImageInputErrorKind::FileTooLarge
    );

    let mut count_limited =
        ImageAttachments::new(limits(1, image.len(), image.len() * 2, 1_000, 2_000));
    count_limited.attach_path(&first).unwrap();
    let missing = temp.0.join("missing.png");
    assert_eq!(
        count_limited.attach_path(&missing).unwrap_err().kind(),
        ImageInputErrorKind::TooManyAttachments
    );

    let mut aggregate_limited =
        ImageAttachments::new(limits(2, image.len(), image.len(), 1_000, 2_000));
    aggregate_limited.attach_path(&first).unwrap();
    assert_eq!(
        aggregate_limited.attach_path(&second).unwrap_err().kind(),
        ImageInputErrorKind::AggregateTooLarge
    );
    let removed = aggregate_limited.remove(0).unwrap();
    assert_eq!(removed.into_content().media_type, ImageMediaType::Png);
    aggregate_limited.attach_path(&second).unwrap();
    aggregate_limited.clear();
    assert!(aggregate_limited.is_empty());

    let mut encoded_limited = ImageAttachments::new(limits(1, 64, 64, 19, 19));
    assert_eq!(
        encoded_limited
            .attach_bytes("clipboard", &gif())
            .unwrap_err()
            .kind(),
        ImageInputErrorKind::EncodedPayloadTooLarge
    );
}

#[test]
fn clipboard_bytes_use_the_same_magic_and_size_admission() {
    let image = png();
    let mut attachments =
        ImageAttachments::new(limits(2, image.len(), image.len() * 2, 1_000, 2_000));
    let long_label = format!("paste\u{1b}{}", "a".repeat(10_000));
    let attached = attachments.attach_bytes(&long_label, &image).unwrap();
    assert_eq!(attached.media_type(), ImageMediaType::Png);
    assert!(!attached.display_name().contains('\u{1b}'));
    assert_eq!(attached.display_name().chars().count(), 81);
    assert!(attached.display_name().ends_with('…'));

    let oversized = vec![0; image.len() + 1];
    assert_eq!(
        attachments
            .attach_bytes("second paste", &oversized)
            .unwrap_err()
            .kind(),
        ImageInputErrorKind::FileTooLarge
    );
}

#[cfg(unix)]
#[test]
fn fifo_devices_and_symlinks_are_rejected_before_any_image_read() {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt as _;
    use std::os::unix::fs::symlink;

    let temp = TempTree::new("non-regular");
    let fifo = temp.0.join("blocked.png");
    let fifo_name = CString::new(fifo.as_os_str().as_bytes()).unwrap();
    // SAFETY: the path is a live NUL-free CString and mode contains only permission bits.
    assert_eq!(unsafe { libc::mkfifo(fifo_name.as_ptr(), 0o600) }, 0);
    let target = temp.write("target.png", &png());
    let linked = temp.0.join("linked.png");
    symlink(&target, &linked).unwrap();

    let mut attachments = ImageAttachments::default();
    for path in [&fifo, &linked] {
        assert_eq!(
            attachments.attach_path(path).unwrap_err().kind(),
            ImageInputErrorKind::OpenFailed
        );
    }
    assert!(attachments.is_empty());
}

#[test]
fn explicit_path_parser_accepts_only_a_whole_local_image_reference() {
    #[cfg(unix)]
    let absolute_path = "/tmp/photo.PNG";
    #[cfg(windows)]
    let absolute_path = r"C:\tmp\photo.PNG";
    #[cfg(unix)]
    let spaced_absolute_path = "/tmp/My Photo.jpg";
    #[cfg(windows)]
    let spaced_absolute_path = r"C:\tmp\My Photo.jpg";

    let absolute = parse_explicit_image_path(absolute_path).unwrap().unwrap();
    assert_eq!(absolute.path(), Path::new(absolute_path));
    assert_eq!(absolute.display_name(), "photo.PNG");

    let quoted = format!("\"{spaced_absolute_path}\"");
    assert_eq!(
        parse_explicit_image_path(&quoted).unwrap().unwrap().path(),
        Path::new(spaced_absolute_path)
    );
    #[cfg(not(windows))]
    assert_eq!(
        parse_explicit_image_path("My\\ Photo.webp")
            .unwrap()
            .unwrap()
            .path(),
        Path::new("My Photo.webp")
    );
    #[cfg(unix)]
    assert_eq!(
        parse_explicit_image_path("file:///tmp/a%20b.gif")
            .unwrap()
            .unwrap()
            .path(),
        Path::new("/tmp/a b.gif")
    );
    #[cfg(windows)]
    assert_eq!(
        parse_explicit_image_path("file:///C:/tmp/a%20b.gif")
            .unwrap()
            .unwrap()
            .path(),
        Path::new(r"C:\tmp\a b.gif")
    );
    #[cfg(windows)]
    assert!(
        parse_explicit_image_path(r"\\server\share\implicit-auth.png")
            .unwrap()
            .is_none()
    );
    #[cfg(windows)]
    assert!(
        parse_explicit_image_path("//server/share/implicit-auth.png")
            .unwrap()
            .is_none()
    );
    assert!(parse_explicit_image_path("photo.png").unwrap().is_some());
    assert!(parse_explicit_image_path("./photo.png").unwrap().is_some());

    for prose in [
        "please inspect /tmp/photo.png",
        "the release is photo.png today",
        "https://example.com/photo.png",
        "photo.txt",
        "one.png\ntwo.png",
        "~/implicit.png",
        "\"unclosed.png",
        "unclosed.png'",
    ] {
        assert!(
            parse_explicit_image_path(prose).unwrap().is_none(),
            "{prose:?} was treated as a local file"
        );
    }
    assert_eq!(
        parse_explicit_image_path("file://remote.example/tmp/photo.png")
            .unwrap_err()
            .kind(),
        ImageInputErrorKind::InvalidReference
    );
}

/// N-2: a terminal ends a dropped path with a newline. Rejecting the whole drop for that trailing
/// byte pushed the path into the composer as bare text, where the leading `/` was then read as a
/// slash command. Trailing whitespace is now trimmed before the line-break test; an INTERIOR break
/// still disqualifies the input, because that is two references rather than one.
#[test]
fn a_dropped_path_with_surrounding_whitespace_is_still_one_image_reference() {
    #[cfg(unix)]
    let dropped = "/tmp/photo.png";
    #[cfg(windows)]
    let dropped = r"C:\tmp\photo.png";

    for input in [
        format!("{dropped}\n"),
        format!("{dropped}\r\n"),
        format!("  {dropped}  "),
        format!("\n{dropped}\n"),
    ] {
        assert_eq!(
            parse_explicit_image_path(&input).unwrap().unwrap().path(),
            Path::new(dropped),
            "{input:?} was not read as a single dropped path"
        );
    }
    assert!(
        parse_explicit_image_path(&format!("{dropped}\n{dropped}"))
            .unwrap()
            .is_none(),
        "two dropped paths must not collapse into one reference"
    );
}

#[test]
fn image_mentions_are_explicit_bounded_and_do_not_match_email_or_prose() {
    #[cfg(unix)]
    let first = "/tmp/a.png";
    #[cfg(windows)]
    let first = "C:/tmp/a.png";
    let text = format!(
        "compare @image({first}) with @./b.webp; then @final.gif. \
                ignore person@example.png and @image please"
    );
    let mentions = parse_image_mentions(&text).unwrap();
    assert_eq!(mentions.len(), 3);
    assert_eq!(
        &text[mentions[0].byte_range.clone()],
        format!("@image({first})")
    );
    assert_eq!(mentions[0].reference().path(), Path::new(first));
    assert_eq!(&text[mentions[1].byte_range.clone()], "@./b.webp");
    assert_eq!(mentions[1].reference().path(), Path::new("./b.webp"));
    assert_eq!(&text[mentions[2].byte_range.clone()], "@final.gif");
    assert_eq!(mentions[2].reference().path(), Path::new("final.gif"));

    let too_many = (0..9)
        .map(|index| format!("@image(images/{index}.png)"))
        .collect::<Vec<_>>()
        .join(" ");
    assert_eq!(
        parse_image_mentions(&too_many).unwrap_err().kind(),
        ImageInputErrorKind::TooManyMentions
    );
    assert_eq!(
        parse_image_mentions("broken @image(images/a.png")
            .unwrap_err()
            .kind(),
        ImageInputErrorKind::InvalidReference
    );
    assert!(
        parse_image_mentions(&format!("@{}.png", "a".repeat(4_097)))
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        parse_image_mentions(&"x".repeat(core_protocol::task::MAX_TASK_TEXT_BYTES + 1))
            .unwrap_err()
            .kind(),
        ImageInputErrorKind::InvalidReference
    );
}

#[test]
fn debug_and_errors_expose_neither_parent_paths_nor_encoded_payloads() {
    let temp = TempTree::new("parent-secret-token");
    let missing = temp.0.join("harmless.png");
    let mut attachments = ImageAttachments::default();
    let error = attachments.attach_path(&missing).unwrap_err();
    let diagnostic = format!("{error:?}");
    assert!(diagnostic.contains("harmless.png"));
    assert!(!diagnostic.contains("parent-secret-token"));

    let path = temp.write("safe.png", &png());
    attachments.attach_path(&path).unwrap();
    let encoded = attachments.as_slice()[0].encoded().to_owned();
    let debug = format!("{attachments:?}");
    assert!(!debug.contains(&encoded));
    assert!(!debug.contains("parent-secret-token"));

    let parsed = parse_explicit_image_path(path.to_str().unwrap())
        .unwrap()
        .unwrap();
    assert!(!format!("{parsed:?}").contains("parent-secret-token"));
}
