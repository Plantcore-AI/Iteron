//! HEIC/HEIF normalization at the local input boundary.
//!
//! Providers accept the protocol's PNG/JPEG/GIF/WebP set, not HEIC. On macOS the fixed system
//! ImageIO frontend (`/usr/bin/sips`) converts an already-bounded, privately copied source into a
//! bounded JPEG. No shell, operator environment, or original path reaches the child process.

use super::ImageInputErrorKind;

#[cfg_attr(
    not(any(target_os = "macos", test)),
    allow(dead_code, reason = "the HEIC converter is macOS-only")
)]
const HEIC_SOURCE_MAX_DIMENSION: u32 = 16 * 1024;
#[cfg_attr(
    not(any(target_os = "macos", test)),
    allow(dead_code, reason = "the HEIC converter is macOS-only")
)]
const HEIC_SOURCE_MAX_PIXELS: u64 = 64 * 1024 * 1024;

pub(super) fn transcode_to_jpeg(bytes: &[u8]) -> Result<Vec<u8>, ImageInputErrorKind> {
    validate_container(bytes)?;
    platform::transcode(bytes)
}

fn validate_container(bytes: &[u8]) -> Result<(), ImageInputErrorKind> {
    if bytes.len() < 12 {
        return Err(ImageInputErrorKind::TruncatedImage);
    }
    if &bytes[4..8] != b"ftyp" {
        return Err(ImageInputErrorKind::InvalidImage);
    }
    let declared = u32::from_be_bytes(
        bytes[..4]
            .try_into()
            .expect("the HEIF box size is four bytes"),
    ) as usize;
    let end = if declared == 0 { bytes.len() } else { declared };
    if end < 16 {
        return Err(ImageInputErrorKind::InvalidImage);
    }
    if end > bytes.len() {
        return Err(ImageInputErrorKind::TruncatedImage);
    }

    let brands = std::iter::once(&bytes[8..12])
        .chain(bytes[16..end].chunks_exact(4).map(|brand| brand as &[u8]));
    let supported = brands.into_iter().any(|brand| {
        matches!(
            brand,
            b"heic" | b"heix" | b"hevc" | b"hevx" | b"heim" | b"heis" | b"mif1" | b"msf1"
        )
    });
    supported
        .then_some(())
        .ok_or(ImageInputErrorKind::InvalidImage)
}

#[cfg_attr(
    not(any(target_os = "macos", test)),
    allow(dead_code, reason = "the HEIC converter is macOS-only")
)]
fn bounded_output_dimensions(
    width: u32,
    height: u32,
) -> Result<Option<(u32, u32)>, ImageInputErrorKind> {
    let pixels = u64::from(width)
        .checked_mul(u64::from(height))
        .ok_or(ImageInputErrorKind::DecodeLimitExceeded)?;
    if width == 0
        || height == 0
        || width > HEIC_SOURCE_MAX_DIMENSION
        || height > HEIC_SOURCE_MAX_DIMENSION
        || pixels > HEIC_SOURCE_MAX_PIXELS
    {
        return Err(ImageInputErrorKind::DecodeLimitExceeded);
    }
    if width <= super::decode::MAX_IMAGE_DIMENSION
        && height <= super::decode::MAX_IMAGE_DIMENSION
        && pixels <= super::decode::MAX_IMAGE_PIXELS
    {
        return Ok(None);
    }

    let pixel_scale = (super::decode::MAX_IMAGE_PIXELS as f64 / pixels as f64).sqrt();
    let width_scale = super::decode::MAX_IMAGE_DIMENSION as f64 / f64::from(width);
    let height_scale = super::decode::MAX_IMAGE_DIMENSION as f64 / f64::from(height);
    let scale = pixel_scale.min(width_scale).min(height_scale);
    let mut target_width = (f64::from(width) * scale).floor().max(1.0) as u32;
    let mut target_height = (f64::from(height) * scale).floor().max(1.0) as u32;
    while u64::from(target_width) * u64::from(target_height) > super::decode::MAX_IMAGE_PIXELS {
        if target_width >= target_height && target_width > 1 {
            target_width -= 1;
        } else if target_height > 1 {
            target_height -= 1;
        } else {
            return Err(ImageInputErrorKind::DecodeLimitExceeded);
        }
    }
    Ok(Some((target_width, target_height)))
}

#[cfg(target_os = "macos")]
mod platform {
    use super::{ImageInputErrorKind, bounded_output_dimensions};
    use std::ffi::OsString;
    use std::fs::{DirBuilder, File, OpenOptions};
    use std::io::{Read as _, Write as _};
    use std::os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _};
    use std::path::{Path, PathBuf};
    use std::process::{Child, Command, ExitStatus, Stdio};
    use std::time::{Duration, Instant};

    const SIPS: &str = "/usr/bin/sips";
    const CONVERSION_TIMEOUT: Duration = Duration::from_secs(8);
    /// How often the reaper re-checks a running `sips`. Short enough that the timeout above is
    /// honoured to roughly its own precision, long enough not to spin a core on `try_wait`.
    const CONVERSION_POLL_INTERVAL: Duration = Duration::from_millis(10);
    const MAX_METADATA_BYTES: u64 = 4 * 1024;

    pub(super) fn transcode(bytes: &[u8]) -> Result<Vec<u8>, ImageInputErrorKind> {
        let temp = PrivateTempDir::new()?;
        let input = temp.0.join("input.heic");
        let output = temp.0.join("output.jpg");
        let mut source = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&input)
            .map_err(|_| ImageInputErrorKind::HeicConversionFailed)?;
        source
            .write_all(bytes)
            .map_err(|_| ImageInputErrorKind::HeicConversionFailed)?;
        drop(source);

        let metadata = run_sips(
            &[
                OsString::from("-g"),
                OsString::from("pixelWidth"),
                OsString::from("-g"),
                OsString::from("pixelHeight"),
                input.as_os_str().to_owned(),
            ],
            &temp.0,
            true,
        )?;
        let (width, height) = parse_dimensions(&metadata)?;
        let target = bounded_output_dimensions(width, height)?;

        let mut args = vec![
            OsString::from("-s"),
            OsString::from("format"),
            OsString::from("jpeg"),
            OsString::from("-s"),
            OsString::from("formatOptions"),
            OsString::from("85"),
        ];
        if let Some((target_width, target_height)) = target {
            args.extend([
                OsString::from("-z"),
                OsString::from(target_height.to_string()),
                OsString::from(target_width.to_string()),
            ]);
        }
        args.extend([
            OsString::from("-o"),
            output.as_os_str().to_owned(),
            input.as_os_str().to_owned(),
        ]);
        let _ = run_sips(&args, &temp.0, false)?;

        let file = File::open(&output).map_err(|_| ImageInputErrorKind::HeicConversionFailed)?;
        let converted = super::super::read_capped(file, super::super::MAX_IMAGE_FILE_BYTES)
            .map_err(|_| ImageInputErrorKind::HeicConversionFailed)?;
        if converted.len() > super::super::MAX_IMAGE_FILE_BYTES {
            return Err(ImageInputErrorKind::FileTooLarge);
        }
        Ok(converted)
    }

    fn run_sips(
        args: &[OsString],
        temp: &Path,
        capture_stdout: bool,
    ) -> Result<Vec<u8>, ImageInputErrorKind> {
        let mut command = Command::new(SIPS);
        command
            .args(args)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("TMPDIR", temp)
            .stdin(Stdio::null())
            .stdout(if capture_stdout {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stderr(Stdio::null());
        let mut child = command
            .spawn()
            .map_err(|_| ImageInputErrorKind::HeicConversionUnavailable)?;
        let status = wait_bounded(&mut child)?;
        if !status.success() {
            return Err(ImageInputErrorKind::HeicConversionFailed);
        }
        if !capture_stdout {
            return Ok(Vec::new());
        }
        let mut output = Vec::new();
        child
            .stdout
            .take()
            .ok_or(ImageInputErrorKind::HeicConversionFailed)?
            .take(MAX_METADATA_BYTES + 1)
            .read_to_end(&mut output)
            .map_err(|_| ImageInputErrorKind::HeicConversionFailed)?;
        if output.len() as u64 > MAX_METADATA_BYTES {
            return Err(ImageInputErrorKind::HeicConversionFailed);
        }
        Ok(output)
    }

    fn wait_bounded(child: &mut Child) -> Result<ExitStatus, ImageInputErrorKind> {
        let deadline = Instant::now() + CONVERSION_TIMEOUT;
        loop {
            if let Some(status) = child
                .try_wait()
                .map_err(|_| ImageInputErrorKind::HeicConversionFailed)?
            {
                return Ok(status);
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                return Err(ImageInputErrorKind::HeicConversionTimedOut);
            }
            std::thread::sleep(CONVERSION_POLL_INTERVAL);
        }
    }

    fn parse_dimensions(metadata: &[u8]) -> Result<(u32, u32), ImageInputErrorKind> {
        let metadata =
            std::str::from_utf8(metadata).map_err(|_| ImageInputErrorKind::HeicConversionFailed)?;
        let property = |name: &str| {
            metadata.lines().find_map(|line| {
                let (key, value) = line.trim().split_once(':')?;
                (key == name)
                    .then(|| value.trim().parse::<u32>().ok())
                    .flatten()
            })
        };
        let width = property("pixelWidth").ok_or(ImageInputErrorKind::HeicConversionFailed)?;
        let height = property("pixelHeight").ok_or(ImageInputErrorKind::HeicConversionFailed)?;
        Ok((width, height))
    }

    struct PrivateTempDir(PathBuf);

    impl PrivateTempDir {
        fn new() -> Result<Self, ImageInputErrorKind> {
            for _ in 0..8 {
                let mut random = [0u8; 16];
                getrandom::fill(&mut random)
                    .map_err(|_| ImageInputErrorKind::HeicConversionFailed)?;
                let suffix = random
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<String>();
                let path = std::env::temp_dir().join(format!("core-heic-{suffix}"));
                match DirBuilder::new().mode(0o700).create(&path) {
                    Ok(()) => return Ok(Self(path)),
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                    Err(_) => return Err(ImageInputErrorKind::HeicConversionFailed),
                }
            }
            Err(ImageInputErrorKind::HeicConversionFailed)
        }
    }

    impl Drop for PrivateTempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
}

#[cfg(not(target_os = "macos"))]
mod platform {
    use super::ImageInputErrorKind;

    pub(super) fn transcode(_bytes: &[u8]) -> Result<Vec<u8>, ImageInputErrorKind> {
        Err(ImageInputErrorKind::HeicConversionUnavailable)
    }
}

#[cfg(test)]
mod tests {
    use super::{bounded_output_dimensions, validate_container};
    use crate::image_input::ImageInputErrorKind;

    fn ftyp(brand: &[u8; 4]) -> Vec<u8> {
        let mut bytes = 24u32.to_be_bytes().to_vec();
        bytes.extend_from_slice(b"ftyp");
        bytes.extend_from_slice(brand);
        bytes.extend_from_slice(&0u32.to_be_bytes());
        bytes.extend_from_slice(b"mif1");
        bytes.extend_from_slice(b"heic");
        bytes
    }

    #[test]
    fn heif_brand_and_box_bounds_are_checked_before_any_platform_converter() {
        assert_eq!(validate_container(&ftyp(b"heic")), Ok(()));
        assert_eq!(
            validate_container(b"not a heic image"),
            Err(ImageInputErrorKind::InvalidImage)
        );
        let mut truncated = ftyp(b"heic");
        truncated[..4].copy_from_slice(&64u32.to_be_bytes());
        assert_eq!(
            validate_container(&truncated),
            Err(ImageInputErrorKind::TruncatedImage)
        );
    }

    #[test]
    fn i_phone_sized_and_48mp_sources_are_reduced_to_the_provider_decode_ceiling() {
        let (width, height) = bounded_output_dimensions(4032, 3024)
            .unwrap()
            .expect("a 12 MP source is resampled");
        assert!(u64::from(width) * u64::from(height) <= super::super::decode::MAX_IMAGE_PIXELS);
        assert_eq!(bounded_output_dimensions(1920, 1080).unwrap(), None);

        let (width, height) = bounded_output_dimensions(8064, 6048)
            .unwrap()
            .expect("a 48 MP source is bounded rather than rejected");
        assert!(u64::from(width) * u64::from(height) <= super::super::decode::MAX_IMAGE_PIXELS);
        assert_eq!(
            bounded_output_dimensions(16_385, 1),
            Err(ImageInputErrorKind::DecodeLimitExceeded)
        );
    }
}
