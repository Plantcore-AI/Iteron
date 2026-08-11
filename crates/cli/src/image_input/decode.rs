use super::ImageInputErrorKind;
use gif::{ColorOutput, DecodeOptions, MemoryLimit};
use image_webp::WebPDecoder;
use iteron_protocol::ImageMediaType;
use std::io::{BufReader, Cursor};
use std::num::NonZeroU64;
use zune_jpeg::JpegDecoder;
use zune_jpeg::zune_core::bytestream::ZCursor;
use zune_jpeg::zune_core::options::DecoderOptions;

/// A 4K frame fits, but attacker-controlled dimensions cannot turn a small compressed file into
/// an unbounded allocation. The independent area limit still permits narrow panoramas.
pub(super) const MAX_IMAGE_DIMENSION: u32 = 8 * 1024;
pub(super) const MAX_IMAGE_PIXELS: u64 = 8 * 1024 * 1024;
/// Decode one frame at a time and reject animations whose aggregate work exceeds eight maximum
/// frames. The count ceiling separately bounds tiny-frame iteration overhead.
pub(super) const MAX_ANIMATION_FRAMES: u32 = 256;
const MAX_TOTAL_FRAME_PIXELS: u64 = 64 * 1024 * 1024;
/// Caller-owned output plus each decoder's internal workspace remain independently bounded.
const MAX_DECODE_BUFFER_BYTES: usize = 64 * 1024 * 1024;

pub(super) fn validate_decodable_with_limits(
    bytes: &[u8],
    media_type: ImageMediaType,
    max_dimension: u32,
    max_frames: u32,
) -> Result<(), ImageInputErrorKind> {
    match media_type {
        ImageMediaType::Png => validate_png(bytes, max_dimension, max_frames),
        ImageMediaType::Jpeg => validate_jpeg(bytes, max_dimension),
        ImageMediaType::Gif => validate_gif(bytes, max_dimension, max_frames),
        ImageMediaType::Webp => validate_webp(bytes, max_dimension, max_frames),
    }
}

fn validate_png(
    bytes: &[u8],
    max_dimension: u32,
    max_frames: u32,
) -> Result<(), ImageInputErrorKind> {
    let decoder = png::Decoder::new_with_limits(
        BufReader::new(Cursor::new(bytes)),
        png::Limits {
            bytes: MAX_DECODE_BUFFER_BYTES,
        },
    );
    let mut reader = decoder.read_info().map_err(|_| invalid())?;
    let (width, height, frames) = {
        let info = reader.info();
        let frames = info
            .animation_control
            .map(|control| {
                control
                    .num_frames
                    .saturating_add(u32::from(info.frame_control.is_none()))
            })
            .unwrap_or(1);
        (info.width, info.height, frames)
    };
    validate_animation_bounds(width, height, frames, max_dimension, max_frames)?;
    let buffer_size = reader
        .output_buffer_size()
        .ok_or(ImageInputErrorKind::DecodeLimitExceeded)?;
    let mut output = bounded_buffer(buffer_size)?;
    for _ in 0..frames {
        reader.next_frame(&mut output).map_err(|_| invalid())?;
    }
    Ok(())
}

fn validate_jpeg(bytes: &[u8], max_dimension: u32) -> Result<(), ImageInputErrorKind> {
    let options = DecoderOptions::new_safe()
        .set_strict_mode(true)
        .set_max_width(max_dimension as usize)
        .set_max_height(max_dimension as usize);
    let mut decoder = JpegDecoder::new_with_options(ZCursor::new(bytes), options);
    decoder.decode_headers().map_err(|_| invalid())?;
    let (width, height) = decoder.dimensions().ok_or_else(invalid)?;
    validate_static_bounds_with_limit(
        u32::try_from(width).map_err(|_| ImageInputErrorKind::DecodeLimitExceeded)?,
        u32::try_from(height).map_err(|_| ImageInputErrorKind::DecodeLimitExceeded)?,
        max_dimension,
    )?;
    let buffer_size = decoder
        .output_buffer_size()
        .ok_or(ImageInputErrorKind::DecodeLimitExceeded)?;
    let mut output = bounded_buffer(buffer_size)?;
    decoder.decode_into(&mut output).map_err(|_| invalid())
}

fn validate_gif(
    bytes: &[u8],
    max_dimension: u32,
    max_frames: u32,
) -> Result<(), ImageInputErrorKind> {
    let mut options = DecodeOptions::new();
    options.set_color_output(ColorOutput::Indexed);
    options.set_memory_limit(MemoryLimit::Bytes(
        NonZeroU64::new(MAX_DECODE_BUFFER_BYTES as u64).expect("decode limit is non-zero"),
    ));
    options.check_frame_consistency(true);
    options.check_lzw_end_code(true);
    let mut reader = options
        .read_info(Cursor::new(bytes))
        .map_err(|_| invalid())?;
    validate_static_bounds_with_limit(
        u32::from(reader.width()),
        u32::from(reader.height()),
        max_dimension,
    )?;

    let mut frame_count = 0u32;
    let mut total_pixels = 0u64;
    while reader.next_frame_info().map_err(|_| invalid())?.is_some() {
        frame_count = frame_count
            .checked_add(1)
            .ok_or(ImageInputErrorKind::DecodeLimitExceeded)?;
        if frame_count > max_frames {
            return Err(ImageInputErrorKind::DecodeLimitExceeded);
        }
        let frame = reader.current_frame_info().ok_or_else(invalid)?;
        total_pixels = add_frame_pixels(
            total_pixels,
            u32::from(frame.width),
            u32::from(frame.height),
            max_dimension,
        )?;
        let buffer_size = reader.buffer_size();
        let mut output = bounded_buffer(buffer_size)?;
        reader
            .read_into_buffer(&mut output)
            .map_err(|_| invalid())?;
    }
    if frame_count == 0 {
        return Err(invalid());
    }
    Ok(())
}

fn validate_webp(
    bytes: &[u8],
    max_dimension: u32,
    max_frames: u32,
) -> Result<(), ImageInputErrorKind> {
    let mut decoder =
        WebPDecoder::new(BufReader::new(Cursor::new(bytes))).map_err(|_| invalid())?;
    decoder.set_memory_limit(MAX_DECODE_BUFFER_BYTES);
    let (width, height) = decoder.dimensions();
    let frames = if decoder.is_animated() {
        decoder.num_frames()
    } else {
        1
    };
    validate_animation_bounds(width, height, frames, max_dimension, max_frames)?;
    let buffer_size = decoder
        .output_buffer_size()
        .ok_or(ImageInputErrorKind::DecodeLimitExceeded)?;
    let mut output = bounded_buffer(buffer_size)?;
    if decoder.is_animated() {
        for _ in 0..frames {
            decoder.read_frame(&mut output).map_err(|_| invalid())?;
        }
        Ok(())
    } else {
        decoder.read_image(&mut output).map_err(|_| invalid())
    }
}

fn validate_static_bounds(width: u32, height: u32) -> Result<(), ImageInputErrorKind> {
    validate_static_bounds_with_limit(width, height, MAX_IMAGE_DIMENSION)
}

fn validate_static_bounds_with_limit(
    width: u32,
    height: u32,
    max_dimension: u32,
) -> Result<(), ImageInputErrorKind> {
    validate_dimensions(width, height, max_dimension)?;
    Ok(())
}

fn validate_animation_bounds(
    width: u32,
    height: u32,
    frames: u32,
    max_dimension: u32,
    max_frames: u32,
) -> Result<(), ImageInputErrorKind> {
    validate_dimensions(width, height, max_dimension)?;
    if frames == 0 || frames > max_frames {
        return Err(ImageInputErrorKind::DecodeLimitExceeded);
    }
    let pixels = u64::from(width)
        .checked_mul(u64::from(height))
        .and_then(|pixels| pixels.checked_mul(u64::from(frames)))
        .ok_or(ImageInputErrorKind::DecodeLimitExceeded)?;
    if pixels > MAX_TOTAL_FRAME_PIXELS {
        return Err(ImageInputErrorKind::DecodeLimitExceeded);
    }
    Ok(())
}

fn validate_dimensions(
    width: u32,
    height: u32,
    max_dimension: u32,
) -> Result<(), ImageInputErrorKind> {
    let pixels = u64::from(width)
        .checked_mul(u64::from(height))
        .ok_or(ImageInputErrorKind::DecodeLimitExceeded)?;
    if width == 0
        || height == 0
        || width > max_dimension
        || height > max_dimension
        || pixels > MAX_IMAGE_PIXELS
    {
        return Err(ImageInputErrorKind::DecodeLimitExceeded);
    }
    Ok(())
}

fn add_frame_pixels(
    total: u64,
    width: u32,
    height: u32,
    max_dimension: u32,
) -> Result<u64, ImageInputErrorKind> {
    validate_dimensions(width, height, max_dimension)?;
    let pixels = u64::from(width)
        .checked_mul(u64::from(height))
        .ok_or(ImageInputErrorKind::DecodeLimitExceeded)?;
    let total = total
        .checked_add(pixels)
        .ok_or(ImageInputErrorKind::DecodeLimitExceeded)?;
    if total > MAX_TOTAL_FRAME_PIXELS {
        return Err(ImageInputErrorKind::DecodeLimitExceeded);
    }
    Ok(total)
}

fn bounded_buffer(size: usize) -> Result<Vec<u8>, ImageInputErrorKind> {
    if size == 0 || size > MAX_DECODE_BUFFER_BYTES {
        return Err(ImageInputErrorKind::DecodeLimitExceeded);
    }
    let mut buffer = Vec::new();
    buffer
        .try_reserve_exact(size)
        .map_err(|_| ImageInputErrorKind::DecodeLimitExceeded)?;
    buffer.resize(size, 0);
    Ok(buffer)
}

const fn invalid() -> ImageInputErrorKind {
    ImageInputErrorKind::InvalidImage
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn animation_count_and_dimensions_use_the_exported_owner_envelope() {
        assert_eq!(
            validate_animation_bounds(
                1,
                1,
                MAX_ANIMATION_FRAMES,
                MAX_IMAGE_DIMENSION,
                MAX_ANIMATION_FRAMES,
            ),
            Ok(())
        );
        assert_eq!(
            validate_animation_bounds(
                1,
                1,
                MAX_ANIMATION_FRAMES + 1,
                MAX_IMAGE_DIMENSION,
                MAX_ANIMATION_FRAMES,
            ),
            Err(ImageInputErrorKind::DecodeLimitExceeded)
        );
        assert_eq!(
            validate_static_bounds(MAX_IMAGE_DIMENSION + 1, 1),
            Err(ImageInputErrorKind::DecodeLimitExceeded)
        );
    }
}
