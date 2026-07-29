use super::{ImageInputErrorKind, decode::validate_decodable};
use core_protocol::input::ImageMediaType;
use std::path::Path;

pub(super) fn extension_media_type(path: &Path) -> Option<ImageMediaType> {
    let extension = path.extension()?.to_str()?;
    extension
        .eq_ignore_ascii_case("png")
        .then_some(ImageMediaType::Png)
        .or_else(|| {
            (extension.eq_ignore_ascii_case("jpg") || extension.eq_ignore_ascii_case("jpeg"))
                .then_some(ImageMediaType::Jpeg)
        })
        .or_else(|| {
            extension
                .eq_ignore_ascii_case("gif")
                .then_some(ImageMediaType::Gif)
        })
        .or_else(|| {
            extension
                .eq_ignore_ascii_case("webp")
                .then_some(ImageMediaType::Webp)
        })
}

pub(super) fn sniff_image(bytes: &[u8]) -> Result<ImageMediaType, ImageInputErrorKind> {
    const PNG: &[u8; 8] = b"\x89PNG\r\n\x1a\n";
    if bytes.starts_with(PNG) {
        validate_png(bytes)?;
        validate_decodable(bytes, ImageMediaType::Png)?;
        return Ok(ImageMediaType::Png);
    }
    if bytes.len() >= 2 && bytes[..2] == [0xff, 0xd8] {
        validate_jpeg(bytes)?;
        validate_decodable(bytes, ImageMediaType::Jpeg)?;
        return Ok(ImageMediaType::Jpeg);
    }
    if bytes.starts_with(b"GIF87a") || bytes.starts_with(b"GIF89a") {
        validate_gif(bytes)?;
        validate_decodable(bytes, ImageMediaType::Gif)?;
        return Ok(ImageMediaType::Gif);
    }
    if bytes.starts_with(b"RIFF") {
        validate_webp(bytes)?;
        validate_decodable(bytes, ImageMediaType::Webp)?;
        return Ok(ImageMediaType::Webp);
    }
    if (bytes.len() >= 4 && PNG.starts_with(bytes))
        || (bytes.len() >= 3 && (b"GIF87a".starts_with(bytes) || b"GIF89a".starts_with(bytes)))
    {
        return Err(ImageInputErrorKind::TruncatedImage);
    }
    Err(ImageInputErrorKind::InvalidImage)
}

fn validate_png(bytes: &[u8]) -> Result<(), ImageInputErrorKind> {
    let mut cursor = 8usize;
    let mut first = true;
    let mut saw_idat = false;
    loop {
        if bytes.len().saturating_sub(cursor) < 12 {
            return Err(ImageInputErrorKind::TruncatedImage);
        }
        let length = u32::from_be_bytes(
            bytes[cursor..cursor + 4]
                .try_into()
                .expect("four-byte chunk length"),
        ) as usize;
        let end = cursor
            .checked_add(12)
            .and_then(|fixed| fixed.checked_add(length))
            .ok_or(ImageInputErrorKind::InvalidImage)?;
        if end > bytes.len() {
            return Err(ImageInputErrorKind::TruncatedImage);
        }
        let kind = &bytes[cursor + 4..cursor + 8];
        let data = &bytes[cursor + 8..cursor + 8 + length];
        let expected_crc = u32::from_be_bytes(
            bytes[cursor + 8 + length..end]
                .try_into()
                .expect("four-byte PNG CRC"),
        );
        if png_crc32([kind, data]) != expected_crc {
            return Err(ImageInputErrorKind::InvalidImage);
        }
        if first && (kind != b"IHDR" || length != 13) {
            return Err(ImageInputErrorKind::InvalidImage);
        }
        if first {
            let width = u32::from_be_bytes(data[0..4].try_into().expect("PNG width"));
            let height = u32::from_be_bytes(data[4..8].try_into().expect("PNG height"));
            let bit_depth = data[8];
            let color_type = data[9];
            let valid_depth = match color_type {
                0 => matches!(bit_depth, 1 | 2 | 4 | 8 | 16),
                2 | 4 | 6 => matches!(bit_depth, 8 | 16),
                3 => matches!(bit_depth, 1 | 2 | 4 | 8),
                _ => false,
            };
            if width == 0
                || height == 0
                || !valid_depth
                || data[10] != 0
                || data[11] != 0
                || data[12] > 1
            {
                return Err(ImageInputErrorKind::InvalidImage);
            }
        } else if kind == b"IHDR" {
            return Err(ImageInputErrorKind::InvalidImage);
        }
        if kind == b"IDAT" {
            // PNG defines the compressed stream as the concatenation of every IDAT data field,
            // and explicitly permits an individual field to be empty. The full decoder below
            // remains responsible for proving that the aggregate stream contains valid pixels.
            saw_idat = true;
        } else if kind[0].is_ascii_uppercase()
            && kind != b"IHDR"
            && kind != b"PLTE"
            && kind != b"IEND"
        {
            return Err(ImageInputErrorKind::InvalidImage);
        }
        if kind == b"IEND" {
            return (length == 0 && saw_idat && end == bytes.len())
                .then_some(())
                .ok_or(ImageInputErrorKind::InvalidImage);
        }
        first = false;
        cursor = end;
    }
}

fn png_crc32<'a>(parts: impl IntoIterator<Item = &'a [u8]>) -> u32 {
    let mut crc = u32::MAX;
    for bytes in parts {
        for byte in bytes {
            crc ^= u32::from(*byte);
            for _ in 0..8 {
                let mask = 0u32.wrapping_sub(crc & 1);
                crc = (crc >> 1) ^ (0xedb8_8320 & mask);
            }
        }
    }
    !crc
}

fn validate_jpeg(bytes: &[u8]) -> Result<(), ImageInputErrorKind> {
    if bytes.len() < 4 || !bytes.starts_with(&[0xff, 0xd8]) {
        return Err(ImageInputErrorKind::TruncatedImage);
    }
    let mut cursor = 2usize;
    let mut saw_frame = false;
    let mut saw_scan = false;
    while cursor < bytes.len() {
        if bytes[cursor] != 0xff {
            return Err(ImageInputErrorKind::InvalidImage);
        }
        let marker_start = cursor;
        while cursor < bytes.len() && bytes[cursor] == 0xff {
            cursor += 1;
        }
        if cursor == bytes.len() {
            return Err(ImageInputErrorKind::TruncatedImage);
        }
        let marker = bytes[cursor];
        cursor += 1;
        match marker {
            0xd9 => {
                return (saw_frame && saw_scan && cursor == bytes.len())
                    .then_some(())
                    .ok_or(ImageInputErrorKind::InvalidImage);
            }
            0x00 | 0x01 | 0xd0..=0xd8 => return Err(ImageInputErrorKind::InvalidImage),
            _ => {}
        }
        let (data, end) = jpeg_segment(bytes, cursor)?;
        if is_jpeg_frame(marker) {
            if data.len() < 6 {
                return Err(ImageInputErrorKind::InvalidImage);
            }
            let height = u16::from_be_bytes(data[1..3].try_into().expect("JPEG height"));
            let width = u16::from_be_bytes(data[3..5].try_into().expect("JPEG width"));
            let components = usize::from(data[5]);
            if height == 0
                || width == 0
                || components == 0
                || data.len() != 6 + components.saturating_mul(3)
            {
                return Err(ImageInputErrorKind::InvalidImage);
            }
            saw_frame = true;
        }
        if marker != 0xda {
            cursor = end;
            continue;
        }
        if !saw_frame || data.is_empty() {
            return Err(ImageInputErrorKind::InvalidImage);
        }
        let components = usize::from(data[0]);
        if components == 0 || data.len() != 4 + components.saturating_mul(2) {
            return Err(ImageInputErrorKind::InvalidImage);
        }
        saw_scan = true;
        cursor = end;
        loop {
            let Some(relative) = bytes[cursor..].iter().position(|byte| *byte == 0xff) else {
                return Err(ImageInputErrorKind::TruncatedImage);
            };
            let scan_marker_start = cursor + relative;
            let mut next = scan_marker_start + 1;
            while next < bytes.len() && bytes[next] == 0xff {
                next += 1;
            }
            if next == bytes.len() {
                return Err(ImageInputErrorKind::TruncatedImage);
            }
            match bytes[next] {
                0x00 | 0xd0..=0xd7 => cursor = next + 1,
                _ => {
                    cursor = scan_marker_start;
                    break;
                }
            }
        }
        debug_assert!(cursor >= marker_start);
    }
    Err(ImageInputErrorKind::TruncatedImage)
}

fn jpeg_segment(bytes: &[u8], length_offset: usize) -> Result<(&[u8], usize), ImageInputErrorKind> {
    if bytes.len().saturating_sub(length_offset) < 2 {
        return Err(ImageInputErrorKind::TruncatedImage);
    }
    let length = usize::from(u16::from_be_bytes(
        bytes[length_offset..length_offset + 2]
            .try_into()
            .expect("JPEG segment length"),
    ));
    if length < 2 {
        return Err(ImageInputErrorKind::InvalidImage);
    }
    let end = length_offset
        .checked_add(length)
        .ok_or(ImageInputErrorKind::InvalidImage)?;
    if end > bytes.len() {
        return Err(ImageInputErrorKind::TruncatedImage);
    }
    Ok((&bytes[length_offset + 2..end], end))
}

fn is_jpeg_frame(marker: u8) -> bool {
    matches!(
        marker,
        0xc0..=0xc3 | 0xc5..=0xc7 | 0xc9..=0xcb | 0xcd..=0xcf
    )
}

fn validate_gif(bytes: &[u8]) -> Result<(), ImageInputErrorKind> {
    if bytes.len() < 14 {
        return Err(ImageInputErrorKind::TruncatedImage);
    }
    if bytes[6..8] == [0, 0] || bytes[8..10] == [0, 0] {
        return Err(ImageInputErrorKind::InvalidImage);
    }
    let mut cursor = 13usize;
    if bytes[10] & 0x80 != 0 {
        cursor = gif_color_table_end(bytes, cursor, bytes[10])?;
    }
    let mut saw_image = false;
    loop {
        let Some(block) = bytes.get(cursor).copied() else {
            return Err(ImageInputErrorKind::TruncatedImage);
        };
        cursor += 1;
        match block {
            0x3b => {
                return (saw_image && cursor == bytes.len())
                    .then_some(())
                    .ok_or(ImageInputErrorKind::InvalidImage);
            }
            0x21 => {
                if cursor == bytes.len() {
                    return Err(ImageInputErrorKind::TruncatedImage);
                }
                cursor += 1; // extension label
                (cursor, _) = gif_sub_blocks(bytes, cursor)?;
            }
            0x2c => {
                if bytes.len().saturating_sub(cursor) < 9 {
                    return Err(ImageInputErrorKind::TruncatedImage);
                }
                let width = u16::from_le_bytes(bytes[cursor + 4..cursor + 6].try_into().unwrap());
                let height = u16::from_le_bytes(bytes[cursor + 6..cursor + 8].try_into().unwrap());
                if width == 0 || height == 0 {
                    return Err(ImageInputErrorKind::InvalidImage);
                }
                let packed = bytes[cursor + 8];
                cursor += 9;
                if packed & 0x80 != 0 {
                    cursor = gif_color_table_end(bytes, cursor, packed)?;
                }
                let Some(code_size) = bytes.get(cursor).copied() else {
                    return Err(ImageInputErrorKind::TruncatedImage);
                };
                if !(2..=8).contains(&code_size) {
                    return Err(ImageInputErrorKind::InvalidImage);
                }
                cursor += 1;
                let (end, has_data) = gif_sub_blocks(bytes, cursor)?;
                if !has_data {
                    return Err(ImageInputErrorKind::InvalidImage);
                }
                cursor = end;
                saw_image = true;
            }
            _ => return Err(ImageInputErrorKind::InvalidImage),
        }
    }
}

fn gif_color_table_end(
    bytes: &[u8],
    cursor: usize,
    packed: u8,
) -> Result<usize, ImageInputErrorKind> {
    let entries = 1usize << (usize::from(packed & 0x07) + 1);
    let end = cursor
        .checked_add(entries.saturating_mul(3))
        .ok_or(ImageInputErrorKind::InvalidImage)?;
    if end > bytes.len() {
        return Err(ImageInputErrorKind::TruncatedImage);
    }
    Ok(end)
}

fn gif_sub_blocks(bytes: &[u8], mut cursor: usize) -> Result<(usize, bool), ImageInputErrorKind> {
    let mut has_data = false;
    loop {
        let Some(length) = bytes.get(cursor).copied() else {
            return Err(ImageInputErrorKind::TruncatedImage);
        };
        cursor += 1;
        if length == 0 {
            return Ok((cursor, has_data));
        }
        has_data = true;
        cursor = cursor
            .checked_add(usize::from(length))
            .ok_or(ImageInputErrorKind::InvalidImage)?;
        if cursor > bytes.len() {
            return Err(ImageInputErrorKind::TruncatedImage);
        }
    }
}

fn validate_webp(bytes: &[u8]) -> Result<(), ImageInputErrorKind> {
    if bytes.len() < 20 || &bytes[8..12] != b"WEBP" {
        return Err(ImageInputErrorKind::TruncatedImage);
    }
    let riff_bytes = u32::from_le_bytes(bytes[4..8].try_into().expect("RIFF length")) as usize;
    let declared_end = riff_bytes
        .checked_add(8)
        .ok_or(ImageInputErrorKind::InvalidImage)?;
    if declared_end > bytes.len() {
        return Err(ImageInputErrorKind::TruncatedImage);
    }
    if declared_end != bytes.len() {
        return Err(ImageInputErrorKind::InvalidImage);
    }
    let mut cursor = 12usize;
    let mut saw_pixels = false;
    while cursor < declared_end {
        if declared_end.saturating_sub(cursor) < 8 {
            return Err(ImageInputErrorKind::TruncatedImage);
        }
        let kind = &bytes[cursor..cursor + 4];
        let length = u32::from_le_bytes(bytes[cursor + 4..cursor + 8].try_into().unwrap()) as usize;
        let data_start = cursor + 8;
        let data_end = data_start
            .checked_add(length)
            .ok_or(ImageInputErrorKind::InvalidImage)?;
        let padded_end = data_end
            .checked_add(length % 2)
            .ok_or(ImageInputErrorKind::InvalidImage)?;
        if padded_end > declared_end {
            return Err(ImageInputErrorKind::TruncatedImage);
        }
        let data = &bytes[data_start..data_end];
        saw_pixels |= match kind {
            b"VP8 " => validate_vp8(data)?,
            b"VP8L" => validate_vp8l(data)?,
            b"VP8X" => {
                if data.len() != 10 {
                    return Err(ImageInputErrorKind::InvalidImage);
                }
                false
            }
            b"ANMF" => validate_anmf(data)?,
            _ => false,
        };
        cursor = padded_end;
    }
    saw_pixels
        .then_some(())
        .ok_or(ImageInputErrorKind::InvalidImage)
}

fn validate_vp8(data: &[u8]) -> Result<bool, ImageInputErrorKind> {
    if data.len() < 10 {
        return Err(ImageInputErrorKind::TruncatedImage);
    }
    if data[3..6] != [0x9d, 0x01, 0x2a] {
        return Err(ImageInputErrorKind::InvalidImage);
    }
    let width = u16::from_le_bytes(data[6..8].try_into().unwrap()) & 0x3fff;
    let height = u16::from_le_bytes(data[8..10].try_into().unwrap()) & 0x3fff;
    if width == 0 || height == 0 {
        return Err(ImageInputErrorKind::InvalidImage);
    }
    Ok(true)
}

fn validate_vp8l(data: &[u8]) -> Result<bool, ImageInputErrorKind> {
    if data.len() < 5 {
        return Err(ImageInputErrorKind::TruncatedImage);
    }
    if data[0] != 0x2f {
        return Err(ImageInputErrorKind::InvalidImage);
    }
    let dimensions = u32::from_le_bytes([data[1], data[2], data[3], data[4]]);
    let version = dimensions >> 29;
    if version != 0 {
        return Err(ImageInputErrorKind::InvalidImage);
    }
    Ok(true)
}

fn validate_anmf(data: &[u8]) -> Result<bool, ImageInputErrorKind> {
    if data.len() < 24 {
        return Err(ImageInputErrorKind::TruncatedImage);
    }
    let mut cursor = 16usize;
    let mut saw_pixels = false;
    while cursor < data.len() {
        if data.len().saturating_sub(cursor) < 8 {
            return Err(ImageInputErrorKind::TruncatedImage);
        }
        let kind = &data[cursor..cursor + 4];
        let length = u32::from_le_bytes(data[cursor + 4..cursor + 8].try_into().unwrap()) as usize;
        let start = cursor + 8;
        let end = start
            .checked_add(length)
            .ok_or(ImageInputErrorKind::InvalidImage)?;
        let padded = end
            .checked_add(length % 2)
            .ok_or(ImageInputErrorKind::InvalidImage)?;
        if padded > data.len() {
            return Err(ImageInputErrorKind::TruncatedImage);
        }
        saw_pixels |= match kind {
            b"VP8 " => validate_vp8(&data[start..end])?,
            b"VP8L" => validate_vp8l(&data[start..end])?,
            _ => false,
        };
        cursor = padded;
    }
    saw_pixels
        .then_some(true)
        .ok_or(ImageInputErrorKind::InvalidImage)
}
