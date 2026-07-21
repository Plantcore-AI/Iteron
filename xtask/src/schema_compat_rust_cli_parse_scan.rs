use anyhow::{Result, bail};

pub(super) fn skip_rust_non_code(bytes: &[u8], start: usize, end: usize) -> Result<Option<usize>> {
    if start >= end {
        return Ok(None);
    }
    if bytes[start..end].starts_with(b"//") {
        return Ok(Some(
            bytes[start..end]
                .iter()
                .position(|byte| *byte == b'\n')
                .map_or(end, |offset| start + offset + 1),
        ));
    }
    if bytes[start..end].starts_with(b"/*") {
        let mut depth = 1usize;
        let mut index = start + 2;
        while index < end {
            if bytes[index..end].starts_with(b"/*") {
                depth = depth.saturating_add(1);
                index += 2;
            } else if bytes[index..end].starts_with(b"*/") {
                depth = depth.saturating_sub(1);
                index += 2;
                if depth == 0 {
                    return Ok(Some(index));
                }
            } else {
                index += 1;
            }
        }
        bail!("Rust source contains an unterminated block comment");
    }
    if bytes[start] == b'r' {
        let mut delimiter = start + 1;
        while delimiter < end && bytes[delimiter] == b'#' {
            delimiter += 1;
        }
        if delimiter < end && bytes[delimiter] == b'"' {
            let hashes = delimiter - start - 1;
            let mut index = delimiter + 1;
            while index < end {
                if bytes[index] == b'"'
                    && index + hashes < end
                    && (hashes == 0
                        || bytes[index + 1..=index + hashes]
                            .iter()
                            .all(|byte| *byte == b'#'))
                {
                    return Ok(Some(index + hashes + 1));
                }
                index += 1;
            }
            bail!("Rust source contains an unterminated raw string");
        }
    }
    if bytes[start] == b'"' || bytes[start] == b'\'' {
        let quote = bytes[start];
        let mut index = start + 1;
        while index < end {
            if bytes[index] == b'\\' {
                index = index.saturating_add(2);
            } else if bytes[index] == quote {
                return Ok(Some(index + 1));
            } else {
                index += 1;
            }
        }
        bail!("Rust source contains an unterminated quoted literal");
    }
    Ok(None)
}

pub(super) fn skip_rust_trivia(bytes: &[u8], mut index: usize, end: usize) -> Result<usize> {
    loop {
        while index < end && bytes[index].is_ascii_whitespace() {
            index += 1;
        }
        if index >= end {
            return Ok(index);
        }
        if bytes[index..end].starts_with(b"//") || bytes[index..end].starts_with(b"/*") {
            index = skip_rust_non_code(bytes, index, end)?.expect("comment is Rust non-code");
            continue;
        }
        return Ok(index);
    }
}

pub(super) fn balanced_rust_object_end(bytes: &[u8], start: usize, end: usize) -> Result<usize> {
    if bytes.get(start) != Some(&b'{') {
        bail!("balanced Rust object parser did not start on an opening brace");
    }
    let mut stack = vec![b'{'];
    let mut index = start + 1;
    while index < end {
        if let Some(next) = skip_rust_non_code(bytes, index, end)? {
            index = next;
            continue;
        }
        match bytes[index] {
            b'{' | b'[' | b'(' => stack.push(bytes[index]),
            b'}' | b']' | b')' => {
                let expected = match bytes[index] {
                    b'}' => b'{',
                    b']' => b'[',
                    b')' => b'(',
                    _ => unreachable!(),
                };
                if stack.pop() != Some(expected) {
                    bail!("CLI machine json! producer has mismatched delimiters");
                }
                if stack.is_empty() {
                    return Ok(index);
                }
            }
            _ => {}
        }
        index += 1;
    }
    bail!("CLI machine json! producer has an unterminated object")
}
