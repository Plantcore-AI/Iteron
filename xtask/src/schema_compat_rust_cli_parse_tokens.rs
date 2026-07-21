use super::cli_parse::{
    balanced_rust_object_end, collect_direct_return_json_objects, function_tail,
    parse_cli_output_source, skip_rust_non_code, skip_rust_trivia, unique_value_function,
};
use super::parse::validate_wire_identifier;
use anyhow::{Context, Result, bail};
use std::collections::{BTreeMap, BTreeSet};

pub(super) fn validate_json_value_blocks(bytes: &[u8], start: usize, close: usize) -> Result<()> {
    for value in json_entry_values(bytes, start, close)?.values() {
        let start = skip_rust_trivia(value, 0, value.len())?;
        if value.get(start) == Some(&b'{') {
            let nested_close = balanced_rust_object_end(value, start, value.len())?;
            if skip_rust_trivia(value, nested_close + 1, value.len())? != value.len() {
                bail!("CLI json! value appends operations after a nested object");
            }
            // Parsing direct string-keyed entries distinguishes a json! object from a Rust side-
            // effect block such as `{ leak(); value }`.
            validate_json_value_blocks(value, start, nested_close)?;
            continue;
        }
        let mut index = start;
        while index < value.len() {
            if let Some(next) = skip_rust_non_code(value, index, value.len())? {
                index = next;
                continue;
            }
            if matches!(value[index], b'{' | b'}' | b';') {
                bail!("CLI json! value contains an executable block or statement");
            }
            index += 1;
        }
    }
    Ok(())
}

pub(super) fn json_entry_values(
    bytes: &[u8],
    start: usize,
    close: usize,
) -> Result<BTreeMap<String, Vec<u8>>> {
    let mut values = BTreeMap::new();
    let mut stack = vec![b'{'];
    let mut entry_start = start + 1;
    let mut index = entry_start;
    while index <= close {
        if index == close || bytes[index] == b',' && stack.len() == 1 {
            let entry = skip_rust_trivia(bytes, entry_start, index)?;
            if entry < index {
                let (field, after) = plain_rust_string(bytes, entry, index)?;
                let colon = skip_rust_trivia(bytes, after, index)?;
                if bytes.get(colon) != Some(&b':') {
                    bail!("CLI json! field '{field}' lacks a colon");
                }
                let value_start = skip_rust_trivia(bytes, colon + 1, index)?;
                if value_start == index
                    || values
                        .insert(field.clone(), bytes[value_start..index].to_vec())
                        .is_some()
                {
                    bail!("CLI json! field '{field}' has an empty or repeated value");
                }
            }
            if index == close {
                break;
            }
            entry_start = index + 1;
        } else if let Some(next) = skip_rust_non_code(bytes, index, close)? {
            index = next;
            continue;
        } else {
            match bytes[index] {
                b'{' | b'[' | b'(' => stack.push(bytes[index]),
                b'}' | b']' | b')' => {
                    let expected = match bytes[index] {
                        b'}' => b'{',
                        b']' => b'[',
                        b')' => b'(',
                        _ => unreachable!(),
                    };
                    if stack.pop() != Some(expected) || stack.is_empty() {
                        bail!("CLI json! value parser found mismatched delimiters");
                    }
                }
                _ => {}
            }
        }
        index += 1;
    }
    Ok(values)
}

pub(super) fn compact_rust(bytes: &[u8]) -> Vec<u8> {
    bytes
        .iter()
        .copied()
        .filter(|byte| !byte.is_ascii_whitespace())
        .collect()
}

pub(super) fn outer_json_object_shape(
    bytes: &[u8],
    start: usize,
    close: usize,
    selector_field: &str,
) -> Result<(String, BTreeSet<String>)> {
    let mut fields = BTreeSet::new();
    let mut record_type = None;
    let mut stack = vec![b'{'];
    let mut entry_start = start + 1;
    let mut index = entry_start;
    while index <= close {
        if index == close {
            parse_outer_json_entry(
                bytes,
                entry_start,
                index,
                selector_field,
                &mut fields,
                &mut record_type,
            )?;
            break;
        }
        if let Some(next) = skip_rust_non_code(bytes, index, close)? {
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
                if stack.pop() != Some(expected) || stack.is_empty() {
                    bail!("CLI machine json! entry has mismatched delimiters");
                }
            }
            b',' if stack.len() == 1 => {
                parse_outer_json_entry(
                    bytes,
                    entry_start,
                    index,
                    selector_field,
                    &mut fields,
                    &mut record_type,
                )?;
                entry_start = index + 1;
            }
            _ => {}
        }
        index += 1;
    }
    let record_type = record_type.with_context(|| {
        format!("json! producer lacks a literal `{selector_field}` selector field")
    })?;
    if fields.is_empty() {
        bail!("CLI machine json! producer has no outer fields");
    }
    Ok((record_type, fields))
}

fn direct_json_object_fields(bytes: &[u8], start: usize, close: usize) -> Result<BTreeSet<String>> {
    let mut fields = BTreeSet::new();
    let mut impossible_selector = None;
    let mut stack = vec![b'{'];
    let mut entry_start = start + 1;
    let mut index = entry_start;
    while index <= close {
        if index == close {
            parse_outer_json_entry(
                bytes,
                entry_start,
                index,
                "__no_nested_selector__",
                &mut fields,
                &mut impossible_selector,
            )?;
            break;
        }
        if let Some(next) = skip_rust_non_code(bytes, index, close)? {
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
                if stack.pop() != Some(expected) || stack.is_empty() {
                    bail!("nested json! object has mismatched delimiters");
                }
            }
            b',' if stack.len() == 1 => {
                parse_outer_json_entry(
                    bytes,
                    entry_start,
                    index,
                    "__no_nested_selector__",
                    &mut fields,
                    &mut impossible_selector,
                )?;
                entry_start = index + 1;
            }
            _ => {}
        }
        index += 1;
    }
    if fields.is_empty() || impossible_selector.is_some() {
        bail!("nested json! literal has an invalid direct-field shape");
    }
    Ok(fields)
}

pub(super) fn cli_nested_literal_fields(
    source: &[u8],
    record_type: &str,
    field: &str,
) -> Result<BTreeSet<String>> {
    validate_wire_identifier("nested CLI record type", record_type)?;
    validate_wire_identifier("nested CLI field", field)?;
    let source = std::str::from_utf8(source).context("CLI output source is not UTF-8")?;
    let file = parse_cli_output_source(source)?;
    let function = unique_value_function(&file, "stream_event", true)?;
    let mut objects = Vec::new();
    collect_direct_return_json_objects(function_tail(function)?, &mut objects)?;
    let mut observed = None;
    for object in objects {
        let close = balanced_rust_object_end(&object, 0, object.len())?;
        let (selector, _) = outer_json_object_shape(&object, 0, close, "type")?;
        if selector == record_type {
            let shape = direct_nested_object_fields(&object, 0, close, field)?;
            if observed.replace(shape).is_some() {
                bail!("CLI producer repeats literal type '{record_type}'");
            }
        }
    }
    observed.with_context(|| {
        format!("CLI producer '{record_type}' lacks direct nested object field '{field}'")
    })
}

fn direct_nested_object_fields(
    bytes: &[u8],
    start: usize,
    close: usize,
    target: &str,
) -> Result<BTreeSet<String>> {
    let mut stack = vec![b'{'];
    let mut entry_start = start + 1;
    let mut observed = None;
    let mut index = entry_start;
    while index <= close {
        if index == close || bytes[index] == b',' && stack.len() == 1 {
            let start = skip_rust_trivia(bytes, entry_start, index)?;
            if start < index {
                let (field, after_field) = plain_rust_string(bytes, start, index)?;
                if field == target {
                    let colon = skip_rust_trivia(bytes, after_field, index)?;
                    if bytes.get(colon) != Some(&b':') {
                        bail!("nested CLI field '{target}' lacks a colon");
                    }
                    let opening = skip_rust_trivia(bytes, colon + 1, index)?;
                    if bytes.get(opening) != Some(&b'{') {
                        bail!("nested CLI field '{target}' is not a direct object literal");
                    }
                    let nested_close = balanced_rust_object_end(bytes, opening, index)?;
                    if skip_rust_trivia(bytes, nested_close + 1, index)? != index
                        || observed
                            .replace(direct_json_object_fields(bytes, opening, nested_close)?)
                            .is_some()
                    {
                        bail!("nested CLI field '{target}' has an ambiguous object value");
                    }
                }
            }
            if index == close {
                break;
            }
            entry_start = index + 1;
        } else if let Some(next) = skip_rust_non_code(bytes, index, close)? {
            index = next;
            continue;
        } else {
            match bytes[index] {
                b'{' | b'[' | b'(' => stack.push(bytes[index]),
                b'}' | b']' | b')' => {
                    let expected = match bytes[index] {
                        b'}' => b'{',
                        b']' => b'[',
                        b')' => b'(',
                        _ => unreachable!(),
                    };
                    if stack.pop() != Some(expected) || stack.is_empty() {
                        bail!("CLI nested field parser found mismatched delimiters");
                    }
                }
                _ => {}
            }
        }
        index += 1;
    }
    observed.with_context(|| format!("CLI producer lacks direct nested object field '{target}'"))
}

fn parse_outer_json_entry(
    bytes: &[u8],
    start: usize,
    end: usize,
    selector_field: &str,
    fields: &mut BTreeSet<String>,
    record_type: &mut Option<String>,
) -> Result<()> {
    let start = skip_rust_trivia(bytes, start, end)?;
    if start == end {
        return Ok(());
    }
    let (field, after_field) = plain_rust_string(bytes, start, end)
        .context("CLI machine json! outer field name must be one plain string literal")?;
    validate_wire_identifier("CLI machine outer field", &field)?;
    let colon = skip_rust_trivia(bytes, after_field, end)?;
    if bytes.get(colon) != Some(&b':') {
        bail!("CLI machine json! outer field '{field}' lacks a colon");
    }
    let value = skip_rust_trivia(bytes, colon + 1, end)?;
    if value >= end {
        bail!("CLI machine json! outer field '{field}' lacks a value");
    }
    if !fields.insert(field.clone()) {
        bail!("CLI machine json! producer repeats outer field '{field}'");
    }
    if field == selector_field {
        let (literal, after_literal) = plain_rust_string(bytes, value, end).with_context(|| {
            format!("json! `{selector_field}` must be one plain string literal")
        })?;
        validate_wire_identifier("json! literal selector", &literal)?;
        if skip_rust_trivia(bytes, after_literal, end)? != end {
            bail!("json! `{selector_field}` value must be exactly one literal");
        }
        if record_type.replace(literal).is_some() {
            bail!("json! producer repeats its `{selector_field}` field");
        }
    }
    if field == "schema_version" {
        const VERSION_VALUE: &[u8] = b"SCHEMA_VERSION";
        if !bytes[value..end].starts_with(VERSION_VALUE)
            || skip_rust_trivia(bytes, value + VERSION_VALUE.len(), end)? != end
        {
            bail!("json! `schema_version` value must be exactly `SCHEMA_VERSION`");
        }
    }
    Ok(())
}

fn plain_rust_string(bytes: &[u8], start: usize, end: usize) -> Result<(String, usize)> {
    if bytes.get(start) != Some(&b'"') {
        bail!("expected a quoted Rust string literal");
    }
    let mut index = start + 1;
    while index < end {
        match bytes[index] {
            b'"' => {
                let value = std::str::from_utf8(&bytes[start + 1..index])
                    .context("Rust string literal is not UTF-8")?;
                return Ok((value.to_owned(), index + 1));
            }
            b'\\' => bail!("escaped Rust strings are unsupported at this schema boundary"),
            byte if byte.is_ascii_control() => {
                bail!("Rust schema literal contains a control character")
            }
            _ => index += 1,
        }
    }
    bail!("unterminated Rust string literal")
}
