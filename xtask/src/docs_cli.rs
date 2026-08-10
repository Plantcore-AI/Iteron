//! Generate `docs/reference/cli.md` from the argument parser itself.
//!
//! The hand-written reference was 63 lines and had silently fallen behind the binary: it did not
//! mention `--max-tokens`, `--dangerously-bypass-permissions` (the permission bypass!), `--image`,
//! `--timeline`, or either of the `reindex` and `workflow` subcommands. A reader consulting it
//! could not discover that a flag skipping the entire capability gate exists.
//!
//! Prose cannot be trusted to track a `#[derive(Parser)]` struct, so it no longer has to. This
//! parses `crates/cli/src/main.rs`, reads the clap attributes and doc comments that already are the
//! specification, and renders the page. `docs check` compares the file on disk against that
//! rendering, so adding a flag without regenerating fails the build (`cargo test -p iteron-xtask`
//! runs the same comparison), and the drift cannot come back.

use anyhow::{Context, Result, bail};
use quote::ToTokens;
use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::Path;

const CLI_SOURCE: &str = "crates/cli/src/main.rs";
const EXTERNAL_SUBCOMMAND_SOURCES: &[(&str, &str)] = &[
    ("plugin", "crates/cli/src/plugin.rs"),
    ("tunables", "crates/cli/src/tunables.rs"),
];
const GENERATED_DOC: &str = "docs/reference/cli.md";
const ROOT_STRUCT: &str = "Cli";
const MAX_CLI_SOURCE_BYTES: u64 = 1024 * 1024;

/// Anti-vacuity floor, in the manner of the spec-shape gate: a parser that quietly stops matching
/// would render an empty table and certify it green. The binary has far more options than this.
const MIN_RENDERED_OPTIONS: usize = 20;

pub fn check(root: &Path) -> Result<()> {
    let expected = render(root)?;
    let path = root.join(GENERATED_DOC);
    let actual = std::fs::read_to_string(&path)
        .with_context(|| format!("missing generated file {}", path.display()))?;
    if actual != expected {
        bail!(
            "generated file {} drifted from the argument parser in {CLI_SOURCE}; run `cargo run --locked -p iteron-xtask -- docs generate`",
            path.display()
        );
    }
    Ok(())
}

pub fn generate(root: &Path) -> Result<()> {
    let rendered = render(root)?;
    let path = root.join(GENERATED_DOC);
    std::fs::write(&path, rendered).with_context(|| format!("cannot write {}", path.display()))?;
    Ok(())
}

/// How many values one option or argument takes, derived from the declared Rust type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Arity {
    /// `bool` — presence is the value.
    Flag,
    /// `Option<T>` or `T` — one value.
    One,
    /// `Vec<T>` — repeatable.
    Many,
}

/// One declared argument: what clap will accept, and the doc comment that already explains it.
#[derive(Debug, Clone)]
struct Arg {
    field: String,
    short: Option<char>,
    long: Option<String>,
    value_name: Option<String>,
    default_value: Option<String>,
    required: bool,
    arity: Arity,
    doc: String,
}

impl Arg {
    fn is_positional(&self) -> bool {
        self.short.is_none() && self.long.is_none()
    }

    /// The value placeholder clap renders: an explicit `value_name`, else the field name in
    /// SCREAMING_SNAKE_CASE, which is exactly clap's own derive default.
    fn placeholder(&self) -> String {
        self.value_name
            .clone()
            .unwrap_or_else(|| self.field.to_ascii_uppercase())
    }

    /// The table's left column: `-p, --print`, `--image <PATH>`, `[TASK]`.
    fn invocation(&self) -> String {
        if self.is_positional() {
            let placeholder = self.placeholder();
            return if self.required {
                format!("`<{placeholder}>`")
            } else {
                format!("`[{placeholder}]`")
            };
        }
        let mut rendered = String::new();
        if let Some(short) = self.short {
            rendered.push_str(&format!("`-{short}`, "));
        }
        let long = self.long.clone().unwrap_or_else(|| self.field.clone());
        rendered.push_str(&format!("`--{long}"));
        if self.arity != Arity::Flag {
            rendered.push_str(&format!(" <{}>", self.placeholder()));
        }
        rendered.push('`');
        rendered
    }

    /// The compact usage fragment used inside a subcommand's own invocation.
    fn usage_fragment(&self) -> String {
        if self.is_positional() {
            let placeholder = self.placeholder();
            return if self.required {
                format!("<{placeholder}>")
            } else {
                format!("[{placeholder}]")
            };
        }
        let long = self.long.clone().unwrap_or_else(|| self.field.clone());
        if self.arity == Arity::Flag {
            format!("[--{long}]")
        } else {
            format!("[--{long} <{}>]", self.placeholder())
        }
    }

    /// The table's right column: the doc comment, plus the facts clap enforces but prose forgets.
    fn meaning(&self) -> String {
        let mut meaning = escape_cell(&self.doc);
        if self.arity == Arity::Many {
            meaning.push_str(" Repeatable.");
        }
        if let Some(default) = &self.default_value {
            meaning.push_str(&format!(" Default `{default}`."));
        }
        meaning
    }
}

/// One node of the subcommand tree: `workflow`, then `workflow run`.
#[derive(Debug, Clone)]
struct Subcommand {
    path: Vec<String>,
    args: Vec<Arg>,
    children: Vec<Subcommand>,
    doc: String,
}

impl Subcommand {
    fn rows(&self, out: &mut Vec<(String, String)>) {
        let mut invocation = format!("core {}", self.path.join(" "));
        if self.children.is_empty() {
            for arg in &self.args {
                invocation.push(' ');
                invocation.push_str(&arg.usage_fragment());
            }
        } else {
            invocation.push_str(" <SUBCOMMAND>");
        }
        out.push((format!("`{invocation}`"), escape_cell(&self.doc)));
        for child in &self.children {
            child.rows(out);
        }
    }
}

fn render(root: &Path) -> Result<String> {
    let path = root.join(CLI_SOURCE);
    let metadata =
        std::fs::metadata(&path).with_context(|| format!("cannot read {}", path.display()))?;
    if metadata.len() > MAX_CLI_SOURCE_BYTES {
        bail!("{CLI_SOURCE} exceeds the 1 MiB parse limit");
    }
    let source = std::fs::read_to_string(&path)
        .with_context(|| format!("cannot read {}", path.display()))?;
    let mut modules = Vec::new();
    for &(module, relative) in EXTERNAL_SUBCOMMAND_SOURCES {
        let path = root.join(relative);
        let metadata =
            std::fs::metadata(&path).with_context(|| format!("cannot read {}", path.display()))?;
        if metadata.len() > MAX_CLI_SOURCE_BYTES {
            bail!("{relative} exceeds the 1 MiB parse limit");
        }
        modules.push((
            module,
            std::fs::read_to_string(&path)
                .with_context(|| format!("cannot read {}", path.display()))?,
        ));
    }
    render_sources(
        &source,
        &modules
            .iter()
            .map(|(module, source)| (*module, source.as_str()))
            .collect::<Vec<_>>(),
    )
}

#[cfg(test)]
fn render_source(source: &str) -> Result<String> {
    render_sources(source, &[])
}

fn render_sources(source: &str, modules: &[(&str, &str)]) -> Result<String> {
    let file = syn::parse_file(source).context("cannot parse the CLI argument parser")?;

    let mut structs: BTreeMap<String, syn::ItemStruct> = BTreeMap::new();
    let mut enums: BTreeMap<String, syn::ItemEnum> = BTreeMap::new();
    for item in &file.items {
        match item {
            syn::Item::Struct(item) => {
                structs.insert(item.ident.to_string(), item.clone());
            }
            syn::Item::Enum(item) => {
                enums.insert(item.ident.to_string(), item.clone());
            }
            _ => {}
        }
    }
    for &(module, source) in modules {
        let file = syn::parse_file(source)
            .with_context(|| format!("cannot parse external CLI module `{module}`"))?;
        for item in file.items {
            if let syn::Item::Enum(item) = item {
                enums.insert(format!("{module}::{}", item.ident), item);
            }
        }
    }

    let cli = structs
        .get(ROOT_STRUCT)
        .with_context(|| format!("{CLI_SOURCE} declares no `{ROOT_STRUCT}` parser struct"))?;
    let syn::Fields::Named(fields) = &cli.fields else {
        bail!("`{ROOT_STRUCT}` must be a named-field struct");
    };

    let mut args = Vec::new();
    let mut subcommands = Vec::new();
    for field in &fields.named {
        let name = field
            .ident
            .as_ref()
            .context("parser fields must be named")?
            .to_string();
        if let Some(enum_name) = subcommand_enum(field) {
            let enum_name = enum_name.unwrap_or_else(|| type_name(&field.ty));
            subcommands = collect_subcommands(&enums, &enum_name, &[])?;
            continue;
        }
        args.push(parse_arg(&name, field)?);
    }

    let options: Vec<&Arg> = args.iter().filter(|arg| !arg.is_positional()).collect();
    if options.len() < MIN_RENDERED_OPTIONS {
        bail!(
            "only {} options were recovered from {CLI_SOURCE}; the parser stopped matching",
            options.len()
        );
    }

    let mut out = String::new();
    writeln!(out, "# CLI reference\n").unwrap();
    writeln!(
        out,
        "<!-- Generated from `{CLI_SOURCE}` by `cargo run --locked -p iteron-xtask -- docs generate`. Do not edit this file directly. -->\n"
    )
    .unwrap();
    writeln!(out, "The executable name is `core`.\n").unwrap();
    writeln!(out, "```text").unwrap();
    writeln!(out, "core [OPTIONS] [TASK] [COMMAND]").unwrap();
    writeln!(out, "```\n").unwrap();
    writeln!(
        out,
        "This page is generated from the argument parser, so every shipped flag and subcommand \
appears here. `core --help` is the same contract for the exact build you have installed, and \
`iteron --version` identifies it by commit and build date.\n"
    )
    .unwrap();

    let positional: Vec<&Arg> = args.iter().filter(|arg| arg.is_positional()).collect();
    if !positional.is_empty() {
        writeln!(out, "## Arguments\n").unwrap();
        write_table(
            &mut out,
            "Argument",
            positional
                .iter()
                .map(|arg| (arg.invocation(), arg.meaning())),
        );
    }

    writeln!(out, "## Options\n").unwrap();
    write_table(
        &mut out,
        "Option",
        options.iter().map(|arg| (arg.invocation(), arg.meaning())),
    );

    writeln!(out, "## Standard options\n").unwrap();
    write_table(
        &mut out,
        "Option",
        [
            ("`-h`, `--help`".to_string(), "Print help.".to_string()),
            (
                "`-V`, `--version`".to_string(),
                "Print the bare `core <version>`.".to_string(),
            ),
            (
                "`--version`".to_string(),
                "Print the version with the commit and build date this binary was built from."
                    .to_string(),
            ),
        ]
        .into_iter(),
    );

    if !subcommands.is_empty() {
        writeln!(out, "## Subcommands\n").unwrap();
        let mut rows = Vec::new();
        for subcommand in &subcommands {
            subcommand.rows(&mut rows);
        }
        write_table(&mut out, "Command", rows.into_iter());
    }

    writeln!(
        out,
        "Local validation runs before a new rollout is opened, so malformed mode, effort,
verification, or TUI/one-shot combinations should fail without creating a
phantom session."
    )
    .unwrap();

    Ok(out)
}

fn write_table(out: &mut String, left_header: &str, rows: impl Iterator<Item = (String, String)>) {
    writeln!(out, "| {left_header} | Meaning |").unwrap();
    writeln!(out, "| --- | --- |").unwrap();
    for (left, right) in rows {
        writeln!(out, "| {left} | {right} |").unwrap();
    }
    out.push('\n');
}

/// `Some(None)` when the field is a subcommand whose enum is its own type; `Some(Some(name))` is
/// reserved for an explicitly named enum. `None` means it is an ordinary argument.
fn subcommand_enum(field: &syn::Field) -> Option<Option<String>> {
    field
        .attrs
        .iter()
        .any(|attr| {
            attr.path().is_ident("command")
                && attr.to_token_stream().to_string().contains("subcommand")
        })
        .then_some(None)
}

/// The qualified type name, unwrapping `Option<T>` / `Vec<T>` while preserving module ownership.
fn type_name(ty: &syn::Type) -> String {
    let syn::Type::Path(path) = ty else {
        return ty.to_token_stream().to_string();
    };
    let Some(segment) = path.path.segments.last() else {
        return ty.to_token_stream().to_string();
    };
    if let syn::PathArguments::AngleBracketed(arguments) = &segment.arguments
        && let Some(syn::GenericArgument::Type(inner)) = arguments.args.first()
    {
        return type_name(inner);
    }
    path.path
        .segments
        .iter()
        .map(|segment| segment.ident.to_string())
        .collect::<Vec<_>>()
        .join("::")
}

fn arity(ty: &syn::Type) -> Arity {
    let text = ty.to_token_stream().to_string().replace(' ', "");
    if text == "bool" {
        Arity::Flag
    } else if text.starts_with("Vec<") {
        Arity::Many
    } else {
        Arity::One
    }
}

/// A field is required when it is neither an `Option<T>`, a `Vec<T>`, a `bool`, nor defaulted.
fn is_required(ty: &syn::Type, default_value: Option<&String>) -> bool {
    let text = ty.to_token_stream().to_string().replace(' ', "");
    !text.starts_with("Option<")
        && !text.starts_with("Vec<")
        && text != "bool"
        && default_value.is_none()
}

fn parse_arg(field_name: &str, field: &syn::Field) -> Result<Arg> {
    let mut arg = Arg {
        field: field_name.to_string(),
        short: None,
        long: None,
        value_name: None,
        default_value: None,
        required: false,
        arity: arity(&field.ty),
        doc: doc_comment(&field.attrs),
    };
    for attr in &field.attrs {
        if !attr.path().is_ident("arg") {
            continue;
        }
        attr.parse_nested_meta(|meta| {
            if meta.path.is_ident("long") {
                arg.long = Some(match meta.value() {
                    Ok(value) => value.parse::<syn::LitStr>()?.value(),
                    Err(_) => field_name.replace('_', "-"),
                });
                return Ok(());
            }
            if meta.path.is_ident("short") {
                arg.short = Some(match meta.value() {
                    Ok(value) => value.parse::<syn::LitChar>()?.value(),
                    Err(_) => field_name.chars().next().unwrap_or('?'),
                });
                return Ok(());
            }
            if meta.path.is_ident("value_name") {
                arg.value_name = Some(meta.value()?.parse::<syn::LitStr>()?.value());
                return Ok(());
            }
            if meta.path.is_ident("default_value") {
                arg.default_value = Some(meta.value()?.parse::<syn::LitStr>()?.value());
                return Ok(());
            }
            // Any other clap knob (`value_enum`, `action`, …) does not change the rendered
            // contract; consume its value if it has one so parsing continues.
            if let Ok(value) = meta.value() {
                let _: syn::Expr = value.parse()?;
            }
            Ok(())
        })
        .with_context(|| format!("cannot read the clap attributes of `{field_name}`"))?;
    }
    arg.required = is_required(&field.ty, arg.default_value.as_ref());
    Ok(arg)
}

fn collect_subcommands(
    enums: &BTreeMap<String, syn::ItemEnum>,
    enum_name: &str,
    prefix: &[String],
) -> Result<Vec<Subcommand>> {
    let item = enums
        .get(enum_name)
        .with_context(|| format!("{CLI_SOURCE} declares no `{enum_name}` subcommand enum"))?;
    let mut subcommands = Vec::new();
    for variant in &item.variants {
        let name = kebab(&variant.ident.to_string());
        let mut path = prefix.to_vec();
        path.push(name);
        let mut args = Vec::new();
        let mut children = Vec::new();
        if let syn::Fields::Named(fields) = &variant.fields {
            for field in &fields.named {
                let field_name = field
                    .ident
                    .as_ref()
                    .context("subcommand fields must be named")?
                    .to_string();
                if subcommand_enum(field).is_some() {
                    children = collect_subcommands(enums, &type_name(&field.ty), &path)?;
                    continue;
                }
                args.push(parse_arg(&field_name, field)?);
            }
        }
        subcommands.push(Subcommand {
            path,
            args,
            children,
            doc: doc_comment(&variant.attrs),
        });
    }
    Ok(subcommands)
}

/// `UserPromptSubmit` -> `user-prompt-submit`, matching clap's derive default for a variant name.
fn kebab(name: &str) -> String {
    let mut out = String::new();
    for (index, character) in name.chars().enumerate() {
        if character.is_ascii_uppercase() {
            if index > 0 {
                out.push('-');
            }
            out.push(character.to_ascii_lowercase());
        } else {
            out.push(character);
        }
    }
    out
}

/// The doc comment, joined into one line. It is already the argument's specification; the table
/// only has to stop it from rotting away from the parser it belongs to.
fn doc_comment(attrs: &[syn::Attribute]) -> String {
    let mut lines = Vec::new();
    for attr in attrs {
        if !attr.path().is_ident("doc") {
            continue;
        }
        let syn::Meta::NameValue(meta) = &attr.meta else {
            continue;
        };
        let syn::Expr::Lit(literal) = &meta.value else {
            continue;
        };
        let syn::Lit::Str(text) = &literal.lit else {
            continue;
        };
        lines.push(text.value().trim().to_string());
    }
    let joined = lines.join(" ");
    joined.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Markdown tables are pipe-delimited, and several doc comments print `text | json | stream-json`.
fn escape_cell(text: &str) -> String {
    text.replace('|', "\\|")
}

#[cfg(test)]
#[path = "docs_cli_tests.rs"]
mod tests;
