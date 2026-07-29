use anyhow::{Context, Result, bail};
use std::collections::BTreeSet;
use std::path::Path;

const REGISTRY_PATH: &str = "xtask/src/seams.rs";
const SOURCE_PATH: &str = "xtask/src/seams/source.rs";
const TRANSITION_PATH: &str = "xtask/src/seams/transition.rs";
const MAIN_PATH: &str = "xtask/src/main.rs";
const VALIDATE_PATH: &str = "xtask/src/validate.rs";
const MAX_AUTHORITY_SOURCE_BYTES: u64 = 256 * 1024;
const TRUSTED_REGISTRY_SOURCE: &str = include_str!("../seams.rs");
const TRUSTED_SOURCE: &str = include_str!("source.rs");
const TRUSTED_TRANSITION_SOURCE: &str = include_str!("transition.rs");
const TRUSTED_MAIN_SOURCE: &str = include_str!("../main.rs");
const TRUSTED_VALIDATE_SOURCE: &str = include_str!("../validate.rs");

pub(super) struct Transition {
    base: BTreeSet<String>,
    remaining: BTreeSet<String>,
    removed: BTreeSet<String>,
}

impl Transition {
    pub(super) fn load(root: &Path, base: &[&str]) -> Result<Self> {
        validate_wiring(root)?;
        let source = read_authority_source(root, REGISTRY_PATH)?;
        let remaining = parse_registry(&source)?;
        let transition = Self::from_sets(base, remaining)?;
        if !transition.removed.is_empty() {
            require_unchanged_policy_surface(root, base, &transition.remaining, &source)?;
        }
        Ok(transition)
    }

    pub(super) fn from_sets(base: &[&str], remaining: BTreeSet<String>) -> Result<Self> {
        let base = base
            .iter()
            .map(|name| (*name).to_owned())
            .collect::<BTreeSet<_>>();
        let additions = remaining.difference(&base).cloned().collect::<Vec<_>>();
        if !additions.is_empty() {
            bail!(
                "candidate seam registry adds declarations not trusted by the base: {}",
                additions.join(", ")
            );
        }
        let removed = base.difference(&remaining).cloned().collect();
        Ok(Self {
            base,
            remaining,
            removed,
        })
    }

    pub(super) fn base(&self) -> impl Iterator<Item = &String> {
        self.base.iter()
    }

    pub(super) fn is_remaining(&self, seam: &str) -> bool {
        self.remaining.contains(seam)
    }

    pub(super) fn has_remaining(&self) -> bool {
        !self.remaining.is_empty()
    }

    pub(super) fn removed(&self) -> impl Iterator<Item = &String> {
        self.removed.iter()
    }

    pub(super) fn require_real_implementations(
        &self,
        implemented: &BTreeSet<String>,
    ) -> Result<()> {
        let missing = self
            .removed
            .difference(implemented)
            .cloned()
            .collect::<Vec<_>>();
        if !missing.is_empty() {
            bail!(
                "candidate removes seam declarations without a real non-test implementation: {}",
                missing.join(", ")
            );
        }
        Ok(())
    }
}

/// Keep a seam implementation change from quietly weakening the policy that will become the next
/// trusted base.
///
/// A governance-only candidate may revise these files while every trusted seam remains declared.
/// Once the same candidate subtracts a declaration, however, its only admitted policy edit is the
/// literal registry subtraction. This keeps policy evolution possible without letting an
/// implementation transition smuggle in a disabled gate.
fn require_unchanged_policy_surface(
    root: &Path,
    base: &[&str],
    remaining: &BTreeSet<String>,
    registry_source: &str,
) -> Result<()> {
    validate_candidate_registry_source(registry_source, base, remaining)?;
    for (relative, trusted) in [
        (SOURCE_PATH, TRUSTED_SOURCE),
        (TRANSITION_PATH, TRUSTED_TRANSITION_SOURCE),
        (MAIN_PATH, TRUSTED_MAIN_SOURCE),
        (VALIDATE_PATH, TRUSTED_VALIDATE_SOURCE),
    ] {
        let candidate = read_authority_source(root, relative)?;
        if candidate != trusted {
            bail!(
                "candidate changes trusted seam-policy file `{relative}` while retiring a seam.\n\
                 Land governance changes separately while the registry is unchanged; a seam \
                 transition may edit only the literal `SEAMS` entries."
            );
        }
    }
    Ok(())
}

fn validate_candidate_registry_source(
    candidate: &str,
    base: &[&str],
    remaining: &BTreeSet<String>,
) -> Result<()> {
    validate_candidate_registry_source_against(TRUSTED_REGISTRY_SOURCE, candidate, base, remaining)
}

fn validate_candidate_registry_source_against(
    trusted: &str,
    candidate: &str,
    base: &[&str],
    remaining: &BTreeSet<String>,
) -> Result<()> {
    let trusted_declaration = registry_declaration(base.iter().copied());
    if trusted.match_indices(&trusted_declaration).count() != 1 {
        bail!("compiled seam authority does not contain one canonical trusted registry");
    }
    let candidate_declaration = registry_declaration(
        base.iter()
            .copied()
            .filter(|name| remaining.contains(*name)),
    );
    let expected = trusted.replacen(&trusted_declaration, &candidate_declaration, 1);
    if candidate != expected {
        bail!(
            "candidate changes trusted seam policy while retiring a seam.\n\
             A seam transition may edit only the literal entries in `const SEAMS`; land any \
             governance changes separately while the registry is unchanged."
        );
    }
    Ok(())
}

fn registry_declaration<'a>(names: impl IntoIterator<Item = &'a str>) -> String {
    let names = names
        .into_iter()
        .map(|name| format!("{name:?}"))
        .collect::<Vec<_>>()
        .join(", ");
    format!("const SEAMS: &[&str] = &[{names}];")
}

fn read_authority_source(root: &Path, relative: &str) -> Result<String> {
    let path = root.join(relative);
    let metadata = std::fs::symlink_metadata(&path)
        .with_context(|| format!("trusted seam authority `{relative}` is missing"))?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        bail!("trusted seam authority `{relative}` must be a regular file");
    }
    if metadata.len() > MAX_AUTHORITY_SOURCE_BYTES {
        bail!("trusted seam authority `{relative}` exceeds {MAX_AUTHORITY_SOURCE_BYTES} bytes");
    }
    let bytes = std::fs::read(&path)
        .with_context(|| format!("cannot read trusted seam authority `{relative}`"))?;
    String::from_utf8(bytes)
        .with_context(|| format!("trusted seam authority `{relative}` is not UTF-8"))
}

fn parse_registry(source: &str) -> Result<BTreeSet<String>> {
    let file = syn::parse_file(source).context("candidate seam registry does not parse as Rust")?;
    if file
        .attrs
        .iter()
        .any(|attribute| !attribute.path().is_ident("doc"))
    {
        bail!("candidate seam registry has an active crate attribute");
    }
    let mut declarations = file.items.iter().filter_map(|item| match item {
        syn::Item::Const(item) if item.ident == "SEAMS" => Some(item),
        _ => None,
    });
    let declaration = declarations
        .next()
        .context("candidate seam registry lacks `const SEAMS: &[&str] = &[..]`")?;
    if declarations.next().is_some() {
        bail!("candidate seam registry repeats `SEAMS`");
    }
    if declaration
        .attrs
        .iter()
        .any(|attribute| !attribute.path().is_ident("doc"))
        || !matches!(declaration.vis, syn::Visibility::Inherited)
        || !is_string_slice_reference(&declaration.ty)
    {
        bail!("candidate seam registry changes the authority shape of `SEAMS`");
    }
    let syn::Expr::Reference(reference) = declaration.expr.as_ref() else {
        bail!("candidate `SEAMS` must be a reference to a literal array");
    };
    if !reference.attrs.is_empty() || reference.mutability.is_some() {
        bail!("candidate `SEAMS` must not be mutable");
    }
    let syn::Expr::Array(array) = reference.expr.as_ref() else {
        bail!("candidate `SEAMS` must be a reference to a literal array");
    };
    if !array.attrs.is_empty() {
        bail!("candidate `SEAMS` literal array must not have active attributes");
    }
    let mut seams = BTreeSet::new();
    for element in &array.elems {
        let syn::Expr::Lit(syn::ExprLit {
            attrs,
            lit: syn::Lit::Str(name),
            ..
        }) = element
        else {
            bail!("candidate `SEAMS` entries must be string literals");
        };
        if !attrs.is_empty() {
            bail!("candidate `SEAMS` entries must not have active attributes");
        }
        if !seams.insert(name.value()) {
            bail!("candidate `SEAMS` contains a duplicate declaration");
        }
    }
    Ok(seams)
}

fn is_string_slice_reference(ty: &syn::Type) -> bool {
    let syn::Type::Reference(outer) = ty else {
        return false;
    };
    if outer.mutability.is_some() || outer.lifetime.is_some() {
        return false;
    }
    let syn::Type::Slice(slice) = outer.elem.as_ref() else {
        return false;
    };
    let syn::Type::Reference(inner) = slice.elem.as_ref() else {
        return false;
    };
    if inner.mutability.is_some() || inner.lifetime.is_some() {
        return false;
    }
    matches!(
        inner.elem.as_ref(),
        syn::Type::Path(path)
            if path.qself.is_none()
                && path.path.segments.len() == 1
                && path.path.is_ident("str")
    )
}

fn validate_wiring(root: &Path) -> Result<()> {
    let main = read_authority_source(root, MAIN_PATH)?;
    let main = syn::parse_file(&main).context("xtask crate root does not parse as Rust")?;
    let mut modules = main.items.iter().filter_map(|item| match item {
        syn::Item::Mod(module) if module.ident == "seams" => Some(module),
        _ => None,
    });
    let module = modules
        .next()
        .context("xtask crate root no longer wires the seam authority")?;
    if modules.next().is_some()
        || module.content.is_some()
        || !module.attrs.is_empty()
        || !matches!(module.vis, syn::Visibility::Inherited)
    {
        bail!("xtask seam authority module wiring changes its trusted shape");
    }

    let validate = read_authority_source(root, VALIDATE_PATH)?;
    let validate = syn::parse_file(&validate).context("xtask validation source does not parse")?;
    let mut functions = validate.items.iter().filter_map(|item| match item {
        syn::Item::Fn(function) if function.sig.ident == "validate" => Some(function),
        _ => None,
    });
    let function = functions
        .next()
        .context("xtask validation source lacks its `validate` function")?;
    if functions.next().is_some()
        || !function
            .block
            .stmts
            .iter()
            .any(is_propagated_seam_validation_call)
    {
        bail!("xtask validation no longer propagates the seam authority result");
    }
    Ok(())
}

fn is_propagated_seam_validation_call(statement: &syn::Stmt) -> bool {
    let syn::Stmt::Expr(syn::Expr::Try(propagated), Some(_)) = statement else {
        return false;
    };
    let syn::Expr::Call(call) = propagated.expr.as_ref() else {
        return false;
    };
    let syn::Expr::Path(function) = call.func.as_ref() else {
        return false;
    };
    let segments = function
        .path
        .segments
        .iter()
        .map(|segment| segment.ident.to_string())
        .collect::<Vec<_>>();
    if segments != ["crate", "seams", "validate"] || call.args.len() != 2 {
        return false;
    }
    let mut args = call.args.iter();
    let Some(syn::Expr::Path(root)) = args.next() else {
        return false;
    };
    let Some(syn::Expr::Reference(files)) = args.next() else {
        return false;
    };
    if files.mutability.is_some() {
        return false;
    }
    matches!(
        (root.path.get_ident(), files.expr.as_ref()),
        (Some(root), syn::Expr::Path(files))
            if root == "root" && files.path.is_ident("files")
    )
}

#[cfg(test)]
mod tests {
    use super::{
        TRUSTED_REGISTRY_SOURCE, Transition, is_propagated_seam_validation_call, parse_registry,
        registry_declaration, validate_candidate_registry_source_against,
    };
    use std::collections::BTreeSet;

    const BASE: &[&str] = &["TrajectoryProjection", "HeldOutEvidenceBridge"];

    fn names(values: &[&str]) -> BTreeSet<String> {
        values.iter().map(|value| (*value).to_owned()).collect()
    }

    #[test]
    fn registry_is_a_literal_unique_private_string_slice() {
        assert_eq!(
            parse_registry(
                r#"const SEAMS: &[&str] = &["TrajectoryProjection", "HeldOutEvidenceBridge"];"#
            )
            .unwrap(),
            names(BASE)
        );
        for invalid in [
            r#"const SEAMS: &[&str] = &["TrajectoryProjection", "TrajectoryProjection"];"#,
            r#"pub const SEAMS: &[&str] = &["TrajectoryProjection"];"#,
            r#"#![cfg(any())]
const SEAMS: &[&str] = &["TrajectoryProjection"];"#,
            r#"#[cfg(any())]
const SEAMS: &[&str] = &["TrajectoryProjection"];"#,
            r#"const SEAMS: &[&str] = &#[cfg(any())] ["TrajectoryProjection"];"#,
            r#"const SEAMS: &[&str] = &[#[cfg(any())] "TrajectoryProjection"];"#,
            r#"const SEAMS: &[String] = &[];"#,
            r#"const SEAMS: &[&str] = OTHER;"#,
            r#"const OTHER: &[&str] = &["TrajectoryProjection"];"#,
        ] {
            assert!(parse_registry(invalid).is_err(), "accepted: {invalid}");
        }
    }

    #[test]
    fn a_candidate_may_only_remove_base_declarations() {
        let transition =
            Transition::from_sets(BASE, names(&["TrajectoryProjection"])).expect("subset");
        assert!(transition.is_remaining("TrajectoryProjection"));
        assert!(!transition.is_remaining("HeldOutEvidenceBridge"));
        assert!(
            Transition::from_sets(BASE, names(&["InventedSeam"])).is_err(),
            "a candidate cannot expand the trusted registry"
        );
    }

    #[test]
    fn every_removed_declaration_needs_an_explicitly_recorded_implementation() {
        let transition = Transition::from_sets(BASE, BTreeSet::new()).unwrap();
        assert!(
            transition
                .require_real_implementations(&names(&["TrajectoryProjection"]))
                .is_err()
        );
        transition
            .require_real_implementations(&names(BASE))
            .unwrap();
    }

    #[test]
    fn a_transition_may_change_only_literal_registry_entries() {
        let base_declaration = registry_declaration(BASE.iter().copied());
        let current_declaration = registry_declaration(super::super::SEAMS.iter().copied());
        let trusted = TRUSTED_REGISTRY_SOURCE.replacen(&current_declaration, &base_declaration, 1);
        let reduced_declaration = registry_declaration(["TrajectoryProjection"]);
        let reduced = trusted.replacen(&base_declaration, &reduced_declaration, 1);
        validate_candidate_registry_source_against(
            &trusted,
            &reduced,
            BASE,
            &names(&["TrajectoryProjection"]),
        )
        .unwrap();

        let weakened = reduced.replace(
            "mod transition;",
            "mod transition;\n// candidate also weakened policy",
        );
        assert!(
            validate_candidate_registry_source_against(
                &trusted,
                &weakened,
                BASE,
                &names(&["TrajectoryProjection"]),
            )
            .is_err()
        );
        assert!(
            validate_candidate_registry_source_against(
                &trusted,
                &trusted,
                BASE,
                &names(&["TrajectoryProjection"])
            )
            .is_err(),
            "a claimed removal must be present in candidate source"
        );
    }

    #[test]
    fn validation_wiring_must_propagate_the_exact_gate_call() {
        let valid: syn::Stmt =
            syn::parse_str("crate::seams::validate(root, &files)?;").expect("statement");
        assert!(is_propagated_seam_validation_call(&valid));
        for invalid in [
            "let _ = crate::seams::validate(root, &files);",
            "crate::seams::validate(other, &files)?;",
            "crate::seams::validate(root, files)?;",
            "other::seams::validate(root, &files)?;",
        ] {
            let statement = syn::parse_str(invalid).expect("statement");
            assert!(
                !is_propagated_seam_validation_call(&statement),
                "accepted: {invalid}"
            );
        }
    }
}
