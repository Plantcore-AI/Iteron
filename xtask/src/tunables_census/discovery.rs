use super::{
    AddressOwnerKind, AddressSelectorKind, CallerInputProof, CallerInputProofKind,
    CensusCandidateKind, CensusDisposition, CensusRow, ExternalAddress, ExternalAddressKind,
    InvariantKind, OwningHumanReviewStatus, QUALITY_INVARIANT_OVERRIDES,
};
use crate::tunables_params::{OwnerRow, UseSiteRow};
use anyhow::{Context, Result};
use quote::ToTokens as _;
use std::collections::BTreeMap;
use std::path::{Component, Path, PathBuf};
use syn::spanned::Spanned as _;
use syn::visit::{self, Visit};

mod forms;

use forms::{
    is_builder_name, is_closed_policy_fallback_value, is_inline_quality_value, is_policy_context,
    is_public, is_quality_constructor, manifest_kind, parameter_name, public_proof_kind,
    source_invariant_disposition, stable_id,
};

pub(super) struct DiscoveryReport {
    pub(super) rows: Vec<CensusRow>,
    pub(super) production_rust_files_scanned: usize,
    pub(super) source_form_counts: BTreeMap<CensusCandidateKind, usize>,
    pub(super) unclassified_source_forms: usize,
}

pub(super) fn scan_production_sources(
    root: &Path,
    excluded_crates: &[&str],
) -> Result<DiscoveryReport> {
    let mut files = Vec::new();
    collect_rust_files(&root.join("crates"), &mut files)?;
    files.sort();
    let mut report = DiscoveryReport {
        rows: Vec::new(),
        production_rust_files_scanned: 0,
        source_form_counts: empty_source_form_counts(),
        unclassified_source_forms: 0,
    };
    for file in files {
        let relative = file
            .strip_prefix(root)
            .unwrap_or(&file)
            .to_string_lossy()
            .replace('\\', "/");
        if is_test_path(&relative) {
            continue;
        }
        let Some(krate) = crate_of(&relative) else {
            continue;
        };
        if excluded_crates.contains(&krate) {
            continue;
        }
        let source = std::fs::read_to_string(&file)
            .with_context(|| format!("reading {}", file.display()))?;
        let discovered = discover_source_report(krate, &relative, &source)?;
        report.production_rust_files_scanned += 1;
        report.unclassified_source_forms += discovered.unclassified_source_forms;
        for (kind, count) in discovered.source_form_counts {
            *report.source_form_counts.entry(kind).or_default() += count;
        }
        report.rows.extend(discovered.rows);
    }
    Ok(report)
}

pub(super) fn source_form_invariant_matches(row: &CensusRow) -> bool {
    row.tier2_id.is_none()
        && source_invariant_disposition(&format!("{}::{}", row.owner.symbol, row.id), &row.value)
            .is_some_and(|disposition| Some(disposition.kind) == row.invariant_kind)
}

#[cfg(test)]
pub(super) fn discover_source(krate: &str, relative: &str, source: &str) -> Result<Vec<CensusRow>> {
    Ok(discover_source_report(krate, relative, source)?.rows)
}

#[cfg(test)]
pub(super) fn unclassified_source_form_count(
    krate: &str,
    relative: &str,
    source: &str,
) -> Result<usize> {
    Ok(discover_source_report(krate, relative, source)?.unclassified_source_forms)
}

#[cfg(test)]
pub(super) fn source_form_observation_counts(
    krate: &str,
    relative: &str,
    source: &str,
) -> Result<BTreeMap<CensusCandidateKind, usize>> {
    Ok(discover_source_report(krate, relative, source)?.source_form_counts)
}

struct FileDiscovery {
    rows: Vec<CensusRow>,
    source_form_counts: BTreeMap<CensusCandidateKind, usize>,
    unclassified_source_forms: usize,
}

fn discover_source_report(krate: &str, relative: &str, source: &str) -> Result<FileDiscovery> {
    let syntax = syn::parse_file(source)
        .with_context(|| format!("parsing {relative} for optimization candidates"))?;
    let mut visitor = CensusVisitor {
        krate,
        relative,
        modules: Vec::new(),
        owner: Vec::new(),
        serde_rename_all: Vec::new(),
        public_trait: Vec::new(),
        ordinals: BTreeMap::new(),
        found: Vec::new(),
        source_form_counts: empty_source_form_counts(),
        unclassified_source_forms: 0,
    };
    visitor.visit_file(&syntax);
    Ok(FileDiscovery {
        rows: visitor.found,
        source_form_counts: visitor.source_form_counts,
        unclassified_source_forms: visitor.unclassified_source_forms,
    })
}

struct CensusVisitor<'a> {
    krate: &'a str,
    relative: &'a str,
    modules: Vec<String>,
    owner: Vec<String>,
    serde_rename_all: Vec<Option<String>>,
    public_trait: Vec<bool>,
    ordinals: BTreeMap<String, usize>,
    found: Vec<CensusRow>,
    source_form_counts: BTreeMap<CensusCandidateKind, usize>,
    unclassified_source_forms: usize,
}

fn empty_source_form_counts() -> BTreeMap<CensusCandidateKind, usize> {
    CensusCandidateKind::all()
        .into_iter()
        .map(|kind| (kind, 0))
        .collect()
}

impl CensusVisitor<'_> {
    fn current_owner(&self) -> String {
        let owner = self
            .modules
            .iter()
            .chain(self.owner.iter())
            .cloned()
            .collect::<Vec<_>>()
            .join("::");
        if owner.is_empty() {
            self.relative
                .rsplit_once("/src/")
                .map_or(self.relative, |(_, path)| path)
                .trim_end_matches(".rs")
                .replace('/', "::")
        } else {
            owner
        }
    }

    fn next_ordinal(&mut self, form: &str, symbol: &str) -> usize {
        let key = format!("{form}\0{}\0{symbol}", self.current_owner());
        let entry = self.ordinals.entry(key).or_default();
        *entry += 1;
        *entry
    }

    fn observe(&mut self, kind: CensusCandidateKind) {
        *self.source_form_counts.entry(kind).or_default() += 1;
    }

    fn field_default(
        &mut self,
        field: &syn::Field,
        field_index: usize,
        kind: CensusCandidateKind,
        value: String,
        attribute: &str,
    ) {
        let field_name = field
            .ident
            .as_ref()
            .map(ToString::to_string)
            .unwrap_or_else(|| format!("unnamed_{field_index}"));
        let owner = self.current_owner();
        let serialized_field_name = serde_field_name(
            field,
            &field_name,
            self.serde_rename_all.last().and_then(Option::as_deref),
        );
        let clap_argument = clap_argument(field, &field_name);
        let flavor = match kind {
            CensusCandidateKind::SerdeDefault => "serde_default",
            CensusCandidateKind::ClapDefault => "clap_default",
            _ => unreachable!("field defaults use serde or clap"),
        };
        self.found.push(CensusRow {
            id: stable_id(
                self.krate,
                self.relative,
                &format!("{owner}.{field_name}.{flavor}"),
            ),
            candidate_kind: kind,
            rust_type: field.ty.to_token_stream().to_string(),
            value,
            owner: OwnerRow {
                krate: self.krate.to_owned(),
                path: self.relative.to_owned(),
                symbol: format!("{owner}::{field_name}"),
            },
            use_sites: vec![UseSiteRow {
                path: self.relative.to_owned(),
                line: field.span().start().line,
                evidence: format!("{attribute} production parser/deserializer default"),
            }],
            disposition: CensusDisposition::RuntimeSettable,
            external_address: Some(match kind {
                CensusCandidateKind::ClapDefault => ExternalAddress {
                    kind: ExternalAddressKind::DirectConfig,
                    selector_kind: if clap_argument.is_some() {
                        AddressSelectorKind::Argument
                    } else {
                        AddressSelectorKind::Path
                    },
                    selector: clap_argument.unwrap_or_else(|| format!("{owner}.{field_name}")),
                    owner_kind: AddressOwnerKind::Schema,
                    owner: format!("clap::{owner}"),
                },
                CensusCandidateKind::SerdeDefault => ExternalAddress {
                    kind: ExternalAddressKind::DirectConfig,
                    selector_kind: AddressSelectorKind::Path,
                    selector: format!("{owner}.{serialized_field_name}"),
                    owner_kind: AddressOwnerKind::Schema,
                    owner: format!("serde::{owner}"),
                },
                _ => unreachable!("field defaults use serde or clap"),
            }),
            caller_input_proof: None,
            binding_requirement: None,
            invariant_kind: None,
            review_evidence: None,
            owning_human_review: None,
            explicit_invariant_override: false,
            applied: true,
            behavior_oracle: Some(format!(
                "explicit input for {owner}::{field_name} replaces the declared {attribute} default"
            )),
            tier2_id: None,
        });
    }

    fn inspect_fields<'a>(&mut self, fields: impl Iterator<Item = &'a syn::Field>) {
        for (field_index, field) in fields.enumerate() {
            if has_cfg_test(&field.attrs) {
                continue;
            }
            for attr in &field.attrs {
                let path = attr.path();
                let rendered = attr.meta.to_token_stream().to_string();
                if path.is_ident("serde") && attribute_option(&rendered, "default") {
                    self.observe(CensusCandidateKind::SerdeDefault);
                    self.field_default(
                        field,
                        field_index,
                        CensusCandidateKind::SerdeDefault,
                        attribute_value(&rendered, "default")
                            .unwrap_or_else(|| "Default::default()".to_owned()),
                        "serde(default)",
                    );
                }
                if (path.is_ident("arg") || path.is_ident("clap"))
                    && (attribute_option(&rendered, "default_value")
                        || attribute_option(&rendered, "default_value_t"))
                {
                    self.observe(CensusCandidateKind::ClapDefault);
                    self.field_default(
                        field,
                        field_index,
                        CensusCandidateKind::ClapDefault,
                        attribute_value(&rendered, "default_value_t")
                            .or_else(|| attribute_value(&rendered, "default_value"))
                            .unwrap_or_else(|| "Default::default()".to_owned()),
                        "clap(default_value)",
                    );
                }
            }
        }
    }

    fn inspect_container_default(
        &mut self,
        ident: &syn::Ident,
        attrs: &[syn::Attribute],
        span: proc_macro2::Span,
    ) {
        for attr in attrs {
            let rendered = attr.meta.to_token_stream().to_string();
            if !attr.path().is_ident("serde") || !attribute_option(&rendered, "default") {
                continue;
            }
            self.observe(CensusCandidateKind::SerdeDefault);
            let owner = self.current_owner();
            self.found.push(CensusRow {
                id: stable_id(self.krate, self.relative, &format!("{owner}.serde_default")),
                candidate_kind: CensusCandidateKind::SerdeDefault,
                rust_type: ident.to_string(),
                value: attribute_value(&rendered, "default")
                    .unwrap_or_else(|| "Default::default()".to_owned()),
                owner: OwnerRow {
                    krate: self.krate.to_owned(),
                    path: self.relative.to_owned(),
                    symbol: owner.clone(),
                },
                use_sites: vec![UseSiteRow {
                    path: self.relative.to_owned(),
                    line: span.start().line,
                    evidence: "serde(default) production container deserializer".to_owned(),
                }],
                disposition: CensusDisposition::RuntimeSettable,
                external_address: Some(ExternalAddress {
                    kind: ExternalAddressKind::DirectConfig,
                    selector_kind: AddressSelectorKind::Path,
                    selector: owner.clone(),
                    owner_kind: AddressOwnerKind::Schema,
                    owner: format!("serde::{owner}"),
                }),
                caller_input_proof: None,
                binding_requirement: None,
                invariant_kind: None,
                review_evidence: None,
                owning_human_review: None,
                explicit_invariant_override: false,
                applied: true,
                behavior_oracle: Some(format!(
                    "explicit input fields for {owner} replace its serde container defaults"
                )),
                tier2_id: None,
            });
        }
    }

    // Keep the independently audited census fields explicit at each discovery site; grouping them
    // would obscure which exact source evidence and behavior oracle justify the emitted row.
    #[allow(clippy::too_many_arguments)]
    fn caller_bound_row(
        &mut self,
        candidate_kind: CensusCandidateKind,
        symbol: String,
        rust_type: String,
        value: String,
        line: usize,
        evidence: &str,
        behavior_oracle: String,
        proof: Option<CallerInputProof>,
    ) {
        let owner = self.current_owner();
        let ordinal = self.next_ordinal("caller_bound", &symbol);
        let source_invariant = proof
            .is_none()
            .then(|| {
                source_invariant_disposition(
                    &format!("{}::{owner}::{symbol}", self.relative),
                    &value,
                )
            })
            .flatten();
        let (disposition, external_address, binding_requirement) = if proof.is_some() {
            (
                CensusDisposition::RuntimeSettable,
                Some(ExternalAddress {
                    kind: ExternalAddressKind::CallerInput,
                    selector_kind: AddressSelectorKind::Argument,
                    selector: format!("{owner}::{symbol}#{ordinal}"),
                    owner_kind: AddressOwnerKind::Protocol,
                    owner: format!("rust-public-api::{}::{owner}", self.relative),
                }),
                None,
            )
        } else if source_invariant.is_some() {
            (CensusDisposition::InvariantReadOnly, None, None)
        } else {
            (
                CensusDisposition::BindingRequired,
                None,
                Some(format!(
                    "no public typed parameter, serde/clap schema, or protocol-envelope field binds {owner}::{symbol} to an external caller input"
                )),
            )
        };
        let (invariant_kind, review_evidence, owning_human_review, applied, behavior_oracle) =
            if let Some(invariant) = source_invariant {
                (
                    Some(invariant.kind),
                    Some(format!(
                        "closed source-form invariant rule: `{owner}` at {} — {}; observed at {}:{line}; mechanical source evidence only, not a claim of human review",
                        self.relative, invariant.rationale, self.relative
                    )),
                    Some(OwningHumanReviewStatus::RequiredNotSourceProven),
                    false,
                    None,
                )
            } else {
                (None, None, None, true, Some(behavior_oracle))
            };
        self.found.push(CensusRow {
            id: stable_id(
                self.krate,
                self.relative,
                &format!("{owner}.{symbol}.{ordinal}"),
            ),
            candidate_kind,
            rust_type,
            value,
            owner: OwnerRow {
                krate: self.krate.to_owned(),
                path: self.relative.to_owned(),
                symbol: owner,
            },
            use_sites: vec![UseSiteRow {
                path: self.relative.to_owned(),
                line,
                evidence: evidence.to_owned(),
            }],
            disposition,
            external_address,
            caller_input_proof: proof,
            binding_requirement,
            invariant_kind,
            review_evidence,
            owning_human_review,
            explicit_invariant_override: false,
            applied,
            behavior_oracle,
            tier2_id: None,
        });
    }

    fn policy_call(&mut self, node: &syn::ExprCall, callee: &syn::Path) {
        let rendered = callee.to_token_stream().to_string().replace(' ', "");
        let leaf = callee
            .segments
            .last()
            .map(|segment| segment.ident.to_string())
            .unwrap_or_default();
        let context = format!("{}::{rendered}", self.current_owner()).to_ascii_lowercase();
        let named_default = leaf == "default" || leaf.starts_with("default_");
        let named_fallback = leaf.contains("fallback");
        if !(named_default || named_fallback) || !is_policy_context(&context) {
            return;
        }
        let kind = if named_fallback {
            CensusCandidateKind::PolicyFallbackCall
        } else {
            CensusCandidateKind::PolicyDefaultConstructor
        };
        self.observe(kind);
        if is_quality_constructor(&rendered, &self.current_owner(), self.relative) {
            self.inline_argument_rows(
                kind,
                &rendered,
                &node.args,
                node.span().start().line,
                "inline production policy default/fallback value",
            );
        }
    }

    fn builder_call(&mut self, node: &syn::ExprCall, callee: &syn::Path) {
        let rendered = callee.to_token_stream().to_string().replace(' ', "");
        let leaf = callee
            .segments
            .last()
            .map(|segment| segment.ident.to_string())
            .unwrap_or_default();
        let context = format!("{}::{rendered}", self.current_owner()).to_ascii_lowercase();
        if !is_builder_name(&leaf) || !is_policy_context(&context) {
            return;
        }
        self.observe(CensusCandidateKind::BuilderQualityDefault);
        if is_quality_constructor(&rendered, &self.current_owner(), self.relative) {
            self.inline_argument_rows(
                CensusCandidateKind::BuilderQualityDefault,
                &rendered,
                &node.args,
                node.span().start().line,
                "inline production quality builder value",
            );
        }
    }

    fn builder_method_call(&mut self, node: &syn::ExprMethodCall) {
        let method = node.method.to_string();
        let rendered_receiver = node.receiver.to_token_stream().to_string();
        let context =
            format!("{}::{rendered_receiver}::{method}", self.current_owner()).to_ascii_lowercase();
        if !is_builder_name(&method) || !is_policy_context(&context) {
            return;
        }
        self.observe(CensusCandidateKind::BuilderQualityDefault);
        let target = format!("{rendered_receiver}::{method}");
        if is_quality_constructor(&target, &self.current_owner(), self.relative) {
            self.inline_argument_rows(
                CensusCandidateKind::BuilderQualityDefault,
                &target,
                &node.args,
                node.span().start().line,
                "inline production quality builder method value",
            );
        }
    }

    fn inline_argument_rows(
        &mut self,
        kind: CensusCandidateKind,
        target: &str,
        arguments: &syn::punctuated::Punctuated<syn::Expr, syn::Token![,]>,
        line: usize,
        evidence: &str,
    ) {
        for (index, argument) in arguments.iter().enumerate() {
            let source_owned_value = if matches!(kind, CensusCandidateKind::PolicyFallbackCall) {
                is_closed_policy_fallback_value(argument)
            } else {
                is_inline_quality_value(argument)
            };
            if !source_owned_value {
                continue;
            }
            self.caller_bound_row(
                kind,
                format!("inline::{target}::argument_{index}"),
                "_ (inferred by rustc)".to_owned(),
                argument.to_token_stream().to_string(),
                line,
                evidence,
                format!(
                    "binding this inline value changes argument {index} supplied to `{target}`"
                ),
                None,
            );
        }
    }

    fn builder_definition(
        &mut self,
        name: &str,
        signature: &syn::Signature,
        proof_kind: Option<CallerInputProofKind>,
        line: usize,
    ) {
        if !is_builder_name(name) {
            return;
        }
        let context = format!(
            "{}::{name} {}",
            self.current_owner(),
            signature.to_token_stream()
        )
        .to_ascii_lowercase();
        if !is_policy_context(&context) {
            return;
        }
        self.observe(CensusCandidateKind::BuilderQualityDefault);
        let Some(proof_kind) = proof_kind else {
            return;
        };
        // The visitor invokes this hook before entering the function body, so include the builder
        // definition itself in the owner path. A top-level `build` would otherwise serialize an
        // empty owner even though its exact source symbol is known.
        self.owner.push(name.to_owned());
        for (index, input) in signature.inputs.iter().enumerate() {
            let syn::FnArg::Typed(parameter) = input else {
                continue;
            };
            let parameter_name = parameter_name(&parameter.pat, index);
            let proof = self.make_public_parameter_proof(proof_kind, &parameter_name, line);
            self.caller_bound_row(
                CensusCandidateKind::BuilderQualityDefault,
                format!("parameter::{parameter_name}"),
                parameter.ty.to_token_stream().to_string(),
                parameter.to_token_stream().to_string(),
                line,
                "public quality builder typed parameter definition",
                format!(
                    "the external caller directly supplies `{parameter_name}` to public builder `{name}`"
                ),
                Some(proof),
            );
        }
        self.owner.pop();
    }

    fn make_public_parameter_proof(
        &self,
        kind: CallerInputProofKind,
        parameter: &str,
        line: usize,
    ) -> CallerInputProof {
        let symbol = self.current_owner();
        CallerInputProof {
            kind,
            path: self.relative.to_owned(),
            symbol: symbol.clone(),
            evidence: format!(
                "public Rust protocol `{symbol}` directly declares typed parameter `{parameter}` at {}:{line}",
                self.relative
            ),
        }
    }

    fn manifest_definition(&mut self, item: &syn::ItemStruct) {
        let Some(kind) = manifest_kind(&item.ident.to_string()) else {
            return;
        };
        self.observe(kind);
        let owner = self.current_owner();
        let symbol = format!("{owner}::{}", item.ident);
        self.found.push(CensusRow {
            id: stable_id(self.krate, self.relative, &format!("{symbol}.manifest_schema")),
            candidate_kind: kind,
            rust_type: item.ident.to_string(),
            value: item.fields.to_token_stream().to_string(),
            owner: OwnerRow {
                krate: self.krate.to_owned(),
                path: self.relative.to_owned(),
                symbol: symbol.clone(),
            },
            use_sites: vec![UseSiteRow {
                path: self.relative.to_owned(),
                line: item.span().start().line,
                evidence: "production dynamic implementation/plugin manifest schema".to_owned(),
            }],
            disposition: CensusDisposition::RuntimeSettable,
            external_address: Some(ExternalAddress {
                kind: ExternalAddressKind::DirectConfig,
                selector_kind: AddressSelectorKind::Path,
                selector: symbol.clone(),
                owner_kind: AddressOwnerKind::Protocol,
                owner: format!("serde-manifest::{}::{symbol}", self.relative),
            }),
            caller_input_proof: None,
            binding_requirement: None,
            invariant_kind: None,
            review_evidence: None,
            owning_human_review: None,
            explicit_invariant_override: false,
            applied: true,
            behavior_oracle: Some(
                "a validated external manifest document supplies the dynamic implementation/plugin fields"
                    .to_owned(),
            ),
            tier2_id: None,
        });
    }

    fn manifest_construction(&mut self, node: &syn::ExprStruct) {
        let Some(kind) = manifest_kind(
            &node
                .path
                .segments
                .last()
                .map(|segment| segment.ident.to_string())
                .unwrap_or_default(),
        ) else {
            return;
        };
        // Construction is source-coverage evidence for the manifest form, not a second tunable.
        self.observe(kind);
    }

    fn inline_struct_values(&mut self, node: &syn::ExprStruct) {
        let rendered = node.path.to_token_stream().to_string().replace(' ', "");
        let owner = self.current_owner();
        if manifest_kind(
            &node
                .path
                .segments
                .last()
                .map(|segment| segment.ident.to_string())
                .unwrap_or_default(),
        )
        .is_some()
        {
            return;
        }
        let kind = if self
            .owner
            .last()
            .is_some_and(|owner| owner == "default" || owner.contains("fallback"))
        {
            CensusCandidateKind::PolicyDefaultConstructor
        } else {
            CensusCandidateKind::BuilderQualityDefault
        };
        let context = format!("{owner}::{rendered}").to_ascii_lowercase();
        if !is_policy_context(&context) {
            return;
        }
        // Observation of the declared source form is independent from whether the literal owns
        // an optimization candidate. Exact accumulator/result constructors still count here.
        self.observe(kind);
        if !is_quality_constructor(&rendered, &owner, self.relative) {
            return;
        }
        for field in &node.fields {
            if !is_inline_quality_value(&field.expr) {
                continue;
            }
            let member = field.member.to_token_stream().to_string();
            self.caller_bound_row(
                kind,
                format!("inline::{rendered}::field::{member}"),
                "_ (inferred by rustc)".to_owned(),
                field.expr.to_token_stream().to_string(),
                field.span().start().line,
                "inline production quality/default struct field value",
                format!("binding this inline value changes `{rendered}.{member}`"),
                None,
            );
        }
    }

    fn inline_local_value(&mut self, local: &syn::Local) {
        let Some(init) = &local.init else {
            return;
        };
        let name = local.pat.to_token_stream().to_string();
        if !is_policy_context(&name.to_ascii_lowercase()) || !is_inline_quality_value(&init.expr) {
            return;
        }
        // Local scalar initializers are runtime accumulator/state observations, not declarations
        // of an externally selectable policy. Keep their source-form coverage without minting a
        // false optimization candidate (for example retry_index=0 or saw_tools=false).
        self.observe(CensusCandidateKind::BuilderQualityDefault);
    }

    fn embedded_asset(&mut self, node: &syn::Macro) {
        let leaf = node
            .path
            .segments
            .last()
            .map(|segment| segment.ident.to_string())
            .unwrap_or_default();
        let kind = match leaf.as_str() {
            "include_str" => CensusCandidateKind::IncludeStrAsset,
            "include_bytes" => CensusCandidateKind::IncludeBytesAsset,
            _ => return,
        };
        let Ok(asset) = syn::parse2::<syn::LitStr>(node.tokens.clone()) else {
            self.unclassified_source_forms += 1;
            return;
        };
        if is_nonproduction_asset(&asset.value()) {
            return;
        }
        self.observe(kind);
        let owner = self.current_owner();
        let ordinal = self.next_ordinal("embedded_asset", &asset.value());
        let id = stable_id(
            self.krate,
            self.relative,
            &format!("{owner}.{leaf}.{}.{}", asset.value(), ordinal),
        );
        let explicit = QUALITY_INVARIANT_OVERRIDES.contains(&id.as_str());
        let symbol = if owner.is_empty() {
            format!("{leaf}!({})", asset.value())
        } else {
            owner
        };
        let line = node.span().start().line;
        self.found.push(CensusRow {
            id,
            candidate_kind: kind,
            rust_type: if leaf == "include_str" { "&str" } else { "&[u8]" }.to_owned(),
            value: node.to_token_stream().to_string(),
            owner: OwnerRow {
                krate: self.krate.to_owned(),
                path: self.relative.to_owned(),
                symbol: symbol.clone(),
            },
            use_sites: vec![UseSiteRow {
                path: self.relative.to_owned(),
                line,
                evidence: format!("production {leaf}! embedded asset `{}`", asset.value()),
            }],
            disposition: CensusDisposition::InvariantReadOnly,
            external_address: None,
            caller_input_proof: None,
            binding_requirement: None,
            invariant_kind: Some(InvariantKind::WireCompatibility),
            review_evidence: Some(format!(
                "{}: `{symbol}` at {} — embedded bytes participate in compiled runtime behavior; observed at {}:{line}; mechanical source evidence only, not a claim of human review",
                if explicit { "explicit census disposition override" } else { "closed embedded-asset disposition rule" },
                self.relative,
                self.relative,
            )),
            owning_human_review: Some(OwningHumanReviewStatus::RequiredNotSourceProven),
            explicit_invariant_override: explicit,
            applied: false,
            behavior_oracle: None,
            tier2_id: None,
        });
    }
}

impl<'ast> Visit<'ast> for CensusVisitor<'_> {
    fn visit_item_mod(&mut self, item: &'ast syn::ItemMod) {
        if has_cfg_test(&item.attrs) {
            return;
        }
        self.modules.push(item.ident.to_string());
        if let Some((_, items)) = &item.content {
            for item in items {
                self.visit_item(item);
            }
        }
        self.modules.pop();
    }

    fn visit_item_struct(&mut self, item: &'ast syn::ItemStruct) {
        if has_cfg_test(&item.attrs) {
            return;
        }
        self.owner.push(item.ident.to_string());
        self.manifest_definition(item);
        self.serde_rename_all
            .push(serde_container_rename(&item.attrs, "rename_all"));
        self.inspect_container_default(&item.ident, &item.attrs, item.span());
        self.inspect_fields(item.fields.iter());
        self.serde_rename_all.pop();
        self.owner.pop();
    }

    fn visit_item_enum(&mut self, item: &'ast syn::ItemEnum) {
        if has_cfg_test(&item.attrs) {
            return;
        }
        self.owner.push(item.ident.to_string());
        self.serde_rename_all
            .push(serde_container_rename(&item.attrs, "rename_all_fields"));
        self.inspect_container_default(&item.ident, &item.attrs, item.span());
        for variant in &item.variants {
            if has_cfg_test(&variant.attrs) {
                continue;
            }
            self.owner.push(variant.ident.to_string());
            self.inspect_fields(variant.fields.iter());
            self.owner.pop();
        }
        self.serde_rename_all.pop();
        self.owner.pop();
    }

    fn visit_item_fn(&mut self, item: &'ast syn::ItemFn) {
        if has_cfg_test(&item.attrs) {
            return;
        }
        let name = item.sig.ident.to_string();
        let proof_kind = is_public(&item.vis).then(|| {
            public_proof_kind(
                &item.attrs,
                &name,
                &self.current_owner(),
                CallerInputProofKind::PublicFunction,
            )
        });
        self.builder_definition(&name, &item.sig, proof_kind, item.span().start().line);
        self.owner.push(name);
        visit::visit_item_fn(self, item);
        self.owner.pop();
    }

    fn visit_item_impl(&mut self, item: &'ast syn::ItemImpl) {
        if has_cfg_test(&item.attrs) {
            return;
        }
        self.owner
            .push(item.self_ty.to_token_stream().to_string().replace(' ', ""));
        visit::visit_item_impl(self, item);
        self.owner.pop();
    }

    fn visit_item_trait(&mut self, item: &'ast syn::ItemTrait) {
        if has_cfg_test(&item.attrs) {
            return;
        }
        self.owner.push(item.ident.to_string());
        self.public_trait.push(is_public(&item.vis));
        visit::visit_item_trait(self, item);
        self.public_trait.pop();
        self.owner.pop();
    }

    fn visit_trait_item_fn(&mut self, item: &'ast syn::TraitItemFn) {
        if has_cfg_test(&item.attrs) {
            return;
        }
        let name = item.sig.ident.to_string();
        let public = self.public_trait.last().copied().unwrap_or(false);
        self.builder_definition(
            &name,
            &item.sig,
            public.then_some(CallerInputProofKind::PublicTraitMethod),
            item.span().start().line,
        );
        self.owner.push(name);
        visit::visit_trait_item_fn(self, item);
        self.owner.pop();
    }

    fn visit_impl_item_fn(&mut self, item: &'ast syn::ImplItemFn) {
        if has_cfg_test(&item.attrs) {
            return;
        }
        let name = item.sig.ident.to_string();
        let proof_kind = is_public(&item.vis).then(|| {
            public_proof_kind(
                &item.attrs,
                &name,
                &self.current_owner(),
                CallerInputProofKind::PublicMethod,
            )
        });
        self.builder_definition(&name, &item.sig, proof_kind, item.span().start().line);
        self.owner.push(name);
        visit::visit_impl_item_fn(self, item);
        self.owner.pop();
    }

    fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
        if let syn::Expr::Path(function) = node.func.as_ref() {
            self.policy_call(node, &function.path);
            self.builder_call(node, &function.path);
        }
        visit::visit_expr_call(self, node);
    }

    fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
        self.builder_method_call(node);
        visit::visit_expr_method_call(self, node);
    }

    fn visit_expr_struct(&mut self, node: &'ast syn::ExprStruct) {
        self.manifest_construction(node);
        self.inline_struct_values(node);
        visit::visit_expr_struct(self, node);
    }

    fn visit_local(&mut self, node: &'ast syn::Local) {
        self.inline_local_value(node);
        visit::visit_local(self, node);
    }

    fn visit_macro(&mut self, node: &'ast syn::Macro) {
        self.embedded_asset(node);
        let leaf = node
            .path
            .segments
            .last()
            .map(|segment| segment.ident.to_string().to_ascii_lowercase())
            .unwrap_or_default();
        let context = self.current_owner().to_ascii_lowercase();
        if leaf != "include_str"
            && leaf != "include_bytes"
            && (leaf.contains("default") || leaf.contains("fallback") || leaf.contains("manifest"))
            && is_policy_context(&context)
        {
            self.unclassified_source_forms += 1;
        }
        visit::visit_macro(self, node);
    }
}

fn attribute_option(rendered: &str, name: &str) -> bool {
    rendered
        .split(|character: char| !character.is_ascii_alphanumeric() && character != '_')
        .any(|token| token == name)
}

fn attribute_value(rendered: &str, name: &str) -> Option<String> {
    let (_, tail) = rendered.split_once(name)?;
    let value = tail.trim_start().strip_prefix('=')?.trim_start();
    Some(
        value
            .split(',')
            .next()
            .unwrap_or(value)
            .trim()
            .trim_end_matches(')')
            .trim()
            .to_owned(),
    )
}

fn serde_container_rename(attrs: &[syn::Attribute], key: &str) -> Option<String> {
    attrs.iter().find_map(|attr| {
        attr.path()
            .is_ident("serde")
            .then(|| attribute_value(&attr.meta.to_token_stream().to_string(), key))
            .flatten()
            .map(|value| value.trim_matches('"').to_owned())
    })
}

fn serde_field_name(field: &syn::Field, rust_name: &str, rename_all: Option<&str>) -> String {
    if let Some(explicit) = field.attrs.iter().find_map(|attr| {
        attr.path()
            .is_ident("serde")
            .then(|| attribute_value(&attr.meta.to_token_stream().to_string(), "rename"))
            .flatten()
    }) {
        return explicit.trim_matches('"').to_owned();
    }
    let rust_name = rust_name.strip_prefix("r#").unwrap_or(rust_name);
    match rename_all {
        Some("camelCase") => camel_case(rust_name, false),
        Some("PascalCase") => camel_case(rust_name, true),
        Some("kebab-case") => rust_name.replace('_', "-"),
        Some("SCREAMING_SNAKE_CASE") => rust_name.to_ascii_uppercase(),
        Some("SCREAMING-KEBAB-CASE") => rust_name.replace('_', "-").to_ascii_uppercase(),
        Some("UPPERCASE") => rust_name.to_ascii_uppercase(),
        Some("lowercase") => rust_name.to_ascii_lowercase(),
        Some("snake_case") | None => rust_name.to_owned(),
        Some(_) => rust_name.to_owned(),
    }
}

fn camel_case(name: &str, upper_first: bool) -> String {
    let mut parts = name.split('_').filter(|part| !part.is_empty());
    let Some(first) = parts.next() else {
        return String::new();
    };
    let mut rendered = if upper_first {
        capitalize(first)
    } else {
        first.to_ascii_lowercase()
    };
    for part in parts {
        rendered.push_str(&capitalize(part));
    }
    rendered
}

fn capitalize(part: &str) -> String {
    let mut chars = part.chars();
    let Some(first) = chars.next() else {
        return String::new();
    };
    first.to_uppercase().chain(chars).collect()
}

fn clap_argument(field: &syn::Field, rust_name: &str) -> Option<String> {
    for attr in &field.attrs {
        if !(attr.path().is_ident("arg") || attr.path().is_ident("clap")) {
            continue;
        }
        let rendered = attr.meta.to_token_stream().to_string();
        if let Some(explicit) = attribute_value(&rendered, "long") {
            return Some(format!("--{}", explicit.trim_matches('"')));
        }
        if attribute_option(&rendered, "long") {
            return Some(format!(
                "--{}",
                rust_name
                    .strip_prefix("r#")
                    .unwrap_or(rust_name)
                    .replace('_', "-")
            ));
        }
    }
    None
}

fn has_cfg_test(attrs: &[syn::Attribute]) -> bool {
    attrs.iter().any(|attr| {
        attr.path().is_ident("test")
            || ((attr.path().is_ident("cfg") || attr.path().is_ident("cfg_attr"))
                && attr.meta.to_token_stream().to_string().contains("test"))
    })
}

fn collect_rust_files(dir: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    if !dir.is_dir() {
        return Ok(());
    }
    for entry in std::fs::read_dir(dir)? {
        let path = entry?.path();
        if path.components().any(|component| {
            matches!(
                component,
                Component::Normal(name)
                    if matches!(name.to_str(), Some("target" | "generated" | "vendor" | "tests" | "benches"))
            )
        }) {
            continue;
        }
        if path.is_dir() {
            collect_rust_files(&path, out)?;
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            out.push(path);
        }
    }
    Ok(())
}

fn is_test_path(relative: &str) -> bool {
    relative.contains("/tests/")
        || relative.ends_with("_tests.rs")
        || relative.ends_with("/tests.rs")
        || relative.contains("/benches/")
        || relative.contains("/target/")
        || relative.contains("/generated/")
        || relative.contains("/vendor/")
}

fn is_nonproduction_asset(asset: &str) -> bool {
    asset.split(['/', '\\']).any(|part| {
        matches!(
            part,
            "tests"
                | "test"
                | "fixtures"
                | "fixture"
                | "golden"
                | "target"
                | "generated"
                | "vendor"
        )
    })
}

fn crate_of(relative: &str) -> Option<&str> {
    relative
        .strip_prefix("crates/")
        .and_then(|rest| rest.split('/').next())
}
