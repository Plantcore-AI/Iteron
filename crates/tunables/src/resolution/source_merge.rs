use super::select_default;
use crate::resolution_prepare::PreparedInput;
use crate::resolution_types::{
    ResolutionProvenance, ResolutionSource, ResolutionValue, ShadowedValue, UnresolvedReason,
};
use crate::{Family, SourceBinding, SourceMergePolicy};

pub(super) struct Selected {
    pub(super) value: ResolutionValue,
    pub(super) provenance: ResolutionProvenance,
    pub(super) explicit: bool,
}

struct Restriction {
    selected: Selected,
    policy: SourceMergePolicy,
}

pub(super) struct ExplicitSelection {
    base: Option<Selected>,
    restrictions: Vec<Restriction>,
    pub(super) shadowed: Vec<ShadowedValue>,
}

impl ExplicitSelection {
    pub(super) fn has_value(&self) -> bool {
        self.base.is_some() || !self.restrictions.is_empty()
    }

    pub(super) fn without_default(mut self) -> (Option<Selected>, Vec<ShadowedValue>) {
        let base = self.base.take().or_else(|| {
            (!self.restrictions.is_empty()).then(|| self.restrictions.remove(0).selected)
        });
        let selected =
            base.map(|base| apply_restrictions(base, self.restrictions, &mut self.shadowed));
        (selected, self.shadowed)
    }

    pub(super) fn with_default(
        mut self,
        family: &Family,
        prepared: &PreparedInput,
    ) -> Result<(Selected, Vec<ShadowedValue>), (UnresolvedReason, Vec<ShadowedValue>)> {
        let base = match self.base.take() {
            Some(base) => base,
            None => match select_default(family, prepared) {
                Ok(default) => default,
                Err(_reason) if !self.restrictions.is_empty() => {
                    // An optional project ceiling (for example max_usd) is allowed to introduce
                    // the bound when the operator intentionally supplied no ceiling.
                    let first = self.restrictions.remove(0);
                    debug_assert!(matches!(
                        first.policy,
                        SourceMergePolicy::TightenMaximum
                            | SourceMergePolicy::TightenBooleanGrant
                            | SourceMergePolicy::IntersectAllowSet
                    ));
                    first.selected
                }
                Err(reason) => return Err((reason, self.shadowed)),
            },
        };
        let selected = apply_restrictions(base, self.restrictions, &mut self.shadowed);
        Ok((selected, self.shadowed))
    }
}

pub(super) fn select_explicit(family: &Family, prepared: &PreparedInput) -> ExplicitSelection {
    let mut winner = None;
    let mut restrictions = Vec::new();
    let mut shadowed = Vec::new();
    let mut bindings = family.source.bindings.to_vec();
    let carries_universal_profile_value = prepared.input.profile.as_ref().is_some_and(|profile| {
        profile.values.iter().any(|value| {
            value.family == family.id && value.as_declared_source == crate::SourceKind::UserConfig
        })
    });
    if carries_universal_profile_value
        && !bindings
            .iter()
            .any(|binding| binding.kind == crate::SourceKind::UserConfig)
        && let Some(binding) = family.profile_binding(crate::SourceKind::UserConfig)
    {
        // Operator profile values outrank built-in/derived/catalog defaults but still remain
        // beneath any immutable cross-field ceiling enforced after source selection.
        bindings.insert(0, binding);
    }
    for binding in &bindings {
        let direct = prepared
            .input
            .declared_values
            .iter()
            .find(|value| value.family == family.id && value.source == binding.kind)
            .map(|value| Selected {
                value: value.value.clone(),
                provenance: declared_provenance(binding, value.evidence_digest_sha256.clone()),
                explicit: true,
            });
        let profile = prepared
            .input
            .profile
            .as_ref()
            .zip(prepared.profile_digest_sha256.as_ref())
            .and_then(|(profile, profile_digest)| {
                profile
                    .values
                    .iter()
                    .find(|value| {
                        value.family == family.id && value.as_declared_source == binding.kind
                    })
                    .map(|value| Selected {
                        value: value.value.clone(),
                        provenance: ResolutionProvenance {
                            source: ResolutionSource::Profile {
                                kind: binding.kind,
                                trust: binding.trust,
                                declared_locator: binding.locator,
                                profile_digest_sha256: profile_digest.clone(),
                            },
                        },
                        explicit: true,
                    })
            });

        let candidate = match (direct, profile) {
            (Some(direct), Some(profile)) => {
                shadowed.push(shadow(profile, "same_source_profile_overridden"));
                Some(direct)
            }
            (Some(direct), None) => Some(direct),
            (None, Some(profile)) => Some(profile),
            (None, None) => None,
        };
        let Some(candidate) = candidate else {
            continue;
        };
        match binding.merge {
            SourceMergePolicy::TightenMaximum
            | SourceMergePolicy::TightenBooleanGrant
            | SourceMergePolicy::IntersectAllowSet => restrictions.push(Restriction {
                selected: candidate,
                policy: binding.merge,
            }),
            SourceMergePolicy::Override
            | SourceMergePolicy::RouteSuggestion
            | SourceMergePolicy::RepositoryScoped => {
                if winner.is_none() {
                    winner = Some(candidate);
                } else {
                    shadowed.push(shadow(candidate, "lower_precedence"));
                }
            }
        }
    }
    ExplicitSelection {
        base: winner,
        restrictions,
        shadowed,
    }
}

fn apply_restrictions(
    mut base: Selected,
    restrictions: Vec<Restriction>,
    shadowed: &mut Vec<ShadowedValue>,
) -> Selected {
    for mut restriction in restrictions {
        let tightened = match restriction.policy {
            SourceMergePolicy::TightenMaximum => {
                crate::resolution_value::numeric_cmp(&restriction.selected.value, &base.value)
                    .is_some_and(|ordering| ordering.is_lt())
            }
            SourceMergePolicy::TightenBooleanGrant => matches!(
                (&base.value, &restriction.selected.value),
                (
                    ResolutionValue::Boolean { value: true },
                    ResolutionValue::Boolean { value: false }
                )
            ),
            SourceMergePolicy::IntersectAllowSet => {
                intersect_allow_set(&base.value, &mut restriction.selected.value)
            }
            SourceMergePolicy::Override
            | SourceMergePolicy::RouteSuggestion
            | SourceMergePolicy::RepositoryScoped => false,
        };
        if tightened {
            shadowed.push(shadow(base, "project_tightened"));
            base = restriction.selected;
        } else {
            shadowed.push(shadow(restriction.selected, "project_tightening_inert"));
        }
    }
    base
}

fn intersect_allow_set(base: &ResolutionValue, project: &mut ResolutionValue) -> bool {
    let (
        ResolutionValue::List { items: base_items },
        ResolutionValue::List {
            items: project_items,
        },
    ) = (base, project)
    else {
        return false;
    };
    let admitted = project_items
        .iter()
        .collect::<std::collections::BTreeSet<_>>();
    let intersection = base_items
        .iter()
        .filter(|item| admitted.contains(item))
        .cloned()
        .collect::<Vec<_>>();
    if intersection == *base_items {
        false
    } else {
        *project_items = intersection;
        true
    }
}

fn declared_provenance(binding: &SourceBinding, digest: String) -> ResolutionProvenance {
    ResolutionProvenance {
        source: ResolutionSource::Declared {
            kind: binding.kind,
            trust: binding.trust,
            declared_locator: binding.locator,
            evidence_digest_sha256: digest,
        },
    }
}

fn shadow(selected: Selected, reason_code: &'static str) -> ShadowedValue {
    ShadowedValue {
        value: selected.value,
        provenance: selected.provenance,
        reason_code,
    }
}
