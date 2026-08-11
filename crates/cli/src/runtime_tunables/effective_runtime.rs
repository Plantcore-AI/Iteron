//! Complete executable projection of one immutable V2 tunables checkpoint.
//!
//! Individual decoders remain small and typed, but production admission must execute all of them
//! as one gate.  This is the seam that proves the checkpoint was consumed by every registered
//! getter before any decoded policy can be installed.

use super::effective_content::{EffectiveContentError, EffectiveContentIdentities};
use super::effective_core::{EffectiveCoreError, EffectiveCoreSettings};
use super::effective_tooling::{EffectiveToolingError, EffectiveToolingSettings};
#[cfg(test)]
use super::effective_view::RuntimeBindingReceipt;
use super::effective_view::{EffectiveTunablesView, EffectiveViewError};
use super::fixed_artifacts::{FixedArtifactError, FixedArtifactReceipts, FixedAuthorityReceipts};
use iteron_record::TunablesCheckpoint;
use iteron_tunables::{RuntimeGetterId, RuntimeOwnerReceipt};

pub(crate) struct EffectiveRuntimeProjection {
    pub core: EffectiveCoreSettings,
    pub tooling: EffectiveToolingSettings,
    pub content: EffectiveContentIdentities,
    #[cfg(test)]
    pub binding: RuntimeBindingReceipt,
}

pub(crate) fn decode_checkpoint(
    checkpoint: &TunablesCheckpoint,
    owner_receipt: Option<&RuntimeOwnerReceipt>,
) -> Result<EffectiveRuntimeProjection, EffectiveRuntimeError> {
    let view = EffectiveTunablesView::from_checkpoint(checkpoint)?;
    let fixed_artifacts = FixedArtifactReceipts::production()?;
    let fixed_authorities = FixedAuthorityReceipts::production()?;
    decode_view(&view, owner_receipt, &fixed_artifacts, &fixed_authorities)
}

#[cfg(test)]
pub(crate) fn decode_checkpoint_with_fixed_artifacts(
    checkpoint: &TunablesCheckpoint,
    owner_receipt: Option<&RuntimeOwnerReceipt>,
    fixed_artifacts: &FixedArtifactReceipts,
) -> Result<EffectiveRuntimeProjection, EffectiveRuntimeError> {
    let view = EffectiveTunablesView::from_checkpoint(checkpoint)?;
    let fixed_authorities = FixedAuthorityReceipts::production()?;
    decode_view(&view, owner_receipt, fixed_artifacts, &fixed_authorities)
}

fn decode_view(
    view: &EffectiveTunablesView,
    owner_receipt: Option<&RuntimeOwnerReceipt>,
    fixed_artifacts: &FixedArtifactReceipts,
    fixed_authorities: &FixedAuthorityReceipts,
) -> Result<EffectiveRuntimeProjection, EffectiveRuntimeError> {
    let (core, tooling, content) = consume_registered_getters(view)?;
    let binding =
        view.seal_runtime_binding_receipt(owner_receipt, fixed_artifacts, fixed_authorities)?;
    #[cfg(not(test))]
    let _ = binding;
    Ok(EffectiveRuntimeProjection {
        core,
        tooling,
        content,
        #[cfg(test)]
        binding,
    })
}

pub(super) fn consume_registered_getters(
    view: &EffectiveTunablesView,
) -> Result<
    (
        EffectiveCoreSettings,
        EffectiveToolingSettings,
        EffectiveContentIdentities,
    ),
    EffectiveRuntimeError,
> {
    // These are the three top-level runtime projections. Nested projections (provider, MCP,
    // execution, app-server, binary media, multimodal admission, and observation tools) enter
    // their own narrower registered getter scopes while the top-level decoders execute.
    let core = view.with_getter(RuntimeGetterId::EffectiveCore, || {
        EffectiveCoreSettings::decode(view)
    })?;
    let tooling = view.with_getter(RuntimeGetterId::EffectiveTooling, || {
        EffectiveToolingSettings::decode(view)
    })?;
    let content = view.with_getter(RuntimeGetterId::EffectiveContent, || {
        super::effective_content::decode(view)
    })?;
    Ok((core, tooling, content))
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum EffectiveRuntimeError {
    #[error(transparent)]
    View(#[from] EffectiveViewError),
    #[error(transparent)]
    Core(#[from] EffectiveCoreError),
    #[error(transparent)]
    Tooling(#[from] EffectiveToolingError),
    #[error(transparent)]
    Content(#[from] EffectiveContentError),
    #[error(transparent)]
    FixedArtifact(#[from] FixedArtifactError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use iteron_tunables::ResolutionValue;
    use std::collections::BTreeMap;

    const CONFIGURED_CONTENT_ARTIFACT_FAMILIES: &[&str] = &[
        "operator_prompt_stream",
        "builtin_prompt_corpus",
        "instruction_bundle",
        "memory_corpus",
        "skill_catalog",
        "provider_model_capability_catalog",
        "mcp_topology_tool_catalog",
        "tool_action_space",
        "rate_card_catalog",
        "router_lexicons",
        "web_search_backend_catalog",
    ];

    const FIXED_ARTIFACT_FAMILIES: &[&str] = &[
        "operator_prompt_stream",
        "builtin_prompt_corpus",
        "instruction_bundle",
        "memory_corpus",
        "skill_catalog",
        "provider_model_capability_catalog",
        "mcp_topology_tool_catalog",
        "tool_action_space",
        "rate_card_catalog",
        "router_lexicons",
        "web_search_backend_catalog",
        "failure_classification_taxonomy",
    ];

    fn fixture_checkpoint() -> TunablesCheckpoint {
        TunablesCheckpoint::V2(
            iteron_record::snapshot_v2_from_resolved(&iteron_record::resolved_fixture::resolved())
                .expect("fixture projects to V2"),
        )
    }

    fn active_fixed_artifact_fixture() -> (TunablesCheckpoint, FixedArtifactReceipts) {
        let resolved = iteron_record::resolved_fixture::historical_resolved_with_fixed_artifacts();
        let checkpoint = TunablesCheckpoint::V2(
            iteron_record::snapshot_v2_from_resolved(&resolved).expect("fixture projects to V2"),
        );
        let mut receipts = FixedArtifactReceipts::default();
        let snapshot = checkpoint.as_v2().expect("V2 fixture");
        for family in FIXED_ARTIFACT_FAMILIES {
            let entry = snapshot
                .entries
                .iter()
                .find(|entry| entry.family_id == *family)
                .expect("fixed family entry");
            let value = serde_json::from_value::<ResolutionValue>(
                entry
                    .effective_value
                    .clone()
                    .expect("configured fixture has effective fixed artifact"),
            )
            .expect("typed fixed value");
            receipts.observe_checkpoint_value(family, value);
        }
        (checkpoint, receipts)
    }

    #[test]
    fn complete_resume_projection_executes_and_seals_every_registered_getter() {
        let checkpoint = fixture_checkpoint();
        let snapshot = checkpoint.as_v2().expect("V2 fixture");
        for family in CONFIGURED_CONTENT_ARTIFACT_FAMILIES {
            let entry = snapshot
                .entries
                .iter()
                .find(|entry| entry.family_id == *family)
                .expect("fixed family entry");
            assert_eq!(
                entry.state,
                iteron_protocol::RunGenesisTunableState::Inactive
            );
            assert!(super::super::fixed_artifacts::configured_absence_reason(
                entry
                    .inactive_reason
                    .as_ref()
                    .expect("typed inactive reason")
            ));
        }
        let effective = decode_checkpoint(&checkpoint, None)
            .expect("the production-compatible V2 fixture must pass the executable gate");
        assert_eq!(
            effective.binding.effective_family_count, effective.binding.getter_count,
            "every effective Full family must have exactly one consumed-family receipt"
        );
        assert_eq!(effective.binding.snapshot_digest_sha256.len(), 64);
    }

    #[test]
    fn deleting_one_real_getter_access_makes_resume_admission_fail_closed() {
        let checkpoint = fixture_checkpoint();
        let view = EffectiveTunablesView::from_checkpoint(&checkpoint).unwrap();
        let _decoded = consume_registered_getters(&view).expect("all real decoders execute");
        view.remove_getter_receipt("provider");
        let fixed_authorities = FixedAuthorityReceipts::production().expect("typed live owners");
        assert_eq!(
            view.seal_runtime_binding_receipt(
                None,
                &FixedArtifactReceipts::default(),
                &fixed_authorities,
            )
            .unwrap_err(),
            EffectiveViewError::MissingGetterReceipt("provider".into())
        );
    }

    #[test]
    fn deleting_or_changing_one_live_fixed_owner_makes_resume_fail_closed() {
        let checkpoint = fixture_checkpoint();
        let view = EffectiveTunablesView::from_checkpoint(&checkpoint).unwrap();
        let _decoded = consume_registered_getters(&view).expect("all real decoders execute");

        let mut missing = FixedAuthorityReceipts::production().expect("typed live owners");
        missing.remove("effort_reasoning_map");
        assert_eq!(
            view.seal_runtime_binding_receipt(
                None,
                &FixedArtifactReceipts::production().expect("typed fixed artifacts"),
                &missing,
            )
            .unwrap_err(),
            EffectiveViewError::MissingFixedAuthorityRuntimeReceipt("effort_reasoning_map".into())
        );

        let mut changed = FixedAuthorityReceipts::production().expect("typed live owners");
        changed.replace_for_test(
            "effort_reasoning_map",
            ResolutionValue::Object {
                fields: BTreeMap::new(),
            },
        );
        assert_eq!(
            view.seal_runtime_binding_receipt(
                None,
                &FixedArtifactReceipts::production().expect("typed fixed artifacts"),
                &changed,
            )
            .unwrap_err(),
            EffectiveViewError::FixedAuthorityRuntimeMismatch("effort_reasoning_map".into())
        );
    }

    #[test]
    fn deleting_one_checkpoint_fixed_consumer_makes_resume_fail_closed() {
        let checkpoint = fixture_checkpoint();
        let view = EffectiveTunablesView::from_checkpoint(&checkpoint).unwrap();
        let _decoded = consume_registered_getters(&view).expect("all real decoders execute");
        view.remove_fixed_consumer_receipt("request_output_cap");
        assert_eq!(
            view.seal_runtime_binding_receipt(
                None,
                &FixedArtifactReceipts::production().expect("typed fixed artifacts"),
                &FixedAuthorityReceipts::production().expect("typed live owners"),
            )
            .unwrap_err(),
            EffectiveViewError::MissingFixedConsumerReceipt("request_output_cap".into())
        );
    }

    #[test]
    fn stale_governed_catalog_is_rejected_before_the_consumer_effect() {
        let (checkpoint, mut receipts) = active_fixed_artifact_fixture();
        receipts.remove("instruction_bundle");
        let effects = std::sync::atomic::AtomicUsize::new(0);
        let result =
            decode_checkpoint_with_fixed_artifacts(&checkpoint, None, &receipts).map(|_| {
                effects.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            });
        assert!(matches!(
            result.unwrap_err(),
            EffectiveRuntimeError::View(EffectiveViewError::MissingFixedArtifactReceipt(
                family
            )) if family == "instruction_bundle"
        ));
        assert_eq!(effects.load(std::sync::atomic::Ordering::SeqCst), 0);
    }

    #[test]
    fn production_resume_rejects_a_historical_effective_fixed_artifact() {
        let (checkpoint, _) = active_fixed_artifact_fixture();
        let error = match decode_checkpoint(&checkpoint, None) {
            Ok(_) => panic!("historical effective fixed artifacts must fail closed"),
            Err(error) => error,
        };
        assert!(matches!(
            error,
            EffectiveRuntimeError::View(EffectiveViewError::MissingFixedArtifactReceipt(_))
        ));
    }

    #[test]
    fn internal_exact_receipt_comparison_accepts_only_identical_checkpoint_values() {
        let (checkpoint, receipts) = active_fixed_artifact_fixture();
        decode_checkpoint_with_fixed_artifacts(&checkpoint, None, &receipts)
            .expect("the internal equality gate admits an exact test receipt set");
    }
}
