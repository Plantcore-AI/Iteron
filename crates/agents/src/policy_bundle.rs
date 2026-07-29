//! One-shot boot consumption of the protocol-owned policy-bundle port.
//!
//! This module has no activation API. The composition root asks a [`PolicyBundleResolver`] once,
//! validates the returned protocol view, binds any governed tool-policy identity to a locally
//! trusted inert [`ToolFilter`], and retains the result behind an [`Arc`].

use crate::ToolFilter;
use core_protocol::bundle::{
    BundleResolutionError, MAX_RESOLVED_BUNDLE_POLICIES, PolicyBundleResolver, ResolvedBundle,
    ResolvedPolicy,
};
use core_protocol::slot::SlotId;
use std::collections::BTreeMap;
use std::sync::Arc;

const TOOL_POLICY_SLOT: &str = "core/tool_policy";

/// A trusted local interpretation of one exact governed tool-policy identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolPolicyBinding {
    policy_id: String,
    version: String,
    digest: String,
    tools: ToolFilter,
}

impl ToolPolicyBinding {
    pub fn new(
        policy_id: impl Into<String>,
        version: impl Into<String>,
        digest: impl Into<String>,
        tools: ToolFilter,
    ) -> Result<Self, BundleResolutionError> {
        let binding = Self {
            policy_id: policy_id.into(),
            version: version.into(),
            digest: digest.into(),
            tools,
        };
        if binding.policy_id.trim().is_empty() || binding.version.trim().is_empty() {
            return Err(BundleResolutionError::Malformed(
                "tool policy catalog identity",
            ));
        }
        if binding.digest.len() != 64
            || !binding
                .digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(BundleResolutionError::Malformed(
                "tool policy catalog digest",
            ));
        }
        Ok(binding)
    }

    fn matches(&self, policy: &ResolvedPolicy) -> bool {
        self.policy_id == policy.policy_id
            && self.version == policy.version
            && self.digest == policy.digest
    }
}

/// Bounded trusted bindings from resolved policy identity to inert agent policy.
#[derive(Debug, Clone, Default)]
pub struct ToolPolicyCatalog {
    by_digest: BTreeMap<String, ToolPolicyBinding>,
}

impl ToolPolicyCatalog {
    pub fn new(
        bindings: impl IntoIterator<Item = ToolPolicyBinding>,
    ) -> Result<Self, BundleResolutionError> {
        let mut by_digest = BTreeMap::new();
        for binding in bindings {
            if by_digest.len() >= MAX_RESOLVED_BUNDLE_POLICIES {
                return Err(BundleResolutionError::Malformed(
                    "tool policy catalog exceeds the bound",
                ));
            }
            if by_digest.insert(binding.digest.clone(), binding).is_some() {
                return Err(BundleResolutionError::Malformed(
                    "tool policy catalog contains a duplicate digest",
                ));
            }
        }
        Ok(Self { by_digest })
    }

    fn resolve(&self, policy: &ResolvedPolicy) -> Result<ToolFilter, BundleResolutionError> {
        let binding =
            self.by_digest
                .get(&policy.digest)
                .ok_or(BundleResolutionError::Malformed(
                    "governed tool policy is not in the trusted catalog",
                ))?;
        if !binding.matches(policy) {
            return Err(BundleResolutionError::Malformed(
                "governed tool policy identity does not match its catalog binding",
            ));
        }
        Ok(binding.tools.clone())
    }
}

/// Immutable process-lifetime answer captured from the resolver exactly once at boot.
#[derive(Debug, Clone)]
pub struct BootPolicySnapshot {
    bundle: Option<Arc<ResolvedBundle>>,
    tools: ToolFilter,
}

impl BootPolicySnapshot {
    pub fn resolve_once(
        resolver: &(impl PolicyBundleResolver + ?Sized),
        catalog: &ToolPolicyCatalog,
    ) -> Result<Arc<Self>, BundleResolutionError> {
        let Some(bundle) = resolver.active_bundle()? else {
            return Ok(Arc::new(Self {
                bundle: None,
                tools: ToolFilter::All,
            }));
        };
        bundle.validate()?;
        let tool_slot = SlotId(TOOL_POLICY_SLOT.into());
        let tools = match bundle.policy_for(&tool_slot) {
            Some(policy) => catalog.resolve(policy)?,
            None => ToolFilter::All,
        };
        Ok(Arc::new(Self {
            bundle: Some(Arc::new(bundle)),
            tools,
        }))
    }

    pub fn resolved_bundle(&self) -> Option<&ResolvedBundle> {
        self.bundle.as_deref()
    }

    pub fn tool_filter(&self) -> &ToolFilter {
        &self.tools
    }

    pub fn narrowed_tools(&self) -> Vec<String> {
        self.tools.narrow()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn digest(seed: char) -> String {
        seed.to_string().repeat(64)
    }

    fn policy(seed: char) -> ResolvedPolicy {
        ResolvedPolicy {
            slot: SlotId(TOOL_POLICY_SLOT.into()),
            policy_id: "tool-policy".into(),
            version: "1.0.0".into(),
            digest: digest(seed),
        }
    }

    fn bundle(seed: char) -> ResolvedBundle {
        ResolvedBundle {
            bundle_id: format!("bundle-{seed}"),
            digest: digest('f'),
            policies: vec![policy(seed)],
        }
    }

    fn catalog(seed: char) -> ToolPolicyCatalog {
        ToolPolicyCatalog::new([ToolPolicyBinding::new(
            "tool-policy",
            "1.0.0",
            digest(seed),
            ToolFilter::Deny(vec!["grep".into()]),
        )
        .unwrap()])
        .unwrap()
    }

    struct Fixed(Option<ResolvedBundle>);

    impl PolicyBundleResolver for Fixed {
        fn active_bundle(&self) -> Result<Option<ResolvedBundle>, BundleResolutionError> {
            Ok(self.0.clone())
        }
    }

    #[test]
    fn absent_bundle_falls_back_to_baseline() {
        let snapshot =
            BootPolicySnapshot::resolve_once(&Fixed(None), &ToolPolicyCatalog::default()).unwrap();
        assert!(snapshot.resolved_bundle().is_none());
        assert_eq!(snapshot.tool_filter(), &ToolFilter::All);
        assert!(snapshot.narrowed_tools().contains(&"grep".into()));
    }

    #[test]
    fn promoted_bundle_shifts_tool_selection() {
        let baseline =
            BootPolicySnapshot::resolve_once(&Fixed(None), &ToolPolicyCatalog::default()).unwrap();
        let promoted =
            BootPolicySnapshot::resolve_once(&Fixed(Some(bundle('a'))), &catalog('a')).unwrap();
        assert!(baseline.narrowed_tools().contains(&"grep".into()));
        assert!(!promoted.narrowed_tools().contains(&"grep".into()));
        assert_ne!(baseline.narrowed_tools(), promoted.narrowed_tools());
    }

    #[test]
    fn active_bundle_without_tool_policy_keeps_that_slot_on_baseline() {
        let mut unrelated = bundle('a');
        unrelated.policies[0].slot = SlotId("core/router".into());
        let snapshot = BootPolicySnapshot::resolve_once(
            &Fixed(Some(unrelated)),
            &ToolPolicyCatalog::default(),
        )
        .unwrap();
        assert!(snapshot.resolved_bundle().is_some());
        assert_eq!(snapshot.tool_filter(), &ToolFilter::All);
    }

    struct MutableResolver {
        calls: AtomicUsize,
        current: Mutex<Option<ResolvedBundle>>,
    }

    impl PolicyBundleResolver for MutableResolver {
        fn active_bundle(&self) -> Result<Option<ResolvedBundle>, BundleResolutionError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(self.current.lock().unwrap().clone())
        }
    }

    #[test]
    fn resolution_is_boot_time_and_immutable() {
        let resolver = MutableResolver {
            calls: AtomicUsize::new(0),
            current: Mutex::new(Some(bundle('a'))),
        };
        let snapshot = BootPolicySnapshot::resolve_once(&resolver, &catalog('a')).unwrap();
        *resolver.current.lock().unwrap() = None;

        assert_eq!(resolver.calls.load(Ordering::SeqCst), 1);
        assert!(snapshot.resolved_bundle().is_some());
        assert!(!snapshot.narrowed_tools().contains(&"grep".into()));
    }

    #[test]
    fn invalid_or_unbindable_bundle_fails_boot_instead_of_using_baseline() {
        let unknown = BootPolicySnapshot::resolve_once(
            &Fixed(Some(bundle('b'))),
            &ToolPolicyCatalog::default(),
        );
        assert!(matches!(
            unknown,
            Err(BundleResolutionError::Malformed(
                "governed tool policy is not in the trusted catalog"
            ))
        ));

        let mut invalid = bundle('a');
        invalid.digest = "not-a-digest".into();
        assert!(BootPolicySnapshot::resolve_once(&Fixed(Some(invalid)), &catalog('a')).is_err());
    }

    struct Broken;

    impl PolicyBundleResolver for Broken {
        fn active_bundle(&self) -> Result<Option<ResolvedBundle>, BundleResolutionError> {
            Err(BundleResolutionError::Unreadable(
                "promotion pointer missing",
            ))
        }
    }

    #[test]
    fn no_active_bundle_is_baseline_but_a_broken_resolver_fails_boot() {
        let baseline =
            BootPolicySnapshot::resolve_once(&Fixed(None), &ToolPolicyCatalog::default()).unwrap();
        assert!(baseline.resolved_bundle().is_none());
        assert_eq!(baseline.tool_filter(), &ToolFilter::All);
        assert!(matches!(
            BootPolicySnapshot::resolve_once(&Broken, &ToolPolicyCatalog::default()),
            Err(BundleResolutionError::Unreadable(_))
        ));
    }
}
