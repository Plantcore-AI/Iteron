//! Adapter from the runtime's immutable permission snapshot to the pure operation gate.

use super::Agent;
use super::permission_policy::{OperationAdmission, OperationPolicy, evaluate_operation};
use iteron_protocol::{ToolUse, Trust};

impl Agent {
    pub(super) fn tool_operation_admission(
        &self,
        call: &ToolUse,
        governing_trust: Trust,
    ) -> OperationAdmission {
        let effects = self
            .registry
            .operation_effects(call)
            .expect("tool-policy proposals refer to registered tools");
        evaluate_operation(
            &call.name,
            &effects,
            OperationPolicy {
                mode: self.permission_mode,
                rules: &self.permission_rules,
                bypass: self.bypass_permissions,
                task_ceiling: self.authority_ceiling,
                policy_capabilities: self.policy_capabilities,
                governing_trust,
                authority: self.operator_authority(),
            },
        )
    }
}
