use iteron_protocol::{Capability, ToolUse};
use iteron_tools::{EffectKnowledge, OperationEffects};
use iteron_tunables::{ResolutionValue, install_param_overrides};

#[test]
fn a_custom_interpreter_cannot_inherit_the_builtin_effect_contract() {
    // This isolated test process owns tunable installation and the interpreter's OnceLock.
    install_param_overrides([
        (
            "sandbox.lib.preferred_confined_shell".into(),
            ResolutionValue::Text {
                value: "/custom/not-installed/interpreter".into(),
            },
        ),
        (
            "sandbox.lib.fallback_confined_shell".into(),
            ResolutionValue::Text {
                value: "/custom/effecting/interpreter".into(),
            },
        ),
    ])
    .unwrap();
    let effects = OperationEffects::classify(
        &ToolUse {
            id: "literal".into(),
            name: "bash".into(),
            input: serde_json::json!({"command":"printf ok"}),
        },
        Capability::CodeExecuting,
    );
    assert_eq!(effects.knowledge, EffectKnowledge::Unknown);
    assert!(effects.required.contains(Capability::TrustMutating));
    assert!(effects.required.contains(Capability::IrreversibleExternal));
}
