//! Pure assembly of recorded context and the stable system prefix.

use core_protocol::{DurableInstructionContext, Trust};

/// Assemble the durable frontend prefix with the context grant bytes recorded beside it.
///
/// Replay supplies the recorded values, while live world access remains behind the Context port.
/// Keeping the ordering and trust fold here prevents the kernel from growing a second prompt
/// assembly policy.
pub fn assemble_recorded_context(
    instructions: &DurableInstructionContext,
    context_text: String,
    context_trust: Trust,
) -> (String, Trust) {
    let mut text = instructions
        .environment
        .as_ref()
        .map(|environment| environment.text.clone())
        .unwrap_or_default();
    text.push_str(&instructions.text);
    text.push_str(&context_text);
    let trust = Trust::governing(
        [
            instructions
                .environment
                .as_ref()
                .filter(|environment| !environment.text.is_empty())
                .map(|environment| environment.trust),
            (!instructions.text.is_empty()).then_some(instructions.trust),
            (!context_text.is_empty()).then_some(context_trust),
        ]
        .into_iter()
        .flatten(),
    )
    .unwrap_or(Trust::Trusted);
    (text, trust)
}

/// Join the stable system prefix and once-resolved context without introducing separators.
pub fn assemble_system_prompt(base: &str, injection: Option<&str>) -> String {
    match injection {
        Some(injection) if !injection.is_empty() => format!("{base}{injection}"),
        _ => base.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core_protocol::DurableEnvironmentContext;

    #[test]
    fn preserves_order_and_least_trust() {
        let instructions = DurableInstructionContext {
            text: "instructions".into(),
            trust: Trust::Untrusted,
            environment: Some(DurableEnvironmentContext {
                text: "environment".into(),
                trust: Trust::Workspace,
            }),
        };
        let (context, trust) =
            assemble_recorded_context(&instructions, "memory".into(), Trust::Trusted);
        assert_eq!(context, "environmentinstructionsmemory");
        assert_eq!(trust, Trust::Untrusted);
        assert_eq!(
            assemble_system_prompt("system", Some(&context)),
            "systemenvironmentinstructionsmemory"
        );
    }
}
