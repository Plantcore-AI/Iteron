use super::ToolResponseOwner;
use iteron_protocol::{Block, ToolResult, ToolUse, Trust};

fn call(id: &str) -> ToolUse {
    ToolUse {
        id: id.into(),
        name: "read_file".into(),
        input: serde_json::json!({"path":"a"}),
    }
}

fn result(id: &str, error: bool) -> ToolResult {
    ToolResult {
        tool_use_id: id.into(),
        content: id.into(),
        is_error: error,
        trust: Trust::Workspace,
        latency_ms: 0,
    }
}

#[test]
fn missing_result_cannot_build_the_next_provider_message() {
    let calls = [call("first"), call("second")];
    let mut response = ToolResponseOwner::new(&calls);
    response.accept(0, result("first", false)).unwrap();
    assert!(response.validate_complete().is_err());
    assert!(response.into_parts().is_err());
}

#[test]
fn a_substituted_or_duplicate_result_cannot_replace_the_admitted_declaration() {
    let calls = [call("first")];
    let mut response = ToolResponseOwner::new(&calls);
    assert!(response.accept(0, result("other", false)).is_err());
    response.accept(0, result("first", false)).unwrap();
    assert!(response.accept(0, result("first", true)).is_err());
    assert!(!response.had_error());
}

#[test]
fn actual_out_of_order_completion_projects_once_in_declaration_order() {
    let calls = [call("first"), call("second")];
    let mut response = ToolResponseOwner::new(&calls);
    response.accept(1, result("second", true)).unwrap();
    response.accept(0, result("first", false)).unwrap();
    assert!(response.had_error());
    let message = response.into_parts().unwrap().message.into_message();
    let ids = message
        .content
        .iter()
        .map(|block| match block {
            Block::ToolResult(result) => result.tool_use_id.as_str(),
            _ => panic!("unexpected model block"),
        })
        .collect::<Vec<_>>();
    assert_eq!(ids, ["first", "second"]);
}
