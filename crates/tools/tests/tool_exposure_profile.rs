use iteron_tools::Registry;
use iteron_tunables::{ResolutionValue, install_param_overrides};
use std::collections::BTreeSet;

#[test]
fn core_tool_exposure_is_a_real_profile_value_not_a_compiled_invariant() {
    install_param_overrides([(
        "tools.tool_search.core_eager_tools".to_owned(),
        ResolutionValue::List {
            items: vec![ResolutionValue::Text {
                value: "read_file".to_owned(),
            }],
        },
    )])
    .expect("the searchable exposure policy installs once in this isolated test process");

    let registry = Registry::coding_agent(std::env::temp_dir()).expect("coding registry");
    let admitted = registry
        .specs()
        .into_iter()
        .map(|spec| spec.name)
        .collect::<BTreeSet<_>>();
    let visible = registry
        .specs_for_task(&admitted, "read_file", Some(1))
        .into_iter()
        .map(|spec| spec.name)
        .collect::<BTreeSet<_>>();

    assert_eq!(
        visible,
        BTreeSet::from(["read_file".to_owned(), "tool_search".to_owned()]),
        "the installed generic profile must own eager exposure; compiled tool names must not leak"
    );
}
