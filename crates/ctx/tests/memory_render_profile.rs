use iteron_ctx::{FileMemory, MemBudget, MemStore, MemoryStrategy};
use iteron_tunables::{ResolutionValue, install_param_overrides};
use std::time::{SystemTime, UNIX_EPOCH};

#[test]
fn memory_render_framing_is_owned_by_the_generic_profile() {
    install_param_overrides([
        (
            "ctx.memory.header".to_owned(),
            ResolutionValue::Text {
                value: "\n<profile-memory>\n".to_owned(),
            },
        ),
        (
            "ctx.memory.footer".to_owned(),
            ResolutionValue::Text {
                value: "</profile-memory>".to_owned(),
            },
        ),
    ])
    .expect("memory rendering parameters install once in this isolated test process");

    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after epoch")
        .as_nanos();
    let repo = std::env::temp_dir().join(format!(
        "iteron-memory-render-profile-{}-{nonce:x}",
        std::process::id()
    ));
    std::fs::create_dir_all(&repo).expect("create repository fixture root");
    let store = MemStore::project(&repo, true);
    FileMemory
        .add(
            &store,
            "The generic optimizer owns memory rendering policy.",
        )
        .expect("add memory fact");

    let rendered = FileMemory
        .recall(
            std::slice::from_ref(&store),
            "optimizer memory",
            &MemBudget::default(),
        )
        .render();
    assert!(rendered.contains("<profile-memory>"), "{rendered}");
    assert!(rendered.contains("</profile-memory>"), "{rendered}");
    assert!(
        !rendered.contains("Memory index (progressive disclosure"),
        "the compiled rendering prompt leaked through the installed profile: {rendered}"
    );

    let _ = std::fs::remove_dir_all(repo);
}
