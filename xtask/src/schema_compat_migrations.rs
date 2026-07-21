//! Executable, typed compatibility migrator registry.
//!
//! Pull-request validation runs from the trusted base xtask binary. A breaking change can name
//! only a migrator already compiled into a prior trusted release; candidate text cannot mint
//! migration authority in the same change.

use anyhow::{Result, bail};
use serde_json::Value;

pub(super) fn apply(
    id: &str,
    surface: &str,
    from_version: u32,
    target_version: u32,
    _value: Value,
) -> Result<Value> {
    match (id, surface, from_version, target_version) {
        #[cfg(test)]
        ("d13-14-test-rename-v1-v2", "protocol.test" | "test.phase", 1, 2) => {
            test_rename_v1_v2(_value)
        }
        #[cfg(test)]
        ("d13-14-test-rename-v2-v3", "protocol.test", 2, 3) => test_rename_v2_v3(_value),
        #[cfg(test)]
        ("d13-14-test-rename-v1-or-v2-v3", "protocol.test", 1 | 2, 3) => test_rename_v2_v3(_value),
        #[cfg(test)]
        ("d13-14-test-changes-selector", "test.phase", 1, 2) => test_changes_selector(_value),
        _ => bail!(
            "compatibility migrator `{id}` is not registered for `{surface}` schema {from_version}->{target_version} in the trusted build plane"
        ),
    }
}

#[cfg(test)]
fn test_changes_selector(mut value: Value) -> Result<Value> {
    value = test_rename_v1_v2(value)?;
    value
        .as_object_mut()
        .expect("test rename returns an object")
        .insert("type".into(), Value::from("notice"));
    Ok(value)
}

#[cfg(test)]
fn test_rename_v2_v3(mut value: Value) -> Result<Value> {
    let object = value
        .as_object_mut()
        .ok_or_else(|| anyhow::anyhow!("test migration requires an object"))?;
    let old = object
        .remove("old")
        .ok_or_else(|| anyhow::anyhow!("test migration lacks old field"))?;
    object.insert("replacement".into(), old);
    object.insert("version".into(), Value::from(3));
    Ok(value)
}

#[cfg(test)]
fn test_rename_v1_v2(mut value: Value) -> Result<Value> {
    let object = value
        .as_object_mut()
        .ok_or_else(|| anyhow::anyhow!("test migration requires an object"))?;
    let old = object
        .remove("old")
        .ok_or_else(|| anyhow::anyhow!("test migration lacks old field"))?;
    object.insert("replacement".into(), old);
    object.insert("version".into(), Value::from(2));
    Ok(value)
}
