//! Ordinary declarative tools execute installed native primitives through their actual guards.
//! No plugin callback, interpreter or capability assertion enters this registration seam.
use crate::{
    OperationEffects, RegisteredExecution, Registry, Tool, ToolError, ToolOutputOwner, err_result,
    registeredfut, schema, workspace_boundary,
};
use iteron_protocol::{Capability, ToolSpec, ToolUse, capability_set::CapabilitySet};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::sync::{Arc, atomic::Ordering};

pub const MAX_ORDINARY_RECIPES: usize = 64;
pub const MAX_RECIPE_BYTES: usize = 16 * 1024;
const MAX_CALL_BYTES: usize = 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolRecipeV1 {
    pub version: u32,
    /// Stable namespaced model-visible name. Host primitive metadata pins purity/capability.
    pub name: String,
    pub description: String,
    pub primitive: String,
    /// Immutable arguments. Supplying a different value for one of these fields is refused.
    #[serde(default)]
    pub fixed_arguments: Map<String, Value>,
    /// Additional literal native-writer scope. Empty denies every recipe write.
    #[serde(default)]
    pub write_paths: Vec<String>,
}

pub(super) struct RecipeBinding {
    recipe: ToolRecipeV1,
    primitive_schema: Value,
    ceiling: CapabilitySet,
    dispatch_policy: Option<Arc<dyn iteron_protocol::extension_dispatch::ExtensionDispatchPolicy>>,
}
impl RecipeBinding {
    pub(super) fn resolve(&self, call: &ToolUse) -> Result<ToolUse, String> {
        if call.name != self.recipe.name
            || !value_bounds(&call.input)
            || !bounded_json(&call.input, MAX_CALL_BYTES)
        {
            return Err("ordinary tool arguments exceed their host envelope".into());
        }
        if self.dispatch_policy.as_ref().is_some_and(|policy| {
            !policy.admits(
                iteron_protocol::extension_dispatch::ExtensionSurfaceV1::Tool,
                &self.recipe.name,
            )
        }) {
            return Err("ordinary tool binding was revoked".into());
        }
        let mut input = call
            .input
            .as_object()
            .ok_or("ordinary tool input must be an object")?
            .clone();
        for (key, fixed) in &self.recipe.fixed_arguments {
            if input.get(key).is_some_and(|value| value != fixed) {
                return Err("ordinary tool input conflicts with a fixed host argument".into());
            }
            input.insert(key.clone(), fixed.clone());
        }
        let resolved = ToolUse {
            id: call.id.clone(),
            name: self.recipe.primitive.clone(),
            input: Value::Object(input),
        };
        schema::validate_arguments(&self.primitive_schema, &resolved.input)
            .map_err(|error| error.model_json(&self.recipe.primitive))?;
        Ok(resolved)
    }
    fn effects(&self, call: &ToolUse, capability: Capability) -> Result<OperationEffects, String> {
        let call = self.resolve(call)?;
        let mut effects = OperationEffects::classify(&call, capability);
        effects.canonical_tool = Some(self.recipe.primitive.clone());
        effects.extension_ceiling = Some(self.ceiling);
        Ok(effects)
    }
}

impl Registry {
    /// Register a bounded declarative projection of an already installed native primitive.
    /// The caller supplies the actual host-admitted extension ceiling, never model authority.
    pub fn register_ordinary_recipe(
        &mut self,
        recipe: ToolRecipeV1,
        ceiling: CapabilitySet,
        dispatch_policy: Option<
            Arc<dyn iteron_protocol::extension_dispatch::ExtensionDispatchPolicy>,
        >,
    ) -> Result<ToolSpec, ToolError> {
        let refuse = |reason: &str| ToolError::Registration(reason.into());
        if recipe.version != 1
            || !valid_name(&recipe.name)
            || recipe.name == recipe.primitive
            || recipe.description.is_empty()
            || recipe.description.len() > 1024
            || recipe.description.chars().any(char::is_control)
            || recipe.fixed_arguments.len() > 32
            || recipe
                .fixed_arguments
                .iter()
                .any(|(key, value)| key.len() > 128 || !value_bounds(value))
            || !bounded_json(&recipe, MAX_RECIPE_BYTES)
            || iteron_protocol::agent_control::validate_write_paths(&recipe.write_paths).is_err()
            || !matches!(
                recipe.primitive.as_str(),
                "read_file"
                    | "grep"
                    | "glob"
                    | "list_dir"
                    | "git_diff"
                    | "git_status"
                    | "write_file"
                    | "edit"
                    | "apply_patch"
                    | "bash"
                    | "process_start"
                    | "process_poll"
                    | "process_write"
                    | "process_stop"
            )
        {
            return Err(refuse("invalid ordinary tool recipe"));
        }
        if self
            .tools
            .iter()
            .filter(|tool| tool.recipe.is_some())
            .count()
            >= MAX_ORDINARY_RECIPES
        {
            return Err(refuse("ordinary tool recipe capacity exceeded"));
        }
        let primitive = self
            .tools
            .iter()
            .find(|tool| {
                tool.spec.name == recipe.primitive
                    && tool.recipe.is_none()
                    && tool.output_owner == ToolOutputOwner::Runtime
            })
            .ok_or_else(|| refuse("ordinary tool primitive is not installed"))?;
        if !ceiling.contains(primitive.spec.capability) {
            return Err(refuse(
                "ordinary tool primitive exceeds the extension ceiling",
            ));
        }
        let mut spec = primitive.spec.clone();
        spec.name = recipe.name.clone();
        spec.description = recipe.description.clone();
        let required = spec
            .input_schema
            .get_mut("required")
            .and_then(Value::as_array_mut);
        if let Some(required) = required {
            required.retain(|key| {
                key.as_str()
                    .is_none_or(|key| !recipe.fixed_arguments.contains_key(key))
            });
        }
        // The real advertised description commits the immutable projection. The strict native
        // schema remains inside its supported subset; no custom unchecked constraint is added.
        use sha2::{Digest, Sha256};
        let digest = format!(
            "{:x}",
            Sha256::digest(
                serde_json::to_vec(&recipe)
                    .map_err(|_| refuse("ordinary recipe commitment unavailable"))?
            )
        );
        spec.description.push_str(&format!(
            " [Iteron native recipe v1; primitive={}; sha256={digest}]",
            recipe.primitive
        ));
        let writer = matches!(
            recipe.primitive.as_str(),
            "write_file" | "edit" | "apply_patch"
        );
        let prior_scope = self.inherited_write_scope.get().cloned();
        if writer {
            if recipe.write_paths.is_empty() {
                return Err(refuse("ordinary recipe writes require a literal scope"));
            }
            if let Some(scope) = &prior_scope
                && scope
                    .intersection_paths(&recipe.write_paths)
                    .map_err(ToolError::Registration)?
                    .is_empty()
            {
                return Err(refuse("ordinary recipe has no inherited writable path"));
            }
        }
        let executor = primitive.run.clone();
        let purpose = primitive.purpose;
        let capability = primitive.spec.capability;
        let binding = Arc::new(RecipeBinding {
            primitive_schema: primitive.spec.input_schema.clone(),
            recipe,
            ceiling,
            dispatch_policy,
        });
        let alias = binding.recipe.name.clone();
        let canonical = binding.recipe.primitive.clone();
        let binding_run = binding.clone();
        let inherited = self.inherited_write_scope.clone();
        let confined = self.confine_execution.clone();
        let isolated = self.workspace_boundary;
        let fixture = self.test_helper_thread.clone();
        let run = move |call: ToolUse, root: std::path::PathBuf| {
            let executor = executor.clone();
            let binding = binding_run.clone();
            let inherited = inherited.clone();
            let fixture = fixture.clone();
            let confined = confined.clone();
            let alias = alias.clone();
            let canonical = canonical.clone();
            registeredfut::box_it(async move {
                let refused = |reason: String| RegisteredExecution {
                    outcome: err_result(call.id.clone(), reason).into(),
                    dispatch_to_terminal_ms: None,
                };
                // Outer dispatch has resolved the exact alias before its ordinary path guards.
                if call.name != canonical {
                    return refused("ordinary tool physical identity mismatch".into());
                }
                if binding.dispatch_policy.as_ref().is_some_and(|policy| {
                    !policy.admits(
                        iteron_protocol::extension_dispatch::ExtensionSurfaceV1::Tool,
                        &alias,
                    )
                }) {
                    return refused("ordinary tool binding was revoked".into());
                }
                let mut effects = OperationEffects::classify(&call, capability);
                for path in effects.targets.clone() {
                    if let Ok(path) = crate::resolve_in_root(&root, &path) {
                        effects.include_resolved_target(&path.to_string_lossy());
                    }
                }
                if !effects.required.is_subset_of(binding.ceiling) {
                    return refused("ordinary tool operation exceeds the extension ceiling".into());
                }
                if let Some(scope) = inherited.get()
                    && let Err(reason) = scope
                        .validate_tool(&call, capability)
                        .and_then(|_| scope.validate_call(&root, &call))
                {
                    return refused(reason);
                }
                if confined.load(Ordering::Acquire)
                    && matches!(call.name.as_str(), "write_file" | "edit" | "apply_patch")
                    && let Err(reason) =
                        workspace_boundary::validate_coding_write_call(&root, &call)
                {
                    return refused(reason);
                }
                if isolated && let Err(reason) = workspace_boundary::validate_call(&root, &call) {
                    return refused(reason);
                }
                let id = call.id.clone();
                let mut completed = if writer {
                    // Mint the final helper envelope from the currently installed immutable task
                    // scope at this dispatch. A later-installed scope cannot leave an old broad
                    // SDK writer executor behind. No model field supplies this authority.
                    let paths = match inherited.get() {
                        Some(scope) => {
                            match scope.intersection_paths(&binding.recipe.write_paths) {
                                Ok(paths) => paths,
                                Err(reason) => return refused(reason),
                            }
                        }
                        None => binding.recipe.write_paths.clone(),
                    };
                    if paths.is_empty() {
                        return refused("ordinary recipe has no inherited writable path".into());
                    }
                    let mut dedicated = match Registry::isolated_writer(root.clone()) {
                        Ok(registry) => registry,
                        Err(_) => return refused("ordinary native writer unavailable".into()),
                    };
                    if dedicated.set_inherited_write_scope(paths).is_err() {
                        return refused("ordinary native writer scope unavailable".into());
                    }
                    dedicated
                        .test_helper_thread
                        .store(fixture.load(Ordering::Acquire), Ordering::Release);
                    let native = dedicated
                        .tools
                        .iter()
                        .find(|tool| tool.spec.name == canonical)
                        .expect("installed SDK native writer")
                        .run
                        .clone();
                    native(call, root).await
                } else {
                    executor(call, root).await
                };

                if let Some(receipt) = &mut completed.outcome.native_mutation
                    && receipt
                        .bind_registered_alias(&id, &canonical, &alias)
                        .is_err()
                {
                    completed.outcome.native_mutation = None;
                    completed.outcome.capture_error =
                        Some("ordinary native receipt identity unavailable".into());
                }
                completed
            })
        };
        self.register(Tool {
            spec: spec.clone(),
            run: Arc::new(run),
            output_owner: ToolOutputOwner::Runtime,
            purpose,
            recipe: Some(binding),
        })?;
        Ok(spec)
    }
    /// Host rollback removes only this freshly installed ordinary binding; it cannot remove a
    /// native primitive. Already-returned executor futures retain their own admitted ownership.
    pub fn remove_ordinary_recipe(&mut self, name: &str) {
        self.tools
            .retain(|tool| tool.spec.name != name || tool.recipe.is_none());
        if let Some(catalog) = &self.deferred_tool_catalog {
            catalog.retain(
                &self
                    .tools
                    .iter()
                    .map(|tool| tool.spec.name.clone())
                    .collect(),
            );
        }
        self.invalidate_spec_snapshot();
    }
    pub fn ordinary_call_projection(&self, call: &ToolUse) -> Result<Option<ToolUse>, String> {
        let Some(binding) = self
            .tools
            .iter()
            .find(|tool| tool.spec.name == call.name)
            .and_then(|tool| tool.recipe.as_ref())
        else {
            return Ok(None);
        };
        binding.resolve(call).map(Some)
    }
    pub fn canonical_tool_name<'a>(&'a self, name: &'a str) -> &'a str {
        self.tools
            .iter()
            .find(|tool| tool.spec.name == name)
            .and_then(|tool| tool.recipe.as_ref())
            .map_or(name, |binding| binding.recipe.primitive.as_str())
    }
    pub(super) fn resolve_ordinary_call(tool: &Tool, call: ToolUse) -> Result<ToolUse, String> {
        match &tool.recipe {
            Some(recipe) => recipe.resolve(&call),
            None => Ok(call),
        }
    }
    pub(super) fn ordinary_effects(
        tool: &Tool,
        call: &ToolUse,
    ) -> Result<OperationEffects, String> {
        match &tool.recipe {
            Some(recipe) => recipe.effects(call, tool.spec.capability),
            None => Ok(OperationEffects::classify(call, tool.spec.capability)),
        }
    }
}
fn valid_name(name: &str) -> bool {
    name.len() <= 64
        && name.as_bytes().first().is_some_and(u8::is_ascii_alphabetic)
        && name
            .split_once("__")
            .is_some_and(|(prefix, suffix)| !prefix.is_empty() && !suffix.is_empty())
        && name
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'-'))
}
fn value_bounds(value: &Value) -> bool {
    let mut stack = vec![(value, 0usize)];
    let mut visited = 0usize;
    while let Some((value, depth)) = stack.pop() {
        visited += 1;
        if visited > 4096 || depth > 16 {
            return false;
        }
        match value {
            Value::Object(fields) => {
                if fields.len() > 64 || fields.keys().any(|key| key.len() > 128) {
                    return false;
                }
                stack.extend(fields.values().map(|value| (value, depth + 1)));
            }
            Value::Array(items) => {
                if items.len() > 512 {
                    return false;
                }
                stack.extend(items.iter().map(|value| (value, depth + 1)));
            }
            Value::String(text) if text.len() > MAX_CALL_BYTES => return false,
            _ => {}
        }
    }
    true
}
fn bounded_json(value: &impl Serialize, limit: usize) -> bool {
    struct Bound(usize);
    impl std::io::Write for Bound {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            if bytes.len() > self.0 {
                return Err(std::io::Error::other("JSON bound"));
            }
            self.0 -= bytes.len();
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    serde_json::to_writer(Bound(limit), value).is_ok()
}

#[cfg(test)]
#[path = "ordinary_recipe/tests.rs"]
mod tests;
