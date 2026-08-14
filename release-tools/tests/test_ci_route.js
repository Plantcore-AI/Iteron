"use strict";

const assert = require("node:assert/strict");
const {classify} = require("../ci_route.js");

function route(files, options = {}) {
  return classify({event: "pull_request_target", files, actor: "contributor", ...options});
}

const docs = route(["README.md", "docs/getting-started/quickstart.md"]);
assert.equal(docs.change_class, "docs");
assert.equal(docs.docs, true);
assert.equal(docs.boundary, true);
assert.equal(docs.rust, false);
assert.equal(docs.supply, false);

const cargo = route(["Cargo.lock", "crates/cli/Cargo.toml"], {
  actor: "dependabot[bot]",
});
assert.equal(cargo.change_class, "dependencies");
assert.equal(cargo.dependency_check, true);
assert.equal(cargo.audit, true);
assert.equal(cargo.supply, true);
assert.equal(cargo.rust, false);

const actions = route([".github/workflows/docs.yml"], {
  actor: "dependabot[bot]",
});
assert.equal(actions.change_class, "infrastructure");
assert.equal(actions.supply, true);
assert.equal(actions.rust, false);
assert.equal(actions.audit, false);

const draft = route(["crates/cli/src/main.rs"], {draft: true});
assert.equal(draft.change_class, "runtime-fast");
assert.equal(draft.dependency_check, true);
assert.equal(draft.rust, false);

const runtime = route(["crates/cli/src/main.rs"]);
assert.equal(runtime.change_class, "runtime-full");
assert.equal(runtime.rust, true);
assert.equal(runtime.boundary, true);

const infrastructure = route(["release-tools/validate.sh"]);
assert.equal(infrastructure.change_class, "infrastructure");
assert.equal(infrastructure.supply, true);
assert.equal(infrastructure.rust, false);

const review = classify({event: "pull_request_review", files: ["crates/cli/src/main.rs"]});
assert.equal(review.change_class, "review");
for (const [name, value] of Object.entries(review)) {
  if (name !== "change_class") assert.equal(value, false, `${name} must be false`);
}

const unknownPush = classify({event: "push", filesKnown: false});
assert.equal(unknownPush.change_class, "full");
for (const [name, value] of Object.entries(unknownPush)) {
  if (name === "change_class") continue;
  assert.equal(value, name === "dependency_check" ? false : true, `${name} route mismatch`);
}

const docsPush = classify({
  event: "push",
  files: ["README.md", "README.zh-CN.md"],
});
assert.equal(docsPush.change_class, "docs");
assert.equal(docsPush.docs, true);
assert.equal(docsPush.boundary, true);
assert.equal(docsPush.rust, false);
assert.equal(docsPush.perf, false);
assert.equal(docsPush.release_build, false);

const infrastructurePush = classify({
  event: "push",
  files: [".github/workflows/docs.yml"],
});
assert.equal(infrastructurePush.change_class, "infrastructure");
assert.equal(infrastructurePush.supply, true);
assert.equal(infrastructurePush.boundary, true);
assert.equal(infrastructurePush.rust, false);
assert.equal(infrastructurePush.perf, false);
assert.equal(infrastructurePush.release_build, false);

const runtimePush = classify({event: "push", files: ["crates/cli/src/main.rs"]});
assert.equal(runtimePush.change_class, "runtime-full");
assert.equal(runtimePush.rust, true);
assert.equal(runtimePush.boundary, true);
assert.equal(runtimePush.perf, true);
assert.equal(runtimePush.release_build, true);
assert.equal(runtimePush.docs, false);
assert.equal(runtimePush.supply, false);
assert.equal(runtimePush.audit, false);

const evolutionPush = classify({
  event: "push",
  files: ["crates/evolve/src/lib.rs"],
});
assert.equal(evolutionPush.evolution, true);

console.log("CI routing cases passed");
