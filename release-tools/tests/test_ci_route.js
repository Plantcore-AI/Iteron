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

const push = classify({event: "push"});
assert.equal(push.change_class, "full");
for (const [name, value] of Object.entries(push)) {
  if (name === "change_class") continue;
  assert.equal(value, name === "dependency_check" ? false : true, `${name} route mismatch`);
}

console.log("CI routing cases passed");
