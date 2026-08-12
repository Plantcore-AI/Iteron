// Workflow prelude — injected on the fresh QuickJS globalThis before the script body runs.
// It (1) installs the determinism traps and (2) layers the DSL combinators over the Rust host
// primitives `__agent` / `__phase` / `__log`. This mirrors how Claude Code layers `parallel` /
// `pipeline` over an `agent` primitive (design §1). The Rust Governor still bounds concurrency
// because every `agent()` await goes through `__agent`, which acquires a permit.

// ---- Determinism traps (review checklist) ---------------------------------------------------
// Deny every wall-clock / entropy surface so the ordered sequence of agent() calls and their
// prompt content is a pure function of (script, args). rquickjs exposes no `crypto`/`performance`
// by default, but we defensively neutralize them if a build ever adds them.
// Some surfaces (e.g. performance.now) are read-only in QuickJS, so `delete` — not assignment — is
// the portable neutralizer; each is wrapped so a hardened/non-configurable build cannot abort setup.
function __trapDelete(obj, key) {
  try {
    if (obj) {
      delete obj[key];
    }
  } catch (e) {}
}
__trapDelete(globalThis.Math, "random");
__trapDelete(globalThis.Date, "now");
__trapDelete(globalThis, "performance");
__trapDelete(globalThis, "crypto");
(function () {
  var RealDate = globalThis.Date;
  function TrappedDate() {
    if (arguments.length === 0) {
      throw new Error("Date() / new Date() with no args is non-deterministic and disabled in workflows");
    }
    return new RealDate(arguments[0], arguments[1], arguments[2], arguments[3], arguments[4], arguments[5], arguments[6]);
  }
  TrappedDate.prototype = RealDate.prototype;
  TrappedDate.parse = RealDate.parse;
  TrappedDate.UTC = RealDate.UTC;
  globalThis.Date = TrappedDate;
})();

// ---- DSL combinators ------------------------------------------------------------------------

// agent(prompt, opts) — resolves to real model text, a schema-validated object (when opts.schema is
// set), or null on a degraded outcome. The host returns a JSON envelope so we never marshal
// ambiguous JS values across the bridge: {ok:false} -> null; {kind:"structured"} -> the object;
// {kind:"text"} -> the string.
globalThis.agent = async function (prompt, opts) {
  opts = opts || {};
  var call = {
    prompt: String(prompt == null ? "" : prompt),
    label: opts.label != null ? String(opts.label) : null,
    phase: opts.phase != null ? String(opts.phase) : null,
    model: opts.model != null ? String(opts.model) : null,
    effort: opts.effort != null ? String(opts.effort) : null,
    agentType: opts.agentType != null ? String(opts.agentType) : null,
    speculativeSiblings: opts.speculativeSiblings != null ? Number(opts.speculativeSiblings) : null,
    // Explicit declaration-order dependencies. A dependency must name an earlier, already-settled
    // agent call; the host rejects implicit waits so a script cannot create an unbounded scheduler
    // deadlock. The durable DAG records the resolved task-id edge, never this JS index alone.
    dependsOn: opts.dependsOn != null ? opts.dependsOn : null,
    quorumGroup: globalThis.__activeQuorumGroup == null ? null : globalThis.__activeQuorumGroup,
    // JSON Schema (draft 2020-12) passed through as-is; the host validates + retries.
    schema: opts.schema != null ? opts.schema : null,
  };
  var raw = await __agent(JSON.stringify(call));
  var res = JSON.parse(raw);
  if (!res.ok) return null;
  return res.kind === "structured" ? res.value : res.text;
};

// parallel(thunks) — BARRIER. Runs every thunk concurrently, preserves declaration/index order,
// maps a rejected thunk to null at its index (design §2.3). Per-call length cap 4096.
globalThis.parallel = async function (thunks) {
  if (!Array.isArray(thunks)) {
    throw new Error("parallel expects an array of thunks");
  }
  if (thunks.length > 4096) {
    throw new Error("parallel: per-call limit of 4096 exceeded (" + thunks.length + ")");
  }
  var settled = await Promise.allSettled(thunks.map(function (t) {
    // A thunk may throw synchronously (before returning its promise); normalize that to a
    // rejection so it maps to null at its index rather than sinking the whole barrier.
    try {
      return Promise.resolve(t());
    } catch (e) {
      return Promise.reject(e);
    }
  }));
  return settled.map(function (s) { return s.status === "fulfilled" ? s.value : null; });
};

// parallelQuorum(thunks) — opt-in early-stop fan. The host owns the immutable quorum policy and
// gives this invocation a child cancellation scope. Evidence members that finish after the policy
// is satisfied are cancelled and settle to null; declaration order remains intact.
globalThis.parallelQuorum = async function (thunks) {
  if (!Array.isArray(thunks)) {
    throw new Error("parallelQuorum expects an array of thunks");
  }
  if (thunks.length > 4096) {
    throw new Error("parallelQuorum: per-call limit of 4096 exceeded (" + thunks.length + ")");
  }
  var group = __quorumBegin(thunks.length);
  var settled;
  try {
    settled = await Promise.allSettled(thunks.map(function (t) {
      var previous = globalThis.__activeQuorumGroup;
      globalThis.__activeQuorumGroup = group;
      try {
        return Promise.resolve(t());
      } catch (e) {
        return Promise.reject(e);
      } finally {
        globalThis.__activeQuorumGroup = previous;
      }
    }));
  } finally {
    __quorumEnd(group);
  }
  return settled.map(function (s) { return s.status === "fulfilled" ? s.value : null; });
};

// pipeline(items, ...stages) — BARRIER-FREE per item. Each item runs its own independent stage
// chain; a throwing stage drops that item to null and skips its remaining stages, while the other
// items keep flowing (design §2.3). Per-call length cap 4096.
globalThis.pipeline = async function (items) {
  var stages = Array.prototype.slice.call(arguments, 1);
  if (!Array.isArray(items)) {
    throw new Error("pipeline expects an array of items");
  }
  if (items.length > 4096) {
    throw new Error("pipeline: per-call limit of 4096 exceeded (" + items.length + ")");
  }
  var runItem = async function (item, i) {
    var cur = item;
    for (var s = 0; s < stages.length; s++) {
      cur = await stages[s](cur, item, i);
    }
    return cur;
  };
  var settled = await Promise.allSettled(items.map(runItem));
  return settled.map(function (s) { return s.status === "fulfilled" ? s.value : null; });
};

// phase(title) — records a phase boundary; returns its 1-based first-seen index.
globalThis.phase = function (title) {
  return __phase(String(title == null ? "" : title));
};

// log(msg) — narrator line.
globalThis.log = function (msg) {
  __log(String(msg == null ? "" : msg));
};
