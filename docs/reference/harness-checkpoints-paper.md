# Harness Checkpoints: Governed Optimization Above a Frozen Agent Model and Safety Kernel

**Submission-shaped draft · Iteron v0.0.5 · empirical results pending**

## Abstract

Agent specialization is often discussed as model adaptation, although many
high-leverage decisions live in the surrounding harness: context selection,
tool policy, routing, scheduling, verification, and collaboration. We propose a
systems abstraction, the **Harness Checkpoint**, that records an immutable,
versioned selection of such policies while freezing both the base model and the
safety kernel. Candidates are represented as a typed Candidate Graph and may be
produced by any optimizer that speaks one protocol. Admission is
capability-monotone; evaluation evidence is independently signed; promotion is
human-governed and separated from runtime authority; rollback uses an explicit
prior checkpoint. This draft specifies the architecture, threat model,
protocol, and evaluation plan. No real campaign has yet established performance
benefit, and every empirical table is marked pending.

## 1. Introduction

An agent runtime combines a probabilistic model with a stateful system that
selects context, exposes tools, schedules work, records effects, and judges
completion. Treating all improvement as weight training couples fast-changing
operational knowledge to a slower model lifecycle and can blur the boundary
between an optimizer and the authority it is meant to obey.

Harness Checkpoints separate these concerns. The optimized object is a typed
harness policy; the base model is identified and frozen for an evaluation, and
the safety kernel remains outside the optimization space. The design goal is
not to prove that harness optimization is faster or better. It is to make a
candidate inspectable, replayable, optimizer-neutral, and unable to expand its
own authority.

## 2. Scope and non-goals

The system covers offline candidate production, immutable manifests, governed
trajectory inputs, independent held-out evidence, staged observations, explicit
promotion records, HotSwap handoff, and deterministic rollback. It does not
train model weights or adapters. Reserved `ModelAdapter` and `ModelWeights` wire
values fail validation. SFT, preference, GRPO, and RL method labels, when
received, report producer provenance for a harness artifact only.

This paper does not claim production readiness, universal optimizer support,
live autonomous evolution, safety completeness, model independence, or
performance superiority.

## 3. System model and threat model

The trusted base contains a frozen safety kernel, versioned protocol contracts,
effect mediation, hard budgets, and durable evidence rules. Outside it are the
base-model provider, candidate producer, evaluator, runtime composition, tools,
and storage adapters. We assume a candidate producer may be buggy or adversarial
and may overfit its input. We also assume untrusted manifest, trajectory, and
evaluation bytes. Organizational compromise, provider misrepresentation, and
host compromise are not solved solely by this protocol.

The critical invariants are: candidates cannot grant capabilities; cannot
relax security, durability, or budget policy; cannot select their own promotion
threshold; cannot authenticate their own held-out result; cannot mutate the
frozen base model; and cannot activate themselves.

## 4. Harness Checkpoints and Candidate Graph

A `PolicyManifest` binds a strategy slot and immutable artifact digest to schema
version, lineage, producer-method provenance, protocol range, requested
capabilities, governed input digest, evaluation-suite digest, and frozen base
model identity. A `PolicyBundle` selects at most one policy for each slot and
pins rollback lineage. Together they form a Harness Checkpoint.

The **Candidate Graph** is a directed acyclic evidence graph. Policy nodes point
to exact parents; bundle nodes point to their member policies and rollback
predecessor; input nodes identify governed trajectories or datasets; evaluation
nodes bind a candidate and base-model identity to independently signed results;
promotion nodes bind an authorized stage transition to the evidence reviewed.
Content digests name edges, so a mutable locator cannot silently change graph
meaning. A cycle, missing parent, duplicate slot, unknown vocabulary, or invalid
digest fails closed.

## 5. Optimizer-neutral producer protocol

The producer contract accepts bounded, governed inputs and returns a harness
artifact plus a manifest. The protocol intentionally does not prescribe search,
bandit, rule synthesis, prompt optimization, or another algorithm. Producer
method is provenance, not authority and not a deployment discriminator. Every
producer must emit the same manifest shape and is evaluated through the same
admission and held-out path. The repository's external bridge identifies this
research contract as `iteron-research/1`.

Optimizer neutrality is limited: common interchange does not prove that all
optimizers are implemented, equivalent, or useful. The current census records
the parameter/addressability surface; it is not a training result.

## 6. Admission and frozen authority

Admission validates schema, vocabulary, identity, digests, protocol range, and
lineage. Effective capabilities are derived by intersection of the candidate's
request, the slot ceiling, the exact-parent ceiling, and runtime authority.
Intersection cannot introduce a capability absent from any upper bound. Model
artifact kinds are reserved and rejected before admission can produce an
eligible candidate.

Safety and policy violations are hard constraints, not reward terms. The frozen
safety kernel owns effect mediation and runtime ceilings; neither candidate
bytes nor optimizer configuration can rewrite those rules.

## 7. Governed evidence and HotSwap

Trajectory governance travels with the record and includes data class, consent,
license declaration, secret-material marker, and retention policy. These fields
remain assertions until verified by a trusted boundary. Consent for harness
optimization does not authorize model training, and no trajectory export target
for model training exists.

An independent evaluator signs held-out evidence bound to the exact candidate
and base model. A non-authoritative gate may recommend the next stage; a separate
offline promotion authority records a human-approved transition. HotSwap is a
governed deployment handoff, not self-activation: the runtime consumes only an
authorized bundle, retains the previous bundle, records stage limits, and can
restore the pinned predecessor. The candidate graph therefore preserves both
the decision and the evidence that justified it.

## 8. Evaluation methodology

The planned evaluation compares a fixed baseline checkpoint with candidate
checkpoints on an immutable held-out task set. Each run must pin model identity,
provider route, harness checkpoint, environment, task, budgets, evaluator,
randomness policy, and software revision. Primary measurements should include
task correctness with uncertainty; secondary measurements may include wall
time, provider-reported usage, monetary cost only where trustworthy pricing
evidence exists, safety/policy violations, replay equivalence, rollback success,
and portable fraction across frozen models.

Baselines, exclusions, failures, and all raw records must be retained. Repeated
tasks must be paired; train/evaluation overlap is a hard rejection. Analysis
must report uncertainty and must not collapse safety violations into a scalar
reward improvement.

| Research question | Baseline | Candidate | Result |
| --- | --- | --- | --- |
| Does a Harness Checkpoint improve held-out correctness? | Frozen baseline harness | Same frozen model and kernel, candidate harness | **PENDING — campaign not run** |
| What runtime overhead does governance add? | Same task without candidate transition | Governed evidence and HotSwap path | **PENDING — campaign not run** |
| Does the checkpoint retain benefit across frozen models? | Per-model baseline | Transferred checkpoint, re-evaluated | **PENDING — campaign not run** |
| Does rollback restore the exact prior bundle? | Pinned prior bundle | Fault-triggered rollback | **PENDING — campaign not run** |

## 9. Implementation evidence

The v0.0.5 source contains typed evolution contracts, reserved model-artifact
refusal, conformance guards, and the `iteron-research/1` bridge. The optimization
census schema v4 reports 2,724 independent candidate rows: 1,894
runtime-settable/applied/externally addressed, zero unaddressed, zero
binding-required, and 830 invariant/read-only.
The harness gap audit describes 28 modules and 66 services. These are structural
inventory facts cited in the [claim sheet](claim-sheet.md), not empirical system
performance.

## 10. Limitations and discussion

Typed contracts cannot establish that labels, digests, or governance assertions
are truthful without authenticated producers and storage. Independent identities
do not alone guarantee organizational independence. A frozen kernel may still
contain bugs. A checkpoint can overfit. Portability is a hypothesis requiring
measurement. Provider behavior, model drift behind an identifier, and cost
truth require external evidence. The pre-alpha runtime does not yet justify an
unattended deployment claim.

## 11. Related design space

Harness Checkpoints intersect policy configuration, contextual bandits, program
synthesis, evaluation-driven development, software release promotion, and
tamper-evident logging. The distinguishing systems choice is the combination of
a frozen model boundary, a frozen safety kernel, optimizer-neutral candidate
shape, capability-monotone admission, independently authenticated evidence, and
human-governed HotSwap. A literature comparison and formal citations are
**PENDING** before submission.

## 12. Reproducibility and ethics statement

A submission must archive manifests, task definitions, raw outcomes, analysis
code, environment identities, exclusions, and negative results without secrets
or customer data. Data use must match recorded consent, licensing, retention,
and deletion obligations. No benchmark result should be published from private
or unreleasable evidence.

## 13. Conclusion

Harness Checkpoints make agent specialization a governed systems artifact above
a frozen model and kernel. The design separates proposal, evaluation,
authorization, and runtime effect. Its performance value remains an empirical
question. This draft therefore contributes a falsifiable protocol and evaluation
plan, not an invented result.
