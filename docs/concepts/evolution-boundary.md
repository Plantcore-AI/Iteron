# Evolution boundary

Iteron includes types for a governed strategy-evolution control plane. It
optimizes harness artifacts only and does **not** train or fine-tune a model or
promote a live policy autonomously.

## Intended separation

The target architecture separates:

1. a fixed runtime trusted computing base;
2. replaceable strategy and world modules;
3. an isolated evolution control plane that produces immutable candidates.

Candidate producers may use search or other optimizer families. The retained
supervised-fine-tuning, preference, GRPO, and RL method names are provenance
labels for a harness artifact only. They do not authorize model training. The
producer is replaceable; the promotion boundary is not.

`ModelAdapter` and `ModelWeights` are reserved wire values that manifest
validation always rejects. Trajectory projection has no model-training target.

## Promotion path

The planned evidence path is:

```text
trajectory → governed dataset → candidate → held-out evaluation
           → shadow → canary → active
```

Every stage needs immutable identity, lineage, budget, consent, and rollback
evidence. Evaluation fixtures and scoring policy must be reviewed independently
from the strategy expected to improve the score.

## Fixed human-controlled constraints

An evolved module may propose bounded actions. It may not:

- grant itself capabilities;
- relax security, durability, or budget policy;
- rewrite trajectories or evaluation evidence;
- choose its own promotion threshold;
- promote or roll back itself;
- expand data use beyond recorded consent.

Live self-evolution is intentionally outside the critical path until the runtime,
effect, recovery, evaluation, and production-distribution gates are credible.
