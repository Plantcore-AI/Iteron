# Evolution boundary

Core Code includes types for a future governed strategy-evolution control plane.
It does **not** currently train, fine-tune, run GRPO, or promote a live policy.

## Intended separation

The target architecture separates:

1. a fixed runtime trusted computing base;
2. replaceable strategy and world modules;
3. an isolated evolution control plane that produces immutable candidates.

Possible candidate-production methods include search, bandits, supervised
fine-tuning, preference optimization, GRPO, and offline reinforcement learning.
The method is replaceable; the promotion boundary is not.

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
