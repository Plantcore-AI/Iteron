# Transactional research hot swap

Research hot swap changes one immutable implementation generation at a safe run boundary. It is
not developer file-watch reload and it never mutates a running candidate in place.

The host-owned transaction is:

1. verify the candidate identity, artifact digest, protocol and capability ceiling;
2. shadow-load the new provider;
3. quiesce the old provider at a declared turn or step boundary;
4. snapshot the old generation's bounded state;
5. migrate and restore the state into the shadow generation;
6. run readiness and behavior oracles;
7. atomically switch the active generation pointer;
8. drain, stop and reap the old process;
9. durably commit the hash-chained activation ledger.

Failure before the atomic switch leaves the old generation active and reaps the shadow process.
Failure after the switch invokes the recorded rollback path. A dependency that cannot become ready
is a typed, deadline-bounded blocked result; there is no silent pending state.

`RuntimeHotSwapExecutor` is the production process implementation of this sequence. It requires
protocol v2, registry-minted old and shadow launch plans, a durable rollback snapshot, exact
module/implementation/artifact/generation/state identities, and an authority digest computed from
the host-intersected capability set. `ActiveImplementationHandle` routes start, observation, and
cancel through the same mutex used by the atomic switch. While a transaction owns that handle,
consumers receive `TransitionInProgress`; they never read across two generations.

Drain really stops and reaps the old process. If a post-switch commit write fails, the executor
relaunches the old verified plan, restores the durable rollback snapshot, requires readiness,
atomically restores the old handle, and then stops the new process. If rebuilding the old provider
fails, the transaction reports `RollbackFailed` instead of claiming an impossible recovery.

Every ledger row binds the transaction, module, candidate, old and new generation, implementation
and artifact digests, state digest, authority digest, phase, timing and outcome. Replay rejects a
missing, duplicated, reordered or modified row.

One turn observes exactly one immutable generation. Canary sessions may select a shadow generation
at their own safe boundary, but a provider cannot route traffic to itself or promote itself.
