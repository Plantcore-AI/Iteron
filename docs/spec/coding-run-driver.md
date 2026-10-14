# Ordinary coding invocation ownership

`runtime/coding_run_driver.rs` owns the invocation's working transcript, submitted recovery
receipts, optional candidate baseline/convergence, current request evidence, loop guard, accepted
response and retained tool round. These fields are private. Boundary intake and request preparation
borrow distinct typed views; a failed or consumed stage cannot admit another physical operation.

| Owner | Actual state / direction |
| --- | --- |
| CodingRunDriver | Boundary → request → physical provider → response → tools/model → completion |
| RequestCycle | Borrowed working projection and actual context recovery; consumed native request |
| CodingProviderExecution | Actual ProviderTurnDriver and USD obligation through physical completion |
| ProviderResponseCommit | Sealed usage, exact physical cleanup and assistant Message receipt |
| ToolRoundExecution | Real declaration slots, pending kernel identity and external dispatch lease |
| ToolImageProjection | Confirmed terminal → private pixel retention → image observation receipt |
| TurnCompletion | Actual steering/control/optional configured verification → closed host action |

The immutable declaration array is retained once and shared with the tool result owner. Neither a
client nor a returned child report can replace it. Actual kernel execution returns through the same
index/call-id validation before the lease is released. With no captured image, composition supplies
None and does not create image storage, namespace or vision work.

Record/effect/controller/budget owners retain their separate authority. The driver receives no
Agent, generic callback, provider implementation or mutable controller snapshot. Physical terminal
truth and signed charge evidence precede logical completion; a loop decision cannot repair them.
The host still performs current effect admission, physical auxiliary work and final run cleanup.

This is a source checkpoint, not architecture or release acceptance. The primary composition module
still exceeds 1,200 production lines. Invocation admission/epilogue and request execution composition
remain to be completed. Same-candidate compiler, native/platform, cancellation, record-fault,
follow-up, default/optional profile and architecture gates have not yet run.
