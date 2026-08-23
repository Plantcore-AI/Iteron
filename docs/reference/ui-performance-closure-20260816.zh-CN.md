# UI/UX 性能工程闭环（2026-08-16）

本页记录 Iteron UI/UX 与性能全面审计的工程闭环，覆盖两份 2026-08-15 审计中的
F-001 至 F-046、D1 至 D49。规范性定义仍以
[UI 活动与性能契约](ui-performance-contract.zh-CN.md) 为准；机器可读阈值位于
`governance/uiux-slo.json`。

这是一份实现与门禁记录，不是实测性能声明。Release qualification 仍须在支持的机器上执行
契约规定的 workload matrix，并发布测量证据。

## 闭环结果

所有有效工程问题均已实现，或因保留了更强的既有不变量而得到解决：

| 领域 | 工程结果 |
| --- | --- |
| 流式输出 | 展示 delta 有界并可合并；terminal summary 对 visible answer 做逐字节对账。敏感模式 scrubber 只保留可能构成模式的有界后缀，不再让普通尾 token 等到无关 finalization 才出现。 |
| Activity 与结束 | 闭合、content-free 的 activity protocol 区分准备、等待 provider、reasoning、response、工具、retry、failover、verification、checkpoint、hook、workflow 持久化、finalization 和 input-ready。只有 authoritative `RunEnded` 才清除 running。 |
| 首帧与会话 | 首帧不再 hydrate 全部历史或扫描全部 run。Prompt history 异步增量加载；session picker 使用可 seek、绑定 generation 的索引，25 条分页并可取消 preview hydrate。 |
| 输入与渲染 | 附件读取、解码、转换和编码全部离开 TUI loop。Markdown 增量 settle，transcript 用持久高度索引，编辑和显示按 Unicode grapheme 处理。 |
| 取消 | Esc 与 Ctrl-C 共用显式取消状态机。先确认 cooperative cancel；更强取消会 kill process group，并在有界时间内等待 reap 证据。Cleanup 中持续显示 cancelling，不能提前显示 idle。 |
| Provider 路径 | 连接、accepted、首字节、首 token、retry、failover 分别展示。存在已验证 snapshot 时，provider discovery 推迟到首帧后；retry 和 idle wait 均有界且可见。 |
| 工具与 Hook | Shell 实时输出通过有界通道展示，terminal ToolResult 仍是 authority。Hook 有界；无冲突 hook 可并行；stop hook 不得静默阻塞 `RunEnded` 或 input-ready。 |
| Context | Tool schema 一次准备并由 provider 与 token estimator 复用。按 route 的 token calibration 使用 provider 实测 usage；skill/memory 先索引 metadata，再有界读取 body。 |
| Record 与 telemetry | Record 只有一个 append authority，delta 有界，索引可识别 crash，terminal boundary 真正批量提交。可重建索引不阻塞 input-ready；telemetry 按至多一次 drain，不再全 run replay。 |
| Workflow 与 protocol | Workflow submission/progress/log、MCP、LSP、marketplace runtime message 和 process output 均有 item、byte、time、concurrency 边界；取消与终态走 typed 独立路径。 |
| Governance | UI/UX 阈值进入源码与 conformance gate。新的运行 ceiling 都有真实 helper 读取，而且只能向下收窄 immutable host maximum。安全、权限、durability、replay、budget、effect-ledger 仍不是可训练值。 |

## 第二轮默认策略闭环

独立的默认策略审计按生产源码闭环，没有照抄 comparator 的孤立常量。确认成立的项目具有以下精确结果：

- 交互式 TUI 首帧前，deferred provider discovery 保持 dormant；one-shot 与 headless 使用独立、
  有界的首次使用 settle 路径；
- stream idle 默认 60 秒；单 route provider 并发默认 4，且与 workflow fan-out 独立；renderer
  以 16 ms 合帧，并以每秒 63 帧为 ceiling；
- adaptive compaction 用所选模型 window 减去 output reserve 得到可用输入，在 82% 触发，保留其中 25%，再受
  host 不可变的 2,000--15,000 token clamp 约束；
- 裸 5xx 只有在证明 pre-dispatch 或 terminal 后才可切换 route；同一 route 永不因 5xx 重试，
  从而保留 effect 的 at-most-once；
- process/shell 默认向模型展示 30,000 bytes；profile 只可上调到 150,000 bytes；独立的 256 KiB
  evidence ring 不变；
- lifecycle event 查找为常数时间；observer 饱和时优先驱逐低价值记录，不扫描队列，也不先牺牲
  高价值 terminal 记录；
- provider 响应版本降级产生固定 compatibility evidence；web search client 禁止 redirect，防止
  credential 跨 origin。

UI/UX conformance 命令包含 16 条从契约值到生产 owner 的源码绑定。源码与 governance 漂移时会
fail closed；它不是拿 `governance/uiux-slo.json` 与自身重复字面量做同义反复。

## 权威 end-turn 语义

“没有工具调用”不代表 Iteron run 已结束，它最多只结束一个 provider step：

```text
model
  -> [tool -> model]*
  -> provider EndTurn
  -> pending steering/control
  -> optional verification
  -> answer complete
  -> finalizing(checkpoint/record/hooks/compaction/cleanup)
  -> RunEnded
  -> input ready
```

客户端不得依据 stream 安静、provider 连接关闭或某条模型回复没有 tool call 推断完成。TUI 必须先用
authoritative complete answer 对账，再把运行展示为结束。

## 有界性与 durability 决策

所有可能携带可变长度数据的生产队列都有 item bound，并同时具有 aggregate-byte 或 per-message
envelope。Cosmetic path 可以受压合并；terminal state 在不能丢失时使用独立 authoritative path。

普通 record append 有意保留同步 write-ahead durability。Append actor 可合并已经相邻的 ticket，
terminal boundary 也是真正的 multi-event batch；普通同步 façade 不会为了制造更大的 batch 而延迟
一个已经完成的 durable append。为了很小的 storage latency 优化而弱化此契约，会违反本次审计的
durability 约束。

## 闭环后的优化 surface

源码生成 census 的精确结果为：

- candidate row 共 2,875 条；
- runtime-settable、advertised、applied、externally addressed 均为 2,009 条；
- unified profile 1,380 条、direct config 303 条、caller input 326 条；
- runtime-settable 未寻址 0 条，待新增 binding 0 条；
- read-only invariant 866 条，必须由 human owner 审查，且不属于可训练 value；
- module identity 28 个；tunable family 160 个，其中 119 个可直接通过 profile 寻址。

这些数字是当前源码 revision 的生成证据，不等于“未来任何源码生成形式或外部论文 adapter 已经天然
存在”的无限集合声明。

## 验证边界

本闭环的 merge gate 为：

```bash
cargo fmt --all
git diff --check
cargo check --workspace --all-targets --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --all-targets --locked
cargo run --locked -p iteron-xtask -- tunables check
cargo run --locked -p iteron-xtask -- boundaries check
cargo run --locked -p iteron-xtask -- conformance check
cargo run --locked -p iteron-xtask -- docs check
cargo run --locked -p iteron-xtask -- lifecycle check
```

定向 terminal evidence 还覆盖 Kitty keyboard negotiation、Shift+Enter、picker 打开时的
SIGTERM/SIGHUP、process-group cancellation、最终文本对账、队列饱和、session paging 与 Unicode
rendering。

## 明确 non-claim 与尚需外部完成的证据

- `governance/uiux-slo.json` 中的阈值是 release requirement；本次改动本身不能证明它们在每种机器、
  terminal、filesystem、network、provider 上的分布。
- 本页不声明外部 provider benchmark、Harbor/Terminal-Bench campaign 或模型质量对比已完成；
  hermetic/synthetic evidence 只验证工程契约。
- 确定性的 two-turn provider fixture 已证明 cache creation/read usage 会进入 context ledger，且不会
  被伪装成 0；它不证明任何外部 provider 或 workload 的 cache hit rate 非零。
- 门禁检查 HTTP/2 enablement 与实际响应版本 compatibility；这不等于已经捕获所有 provider route
  的原始 TLS ALPN。
- 866 条 invariant 仍需对应 human owner 审查，agent 不能代替该 approval。
- Harness optimization 不训练模型权重；当前实现支持 harness-only candidate search，同时保留 host
  invariant。
- 少数 legacy production module 仍超过建议的 1,200 行维护目标。它们的行为由上述门禁覆盖；进一步
  拆分属于 maintainability 工作，不是尚未解决的 UI correctness 问题。
