# UI 活动与性能契约

本契约定义 Iteron 何时可以把一次运行展示为“有响应、已完成或已取消”。它适用于交互式
TUI、一次性客户端、workflow/tool 卡片、评测命令和进化命令。机器可读阈值位于
`governance/uiux-slo.json`，结构门禁命令为：

```bash
cargo run --locked -p iteron-xtask -- conformance uiux
```

该命令检查契约和固定阈值；release 仍必须运行本页列出的真实测量。JSON 合法不等于性能
证据。

## 完成 authority

“没有工具调用”不是完成条件。Provider 的 `EndTurn` 只结束一个模型 step；runtime 仍需处理
pending steering、取消、verification、checkpoint、record、必需 hook 和未知外部 effect。只有
authoritative `RunEnded` 才结束客户端运行态。

用户应看到的顺序是：

```text
model
  -> [tool proposed -> hook/approval -> queued -> running -> settled -> model]*
  -> provider EndTurn
  -> steering/control
  -> optional verification
  -> answer complete
  -> finalizing(checkpoint/record/hooks/compaction/cleanup)
  -> RunEnded
```

客户端不得从 stream 沉默或没有 tool call 推断完成。终态事件必须用完整 authoritative
assistant message 对账流式文本，保证 presentation queue 饱和时也不会永久缺字或重字。

## Activity 投影

Activity 是 additive、content-free 的展示状态；durable `Phase`、policy、effect ledger 和
terminal event 仍是 authority。Activity 携带 run/activity/parent 身份、闭合 kind/state、owner、
时间戳、可选 attempt/deadline、取消 authority、有界 detail code 和有界数值进度。

- 本地准备不得标为 `thinking`。
- TTFT 从实际 transport `request_sent` 开始，不把 context 或 route admission 算进去。
- 超过 250 ms 的工作必须有名字；超过 1 秒显示耗时；超过 2 秒且语义允许时提供取消或处理建议。
- Retry 显示 attempt、limit、reason、绝对重试时间和倒计时。
- `answer complete` 与 `finalizing` 是两个状态。
- 只有 runtime 接受了更强 authority 后才能显示 force cancel；未完成的 effecting call 保持
  `Unknown`，直到完成 reconciliation。

## Provider 等待契约

成功响应 header 必须在任何模型 token 之前产生 `accepted` activity。UI 分开显示连接、已接受/
provider 生成中、首字节、首 token、reasoning 和响应流。Retry 与 route failover 必须展示 attempt、
有界等待和选中的 route；安静的 stream 不得被展示成无法解释的卡死。

交互默认值为：连接 10 秒、响应 header 60 秒、stream idle 120 秒；首 token 3 秒开始提示慢，
12 秒给出 stall 处理建议。服务端 retry delay 是下界，但交互等待超过 60 秒时必须用 typed
remedy 结束，不能静默休眠。单 route 默认并发为 4，与 workflow fan concurrency 独立调参，并继续
受 provider quota、cost authority、session budget 与 host ceiling 收窄。
交互式 deferred discovery 只有首帧后才启动；未缓存的 selected route 可以使用有界的首次使用
admission wait，但 discovery 的构造本身不得产生网络 I/O。实际响应不是 HTTP/2 时必须产生固定的
compatibility evidence，不能静默改变运行声明。

对 OpenAI-compatible stream，完整 tool call 是比错误的 `finish_reason: stop` 更强的执行证据；
仅此兼容情形继续作为 tool use，并发出固定 notice。未完整 tool call，以及 refusal、stop-sequence、
unknown terminal 仍然 fail closed。

## Context 与 cache 可见性

核心文件工具从第一次模型请求起可见。Deferred tool 在同一 run 内只做单调扩展，follow-up 不得
重排并破坏稳定 provider prefix。Skill 先按任务/路径相关性选择，再按确定性顺序补足。实时 token
明确标为估算，直到 provider usage 到达；cache read/write 只展示真实测量，未知值不得显示成 0。

Adaptive compaction 用所选模型 context window 减去 output reservation 得到可用输入；默认 recent
tail 为可用输入的 25%，并受 host 的 2,000--15,000 token clamp 约束。Process/shell 默认向模型
展示 30,000 bytes；profile 只可上调到 150,000 bytes；独立的 256 KiB evidence ring 与 resume
cursor 仍为 authority。

Renderer 将相邻更新合并 16 ms，且不得超过每秒 63 帧。这样 token streaming 连续可见，同时不把
名义 16 ms timer 错当成 60 fps / 16.67 ms，也不会对每个 provider delta 单独重绘。

## 主线程边界

TUI event loop 只投影状态和渲染。文件、session/history hydrate、provider discovery、附件、
completion 扫描、协议请求、record maintenance、hook 和 workflow 持久化均在有界 actor 中。
首帧不得执行复杂度依赖 session、content object、history 或 workflow 总量的工作。

Session picker 先显示 shell，再以 25 条分页，并在离页尾 5 条时预取。附件公开 queued、
reading、decoding、ready、failed、cancelled。长 shell 命令最迟 10 秒交还 session 和 partial
output，而不是等进程退出后才一次性显示。

Session metadata 与 content reference 是可重建的增量 direct index。普通 turn、首帧、标题查询和
picker page 不得扫描或重写全部 session。跨进程恢复仍验证 authoritative rollout 与 effect journal；
普通进程内 follow-up 使用已经准入的 working set，不得每条消息重放整个 run。

## 测量矩阵

Release qualification 至少覆盖：

- warm startup，以及含 10,000 sessions 的 cold startup；
- 1 MiB 未闭合 Markdown 段落和代码围栏；
- presentation consumer 饱和/变慢，且 text/reasoning 交错；
- 慢盘、锁竞争、cache miss、index rebuild；
- 慢且并发的 shell、MCP、LSP、hook、verifier 和 workflow；
- retry、failover、provider terminal、cooperative cancel、force cancel；
- Unicode grapheme、CJK、emoji、tmux、窄终端；
- 最终文本逐字节一致，以及队列压力下 RSS 有界。

任何性能目标都不得弱化安全、权限、预算、durability、replay 或 effect-ledger 保证。
