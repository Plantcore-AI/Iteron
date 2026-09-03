# MCP 客户端兼容性

Iteron 的 MCP 客户端分成两个明确模式：2025 版本使用 `initialize` 和会话；
`2026-07-28` 使用每请求元数据、`server/discover` 和无状态请求。两种模式不共享
session 状态。

## 支持矩阵

状态只使用 `pass`、`fail`、`unsupported`、`blocked`。`pass` 后面的括号说明证据层级。

| 协议版本 | stdio | HTTP JSON | HTTP SSE 响应 | OAuth | 版本特有能力 |
|---|---|---|---|---|---|
| `2025-06-18` | pass（CLI E2E） | pass（官方 conformance） | pass（传输回归） | pass（本地 OAuth） | 状态式 initialize/session |
| `2025-11-25` | pass（CLI E2E） | fail（官方 elicitation defaults） | fail（官方 SSE 重连） | pass（本地 OAuth） | form elicitation 的单元测试通过，官方 defaults 场景仍失败 |
| `2026-07-28` | pass（CLI E2E） | fail（官方自定义参数 header） | pass（传输回归） | pass（本地 issuer/CIMD E2E） | discover、请求元数据、标准路由头、交互式 MRTR、私有列表缓存 |
| `2024-11-05` | unsupported | unsupported | unsupported | unsupported | 不进入兼容承诺或测试矩阵 |

`2024-11-05` 的 `unsupported` 只描述公开测试承诺；当前状态式协商代码仍可能接受它，
本次没有删除这条旧运行时路径，也没有将它标记为 deprecated。

当前审核基线对应的三版本 × 双传输证据如下；数字为通过 check 数/总 check 数：

| 协议版本 | stdio | HTTP |
|---|---|---|
| `2025-06-18` | pass（4/4） | pass（4/4） |
| `2025-11-25` | pass（4/4） | fail（20/27） |
| `2026-07-28` | pass（4/4） | fail（41/56） |

这里的 HTTP 格汇总该版本的全部官方 HTTP 场景，所以任一已知失败都会使整格保持
`fail`；它不会因回归门禁接受“已审核失败”而变成 `pass`。

## 证据层级

| 证据来源 | 状态 | 能证明什么 | 不能证明什么 |
|---|---|---|---|
| 锁定的官方 conformance 场景服务端 | pass | 三个版本的 localhost HTTP 报文兼容性 | 任意第三方业务 server 都兼容 |
| Iteron 本地 stdio/OAuth/异常夹具 | pass | 进程生命周期、版本回退、认证和有界失败路径 | 不同 SDK 的序列化差异 |
| 正式发布的 TypeScript/Python SDK server 交叉测试 | blocked | 尚未建立自动化 SDK 交叉兼容农场 | 不得据此发布生态兼容承诺 |
| 第三方真实业务 server 自动化调用 | blocked | 本期没有绑定某个特定 server | 不得把手工试用写成发布门禁 |

`blocked` 表示缺少可重复执行的独立证据，不表示已知实现必然失败。任何后续真实 server
清单都必须按普通测试对象管理，不能为某个产品写特判。

## 已验证与尚未通过

官方 client conformance 固定在
`modelcontextprotocol/conformance@49103de6ed70804e940637bf3e9e29e4a3f54e64`。
完整报告逐项记录版本、传输、场景、check id、状态和经过限长的失败摘要，并从实际结果
生成三版本 × stdio/HTTP 的六格矩阵；回归门禁拒绝新增失败、既有通过项或必测场景消失、
runner/报告异常以及未经审核的基线变化。每次 Rust CI 会发布名为
`iteron-mcp-conformance` 的完整机器可读报告 artifact。仓库不提交容易与执行结果脱节的
“最新报告”或静态矩阵。

当前已通过的关键官方场景包括：两个 2025 版本的初始化和工具调用，以及 2026 的工具
调用、每请求元数据、同版本安全重试、MRTR 状态回显、不同 JSON-RPC id、标准路由头、
非法工具 header 定义拒绝和 JSON Schema `$ref` 保留。

当前基线保留两类已知失败：

- 2025 的官方 elicitation defaults 与 SSE graceful reconnect；
- 2026 的 `x-mcp-header` 自定义参数 header。标准 `Mcp-Method`/`Mcp-Name` 已通过。

这些失败不会被写成“支持”。基线只允许它们保持可见；出现新的失败会使门禁失败。

## 未实现能力

| 能力 | 状态 | 边界 |
|---|---|---|
| 旧式 HTTP+SSE 双端点 fallback | unsupported | 只支持当前 Streamable HTTP 请求及 JSON/SSE 响应 |
| Roots | unsupported | 不向 server 发布客户端文件系统根目录 |
| Sampling | unsupported | server 不能反向请求 Iteron 调用模型 |
| Logging | unsupported | 不接收 MCP logging 通知 |
| Tasks | unsupported | 不实现协议任务生命周期 |
| 资源订阅 | unsupported | 不订阅资源变更通知 |
| 图片与音频内容 | unsupported | 工具结果目前只向 agent 投影文本内容 |

交互式 TUI 会把 2026 MRTR 请求显示为独立 JSON 表单。批准后，运行时在同一个 server、
同一个工具调用上回送对应的 `requestState` 与 `inputResponses`；拒绝、关闭前端、错误的
请求 ID 和不符合服务端 schema 的答案都会安全失败。表单有独立的有界通道，不会混入
普通聊天输入；答案正文也不会写入生命周期事件。非交互 one-shot/headless 模式不安装
输入处理器，因此不会等待一个不存在的用户。2025 及更早协议始终走普通 `tools/call`，
即使交互处理器存在也不会进入 MRTR。

这条路径分别由 stdio 产品调用测试、HTTP 两轮 wire 测试、app-server 关联测试和 TUI
表单测试覆盖；它证明 Iteron 自己的各层可以完成往返，但不替代上文仍为 `blocked` 的
正式第三方 SDK 交叉兼容证据。

## 管理命令

```text
iteron mcp add <name> --url <https-or-loopback-url>
iteron mcp add <name> --stdio <command> [--env <NAME>]... -- <args...>
iteron mcp list [--format text|json]
iteron mcp get <name> [--format text|json]
iteron mcp remove <name>
iteron mcp auth login <name> [--client-id <id-or-CIMD-url>]
iteron mcp auth status <name> [--format text|json]
iteron mcp auth logout <name>
iteron mcp test <name> [--format text|json]
iteron mcp status [name] [--format text|json]
iteron mcp doctor [--connect] [--format text|json]
```

`mcp test` 只连接、认证、协商并列出工具，不调用业务工具。`status` 和不带
`--connect` 的 `doctor` 不访问网络。

客户端默认探测 `2026-07-28`。服务端确认支持后使用无状态请求；服务端在同一连接上
明确返回仅支持已知 2025 版本时，客户端才执行状态式初始化，并在诊断中报告最终版本。
未知版本、无关协议错误和损坏的 discovery 响应不会触发降级。

## OAuth 与凭据

`auth login` 使用 loopback callback、PKCE、随机 state、issuer/resource 绑定和一次性
授权码交换。授权服务支持 CIMD 时，可通过 `--client-id` 提供 HTTPS Client ID Metadata
Document URL。2026 模式要求该 HTTPS CIMD URL，不会静默回退到 DCR；未启用 2026 模式的
2025 兼容路径仅在服务端明确提供 DCR endpoint 后才允许动态注册。

token 写入 `~/.iteron/mcp-credentials/<binding-id>`，文件权限为 `0600`，并绑定 server
名称、resource、issuer 和完整配置摘要。配置文件、JSON 诊断和命令输出都不包含 token、
Authorization header、环境变量值或 callback query。`auth logout` 最佳努力撤销凭据，
无论远端撤销是否成功都会删除本地文件。

stdio 子进程默认看不到 Iteron 进程的环境变量。只有通过 `mcp add --env NAME` 明确保存的
变量名会在启动时读取并转交；配置、`get` 和诊断仅显示名称，不显示值。

## 安全边界

- MCP server 提供的只读、幂等或风险注解不改变 Iteron 权限；工具仍按
  `Effecting + IrreversibleExternal` 处理。
- 非 loopback 明文 HTTP、URL 用户信息、重定向和跨 issuer origin 的 OAuth endpoint
  会被拒绝。
- session、列表 cursor、SSE 帧、缓存、MRTR 轮数/输入量、OAuth callback 和所有网络
  请求均有固定上限。
- 2026 的 `ttlMs`/`cacheScope` 只控制当前 client 私有列表缓存，不授予工具权限。

## 本地复现

```bash
cargo test --locked -p iteron-cli --test mcp_commands -- --test-threads=1
cargo test --locked -p iteron-mcp --lib

cd tests/mcp_conformance
npm ci
python3 -m unittest test_runner.py
cargo build --locked -p iteron-mcp --example conformance_client
python3 run.py ../../target/debug/examples/conformance_client \
  --baseline-report regression-baseline-v1.json \
  --report /tmp/iteron-mcp-conformance.json
```

官方 suite 需要 Node.js 22；测试只连接 suite 自己启动的 localhost server。
