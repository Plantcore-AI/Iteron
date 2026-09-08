# MCP 客户端兼容性

Iteron 的 MCP 客户端分成两个明确模式：2025 版本使用 `initialize` 和会话；
`2026-07-28` 使用每请求元数据、`server/discover` 和无状态请求。两种模式不共享
session 状态。

## 支持矩阵

状态只使用 `pass`、`fail`、`unsupported`、`blocked`。`pass` 后面的括号说明证据层级。

| 协议版本 | stdio | HTTP JSON | HTTP SSE 响应 | OAuth | 版本特有能力 |
|---|---|---|---|---|---|
| `2025-06-18` | pass（CLI E2E） | pass（官方 conformance） | pass（传输回归） | pass（官方 OAuth） | 状态式 initialize/session |
| `2025-11-25` | pass（CLI E2E） | pass（官方 conformance） | pass（传输回归） | pass（官方 OAuth） | form elicitation 与 SSE 恢复 |
| `2026-07-28` | pass（CLI E2E） | pass（官方 conformance） | pass（传输回归） | pass（官方 OAuth） | discover、请求元数据、路由/参数头、MRTR、私有列表缓存 |

`2024-11-05` 与 `2025-03-26` 不在兼容矩阵与发布承诺范围内，客户端会拒绝服务端协商到
这两个版本；本文不将它们标记为 deprecated。

当前审核基线对应的三版本 × 双传输证据如下；数字为通过 check 数/总 check 数：

<!-- generated:mcp-conformance-matrix:start -->
| 协议版本 | stdio | HTTP 非认证 | HTTP OAuth |
|---|---|---|---|
| `2025-06-18` | pass (4/4) | pass (4/4) | pass (114/114) |
| `2025-11-25` | pass (4/4) | pass (21/21) | pass (542/542) |
| `2026-07-28` | pass (4/4) | pass (52/56; unsupported=4) | pass (789/789) |
<!-- generated:mcp-conformance-matrix:end -->

表格由完整执行报告进行逐字一致性校验。`2026-07-28` 的 4 个 `unsupported` 检查包括
明确未实现的 Roots/Sampling，以及无状态模式不会发送的 initialize/initialized；它们
不会被改写成通过，也不属于已知失败。

## 证据层级

| 证据来源 | 状态 | 能证明什么 | 不能证明什么 |
|---|---|---|---|
| 锁定的官方 conformance 场景服务端 | pass | 三个版本的 localhost HTTP 报文兼容性 | 任意第三方业务 server 都兼容 |
| Iteron 本地 stdio/OAuth/异常夹具 | pass | 进程生命周期、版本回退、凭据生命周期和有界失败路径 | 不同 SDK 的序列化差异 |
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

当前已通过的关键官方场景包括：两个 2025 版本的初始化、工具调用和 elicitation 默认值；
2026 的工具调用、每请求元数据、MRTR 状态回显、标准/自定义参数头、非法
header 定义拒绝和 JSON Schema `$ref` 保留；以及三个版本共 42 个 OAuth 场景。审核
基线不再保留 `expectedFailures`。新增失败、原通过项消失、场景缺失或 runner 异常都会
阻断门禁。

固定 suite 的 `sse-retry` fixture 会协商本项目不支持的 `2025-03-26`，因此不作为
`2025-11-25` 的官方兼容证据。该版本的 SSE 断流、`retry` 延迟和 `Last-Event-ID` 恢复由
HTTP wire 黑盒回归测试覆盖；客户端仍会拒绝 fixture 返回的未支持版本。

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

HTTP 连接会把同一个交互入口适配为标准 `elicitation/create` handler，因此只有真正能够
回答服务端 form request 时才宣告 `elicitation.form`。stdio 回退到状态式 2025 后不会
宣告该能力，因为当前 stdio response router 不处理服务端主动请求。

这条路径分别由 stdio 产品调用测试、HTTP 两轮 wire 测试、app-server 关联测试和 TUI
表单测试覆盖；它证明 Iteron 自己的各层可以完成往返，但不替代上文仍为 `blocked` 的
正式第三方 SDK 交叉兼容证据。

## 管理命令

```text
iteron mcp add <name> --url <https-or-loopback-url>
  [--oauth-resource <URL>] [--oauth-scopes <SCOPE,SCOPE>]
  [--oauth-client-registration <auto|cimd|dcr>]
  [--oauth-client-id <id-or-CIMD-url>]
  [--oauth-client-secret-env <ENV_NAME>] [--oauth-issuer <URL>]
iteron mcp add <name> --stdio <command> [--env <NAME>]... -- <args...>
iteron mcp list [--format text|json]
iteron mcp get <name> [--format text|json]
iteron mcp remove <name>
iteron mcp auth login <name>
  [--oauth-resource <URL>] [--scopes <SCOPE,SCOPE>]
  [--oauth-client-registration <auto|cimd|dcr>]
  [--client-id <id-or-CIMD-url>] [--client-secret-env <ENV_NAME>]
  [--oauth-issuer <URL>]
iteron mcp auth status <name> [--format text|json]
iteron mcp auth logout <name>
iteron mcp test <name> [--format text|json]
iteron mcp status [name] [--connect] [--format text|json]
iteron mcp doctor [--connect] [--format text|json]
```

`mcp test` 只连接、认证、协商并列出工具，不调用业务工具。`status` 和不带
`--connect` 的 `doctor` 不访问网络。`status --connect` 执行有界探测，并报告当前实际协商版本和工具数量。

客户端默认探测 `2026-07-28`。服务端确认支持后使用无状态请求；服务端在同一连接上
明确返回仅支持已知 2025 版本时，客户端才执行状态式初始化，并在诊断中报告最终版本。
未知版本、无关协议错误和损坏的 discovery 响应不会触发降级。

## OAuth 与凭据

`auth login` 使用 loopback callback、PKCE、随机 state、issuer/resource 绑定和一次性
授权码交换。OAuth 能力发现先于受保护的 MCP 初始化，并且不读取或推断 MCP 日期版本。
`auto` 根据明确配置的预注册 client、服务端可用的 CIMD、服务端公布的 DCR endpoint
选择注册方式；`cimd` 与 `dcr` 强制模式不会静默互换。token endpoint 支持 `none`、
`client_secret_basic` 与 `client_secret_post`。

endpoint、OAuth resource 和 authorization-server issuer 分开验证：同源的 `/mcp`、
origin 根路径和连接查询参数差异合法；显式 resource 必须与 metadata 精确匹配；未明确
绑定的跨 origin resource 会被拒绝。authorization endpoint 只有在 issuer-bound callback
可用，或与 issuer/token endpoint 同源时才可跨 origin；预注册 client secret 只会发送到
与操作员固定 issuer 同源的 token endpoint。token/registration/revocation endpoint 还必须
由 issuer metadata 明确公布，通过 HTTPS 或 loopback HTTP 验证且没有 userinfo/fragment。
授权地址若跨入更高权限网络区，只会显示给操作员，不会由 Iteron 自动交给浏览器打开。

scope 优先级为登录命令、server 配置、`WWW-Authenticate`、resource/authorization
metadata、空集合。operator 指定的 scope 不会被自动删改；自动发现值被 provider 拒绝
时只重试一次空 scope。有效的 403 `insufficient_scope` challenge 会成为独立诊断，要求
用户确认后以显式 `--scopes` 重新登录，而不是把同一 token 当成 session 失效或自动重放
请求。已有凭据上的显式重新登录会把 challenge scope 与原授权合并，并在访问新的
authorization server 或发送 client secret 之前固定原 resource 与 issuer；同一操作不会
进行第二次 step-up。

token 写入 `~/.iteron/mcp-credentials/<binding-id>`，文件权限为 `0600`。最终 schema v1
绑定 server、resource、issuer、初始网络区、client、token 鉴权方法、requested/granted
scopes 和完整配置摘要；早期 Draft 的不完整 v1 会要求重新登录，不维护第二套格式。DCR client secret
只进入私有凭据文件。配置文件、JSON 诊断和命令输出都不包含 token、Authorization
header、环境变量值或 callback query。`auth logout` 最佳努力撤销凭据，无论远端撤销是否
成功都会删除本地文件。环境变量提供的 bearer/PAT 在 `auth status`、`status` 和 `doctor`
中显示为 `external`。

stdio 子进程默认看不到 Iteron 进程的环境变量。只有通过 `mcp add --env NAME` 明确保存的
变量名会在启动时读取并转交；配置、`get` 和诊断仅显示名称，不显示值。

## 安全边界

- MCP server 提供的只读、幂等或风险注解不改变 Iteron 权限；工具仍按
  `Effecting + IrreversibleExternal` 处理。
- 非 loopback 明文 HTTP、URL 用户信息、未验证的跨 origin resource 和 metadata redirect
  会被拒绝；凭据只发送到配置 endpoint 或已验证 metadata 明确公布的 token endpoint。
- OAuth 出站请求会解析并固定本次连接使用的地址；首次登录保存资源的初始网络区，后续
  refresh 和 revoke 继续从该边界检查。公网 MCP 不能把 discovery、注册、token、refresh
  或 revoke 请求引向 private、loopback 或 link-local 网络，跨网络区 DNS 结果会被拒绝，
  这些请求不使用环境代理。
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
cargo build --locked -p iteron-mcp --example conformance_client -p iteron-cli --bin iteron
python3 run.py ../../target/debug/examples/conformance_client \
  --baseline-report regression-baseline-v1.json \
  --report /tmp/iteron-mcp-conformance.json
python3 check_document.py /tmp/iteron-mcp-conformance.json \
  ../../docs/mcp-compatibility.md
```

官方 suite 需要 Node.js 22；测试只连接 suite 自己启动的 localhost server。
