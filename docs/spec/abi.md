# 4. 稳定类型 ABI (The Stable Typed ABI)

### 4.1 为什么需要一个稳定的 seam

前面几节确立了 Core Code 的承重不变式：microkernel（TCB）冻结，其余每个 module 都是一个可 tune / train / evolve 的 strategy slot。这条不变式只有在**module 与 kernel、module 与 module 之间存在一个稳定、类型化、版本化的接缝（seam）**时才成立。这个接缝就是 **Stable Typed ABI**。

它回答一个反复出现的疑问：*模块之间到底怎么连接？演进（evolution）会不会把接口本身改掉？* 明确的答案是：

> **接口不变。** ABI 的**形状（shape）是版本化且稳定的**；演进改变的是**接缝背后 module 的实现（implementation）**，从不改变接缝本身。一次运行（run）一旦启动，就被钉死在**恰好一个** ABI 版本上；任何"看不懂当前 ABI"的候选实现，会在 admission 阶段被拒绝，而**不是**被允许去改写 ABI。演进换的是 slot 里坐着的东西，不是 slot 的插口。

这条区分是整个 trainable-harness 论断能落地的原因。如果每次进化一个 module 都要改动接口，那么"冻结核 + 可进化外围"就是一句空话：接口漂移会把 authority 重新引回 TCB，把互换性（interchangeability）摧毁。因此 ABI 的稳定性**本身就是一条安全不变式**，与 kernel 冻结同级。

Core Code 把这个接缝收敛成**恰好五个 typed contract**。任何 strategy module、任何 model adapter、任何 vertical pack 想要参与运行，都**只能**通过这五个契约与系统对话：它们不能直接调用 kernel 的内部函数，不能彼此直接调用，不能自己执行 effect。它们**只提议（propose）typed 值**；kernel 审计、裁决、执行。

| # | 契约 | 方向 | 一句话职责 | protocol 里的现有种子 |
|---|---|---|---|---|
| 1 | `TaskEnvelope` | 外 -> runtime | 一个进入系统的 task，连同它的验收契约、预算与授权上限 | `Op::UserInput`（`lib.rs`）+ `SqEnvelope` |
| 2 | `ContextRequest` | module -> kernel | 一个 module 对**已授权** context 的类型化请求 | `EventKind::ContextInjection` / `DurableInstructionContext`（新增 request 侧） |
| 3 | `ToolIntent` | module -> kernel | 一次被提议的 tool 调用，按 purity / capability 定型 | `ToolUse` / `ToolSpec` + `Capability` / `Purity`（`tool.rs`）**已有** |
| 4 | `EffectProposal` | kernel gate <-> broker | 一个被提议的、对外可见的 effect，带 durable id | `EventKind::EffectIntent`（`event.rs`）**已有** |
| 5 | `ArtifactRef` | runtime -> 外 | 一个产物的稳定句柄：hash · schema · producer · provenance · permissions | `FileDiff`（`diff.rs`）、`Checkpoint.tree_ref`（作为 locator；新增统一封装） |

> **模块如何连接**：只通过这五个契约。kernel 用注入的 port（injected port）构造运行时的 `Agent`，把具体 strategy crate 的依赖丢掉；module 之间不直接握手，而是各自向 kernel 提交/接收上表中的 typed 值。加一个新 module（例如某垂类的 `db/query_planner` slot）**只需**让它讲这五个契约，不需要碰 microkernel：这就是可扩展性（extensibility）的机械保证，而非口头承诺。

以下四节逐个给出五个契约的字段级 schema、它们映射到的种子、以及规范性（normative）约束；随后给出版本化与稳定性保证，最后给出一条完整的端到端往返。

---

### 4.2 五个契约的字段级 schema

契约以 protocol-native 的形式呈现（Rust 类型 + serde JSON 线格式）。所有契约 **MUST** 满足五条系统不变式：Bounded（每个可变长字段有显式上界）、Recoverable、Reproducible、Observable（每次跨接缝的提议都落 EQ 事件）、Security-bounded（deny-by-default，trust 与 capability 随值携带、不可凭文本升级）。

#### 4.2.1 `TaskEnvelope` ， task 入口 + 验收契约

`TaskEnvelope` 是**唯一**合法的 task 入口。它把"要做什么"与"怎么算做完"绑在同一个类型里，使得 verifier 与 evolution 的 held-out 评估有一个**权威的验收锚点**，而不是从散落的 prompt 文本里猜。

```rust
/// A task entering the runtime, with its acceptance contract, budget, and authority ceiling.
/// Seed: Op::UserInput + SqEnvelope (protocol_version stamping).
pub struct TaskEnvelope {
 /// 绑定到一个 SQ submission；一次 run 内唯一。
 pub task_id: SubmissionId,
 /// 本次 run 钉死的 protocol 版本（由 admission 盖章，不是对端声明的值）；skew 在
 /// `SqEnvelope::into_current` 处被硬拒，永远到不了这个类型（见 §4.3）。
 pub protocol_version: u32,
 /// 结构化的 task 载荷。文本形态兼容 Op::UserInput { text }。
 pub input: TaskInput,
 /// 输入的信任来源。operator 直接输入 = Trusted；来自文件/网页/上游 = 更低。
 /// trust 随值携带，imperative 文本不能把 data 升级成 operator authority。
 pub trust: Trust,
 /// 验收契约：如何客观判定这个 task 完成。一组具名、机器可跑的 check，
 /// 而非自由文本。这是 held-out 评估与 verifier slot 的锚点。
 pub acceptance: Acceptance,
 /// 预算与截止：turn / wall-clock / 货币 / 连续工具错误上限。Bounded 不变式的载体。
 pub budget: Budget,
 /// 治理这个 task 的已编译 vertical profile 句柄。**v1 冻结形状里没有这一项**；见下。
 // pub profile_ref: Option<ArtifactRef>,
 /// 这个 task 的 capability 上限（tier ceiling）。任何下游 ToolIntent /
 /// EffectProposal 的授权都 MUST 是它的子集：intersection-only，从不 union。
 pub ceiling: CapabilitySet,
}

pub enum TaskInput {
 /// 兼容 Op::UserInput 的自由文本 task。
 Text { text: String },
 /// 结构化 task（例如 SWE 风格的 issue + repo 指针 + 目标测试）。
 Structured { schema: SchemaId, body: serde_json::Value },
}

/// 验收如何被客观判定：一组具名、机器可跑的 check，每个带自己的量词。
pub struct Acceptance {
 pub checks: Vec<AcceptanceCheck>, // Bounded: <= MAX_ACCEPTANCE_CHECKS
}

pub struct AcceptanceCheck {
 /// check 在本 task 内的稳定身份，不是显示名。
 pub id: String,
 pub quantifier: Quantifier,
}

/// "过了没有"不是一个问题：回归套件要**保持**通过，bug fix 的测试要**开始**通过。
pub enum Quantifier {
 MustPass, // 改动之后必须通过；对改动之前不作断言
 MustFlipToPass, // 改动之前必须失败、之后必须通过：证明改动确实做了事
 MustStayPassing, // 改动前后都必须通过：证明改动没有打坏别的东西
}
```

**JSON 线格式（示意，公开安全）**

```json
{
 "task_id": 1,
 "protocol_version": 1,
 "input": { "kind": "text", "text": "修复 parser 对空输入的 panic 并让测试通过" },
 "trust": "trusted",
 "acceptance": { "checks": [
 { "id": "suite::regression", "quantifier": "must_stay_passing" },
 { "id": "test_parses_nested_braces", "quantifier": "must_flip_to_pass" } ] },
 "budget": { "max_turns": 60, "max_usd": null, "max_wall_secs": 900, "max_consecutive_tool_errors": 3 },
 "ceiling": ["read_only", "reversible_local", "code_executing"]
}
```

规范性约束：

- 一个 `TaskEnvelope` **MAY** 携带空的 acceptance 集合（`Acceptance::is_unspecified()`）：自由文本 task 本来就没有机器 oracle，空集只表示「未指定」，**MUST NOT** 被任何读者读成「已通过」。但 `is_unspecified()` 为真的 task **MUST NOT** 被 evolution 采纳为 held-out 评估输入或结论锚点（否则候选可自评自证）；该拒绝的机械执行点属于 held-out scoring bridge（#27，runner 见 #33），本节只规定契约。
- `ceiling` **MUST** 由 kernel 强制为所有下游提议授权的上界。任何 module **MUST NOT** 提议超出该上限的 capability。
- `trust` **MUST** 随值传播；一个 `TaskInput::Text` 里出现的祈使句 **MUST NOT** 被任何 module 当作 operator authority（untrusted-input 原则）。
- 任何跨接缝的 authority **MUST** 以**集合**（`CapabilitySet`）承载，**MUST NOT** 表示为某个序上的一个点。`Capability` 的 `Ord` 只为 `BTreeSet` 存储而存在，是声明序而非授权序：以单个 class 作上限并用 `<=` 判定，会让一个只意在「可 egress」的上限静默放行 `CodeExecuting` 与 `TrustMutating`。合并运算**只有** intersection：widening 在类型上不可表达。
- 冻结的 `Budget` 就是 `core_protocol::Budget`（`crates/protocol/src/lib.rs`），它已随 `EventKind::ChildStarted` 落在 durable 记录上，形状不可另铸；token 轴按 §4.3(b)3 以 `max_tokens: Option<u64>` + `skip_serializing_if` 追加，归属 #18，追加后两个载体的字节都逐字节不变。
- `profile_ref` 是 §4.2.1 里唯一可以事后无损追加的字段：当第一个真实消费者出现时，按 §4.3(b)3 以 `#[serde(default, skip_serializing_if = "Option::is_none")] pub profile_ref: Option<ArtifactRef>` 追加，`None` 与今天的字节逐字节一致。今天的 bundle 解析走 boot-time `PolicyBundleResolver`（进程级、只读），不经过 envelope。

  该 port 声明在 **`core_protocol::bundle`**，不在 `crates/evolve`。这一条是被一次合并后复审改正的：冻结时它被声明为 `core_evolve::PolicyBundleResolver`，签名里三个类型（`PolicyBundle` / `StrategySlot` / `ContractError`）全部来自 `core-evolve`，于是 #28 要在 `crates/agents` 里实现它就必须先引入 `core-evolve` —— 正是 #26 验收条目 5 用 grep 守着的那条禁止依赖。该 grep 当时为绿，只因为那个 trait 没有任何实现者与调用者：它测的是「没人用」，不是「不变式成立」。
  port 落在 `core-protocol` 后，producing 侧（`crates/evolve`）与 consuming 侧（`crates/agents`）都已依赖它，**两侧零新增依赖**。跨接缝传的是 `ResolvedBundle` 这个只读投影（只带 slot 身份与 digest，不带 policy 本体、locator 或 lineage），由 `PolicyBundle::resolve()` 生成，并在 `SlotId` 无法表达某个 slot 时**整体拒绝**而非丢弃该条 —— 丢弃会让那个 slot 跑内置策略，而 promotion journal 记录它已被治理。

`Acceptance` 是必带字段，不是 `Option`：一个 task 总要说清「怎么算做完」，哪怕答案是空集。v1 冻结形状里没有 `oracle` / `min_strength` / `objective_digest`：`AcceptanceCheck.id` 是 check 在 task 内的稳定句柄，由 verifier slot 解析到具体 oracle；oracle 引用类型、强度序数与 held-out digest 按 §4.3(b)3 以 `Option` + `skip_serializing_if` 追加，归属 #51（`crates/verify` 的所有权 issue）：今天的 `crates/verify/src/oracle.rs::OracleStrength` 不带 serde 且 `core-verify` 依赖 `core-protocol`，反向依赖会成环。

#### 4.2.2 `ContextRequest` ， 对已授权 context 的类型化请求

今天 `ctx` crate 直接产出一个 context pack，没有 typed request；这让"什么进了 context"难以审计、难以让 optimizer 搜索。`ContextRequest` 把 context 选择变成一次**受约束的、可观测的提议**：module 说"我要什么、为了什么、最多多少字节、我愿意信到什么 trust 层级"，kernel 返回一个 bounded、trust-tagged 的 `ContextGrant`，并把它落成 `ContextInjection` 事件（replay 从记录重建 context，而非从磁盘：见 §5 records-and-replay）。

```rust
/// A module's typed request for authorized context. Never performs I/O itself;
/// the kernel resolves it into a bounded, trust-tagged grant.
pub struct ContextRequest {
 pub request_id: RequestId,
 /// 谁在请求（通常是 context 或 memory slot）。
 pub slot: SlotId,
 /// 请求的具体 selector。审计锚点是 (request_id, slot) 加 selector 本身：这正是一条
 /// 被记录下来的 request 所包含的全部内容。
 pub selectors: Vec<ContextSelector>, // Bounded: <= MAX_SELECTORS
 /// 本次请求可注入的总字节上限（Bounded 不变式）。
 pub max_bytes: u32,
 /// 请求方愿意作为"权威"对待的最高 trust 层级；缺省不可升 trust。
 pub trust_ceiling: Trust,
}

pub enum ContextSelector {
 RepoOutline { root: String, depth: u8 },
 Instructions { scope: InstructionScope }, // 项目/用户级指令文件
 MemoryKeys { keys: Vec<String> }, // memory slot 的读路径
 Transcript { last_n_turns: u16 },
 EnvironmentFacts, // cwd、git 状态等 frontend 事实
}

/// kernel 的回应：bounded、trust 标注、可落 ContextInjection 事件。
pub struct ContextGrant {
 pub request_id: RequestId,
 /// 已渲染的 context 段，每段带自己的 trust provenance。
 pub segments: Vec<ContextSegment>,
 /// 实际注入字节；MUST <= 请求的 max_bytes，且 MUST <= protocol 侧硬上限
 /// MAX_CONTEXT_GRANT_BYTES。
 pub bytes: u32,
}

pub struct ContextSegment {
 pub text: String,
 pub trust: Trust, // 合并多段 context 不会静默抬高 trust
 pub source: ContextSource, // instructions / memory / skills / environment / repo_outline / transcript
}
```

`ContextSource` 是一个封闭词表（`instructions` / `memory` / `skills` / `environment` / `repo_outline` / `transcript`，外加 `unknown` 降级臂），**MUST NOT** 用自由字符串代替：module 不得为自己提供的字节编造 provenance 标签。它**刻意不是** `ContextSelector` 的镜像：kernel 会注入一份没有任何 selector 请求过的 skill 清单，grant 必须能如实报告这个来源，而不是假装它被请求过。

规范性约束：

- 一个 `ContextRequest` **MUST NOT** 自行读文件、遍历 workspace 或读 env：它只**声明意图**；实际物化由 kernel 的受审边界完成（kernel 的 negative space 里"读文件/读 env"是 kernel 也不做的，由受 capability 约束的 provider/tool 边界做，但**选择**逻辑在 context slot）。
- 一组 segment 的 **governing trust** **MUST** 是各段 trust 的**最小值**（`min`）；合并 **MUST NOT** 抬高 trust。空集**没有** governing tier，**MUST** 由调用方显式 fail-closed 处理，**MUST NOT** 隐式取 `Trusted`（空集的数学恒等元）。`Trust` 是封闭的三级安全格（`Untrusted < Workspace < Trusted`），其 skew 契约是 fail-closed 拒绝，**MUST NOT** 追加 `Unknown` 之类的降级臂：那会在 derived `Ord` 下排在 `Trusted` 之上并使 `min` 失效（见 Errors.md 2026-07-27e 已记录的回归）。这直接对应 `DurableInstructionContext` 中 environment 段独立带 trust 的设计。
- 注入的总字节 **MUST** 被 bound：一次 grant **MUST NOT** 超过 request 的 `max_bytes`，且 **MUST NOT** 超过 protocol 侧的硬上限 `MAX_CONTEXT_GRANT_BYTES`。二者是**各自独立**的上界，不是联合封顶。kernel 侧的 per-source 常量（如 `MAX_DURABLE_ENVIRONMENT_CONTEXT_BYTES`）继续**各自**约束各自的来源，不参与总量封顶。
- `SlotId` 是跨接缝的**身份**，与 kernel 调用的 `StrategySlot` trait 是两个类型。其文法 **MUST** 是 `core_evolve::StrategySlot` 的严格子集：**每一个合法的 `SlotId` 都是合法的 `core_evolve::StrategySlot`，反之不成立**。方向不可颠倒：policy bundle 指向一个 kernel 没有的 slot 是惰性的、无害的；kernel 拥有一个任何 bundle 都无法命名的 slot 是不可治理的空洞。

> 一个 per-request 的 `purpose: Option<String>` 若日后需要，**MAY** 按 §4.3(b)3 以 `Option` + `skip_serializing_if` 追加，线格式零代价。per-**selector** 的 purpose 则不行：`ContextSelector` 是 internally tagged enum，没有承载「所有变体共有字段」的位置，逐变体添加是破坏性 diff。

#### 4.2.3 `ToolIntent` ， 按 purity / capability 定型的被提议调用

这个契约**已经**在 `protocol::tool` 里有成熟的种子：`ToolUse`（一次模型发起的调用）、`ToolSpec`（工具声明的契约）、外加 `Purity` 与 `Capability` 两个类型化的轴。`ToolIntent` 把它们组装成 tool_policy slot 向 kernel 提交的提议单位。

关键点（对应 R1 决议）：**tool 的选择与策略（选哪个工具、给什么参数、按 vertical 调优）是可进化的 `tool_policy` slot；而这些工具的 effect 的授权（authority）由 kernel 的 capability gate + effect broker 独占。** `bash` 是一个 tool：它的 effect 被 kernel 中介与 admit，但 bash **不是** kernel 内部的逻辑。

```rust
/// A proposed tool call, typed by purity and admitted authority. Seed: ToolUse/ToolSpec + Purity/Capability.
pub struct ToolIntent {
 /// 提议这次调用的 slot（通常是 tool_policy 或 planner）。harness 侧归属，绝不从模型读。
 pub proposed_by: SlotId,
 /// 兼容 ToolUse：模型发起的一个 tool_use block。
 pub call: ToolUse, // { id, name, input: Value }
 /// 声明的纯度：Pure 可早派发/memoize；Effecting 必须等整轮 + 过 policy。
 pub purity: Purity, // Pure | Effecting
 /// gate 为这次调用放行的 authority 类集合。是集合，不是某个序上的一个点。
 pub admitted: CapabilitySet,
 /// 这次调用的**参数**所携带的信任层级（例如源自 untrusted 网页则更低）。
 pub argument_trust: Trust,
}
```

声明的 capability 类留在注册契约 `ToolSpec.capability` 上，由 `crates/tools/src/lib.rs::Registry::register` 在注册期强制（本节第一条 MUST 即在此生效）；ToolIntent 不在带内重复声明它，gate 从注册表按 `call.name` 取。v1 冻结形状里没有 `intent_id`：ToolIntent 不是 durable 记录、不铸造 effect 身份（durable 身份是 `EffectProposal.id`），关联走 `call.id`；若日后确有需要，按 §4.3(b)3 以 `Option<RequestId>` 追加。

规范性约束（多数由 `tool.rs` 在注册期已强制）：

- `purity` 与 `capability` 的耦合 **MUST** 在注册时校验：`Pure` 与任一 egress capability（`IrreversibleExternal`）耦合是**注册错误**，不是风格问题：mislabel 是安全缺陷。
- 只有 `ReadOnly` 与 `ReversibleLocal` **MAY** 无人值守运行（`runs_unattended()`）；`CodeExecuting`、`TrustMutating`、`IrreversibleExternal` **MUST** 走审批，且 egress **MUST** 处于 Trusted 上下文。
- `ToolIntent.admitted` 是 gate 的收窄结果，deny-by-default 构造、intersection-only 收窄，**MUST NOT** 由任何 module 凭空铸造；它 **MUST NOT** 被读作"可以产生对外可见 effect"的授权：那一步授权只发生在 `EffectProposal` 过 broker 之时。`Pure` + `ReadOnly` 的 intent **MAY** 仅凭其 admission 早派发，因为它运行在 no-egress 只读 cell 里，mislabel fail-closed。

#### 4.2.4 `EffectProposal` ， 带 durable id 的对外可见 effect

这是**唯一**能让世界发生可见改变的通道，其种子是 `EventKind::EffectIntent`：一个 effecting tool 调用的**写前 admission**（write-ahead），在进入 registry executor 之前 **MUST** 被 fsync。凡是 provider / hooks / subagent / verify / memory 产生的 effect，都 **MUST** 经过这**同一个** effect broker 与同一个 capability gate。

```rust
/// A proposed externally-visible effect with a durable identity. Seed: EventKind::EffectIntent.
pub struct EffectProposal {
 /// harness 铸造的 durable id；EffectIntent 的关联键。
 pub id: EffectId,
 /// 关联到发起它的具体模型调用（tool_use id），不只是一个 tool 类别。
 pub tool_use_id: String,
 pub tool: String,
 /// gate 放行的 authority 类集合；与 ToolIntent 同一种载体，同样只能收窄。
 pub admitted: CapabilitySet,
 /// 脱敏、bounded 的参数投影（审计证据，不是 ambient 能力句柄）。
 pub arguments: serde_json::Value,
 /// 资源/workspace 出处。
 pub workspace: String,
}
```

gate 裁决与终态（对应 `event.rs` 的既有类型）：

- kernel 的 capability gate 产出一个 `Verdict`：`Ask`（请求人工）-> `Auto`（批准）或 `Deny`（拒绝）。请求与裁决**都**落 `EventKind::Approval` 事件，使审批成为**replay 决策日志**：确定性 replay 读记录里的 verdict，**不**重新弹窗（operator 不在 replay 里）。
- 批准后，broker 执行；若 kernel 观测到派发但**无法证明**终态，它 **MUST** 记 `EventKind::EffectUnknown` 而**绝不**自动重试（可能重复的对外操作宁可标记未知，也不冒重复之险）。正常完成落 `EventKind::ToolDone { effect_id }`。

规范性约束：

- 每个 `EffectProposal` 在执行前 **MUST** 有一个 fsynce 的 `EffectIntent`（durable id + 脱敏参数投影）。
- `TrustMutating` 与 `IrreversibleExternal` **MUST NOT** 被任何 mode 或 session rule 自动批准；仓库配置 **MAY** 收紧一个已授予的 grant 或预算，但 **MUST NOT** 凭空铸造 code execution、provider routing、endpoint routing、MCP 进程或 lifecycle hook。
- broker 是**唯一** effect 出口；任何 module **MUST NOT** 绕过它直接产生对外 effect。

字段名为 `id`（不是 `effect_id`）：这个值直接从 `EventKind::EffectIntent` 读出、再写回，而那条 durable 记录的字段就叫 `id`。

#### 4.2.5 `ArtifactRef` ， 产物的稳定句柄

运行产生的每一个可复用产物：一个文件补丁、一个 workspace checkpoint、一个已编译的 vertical profile、一个 PolicyManifest（harness checkpoint）、一个 governed dataset：都 **MUST** 通过 `ArtifactRef` 引用，而非内联传递内容。它把 hash、schema、producer、provenance、permissions 收敛成一个可审计、可 replay 的句柄。种子是 `FileDiff`（结构化补丁）与 `Checkpoint.tree_ref`（快照账本引用）。注意方向：`Checkpoint.tree_ref` 种下的是一个 `schema: checkpoint` 句柄的 **`locator`**，**MUST NOT** 被当作 `hash`。`crates/record` 的 `valid_object_id` 接受 40 或 64 hex，它是 git 对自己 framed tree object 的 oid，而非产物字节的摘要；把它放进 `hash` 会让 content-address 的断言变成假的。`hash` **MUST** 由铸造这个 ref 的 producer 对产物字节自行计算。

```rust
/// A stable handle to a produced artifact. Seed: FileDiff, Checkpoint.tree_ref.
pub struct ArtifactRef {
 /// 内容寻址：产物字节的 SHA-256（64 hex）。
 pub hash: String,
 /// 产物的类型化 schema：决定读它的人如何解释它。
 pub schema: ArtifactSchema,
 /// 谁产生了它（slot / tool / run），用于归属与审计。
 pub producer: Producer,
 /// 出处链：父 hash / run id / 触发它的 effect_id。tamper-evident。
 pub provenance: Provenance,
 /// 读取或作用于它所需的 capability 类（deny-by-default）。
 pub permissions: CapabilitySet,
 /// bounded 定位串（<= MAX_ARTIFACT_LOCATOR_BYTES）。
 pub locator: String,
}

pub enum ArtifactSchema {
 FileDiff, // 种子：protocol::FileDiff（结构化补丁）
 Checkpoint, // 种子：EventKind::Checkpoint { tree_ref }
 PolicyManifest, // harness checkpoint（evolve schema v3）
 GovernedDataset, // evolution 的治理数据集
 VerticalProfile, // 已编译的垂类 profile
 Trajectory, // evolution 采样出的一条 run trajectory（4.3(d) 管线的首个输入）
}

pub struct Provenance {
 pub run_id: RunId,
 pub parent_hashes: Vec<String>, // hash-chained 血缘
 pub effect_id: Option<EffectId>, // 若由一个 admitted effect 产生
}
```

规范性约束：

- 每个 `ArtifactRef.hash` **MUST** 是内容的 SHA-256，且 producer 一侧内容不可变（content-addressed，immutable）。
- 跨越 non-authoritative 的 evolution 边界（trajectory / dataset / PolicyManifest）时，**MUST** 只以 `ArtifactRef` 引用，使 evolution 的 append-only registries 能做 hash 校验：这也是为什么 evolution 侧的产物"可提议但不可改写证据"。
- `permissions` **MUST** 以 deny-by-default 解释：一个 `ArtifactRef` 的持有并不授予读取或执行它的权利，读取仍需相应 capability。
- 内容寻址 / tamper-evident 的证据句柄（`ArtifactRef.schema` 与 `producer.kind`）**MUST** 原样保留未知 tag 本身（照 `ProviderStateFormat::Unknown(String)` / `StopReason::Unknown(code)` 的模式），使 decode 后再 encode 逐字节不变；保留的 tag **MUST** 有界（`MAX_ARTIFACT_TAG_BYTES`）、不含控制字符，且永不被解释。

---

### 4.3 ABI 版本化与稳定性保证

ABI 的价值全在于它**稳定且可演化**：两者不矛盾，靠的是把"版本化"与"钉死"分开。

**(a) 两级版本号，各有其职。**

| 版本量 | 作用域 | 现值 | 规则 |
|---|---|---|---|
| `PROTOCOL_VERSION`（`wire.rs`） | SQ/EQ 线格式，以及它钉死的那一代五契约形状 | `1` | 任何**改变已发布形状**的改动 **MUST** bump 它：删除或改写任一 surface 的字段、tag、`version_field`、`selector` 或 fixture 集，五契约自 freeze 起同受此约束（§4.3(c)）。**纯新增 MUST NOT** bump 它：一个全新的顶层 tag，或一个 `Option` + `skip_serializing_if` 的追加字段，§4.3(b) 第 2、3 条已保证这两者的线格式逐字节不变；W1 freeze 新增五契约 surface 即属此类。`core-xtask boundaries check-base` / `check-pr` 以受信基线的 surface 集比对判定，防止悄悄改形 |
| `EVOLUTION_SCHEMA_VERSION`（`evolve`） | PolicyManifest / dataset / trajectory 文档 | `3` | evolution 产物的 schema 版本；与运行时 ABI 解耦升级 |

`SqEnvelope` / `EqEnvelope` 给每条跨接缝的消息盖 `protocol_version`。`into_current()` 对版本 skew **硬拒**（`ProtocolVersionError`）：一次 run 只接受**恰好一个** `PROTOCOL_VERSION` 的消息。这是"一次 run 钉死一个 ABI 版本"的机械实现。

**(b) 向前兼容靠 additive-only，不靠改形。** 契约的演化 **MUST** 遵循三条既有纪律（在 `event.rs` 中已由测试锁定）：

1. **未知项退化，不炸整条 replay。** 顶层枚举带 `#[serde(other)] Unknown`（`Op::Unknown`、`EventKind::Unknown`）：更新的写端产生的未知 tag，在旧读端**降级为 Unknown** 并丢弃其 payload，而不是让整条 rollout 解析失败。这保证一个新 module 的新字段不会打死老 kernel 的 replay。但内容寻址 / tamper-evident 的证据句柄（`ArtifactRef.schema` 与 `producer.kind`）**MUST** 原样保留未知 tag 本身（照 `ProviderStateFormat::Unknown(String)` / `StopReason::Unknown(code)` 的模式），使 decode 后再 encode 逐字节不变；保留的 tag **MUST** 有界（`MAX_ARTIFACT_TAG_BYTES`）、不含控制字符，且永不被解释。
2. **新语义 = 新顶层 tag，不改旧 tag。** 当一个已发布的形状需要新增会破坏兼容的字段时，**MUST** 引入一个**新的顶层 tag**（如 `workflow_v2`、`subagent_finished_v2`），让只懂 v1 的读端把它当 `Unknown` 跳过，而**不能**在已知 v1 tag 内部塞入 v2-only 字段或新枚举值。`validate_compatibility_tag()` 在落盘前强制这一契约。
3. **可选字段 + `None` 保持旧线格式字节兼容。** 追加字段 **MUST** 是 `Option` 且 `skip_serializing_if = "Option::is_none"`，使 `None` 序列化出的字节与历史记录**逐字节一致**（`RunStart.environment`、`DurableInstructionContext.environment`、`ToolDone.effect_id` 皆如此）。

**(c) 稳定性保证（正式陈述）。** 综合以上：

> 对于一次给定 `PROTOCOL_VERSION` 的运行，五个契约的**形状是不可变的**。演进 **MUST NOT** 在运行中改变任何契约的字段集、tag 或语义。演进被允许改变的**只有** `StrategySlot` 背后的实现：即某个 slot 里坐着哪个 policy：其结果是一个新的、版本化、可 diff 的 **PolicyManifest（harness checkpoint）**，而非一个新的 ABI。任何无法讲当前 `PROTOCOL_VERSION` 五契约的候选实现，**MUST** 在 admission 阶段被拒绝。

据此明确：**microkernel 的接口在演进中不变。** 演进是"换 slot 里的实现"，接口是它必须遵守的、被版本钉死的语法。候选可以 propose，但**不能**授予自己 capability、改写证据、放松预算、伪造自己的 held-out 结果、或自我晋升：admission 强制 `候选授权 = subset(slot 上限 INTERSECT 精确父上限)`，intersection-only，"never union"，capability-monotone。

**(d) 演进如何"透过"稳定 ABI 生效。** 一次演进周期把 trajectory（`ArtifactRef`）-> governed dataset（`ArtifactRef`）-> candidate producer -> `PolicyManifest`（一个新 slot 实现的封装）-> admission -> 独立 held-out 评估 -> shadow -> canary -> active，最后以确定性 rollback 兜底。整个管线是**离线、非授权、人工门控**的，且**不开源**（bring-your-own 或闭源 evolution 服务）。它产出的 PolicyManifest 换掉一个 slot 的实现：运行时的五契约形状，一字不改。

---

### 4.4 一次完整的端到端往返

下面用一个**修 bug 的编码 task**，走通"TaskEnvelope 进 -> module 返回 ContextRequest / ToolIntent 提议 -> kernel admit 一个 EffectProposal -> ArtifactRef 出"的全程。每一步标注它落哪个 EQ 事件（Observable 不变式），并显示 trust 与 capability 如何一路收紧。

**场景**：operator 要求"修复 `parser` 对空输入的 panic，并让 `cargo test -p parser` 通过"。垂类 profile = core baseline。`ceiling = {ReadOnly, ReversibleLocal, CodeExecuting}`（本 task 不允许 egress，也不允许改 trust）。集合逐项列全这次 run 真正需要的类：没有序可依，`{ReversibleLocal}` 并不隐含 `ReadOnly`，跑测试也要显式的 `CodeExecuting`。

**步骤 0 ， TaskEnvelope 入口。** frontend 把 operator 输入包成 `SqEnvelope { protocol_version: 1, op: UserInput }`，kernel 据此构造 `TaskEnvelope`：`trust = Trusted`（operator 亲自输入），`acceptance.checks = [{ id: "suite::parser", quantifier: MustFlipToPass }]`，`budget` 见下，`ceiling = {ReadOnly, ReversibleLocal, CodeExecuting}`。
-> 落事件：`RunStart`（genesis，seq-0，携带 `created_at`、`config_digest`、`max_usd`）。

**步骤 1 ， context slot 提议 ContextRequest。** context module（不做任何 I/O）提交：

```json
{ "request_id": 11, "slot": "core/context",
 "selectors": [
 { "kind": "repo_outline", "root": "crates/parser", "depth": 2 },
 { "kind": "instructions", "scope": "project" },
 { "kind": "environment_facts" } ],
 "max_bytes": 32768, "trust_ceiling": "workspace" }
```

kernel 物化为 `ContextGrant`：repo outline 段 `trust = Workspace`，instruction 段 `trust = Untrusted`（项目指令是 data，不是 authority），environment 段 `trust = Workspace`；合并**不升 trust**。
-> 落事件：`ContextInjection { text, trust, instructions }`。replay 时 context 从此事件重建，绝不重读磁盘。

**步骤 2 ， planner / tool_policy 提议 ToolIntent（只读探查）。** 模型据 context 决定先读文件定位 panic。tool_policy slot 提交一个 `ToolIntent`：`call = read_file(crates/parser/src/lib.rs)`，`purity = Pure`，`argument_trust = Workspace`，`admitted = {}`（deny-by-default 构造：module 从不铸造授权）。capability gate 按 `call.name` 从注册表取 `ToolSpec.capability = ReadOnly`，与 `ceiling` 求交，收窄出 `admitted = {ReadOnly}`。此时 `purity = Pure` 且 `runs_unattended()` 为真（admitted 非空、其中每一类都 unattended-safe，且 `argument_trust > Untrusted`），它在 no-egress 只读 cell 里**早派发**，无需审批。
-> 落事件：`ToolReady { tool, purity_pure: true }` -> `ToolDone { result }`（`result.trust = Workspace`）。

**步骤 3 ， tool_policy 提议 ToolIntent（写补丁）。** 定位到 bug 后，tool_policy 提议一次编辑：`call = edit(...)`，`purity = Effecting`，`argument_trust = Workspace`，`admitted = {}`；gate 从注册契约取 `ToolSpec.capability = ReversibleLocal`，与 `ceiling` 求交后 `admitted = {ReversibleLocal}`。因 `Effecting`，它**不能**早派发：必须等整轮结束并过 policy。

**步骤 4 ， kernel admit 一个 EffectProposal。** 该 `ToolIntent` 的 effect 侧被铸成 `EffectProposal`：

```json
{ "id": "eff-7", "tool_use_id": "call-42", "tool": "edit",
 "admitted": ["reversible_local"],
 "arguments": { "path": "crates/parser/src/lib.rs", "hunk": "…（脱敏投影）" },
 "workspace": "/repo" }
```

capability gate 裁决：`{ReversibleLocal}` 是 `ceiling` 的子集（子集判定，不是 `<=`）AND 当前 mode 允许 -> `Verdict::Auto`。
-> 落事件（顺序有意义）：`Approval { verdict: Auto }` -> **fsync** `EffectIntent { id: eff-7, … }`（写前 admission）-> broker 执行编辑 -> `ToolDone { result, effect_id: eff-7 }`。若 broker 派发后无法证明终态，则落 `EffectUnknown { id: eff-7 }` 而**不重试**。

**步骤 5 ， ArtifactRef 出（补丁 + checkpoint）。** 编辑落地后，broker 产出两个内容寻址产物，各以 `ArtifactRef` 引用：

```json
{ "hash": "3b1f8e2c4a6d0b9f1e3c5a7d9b1f3e5c7a9d1b3f5e7c9a1d3b5f7e9c1a3d5b7f",
 "schema": "file_diff", "producer": { "kind": "slot", "slot": "core/tool_policy" },
 "provenance": { "run_id": "run-9", "parent_hashes": [], "effect_id": "eff-7" },
 "permissions": ["reversible_local"], "locator": "diff://run-9/eff-7" }
```

同时 kernel 落 `Checkpoint { at: <seq>, tree_ref }`：一个 `schema: "checkpoint"` 的 `ArtifactRef`，使这次改动可确定性 rollback。

**步骤 6 ， verifier 对验收契约裁决。** verifier slot 把 `TaskEnvelope.acceptance` 里的 `suite::parser` 解析到具体 oracle，跑 `cargo test -p parser`（本身是一次 `CodeExecuting` 的 `ToolIntent` -> `EffectProposal`，在隔离 no-egress cell 中执行）。改动前失败、改动后通过 -> `MustFlipToPass` 满足，`Acceptance` 全体 check 通过。
-> 落事件：`Phase { Verify }`、`ToolDone`、最终 `Done { outcome: "success" }`。

**这条往返里 seam 做了什么，值得点明**：

1. trust 单调不升：operator `Trusted` 与仓库 `Untrusted`/`Workspace` 段全程分层，指令文本没有变成 authority。
2. capability 单调收紧：`ceiling` 封顶一切下游提议；gate 是唯一裁决点；broker 是唯一 effect 出口。
3. 每一次跨接缝的提议都留下一条 EQ 事件，使整条 run 是**完整、可 replay、可归属**的记录：这也是 evolution 的 held-out 评估能信任其输入的原因。
4. 产物只以 `ArtifactRef` 出境，content-addressed 且 provenance 可追：补丁、checkpoint、（若本 run 被采样进 evolution）trajectory，都是同一套句柄。

**与"生产级编码 agent 的特性如何落进本系统"的对应**：一个成熟编码 agent 的能力，在这套 ABI 里**逐项**有归属：上下文压缩/检索 = `context` slot 经 `ContextRequest`；多步计划与子任务扇出 = `planner` / `collaboration` slot；工具选择与参数（含 `bash`）= `tool_policy` slot 经 `ToolIntent`；模型路由 = `model_router` slot；自检/择优 = `verifier` slot 经 `Acceptance`。**这些全是接缝背后可进化的实现**；而它们能做什么的**授权**：capability gate、effect broker、durable 记录、rollback：恒在冻结的 microkernel 里。特性演进改的是 slot 实现，产物是 PolicyManifest；接口，不变。

---

### 4.5 本节的规范性小结

- 一个 strategy module **MUST** 只通过五个契约（`TaskEnvelope`、`ContextRequest`、`ToolIntent`、`EffectProposal`、`ArtifactRef`）与系统交互；它 **MUST NOT** 直接调用 kernel 内部、直接调用其他 module、或自行产生对外 effect。
- 五契约的**形状**在一个 `PROTOCOL_VERSION` 内 **MUST** 不可变；演进 **MUST** 只改变 slot 背后的实现（产出 PolicyManifest），**MUST NOT** 在运行中改变任何契约的字段、tag 或语义。
- 一次 run **MUST** 钉死恰好一个 `PROTOCOL_VERSION`；版本 skew **MUST** 被硬拒。
- 契约演化 **MUST** 是 additive-only：未知项降级为 `Unknown`；破坏性新语义 **MUST** 走新顶层 tag；追加字段 **MUST** 是 `Option` 且 `None` 保持旧线格式字节兼容。
- 任何契约值 **MUST** 携带其 `trust` 与（对 effecting 路径）`capability`；二者 **MUST** 单调、deny-by-default，且 **MUST NOT** 因文本内容或合并而被升高。
- 新增一个 vertical slot（如 `db/query_planner`）**MAY** 在不触碰 microkernel 的前提下完成，前提是它讲当前 ABI 的五契约。

> **诚实状态（pre-alpha）**：本节描述的是 ABI 的**目标形状**与其稳定性契约。当前实现是一个运行中的 modular monolith：`ToolIntent`、`EffectProposal` 已有成熟种子（`tool.rs`、`event.rs`），`ArtifactRef` 的种子分散在 `FileDiff` 与 `Checkpoint`，`TaskEnvelope` 与 `ContextRequest` 的 request 侧仍在收敛；kernel 目前仍硬依赖若干具体 crate，部分 effect 尚未完全收束到单一 broker。线上自进化激活为明确 NO-GO。上述规范性陈述是**承重的方向**，不是"已交付"的声明。
