# 5. 策略模块与可进化槽 (Strategy Modules & Evolvable Slots)

§3 冻结了微内核，§4 冻结了五个 typed 契约。本节回答余下的那一半问题：**被冻结的接缝背后坐着什么、kernel 通过什么调用它、以及它凭什么可以被整个换掉而无需重新审计权限。** 答案是 **strategy slot**：一个具名的决策点，kernel 经由一个注入端口 (injected port) 调用它；它自己不持有授权，也不接触外部世界。

本节给出该端口的规范定义（§5.1 trait、§5.2 身份文法、§5.3 观测与决策的载体、§5.4 收窄契约）、九个跨垂类核心槽（§5.5）、一条槽在运行时如何绑定到一条 policy（§5.6），最后是诚实的现状陈述（§5.7）。本节所有 MUST / SHOULD / MAY 按 RFC-2119 解读。

> **口径 (R2)。** 本节规定的是 slot 空间的**目标形态**。九条核心槽**都已有生产实现并在合成根装配**（逐条见 §5.7）；尚未落地的是把一条槽**换掉**的那条链路——晋升、签名、回滚（§6）。被冻结的是端口，不是端口后面坐着的东西。

### 5.1 一个 slot 是什么：一个注入端口，不是一个子系统

```rust
// crates/protocol/src/slot.rs:140-150
pub trait StrategySlot: Send + Sync {
    /// 这个实现对应哪个槽。
    fn slot(&self) -> &SlotId;

    /// 只依据调用方已经收集好的东西做决策。
    fn decide(&self, observation: &SlotObservation) -> SlotOutcome;
}
```

整个端口就是这两个方法，**没有第三个**。三处刻意的缺席各自是一条规范约束：

- **同步，没有 `async`。**（`crates/protocol/src/slot.rs:31-42`）kernel 本身是 async 的，但把 trait 方法变成 async 不是免费的：要么引入 `async_trait`（热路径上每次调用一次装箱分配），要么引入关联 future 类型（使该 trait 难以作为 `dyn` 存放）。因此端口被定型为**在已收集好的输入之上同步求值**；需要 await 的 slot 是调用方一侧的问题，不是签名的问题。
- **一个 slot MUST NOT 执行 I/O。**（`crates/protocol/src/slot.rs:41`）这是一条真实约束而非偏好：I/O 由调用方完成，其结果作为 `SlotObservation` 交给 slot。正因为 slot 够不着任何环境权限 (ambient authority)，替换一条 slot 才不需要重新审计它能碰到什么。
- **不返回 `Result`。** 一次 slot 调用在类型上不会失败。实现因此 MUST 把「我没有可用判断」表达成一个**值**（例如一条空的 `decision` 配上 `CapabilitySet::none()`；`crates/protocol/src/capability_set.rs:56`），MUST NOT 用 panic 代替错误。

`Send + Sync` 与对象安全 (object safety) 同样是契约的一部分：composition root 需要把实现存成 `Arc<dyn StrategySlot>` 并跨 await 点持有（`crates/protocol/src/slot.rs:136-139`，对象安全由 `crates/protocol/src/slot.rs:267-272` 的测试钉住）。

### 5.2 槽身份：`SlotId`，以及两个都叫 StrategySlot 的类型

```rust
// crates/protocol/src/slot.rs:58-60
#[serde(transparent)]
pub struct SlotId(pub String);
```

文法由 `SlotId::validate` 强制（`crates/protocol/src/slot.rs:68-87`），且**只**有这三条：长度 1..=128 字节（`MAX_SLOT_ID_BYTES`，`crates/protocol/src/slot.rs:48`）；**恰好一个** `/`，且两侧均非空；除该 `/` 外只允许 `[a-z0-9_-]`。大写被**拒绝**而非规范化（`crates/protocol/src/slot.rs:64-67`）：规范化会让两个此处不相等的 `SlotId` 在持久化后相撞，把身份变成近似身份。**词表是开放的，文法不是**：`core/tool_policy` 与 `acme-verticals/triage_router` 同样合法，kernel 不枚举它们，所以**加一个槽不是一次 kernel 变更**。一个**无前缀**的名字（如 `router`）不是可构造的槽身份。线格式是一个裸字符串 `"core/context"`（`#[serde(transparent)]`；快照见 `crates/protocol/tests/abi_freeze.rs:661-662`）。

**两个都叫 StrategySlot 的类型，必须分清。**（`crates/protocol/src/slot.rs:3-11`）

| 类型 | 位置 | 是什么 |
|---|---|---|
| `StrategySlot`（trait） | `crates/protocol/src/slot.rs:140` | kernel 调用的**端口**：「kernel 调的是什么」 |
| `iteron_evolve::StrategySlot`（newtype） | `crates/evolve/src/lib.rs:131` | policy bundle 里持久化的**身份**：「这个制品是给哪个槽的」 |

`SlotId` 是在二者之间穿行的那个身份。两侧文法**并不相等**，而且不等有方向（`crates/protocol/src/slot.rs:13-29`）：evolve 侧接受 `[a-z0-9/_.-]`、任意个 `/`（不以 `/` 开头或结尾、不含 `//`）、<=128 字节（`crates/evolve/src/lib.rs:133-150`），因此 `db/query.planner` 与 `acme/billing/router` 在 evolve 侧合法而在 kernel 侧非法，`Acme/Router` 则两侧都非法。规范约束是一条**严格子集**关系：

> 每一个合法的 `SlotId` **MUST** 是一个合法的 `iteron_evolve::StrategySlot`；反向 **MUST NOT** 被假定成立。

方向不可颠倒：bundle 指向一个 kernel 没有的槽是惰性的、无害的；kernel 拥有一个任何 bundle 都无法命名的槽，则是一个不可治理的空洞（那条槽会静默回落到内建策略，且没有任何东西报告这件事）。因此一条 bundle 条目若命名了本侧无法表达的槽，**MUST** 被拒（`BundleResolutionError::UnrepresentableSlot`，`crates/protocol/src/bundle.rs:171`），**MUST NOT** 被静默丢弃。

### 5.3 决策的输入与输出：`SlotObservation` / `SlotOutcome`

```rust
// crates/protocol/src/slot.rs:113-121
pub struct SlotObservation {
    pub slot: SlotId,               // 在问哪个槽
    pub ceiling: CapabilitySet,     // 当前生效的授权上界；slot 可在其内收窄，永不可扩张
    pub payload: serde_json::Value, // 调用方已收集好的、决策所针对的载荷
}

// crates/protocol/src/slot.rs:128-134
pub struct SlotOutcome {
    pub admitted: CapabilitySet,     // 本次决策所准入的授权，已收窄
    pub decision: serde_json::Value, // slot 的结构化决策，由调用方解释
}
```

规范性约束：

- **observation 就是一条 slot 能看到的全部世界。**（`crates/protocol/src/slot.rs:108-109`）调用方收集它，slot **MUST NOT** 自行伸手去取任何别的东西。
- **`ceiling` 与 `admitted` MUST 是 `CapabilitySet`，即一个集合，而不是某个序上的点。**（`crates/protocol/src/capability_set.rs:1-19`、`crates/protocol/src/capability_set.rs:52`）该类型**唯一的组合操作**是 `intersect`（`crates/protocol/src/capability_set.rs:79-84`），判断用 `contains` 与 `is_subset_of`（`crates/protocol/src/capability_set.rs:75`、`crates/protocol/src/capability_set.rs:87`，后者正是用来代替 `<=` 的）；**刻意不提供** union、`max` 与 `Ord`：扩张授权在类型上不可表达。
- **`payload` 与 `decision` 是 `serde_json::Value`，这是刻意的。** 每条 slot 各自的载荷与决策 DTO 形状是**该 slot 本地的、自行版本化的**，**不属于 ABI**；被冻结的只有信封本身，即 `{slot, ceiling, payload}` 与 `{admitted, decision}` 这两组字段名（快照见 `crates/protocol/tests/abi_freeze.rs:536-543`）。
- 两个结构体**持有**而非借用其字段：记录边界拒绝任何泛型（含生命周期），因为借用字段无法被序列化进该边界所要保证的持久记录（`crates/protocol/src/slot.rs:110-112`）。
- `SlotObservation` **不带** `Trust` 字段。trust 随数据本身流动（context segment 与 tool 参数，见 §4），不由槽的观测信封携带。

### 5.4 收窄契约：`decide_narrowed`

「slot 不得扩张授权」如果只写在文档注释里，就是一条每个实现者都必须自行记住的规矩。它因此被做成了一个函数：

```rust
// crates/protocol/src/slot.rs:156-162
pub fn decide_narrowed(slot: &dyn StrategySlot, observation: &SlotObservation) -> SlotOutcome {
    let outcome = slot.decide(observation);
    SlotOutcome {
        admitted: outcome.admitted.intersect(observation.ceiling),
        decision: outcome.decision,
    }
}
```

实现者 **MUST NOT** 执行 I/O，也 **MUST NOT** 返回超出 `observation.ceiling` 的授权；而调用方 **SHOULD** 经由 `decide_narrowed` 调用 slot，而不是直接调 `decide`，因为只有前者会替每一个实现强制第二条（`crates/protocol/src/slot.rs:146-148`）。由此得到的性质与实现者的品行无关：**slot 是一条 policy，永远不是授权的来源**（`crates/protocol/src/slot.rs:125-127`）。仓库里用一个**故意越权**的测试替身证明这一点：它对每次观测都索要 `{ReadOnly, CodeExecuting, IrreversibleExternal}`，而当上界为 `{ReadOnly}` 时，收窄后的结果只剩 `ReadOnly`（`crates/protocol/src/slot.rs:171-206`）。

### 5.5 九个核心槽

九个 well-known 核心槽构成跨垂类的基线，其身份由 `crates/evolve/src/lib.rs:156-182` 的九个构造器铸造：

| Slot | 决策 | 基本形态（可训练 / 可调） | 与 kernel 的交互 | 例子 |
|---|---|---|---|---|
| `core/router` | 把任务或子任务路由到哪条处理路径 | 分类 / 打分策略 | 只读观察，产出 `ToolIntent` 或子任务，经 driver | 把「改一个 typo」直接路由到 quick-edit，而非 full plan |
| `core/planner` | 把任务分解为步骤 | 规划策略（prompt / adapter / search） | 产出计划，不直接产生 effect | 把「加一个 API endpoint」拆成 定位、改路由、加测试 |
| `core/context` | 选择投喂给 model 的上下文 | 检索 / 裁剪 / 排序策略 | 发 `ContextRequest`，由 kernel 返回受约束的 `ContextGrant` | 只召回被改文件的调用点，而非整仓 |
| `core/memory` | 何时写、何时读长期记忆 | 记忆读写策略 | 经 ABI，不直连存储 | 记住「本仓库用 pnpm 不用 npm」 |
| `core/scheduler` | 并发或串行、预算分配 | 调度策略 | 在 kernel 的预算与 deadline 之下运作 | 三个独立文件并行改，verify 串行 |
| `core/tool_policy` | **选哪个工具、带什么参数**（见 R1） | 工具选择与参数策略 | 产出 `ToolIntent`；effect 由 broker 仲裁与准入 | 选 `rg` 而非 `grep -r`；给 bash 的确切命令行 |
| `core/verifier` | 如何自检产出 | 验证策略 / 自建 verifier | 产出验证请求 | 改完先跑受影响的 test 子集 |
| `core/model_router` | 选哪个 base model 或哪一档 | 模型选择策略 | 只做选择，不改 model | 简单编辑走小模型，难 bug 走强模型 |
| `core/collaboration` | 多 agent 协作与移交 | 协作策略 | 经 ABI 移交 | 把「写文档」移交给 doc 子 agent |

（注意 R2 口径：本表描述成熟形态的功能全集；早期演示切片只做穿过其中一条薄纵切）

命名空间是开放的：一个垂类包 MAY 在自己的前缀下新增槽（如 `db/query_planner`、`support/escalation_router`）而**完全不触碰微内核**。新增能力 = 新增槽 + 新增 policy，永不 = 修改内核。自由形态的产出（生成代码或 graph）经由一个 code-valued 逃生槽与一条 blob 到 typed 的晋升路径被收编进同一个空间，见 §6.2。§6.2 从进化的角度复述本表，槽的定义以本节为准。

### 5.6 一条槽如何在运行时绑定到一条 policy

一条槽由哪条 policy 治理，取决于**运行时生效的 policy bundle**；该 bundle 在 boot 时经一个只读接缝取得一次：

```rust
// crates/protocol/src/bundle.rs:206-213
pub trait PolicyBundleResolver: Send + Sync {
    fn active_bundle(&self) -> Result<Option<ResolvedBundle>, BundleResolutionError>;
}

// crates/protocol/src/bundle.rs:56-69 与 crates/protocol/src/bundle.rs:80-85
pub struct ResolvedPolicy { pub slot: SlotId, pub policy_id: String, pub version: String, pub digest: String }
pub struct ResolvedBundle { pub bundle_id: String, pub digest: String, pub policies: Vec<ResolvedPolicy> }
```

规范性约束：

- 该视图只携带**身份**（槽、policy_id、version、64 位小写 hex digest），**从不携带 policy 本体**；PolicyManifest 本身见 §6。
- 这里**刻意没有**任何「设置当前 bundle」的方法：晋升是人工门控的，只存在于进化侧（`crates/protocol/src/bundle.rs:204-205`）。
- `Ok(None)` 表示没有生效的 bundle、内建策略生效，这是**正常状态而非错误**；调用方 **MUST NOT** 把 `Err(..)` 折叠进这个分支（`crates/protocol/src/bundle.rs:209-212`）。
- 同一个槽被命名两次 **MUST** 被拒（`DuplicateSlot`，`crates/protocol/src/bundle.rs:173`），**MUST NOT** 用 first-wins 或 last-wins 悄悄化解：否则运行记录说不清究竟哪条 policy 在治理它。一次 bundle 至多 128 条（`MAX_RESOLVED_BUNDLE_POLICIES`，`crates/protocol/src/bundle.rs:46`）。
- 查询用 `ResolvedBundle::governs` 与 `ResolvedBundle::policy_for`（`crates/protocol/src/bundle.rs:92-99`）：它们是对「已经给出的那个答案」的纯查询，不会二次询问 resolver，因此不可能与它所描述的 bundle 不一致。

### 5.7 诚实的现状 (R2)

**九条核心槽都已有生产实现，并在合成根被真实装配。** 本段此前称「今天仓库里没有一条生产用的 slot、唯一实现是测试替身 `Greedy`、没有任何生产代码构造 `Arc<dyn StrategySlot>`」——**这三句都已不再成立**，是实现推进后未同步更新的陈述。现状是：

| Slot | 生产实现 |
|---|---|
| `core/router` | `crates/agents/src/decompose.rs` `RouterStrategy` |
| `core/planner` | `crates/agents/src/planner.rs` `PlannerStrategy` |
| `core/context` | `crates/ctx/src/context_strategy.rs` `ContextStrategy` |
| `core/memory` | `crates/ctx/src/memory.rs` `MemoryRecallStrategy` |
| `core/scheduler` | `crates/sched/src/strategy.rs` `SchedulerStrategy` |
| `core/tool_policy` | `crates/tools/src/tool_policy.rs` `ToolPolicy` |
| `core/verifier` | `crates/verify/src/strategy.rs` `VerifierStrategy` |
| `core/model_router` | `crates/provider/src/catalog.rs` `ModelRouterStrategy` |
| `core/collaboration` | `crates/workflow/src/collaboration.rs` `CollaborationStrategy` |

九者由 `crates/cli/src/bundle_adapter/strategies.rs` 的 `CompiledSlots` 持成 `Arc<dyn StrategySlot>`，经 `crates/cli/src/runtime/agent_config.rs` 进入 Agent 并由子代理继承；每个域都经 `decide_narrowed` 调用。绑定与身份由 `crates/cli/src/bundle_adapter/strategies.rs` 的两条 conformance 测试钉死，其中一条把 §5.4 的收窄契约**在这九条生产实现上**而非仅在测试替身上验证。

**仍然只是目标契约的部分：** `crates/evolve/src/lib.rs` 的九个构造器铸造的仍是**身份**而非实现；一条槽被外部 policy bundle **替换**掉的完整链路（晋升、签名、回滚）属 §6，尚未打通。因此本节的端口语义是已交付的，晋升语义不是。

**被冻结的东西要说清楚。** 冻结的是端口本身、两个载荷信封的字段集（`crates/protocol/tests/abi_freeze.rs:536-543`），以及 `SlotId` 的文法与它相对 evolve 侧的子集方向。**没有**被冻结的是：任何一条槽的 `payload` / `decision` 具体形状（它们是 `serde_json::Value`，本地定义、本地版本化，跨槽不通用），以及任何一条 policy 的内容。

**签名变更的路径是明示的。** 若将来某条 slot 确实必须做 I/O 或必须 await，那是一次**签名变更**：MUST 与它的第一个真实调用方一起被显式提出（`crates/protocol/src/slot.rs:40-42`），并走 §16 的变更控制；MUST NOT 靠在某个实现里偷偷做 I/O 来绕过。
