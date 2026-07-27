## 0. 约定与术语 (Conventions & Terminology)

### 0.1 规范性语言 (Normative Language)

本规范中的关键词 **MUST**、**MUST NOT**、**SHOULD**、**SHOULD NOT**、**MAY** 按 RFC 2119 / RFC 8174 解释，且仅当以此加粗大写形式出现时才具有规范性含义。

- **MUST / MUST NOT**：绝对要求 / 绝对禁止。任何声称符合本规范的实现（见 §14 一致性）必须满足。
- **SHOULD / SHOULD NOT**：强烈建议 / 强烈不建议；偏离时须有明确、可记录的理由。
- **MAY**：可选项，不构成一致性要求。

非加粗的「应」「可以」「需要」等词为叙述性说明，不具规范性含义。

### 0.2 术语表 (Glossary)

本表定义全文使用的规范性术语；后续各节 **MUST** 与此表一致，不得引入同义异名。

| 术语 | 定义 |
|---|---|
| **微内核 / TCB (microkernel / Trusted Computing Base)** | 被**冻结**、不参与优化的最小可信基。它拥有并且**仅**拥有 §3 枚举的那组职责；其「负空间」（内核绝不做的事）是本规范可审计的核心安全断言。 |
| **可信计算基 (Trusted Computing Base)** | 同「微内核 / TCB」；全文统一以「微内核」或「TCB」指代，不使用其他译名。 |
| **capability admission（能力准入）** | 微内核中的纯逻辑判定：给定一个 candidate 的申请能力，判定其是否被允许。规则为 **交集**（candidate 授权 = subset(该 slot ceiling  INTERSECT  其确切父辈 ceiling)），**只做交集、永不做并集（"never union"）**，因此授权在晋升下**单调不增（capability-monotone）**。准入是一个纯策略边界，本身**不授予**任何能力。 |
| **effect broker（副作用中枢）** | 微内核中唯一的对外副作用出口。一切外部可见副作用（写文件、执行命令、调用外部服务、网络出口等）**MUST** 经由它，被赋予持久身份与终态；崩溃后一个未知终态**不得**被自动重放。全文统一用英文「effect broker」，不使用「效果代理」。 |
| **pure reducer（纯归约器）** | 微内核中的确定性状态归约：`reduce(state, command) -> (state, Vec<ActionRequest>)`，**无任何 I/O**。它决定「下一步要发起哪些动作」，但不亲自执行。 |
| **agent-loop driver（回路驱动）** | 微内核中把 reducer 产出的 ActionRequest 通过 effect broker 执行的最薄执行体；它只调度，不含策略。 |
| **record / checkpoint / replay** | 微内核中的证据面：一条 append-only、SHA-256 哈希链、防篡改、可崩溃重演、可 resume/continue/fork 的规范记录。 |
| **稳定类型 ABI (Stable Typed ABI)** | 微内核与策略模块之间唯一的通信契约，由五个类型构成：**TaskEnvelope**、**ContextRequest**、**ToolIntent**、**EffectProposal**、**ArtifactRef**。ABI 是**版本化且稳定**的（见 §0.3 与 §4）。 |
| **StrategySlot（策略槽）** | 可进化策略空间的元素。类型为**开放命名字符串**（open namespaced-string），非封闭枚举。九个核心槽：`router`、`planner`、`context`、`memory`、`scheduler`、`tool_policy`、`verifier`、`model_router`、`collaboration`。垂类包 MAY 增加自有槽（如 `db/query_planner`），且**不触碰微内核**。另有一个 code-valued 逃生槽，带 blob->typed 的晋升路径。 |
| **策略模块 (strategy module)** | 实现某个 StrategySlot 的可替换、可进化组件；它返回**有界的提议**并接收**能力受限的结果**，**MUST NOT** 持有环境权威。 |
| **世界模块 (world module)** | 位于 effect broker **之后**、真正实施某类副作用的可替换组件（如 sandbox 执行、仓库读写、浏览器、数据库适配）。它在 effect broker 的能力受限句柄下执行，本身不持有环境权威。世界模块是「机制面」的实现载体，区别于「策略面」的 strategy module。 |
| **harness checkpoint / PolicyManifest** | 一套 harness 被训练出来的状态的一等制品：**方法无关**（搜索/GEPA、SFT、偏好、GRPO、RL 均发射同一形状）、**可版本化、可 diff**、被独立评估、像发布一样晋升/回滚、可跨冻结基座模型携带。其代数：diff、merge、restrict、retire、transfer。全文可用「harness checkpoint」作口语句柄，`PolicyManifest` 为其正式类型名。 |
| **candidate producer（候选产出器）** | 消费受治理数据集、以某种方法产出一个 candidate PolicyManifest 并送入 admission 的离线组件；它**没有** eval/loader/registry/runtime/activation 句柄。 |
| **independent evaluator（独立评估器）** | 与 producer 分离、独立密钥的评估身份；它在垂类拥有的 held-out 目标上对 candidate 打分并签名。producer **结构上无法伪造**该签名，因此不能自证晋升。 |
| **进化管线 (evolution pipeline)** | 离线、非权威、人类把关的晋升流水线：trajectory -> 受治理数据集 -> candidate producer -> PolicyManifest -> admission -> 独立 held-out 评估 -> shadow -> canary -> active，带确定性回滚。**不随开源基座一同开源**。 |
| **五条不变量 (Five Invariants)** | Bounded（有界）、Recoverable（可恢复）、Reproducible（可复现）、Observable（可观测）、Security-bounded（安全有界，deny-by-default）。本规范任一机制 **MUST** 同时满足。 |
| **三面 (Three Planes)** | 固定的微内核 TCB／可替换的策略与世界模块／离线的进化控制面。 |
| **垂类包 (vertical pack)** | 针对某一垂类的一组 StrategySlot 取值（含自加槽）与配置，编译为一个 PolicyManifest。 |

### 0.3 两个贯穿全文的规范性结论 (Canonical Resolutions)

为避免同一结论以多种措辞散落各处，以下两条在此给出**规范性正本**；全文他处的相关表述均以本节为准。

**R1：bash 与工具的归属。** 微内核 **MUST** 只拥有 **effect broker + capability admission**，即「任何工具（含 bash）被允许做什么」的**权威**。工具的**选择与策略**（用哪个工具、以什么参数、按垂类调优）是可进化的 **`tool_policy` 策略槽**。因此 bash 是一个其副作用经微内核中介与准入的**工具**，而**不是**内核内部的逻辑。任何「必须改内核接口才能加某个工具」的诉求，几乎总是一次安置错误（把机制面误当成权威面）。

**R2：成熟形态 vs 早期切片。** 成熟形态（覆盖度与业界生产级 coding agent 同量级）是**前瞻性定位**，**MUST NOT** 被用来描述任何早期演示切片的工作量。早期切片是一条薄的垂直切片（单一垂类、单一冻结模型、少数几个槽被训练）。二者的口径在本规范中**严格分开**（公开侧只谈成熟形态的目标边界；内部侧 §8 给出切片范围）。

**关于「是否训练 model」（规范性正本）。** 默认 **MUST NOT** 训练 model：主路径是在**冻结**的 base model 之上进化 harness，以求得 model×harness 协同设计之*效*（可移植、model 无关）；harness 会自适应该 model 的能力，**包括**其 post-training 引入的标记/能力（例如某个 `ultracode` 之类的标记）。当确需改权重时，curated 轨迹与 harness checkpoint **MAY** 作为 post-training 语料回流，但 **MUST** 重新经过 §6 的同一道 admission 与评测门。即：训练可发生在两侧，但 harness 是那个恒可用、可移植、model 无关的一侧；本规范的主张不依赖训练 model。

**关于「ABI 在进化中是否改变」（规范性正本，正文见 §4）。** 稳定类型 ABI 的**形状**在一次运行内与跨进化过程中 **MUST NOT** 改变；进化改变的是 ABI **之后**的模块**实现**（PolicyManifest 的内容），而非 ABI 契约本身。ABI 的演进只走显式的版本化路径（§16 变更控制）。
