# 6. 进化边界与 Harness Checkpoint (Evolution Boundary & PolicyManifest)

前面几节确立了两条不变量:microkernel 是冻结的 TCB,ABI(TaskEnvelope / ContextRequest / ToolIntent / EffectProposal / ArtifactRef)是稳定的类型边界。本节回答由此产生的核心问题:**在这个冻结的骨架之上,到底什么在进化,以什么形式沉淀,又如何安全地上线。** 这三问分别由类型(§6.1 至 §6.4)、流水线(§6.5)、门控(§6.6 至 §6.8)三组规范回答。

Iteron 的定位可以压成一句:**特化一个 agent 意味着训练 harness,而不是训练 model。** 每一个非 kernel 的决策都是某个 typed policy space 里的一条 policy;它被训练出来的状态是一等公民,我们称之为 **harness checkpoint**,其具体类型是 `PolicyManifest`。它由任意训练方法(search/GEPA、SFT、preference、GRPO、RL)以**同一种形式**产出,由一个**独立的 evaluator** 在 vertical 自持的 held-out 目标上打分,像 release 一样被 promote 与 rollback,并能跨冻结的 base model 携带。一句话:**weights 学的是 prior,harness 学的是 situation。** 权重沉淀通用先验,harness checkpoint 沉淀某个 vertical 的具体情境(私有轨迹、人工纠正、工具清单、自持 verifier);这些信号对每一个 base model 都天然是 out-of-distribution 的,而且刷新速度快于任何模型发布周期。

本节的规范性内容围绕以下六件事展开:harness checkpoint 的类型(§6.1)、可进化的 typed policy space(§6.2)、方法无关性与模型的关系(§6.3)、checkpoint algebra(§6.4)、离线非权威的进化流水线(§6.5)、capability-monotone admission 与独立 evaluator(§6.6 与 §6.7),最后是进化边界的硬约束、open-substrate/closed-pipeline 拆分,以及诚实的现状披露(§6.8 至 §6.10)。

> **术语锚定。** 本节所有类型名与 `crates/evolve` 一一对应:`StrategySlot`、`PolicyManifest`、`PolicyRef`、`PolicyBundle`、`EvolutionMethod`、`ArtifactKind`、`DeploymentStage`、`ManifestAdmissionPolicy`/`CapabilityAdmission`/`EffectiveCapabilities`、`IndependentEvaluator`/`HeldOutEvaluation`、`PromotionGate`(非权威建议)与 `PromotionAuthority`(离线执行权威)。这些是契约与离线评估器,**不是**运行时 TCB 的一部分。

---

### 6.1 Harness Checkpoint 的类型定义:`PolicyManifest`

harness checkpoint 是对 `StrategySlot` ABI 上一条 policy 的**已训练状态**的一次不可变、可版本、可 diff 的快照。它的载体类型是 `PolicyManifest`。不可变意味着一个已发布的 manifest 的字节永不被原地修改;任何变化都表现为一条新的 `PolicyRef`(见下)。可版本意味着它带 `schema_version` 与语义化 `version`。可 diff 意味着两个 manifest 之间的差异是结构化、slot 级可归因的(见 §6.4)。

一个 `PolicyManifest` MUST 携带下列字段(与 in-repo 契约逐字段对应):

| 字段 | 类型 | 含义 | 规范性 |
|---|---|---|---|
| `schema_version` | `u16` | 契约版本,当前为 3 | MUST 等于运行时支持版本;加载器只迁移 N-1,拒绝其余(§6.4 载入语义) |
| `policy` | `PolicyRef` | 不可变身份 = `{slot, policy_id, version, digest}` | `digest` MUST 为 artifact 字节的 SHA-256(64 位小写 hex),**不是** mutable URL |
| `artifact_kind` | `ArtifactKind` | 实现形态:`Rules`/`Prompt`/`WasmComponent`/`ModelAdapter`/`ModelWeights`/`ExternalService`/`Builtin`/`GeneratedCode` | manifest **绝不是**把任意 native code 载入 kernel 的许可 |
| `artifact_locator` | `String`(<=2048B) | artifact 字节的定位符 | MUST 非空;超长触发 `LocatorTooLong` |
| `parent` | `Option<PolicyRef>` | 精确父策略身份(用于 lineage 与 admission) | root candidate 为 `None` |
| `method` | `EvolutionMethod` | 如何产出(见 §6.3) | **promotion 语义故意不依赖此字段** |
| `protocol` | `ProtocolRange {min,max}` | 兼容的 ABI 协议区间 | MUST 非倒置(`min <= max`,否则 `InvertedProtocolRange`) |
| `required_capabilities` | `BTreeSet<Capability>` | 声明其运行需要的能力(五个独立 `Capability` 类构成的一个集合) | candidate 只能**声明**,不能**授予**(§6.6) |
| `training_dataset_digest` | `Option<String>` | governed dataset 的 digest | 任何 data-derived method MUST 钉死;仅 `HandAuthored` 可为空 |
| `evaluation_suite_digest` | `String` | 评估套件 digest | MUST 存在(64 位 hex) |
| `base_model` | `BaseModelId` | 该 policy 所依据的冻结基座模型(family / id / digest) | schema 3 起 MUST 存在且有界;由 schema 2 迁移而来的文档携带 `BaseModelId::unspecified()` 哨兵,well-formed 但永不 admissible。**`model_digest` MUST 是规范 64 位小写 hex**,与本 crate 其他 digest 同规;三个分量均 MUST NOT 含控制字符。缺失该字段 MUST 拒收,MUST NOT 默认为哨兵 —— 哨兵只属于诚实声明自己是 schema 2 的文档 |

字段类型约束定义了失败模式的完整集合。`slot` 违反命名规则触发 `InvalidSlot`;任一 digest 非规范 64 位小写 hex 触发 `MalformedDigest`;learned method 缺 `training_dataset_digest` 触发 `MissingTrainingDataset`。这些错误在反序列化边界即被拒,fail-closed;一个无法通过 `validate` 的 manifest 永远进不到 admission。

**worked example: 一个 GRPO 产出的 planner checkpoint。** 下面的 JSON 是一条合法 manifest 的骨架:

```json
{
  "schema_version": 3,
  "policy": { "slot": "iteron/planner", "policy_id": "planner-grpo",
              "version": "1.4.0", "digest": "3f9a…(64 hex)" },
  "artifact_kind": "model_adapter",
  "artifact_locator": "registry://planner-grpo@1.4.0",
  "parent": { "slot": "iteron/planner", "policy_id": "planner-sft", "version": "1.3.0", "digest": "…" },
  "method": "grpo",
  "protocol": { "min": 1, "max": 1 },
  "required_capabilities": ["read_only"],
  "training_dataset_digest": "a17c…(64 hex)",
  "evaluation_suite_digest": "b820…(64 hex)",
  "base_model": { "model_family": "example-family", "model_id": "example-base-1", "model_digest": "c04e…(64 hex)" }
}
```

**worked example: 一条被拒的 manifest。** 若上例把 `method` 改为 `grpo` 却把 `training_dataset_digest` 置为 `null`,`validate` 立即返回 `MissingTrainingDataset` 并拒绝整条 manifest;若把 `policy.slot` 写成 `/core/planner`(前导 `/`),返回 `InvalidSlot`;若把 `protocol` 写成 `{min:2,max:1}`,返回 `InvertedProtocolRange`。三者都在进入流水线之前失败,不消耗任何评估预算。

契约层的校验(`PolicyManifest::validate`)会强制:learned method 必须钉死 `training_dataset_digest`,`slot` 必须是合法 namespace,所有 digest 必须是规范 hex。注意契约层**只校验编码与边界**;它不重算 digest、不检测 train/eval 重叠、不认证 producer。那三件事是未来 evolution TCB 与独立 evaluator 的职责(§6.6 与 §6.7)。这是"深度防御在有边界的反序列化器之后"的一贯风格,而非把校验当作授权:通过 `validate` 只证明这条 manifest 语法自洽,**不**证明它可信、可晋升、或可运行。

**为什么它是一个"checkpoint"而不是一个 config bag。** 让 `PolicyManifest` 成为一个参数空间里的点、而非松散配置,是三件事共同保证的:(1) 一个**共享目标**,所有 slot 对齐到同一个 vertical 自持的 held-out objective;(2) **slot 级归因**,checkpoint diff 能把 held-out delta 拆到每个 slot(§6.4);(3) **typed admission**,每条 candidate 的权限被 §6.6 的 lattice 约束。有了这三者,"训练 harness"才从手艺(heuristic craft)变成一门**系统工程学科**:一个在 typed policy space 上、针对 held-out 目标的优化问题。

---

### 6.2 什么在进化:the typed policy space Θ_H (`StrategySlot` ABI)

什么是可进化的,答案是精确的:**除 microkernel 外的每一个决策点都是一条 policy,住在一个 kernel 稳定化的 typed 命名空间里。** 这个命名空间就是 `StrategySlot`。

可扩展性由开放命名空间保证。`StrategySlot` **MUST** 是一个开放的、namespaced 的**字符串类型**,而**不是**封闭 enum。这是刻意的:一个 vertical pack MUST 能新增自己的 slot(如 `db/query_planner`、`support/escalation_router`)而**完全不触碰 microkernel**。命名规则由 smart constructor 强制:小写、`[a-z0-9/_.-]`、不以 `/` 开头或结尾、不含 `//`、<=128 字节。任一违反触发 `InvalidSlot`,并在构造点即被拒;因此一个非法 slot 名永远无法进入任何 manifest。若命名空间是封闭 enum,新增 vertical 就必须改 kernel 并重新走 ABI 版本演进,这恰是开放字符串类型要避免的耦合。

有 9 个 **well-known core slots** 构成跨 vertical 的基线:

| Slot | 决策 | 基本形态(可训练/可调) | 与 kernel 的交互 | 例子 |
|---|---|---|---|---|
| `core/router` | 把任务/子任务路由到哪条处理路径 | 分类/打分策略 | 只读观察,产出 `ToolIntent`/子任务,经 driver | 把"改一个 typo"直接路由到 quick-edit,而非 full plan |
| `core/planner` | 把任务分解为步骤 | 规划策略(prompt/adapter/search) | 产出计划,不直接产生 effect | 把"加一个 API endpoint"拆成 定位, 改路由, 加测试 |
| `core/context` | 选择投喂给 model 的上下文 | 检索/裁剪/排序策略 | 发 `ContextRequest`,由 broker/reducer 满足 | 只召回被改文件的调用点,不是整仓 |
| `core/memory` | 何时写/读长期记忆 | 记忆读写策略 | 经 ABI,不直连存储 | 记住"本仓库用 pnpm 不用 npm" |
| `core/scheduler` | 并发/串行、预算分配 | 调度策略 | 在 kernel 预算/deadline 下运作 | 三个独立文件并行改,verify 串行 |
| `core/tool_policy` | **选哪个工具、带什么参数**(见 R1) | 工具选择与参数策略 | 产出 `ToolIntent`;effect 由 broker 仲裁与 admit | 选 `rg` 而非 `grep -r`;给 bash 的确切命令行 |
| `core/verifier` | 如何自检产出 | 验证策略/自建 verifier | 产出验证请求 | 改完先跑受影响的 test 子集 |
| `core/model_router` | 选哪个 base model / 档位 | 模型选择策略 | 只做选择,不改 model | 简单编辑走小模型,难 bug 走强模型 |
| `core/collaboration` | 多 agent 协作/移交 | 协作策略 | 经 ABI 移交 | 把"写文档"移交给 doc 子 agent |

**worked example: 一个 vertical pack 新增 slot。** 一个数据库 vertical 需要一个查询计划器决策点。它在自己的 pack 里声明 `db/query_planner`,给出该 slot 的能力天花板(如 `ReadOnly`),并对着该 slot 产出 `PolicyManifest`。microkernel 一行不动,五个 ABI 契约一字不改;新 slot 只是命名空间里多出的一个合法坐标。若该 pack 误写 `db//query_planner`(含 `//`),smart constructor 拒绝,pack 加载失败,fail-closed。

**R1 的落点(bash / tools)。** microkernel **只**拥有 effect broker 加 capability admission,即"任何工具(含 bash)能做什么"的**权威**。而"选哪个工具、带什么参数、每个 vertical 如何调优"是**可进化的 `core/tool_policy` slot**。因此:**bash 是一个工具,它的 effect 被 kernel 仲裁与 admit,但 bash 不是"kernel 里的逻辑"。** `core/tool_policy` 可以学会在某个 vertical 里优先用 `rg`、给测试命令加正确的 flag、避免破坏性命令;这些都是 harness 学到的 situation,kernel 一行不动。换言之,一条 `core/tool_policy` policy 可以**提议**运行 `rm -rf build/`,但该 effect 是否被执行由 effect broker 依据 §6.6 的 `EffectiveCapabilities` 独立裁决:policy 提议,kernel 处置。

**escape-hatch code slot(ADAS 式自由发现的收编)。** 命名空间开放还不够;要让自由形态的架构搜索(ADAS/DGM 式产出 code 或 graph)也能编译**进入**这个空间而非否定它,ABI 定义了一个 **code-valued escape-hatch slot**,其 `artifact_kind` 为 `GeneratedCode` 或 `WasmComponent`,并配一条 **defined blob 到 typed 的 promotion path**:一个自由形态 blob 先作为隔离组件被 admit(受 §6.6 的能力天花板约束,通常从 `ReadOnly` 或 `ReversibleLocal` 起步),经独立评估通过后,再"晋升"为 typed slot 上的一条具名 policy。换言之,最大表达力的发现方法不是这个类型系统的反例,而是它的一个**producer**。(诚实边界:该晋升路径目前是**设计承诺**,尚未有 ADAS 式 artifact 真正 round-trip 进空间,见 §6.10。)

**production coding-agent 的特性如何映射进来。** 一个成熟 coding agent 的典型能力,逐一对应到 slot:多档模型选择映射到 `core/model_router`;子仓/子任务分派映射到 `core/router` 加 `core/collaboration`;仓库级检索与上下文压缩映射到 `core/context`;工具白名单与命令构造映射到 `core/tool_policy`;跑测试/lint 的自检回路映射到 `core/verifier`;"记住项目约定"映射到 `core/memory`。**没有任何一个成为 kernel 逻辑;它们全部是 policy。** kernel 只提供身份、能力仲裁、单一 effect broker、确定性归约、证据链、预算、版本登记、kill/rollback,以及跑归约器动作请求的 bounded driver。这条映射说明"落地一个成熟形态"不需要在 kernel 里长出任何新逻辑:成熟形态是 slot 空间里若干条已训练 policy 的组合,早期切片则可以只填其中一两个 slot(如先只训 `core/tool_policy`),其余 slot 走手写基线。

---

### 6.3 方法无关性,以及进化与 model 的关系(四个核心边界)

**方法无关性(method-agnosticism)是硬约束。** `EvolutionMethod` 枚举了产出方式:`HandAuthored`、`Search`、`ContextualBandit`、`SupervisedFineTune`、`PreferenceOptimization`、`Grpo`、`OfflineRl`、`OnlineRl`、`GeneratedCode`。规范性要求:**promotion 语义 MUST NOT 依赖 `method` 字段。** 一条 GEPA 式反射搜索产出的 prompt policy,与一条 GRPO 产出的 adapter policy,走**完全相同**的 admission, held-out, shadow, canary, active 流水线,用**完全相同**的 `PolicyManifest` 类型。这正是把"九个各自为政的 optimizer"降格为"可互换的 producer"的机制:换一个训练方法,只是换一个填 `PolicyManifest` 的 producer,门控与晋升逻辑一字不改。

进化边界在四个维度上被精确界定:

**(a) 进化不涉及 kernel selection,也不涉及任何运行中的 agent step。** 进化流水线**不选择、不替换、不搜索 kernel**。microkernel 是冻结 TCB;进化只在 `StrategySlot` 空间里产出 candidate。它也不是一个"跑起来的 agent 在自己改自己":candidate producer 是**离线**的,`crates/evolve` 明确"outside the runtime trusted computing base",没有 runtime registry handle、没有 loader,**live self-evolution activation 是 NO-GO**。一个正在服务请求的运行时实例,无法在其自身的关键路径上创建、admit 或激活任何 policy。

**(b) step 1 不训练任何 model weights。** 第一步里,唯一被"训练"的对象是 harness(即 `StrategySlot` 空间里的 policy)。base model 是**冻结**的。harness 会 **co-adapt 到给定的 model**,包括适配该 model 的 post-training 标签:例如某个 model 暴露一个 `ultracode` 之类的 post-training tag 表示"高强度代码推理档位",`core/model_router` / `core/tool_policy` 可以学会在合适场景下打这个 tag。这是"harness 学 situation"的一个具体形态:**不改 model,只学会更好地使用 model。** (作为对比,`ArtifactKind` 里确实保留了 `ModelAdapter`/`ModelWeights` 形态位,以便未来某条 slot policy 的实现恰好是一个 adapter,但那属于后续;step 1 的骨架实验以冻结 model 为基线。)

**(c) 流水线的产出可用于训练 model。** 这是 open-substrate/closed-pipeline 拆分(§6.9)的直接推论。流水线沉淀两类可复用资产:治理过的 **trajectory**(`TrajectoryEnvelope`,内含 `RewardVector` 与 `DataGovernance`)与 **PolicyManifest**。这两类 artifact **MAY** 在后续被喂给 model 的 post-training(SFT/preference/RL 语料)。也就是说,同一批 artifact 在 step 1 用来训 harness,在后续 **OPTIONALLY** 可用来训 model;但这条路径受 §6.6 的 consent/governance 门控(`TrainingConsent::Allowed` 才可转化),且是可选增量,不是 step 1 的前提。越过 recorded consent 把 trajectory 转作 model 训练语料是被禁止的(§6.8)。

**(d) ABI 在进化下不变。** 这是最强的一条边界:进化在冻结的五个 ABI 契约**之上**发生,**从不修改**它们。协议演进走独立的、人控的 version registry 与 N-1 迁移(§6.4),不是进化流水线能触及的。一条 candidate 只能在既有 ABI 的形状内提出动作;它无法新增、删除或改写 TaskEnvelope、ContextRequest、ToolIntent、EffectProposal、ArtifactRef 中的任何一个。进化时 microkernel 接口是否会变,答案是**不会**,这正是 checkpoint 能跨 model、跨版本携带的前提:坐标系不动,坐标系上的点才能被 diff、merge、transfer(§6.4)。

**成本(generic 描述)。** 进化 loop 的成本主要落在**离线**侧且与"每次上线"解耦:producer 的搜索/训练是一次性算力;而 harness 与 context 是会沉淀、增值的资产。规范表述:**计算是一次性的;架构(harness)与上下文(context)才是会沉淀、增值的资产。** admission、证据记录、promotion 引入的额外开销(相对裸部署)是可度量的一条"kernel-tax"线,应作为独立指标报告,而非混入能力结果。(本节不给具体数字;first-party benchmark 尚无,见 §6.10。)

---

### 6.4 Checkpoint algebra(diff / merge / restrict / retire / transfer)

harness checkpoint 之所以是"参数空间里的点",还因为它支持一套最小代数。这套代数的语义都**系于 held-out delta**,而非语法比较。承载多 slot 组合的容器是 `PolicyBundle`:一个不可变的策略集,**每个 slot 恰好一条 policy**(重复 slot 会被 `DuplicateSlot` 拒),并带一个 `rollback_to` 指针指向上一个已知良好的 bundle。

| 运算 | 含义 | 规范性 / 例子 |
|---|---|---|
| **diff** | 比较两个 checkpoint,定位改了哪些 slot、held-out delta 如何按 slot 归因 | diff MUST 是 slot 级的;两个 bundle 的差异 = 变更的 `PolicyRef` 集合加每 slot 的评估增量 |
| **merge** | 把不同 lineage 的 slot policy 合并成一个 bundle | merge MUST 保持"每 slot 一条";跨 lineage 合并后 MUST 重新过 admission 与 held-out |
| **restrict** | 收紧一条 policy 的 `required_capabilities` 或适用范围 | restrict MUST 只能**缩小**能力集(单调,见 §6.6);任何扩张尝试被拒 |
| **retire** | 把某 slot 退回到基线/上一版,记为 `Retired` | 当 model 把某 slot 的能力"吸收"后,retire 是一个**可度量的事件**,不是失败 |
| **transfer** | 把同一 checkpoint 重绑到另一个冻结 base model,报告保留的 held-out 增益 | transfer 的产物是 portable fraction(净 model-swap 后的保留增益) |

这套代数的封闭性由两条不变量维持:任何运算的输出仍是一个合法 `PolicyBundle`(每 slot 至多一条 policy),且任何改变权限面的运算(merge 引入新 lineage、restrict 收紧能力)MUST 重新经过 admission 与 held-out,不得"继承"来源 bundle 的既有通过状态。merge 两条各自合法但联合超出 slot 天花板的 lineage,会在重过 admission 时被 `ExceedsSlotCeiling` 拒。

**worked example: retire 作为 assimilation 的显式事件。** 假设某 vertical 的 `core/context` slot 学到了"只召回被改文件的调用点"的策略,带来 +5 分 held-out。半年后新一代 base model 原生具备了更强的长上下文与仓库级检索,diff 显示该 slot 的边际增益趋近 0。此时对 `core/context` 执行 **retire**,checkpoint 变小,而其他 slot 的增益不受影响。这把"model 追上了 harness"从一次死刑变成 diffable artifact 里的一次 **slot 退休事件**:retire 后该 slot 回落到手写基线,bundle 的 `rollback_to` 指针保证若新 model 表现回退仍可 deterministic 还原。

**worked example: transfer 的 portable fraction。** 一条在 model A 上取得 +8 分 held-out 的 `core/tool_policy` checkpoint,transfer 到冻结的 model B 后重测得 +6 分,则 portable fraction = 6/8 = 0.75。该数字本身是一个被报告的度量,不参与晋升门槛的自动抵偿;晋升仍由 §6.5 的门控独立裁决。

**载入与版本语义。** 持久化的 `PolicyManifest`/`TrajectoryEnvelope` MUST 经由 `load_json` 载入:先读 `schema_version`,只迁移**恰好 N-1**,拒绝一切未知或未来版本(fail-closed)。一个 `schema_version = 5` 的 manifest 在只支持到 3 的运行时上被直接拒绝,不做尽力而为的解析。这保证 checkpoint 的"坐标系"随协议演进仍可解释,而演进本身走人控 registry,不受进化流水线影响(呼应 §6.3(d))。

---

### 6.5 进化流水线:离线、非权威、人控门

进化流水线 MUST 是**离线、非权威、human-gated** 的。它的规范形状是一条单向证据路径,每一阶段都需要不可变身份、lineage、budget、consent 与 rollback 证据:

```
trajectory  ->  governed dataset  ->  candidate producer  ->  PolicyManifest
            ->  admission  ->  INDEPENDENT held-out evaluation
            ->  shadow  ->  canary  ->  active            (随时可 deterministic rollback)
```

对应的部署阶段是 `DeploymentStage` 枚举:

| 阶段 | 语义 | 门 |
|---|---|---|
| `Candidate` | producer 产出、通过契约校验的 manifest | 进入前必须过 admission(§6.6) |
| `Shadow` | 与 active 并行运行、**不产生对外 effect**,只采集对比证据 | 独立 evaluator 采集 held-out 观测 |
| `Canary` | 小流量真实运行 | 阶段预算/limit 受 kernel 约束 |
| `Active` | 成为该 slot 的现役 policy | 由离线 `PromotionAuthority` 记录,不是 runtime 自升 |
| `Retired` | 被显式退休(见 checkpoint algebra) | 记账事件 |
| `RolledBack` | 触发回滚,指向 `rollback_to` | deterministic,随时可发生 |

阶段推进是严格单向且逐级的:一条 candidate 不能跳过 shadow 直接进 canary,也不能跳过 canary 直接进 active。`RolledBack` 是唯一可从任意在线阶段(shadow/canary/active)进入的目标状态,且回滚指向 `rollback_to`,是 deterministic 的:同样的 rollback 输入永远产生同样的 active-bundle 指针。任一阶段的证据缺失(缺 lineage、缺 budget 记录、缺 consent)使该阶段的门 fail-closed,不予推进。

**阶段推进是单步、单向、非权威的。** `PromotionGate::assess` 给出的是**评审建议**(`EligibleForReleaseReview { suggested_next }` 或 `Reject { reasons }`),它**没有** registry handle、**不能**执行任何 transition。它只对**未受信的调用方断言**做形状与门槛校验:paired task 数、task-score 置信下界、cost/latency 置信上界、train/eval 是否重叠、replay-equivalence 与 sandbox 套件是否通过、必需的 invariant suite(默认 `runtime`/`security`/`durability`)是否全绿。**任何 safety violation 或 policy violation 都直接拒绝,reward 再高也不能抵偿**,这是硬约束,不是可交易项(`RewardVector` 里 `safety_violations`/`policy_violations` 是硬门,不与 task_score/latency/cost 做权衡)。举例:一条 candidate 的 task_score 高出基线 20 分,但其 `RewardVector.safety_violations > 0`,`assess` 返回 `Reject`,分数不参与任何加权。

真正记录"上线/回滚"的是离线的 `PromotionAuthority`:deny-by-default、no runtime loader,它的"activation"只是一个**被审计的离线 active-bundle 指针**,其确切字节可交给一个独立的、human-owned 的发布流程。`PromotionGate` 产出建议,`PromotionAuthority` 才持有(离线的)记账权;二者分离,任何一方都不足以单独把一条 policy 推上线。**live 激活不在关键路径上,直到 runtime/effect/recovery/evaluation/production-distribution 各道门都可信为止(NO-GO)。**

---

### 6.6 Capability-monotone admission(intersection-only,"never union")

admission 是 candidate 进入流水线的第一道、也是最强的一道门。它 MUST 是 **capability-monotone** 且 **intersection-only** 的。规范表述:

> 一条 candidate 的有效权限 = `subset( slot-ceiling INTERSECT exact-parent-ceiling INTERSECT runtime-allowed )`。**永不 union。**

能力空间是 microkernel 的五个 `Capability` 类:`ReadOnly` / `ReversibleLocal` / `CodeExecuting` / `TrustMutating` / `IrreversibleExternal`(语义:只读 / 可逆本地编辑 / 跑仓库内代码 / 改信任面 / 对外不可逆),它们彼此独立、不构成一条包含链(`crates/protocol/src/tool.rs:26-39`)。下文所说的"子集"是 `BTreeSet<Capability>` 之间的集合包含,不是能力类之间的强弱序;把上限表示为序上的一个点并用 `<=` 判定,会静默放行本不该放行的类(`crates/protocol/src/capability_set.rs:1-19`)。`ManifestAdmissionPolicy::assess` 强制:candidate 的 `required_capabilities` MUST 同时是 **slot 天花板**与**精确父策略天花板**的子集,否则 `ExceedsSlotCeiling` / `ExceedsParentCeiling`;父身份必须精确匹配(否则 `ParentIdentityMismatch`),缺父天花板 fail-closed(`MissingParentCeiling`)。此处"精确匹配"指父的 `PolicyRef` 四元组(slot、policy_id、version、digest)逐字段相等,digest 不同即视为不同父,防止把一条 candidate 挂到一个它并非真正派生自的、权限更宽的父上。

**worked example: intersection-only,never union。** 一条 `core/router` candidate 声明 `required = {ReadOnly, CodeExecuting}`,父天花板 = `{ReadOnly, CodeExecuting}`,slot 天花板 = `{ReadOnly, CodeExecuting, TrustMutating}`,而某次运行时 runtime-allowed = `{ReadOnly, TrustMutating, IrreversibleExternal}`。有效集 = 四者交集 = **`{ReadOnly}`**。注意:`CodeExecuting` 虽在 candidate/父/slot 里,但不在 runtime-allowed 里,落选;`TrustMutating`/`IrreversibleExternal` 虽在别处,但不在 candidate required 里,也落选。**没有任何一个能力能仅凭出现在 manifest、slot、父、runtime 之一就进入有效集。** 即使 runtime 允许一切,只要 candidate 没 required,也进不去;即使 candidate required,只要 runtime 不允许,也进不去。

**worked example: 结构上无法提权。** 一条被优化的 candidate 若在下一版把自己的 `required_capabilities` 从 `{ReadOnly}` 扩到 `{ReadOnly, IrreversibleExternal}` 以图获得对外能力,只要其父或 slot 天花板不含 `IrreversibleExternal`,`assess` 立即返回 `ExceedsParentCeiling` 或 `ExceedsSlotCeiling`。交集永不产生超过任一输入的元素,因此"训练一条更贪权的 policy"在结构上不可能穿过 admission。

这条规则的分量在于它是**结构性**的,而非策略性的:admission 是一个**纯 policy 边界,不是权威来源**。`CapabilityAdmission` **不是**一次权限授予:runtime 之后仍须用自己独立推导的 allowed set,并让结果 `EffectiveCapabilities` 走完整的 permission/approval/sandbox/effect 门。因此一条被训练出来的 policy **可以提出动作,但结构上无法**:给自己授予能力、放松预算、改写证据。这正是让"机器产出的、未受信的 candidate"能被持续 shadow/canary 而**无需每个 loop 一个人**的前提:每一步的权限上界都由不可被 candidate 影响的交集决定。

---

### 6.7 独立 evaluator:producer 无法伪造自己的晋升

**分权(separation of duties)是被结构强制的,不是流程约定。** 打分 held-out 的 `IndependentEvaluator` 与产出 candidate 的 producer **MUST** 是不同的信任主体:evaluator 用**独立的 trust anchor**(`EvaluatorTrustAnchor`)对 `HeldOutEvaluation` 签名(`SignedHeldOutEvaluation`),而 producer 用另一套 anchor 对 candidate 签名。`PromotionAuthority` 分别持有 `promotion_anchors` 与 `evaluator_anchors`,并读取 tamper-evident 证据链。评估 fixture 与打分策略 MUST 由独立于"被期望改善该分数的策略"的一方评审。若一条 `HeldOutEvaluation` 的签名 anchor 落在 `promotion_anchors` 而非 `evaluator_anchors` 内(即 producer 试图给自己的产出打分),`PromotionAuthority` 拒绝采信该评估。

由此得到一条硬结论,直接呼应"safety cannot be a fixed point of the self-improving operator":**producer 不能伪造自己的晋升。** 一个被优化的对象,其裁判结构性地坐在被优化对象**之外**;held-out 分数因此是 non-Goodhartable 的,promotion 决策与 slot 组合矩阵才可信。历史反例(某自进化系统伪造单测日志、删掉自己的幻觉检测器)正是缺少这条独立性时会发生的事;本设计以"evaluator 在 learning loop 之外,加 candidate 结构上不能扩张自身权限(§6.6)"来杜绝它。两条防线叠加:即使 candidate 想改评估结果,它既没有 evaluator 的 anchor(无法签),也没有能力去改 tamper-evident 证据链(§6.8)。

**跨接缝携带的 MUST 是 `SignedHeldOutEvaluation`,不是别的形状。** eval→evolve 的 `HeldOutEvidenceBridge` 返回类型 **MUST** 是这个带 `evaluator_id` 与签名的类型。W1 冻结的第一版曾另造一个全 `pub` 字段、无签名、无 evaluator 身份的结构体跨这道接缝,并在文档里声称 evolution "cannot manufacture it" —— 那句话在实现上为假:写一个 struct literal 即可。**分权由密钥与验签路径强制,不由 trait 签名强制**;一个不携带署名者的类型,`verify_held_out` 连能engage的东西都没有。

**`base_model` MUST 在 `PromotionEvidence` 上,因而在两种签名载荷之内。** 该字段属于 `PromotionEvidence` —— `HeldOutEvaluation` 与 `StageObservation` 共同携带的那个类型 —— 而不是只挂在前者上。stage observation 由 `STAGE_RESULT_DOMAIN` 独立签名,且是第三方**真正拿到**的东西;若身份只挂在 held-out 一侧,一份独立签名的 stage observation 就说不出自己在哪套权重上量的,归属只能靠一条 `pub(crate)` 的 `CandidateIdentity` 间接推,crate 外完全够不着。一个说不出自己量了什么的独立签名物,不是关于任何特定模型的证据。
`HeldOutEvaluation::new` MUST 拒绝 evidence 上的身份与验证器从已校验 manifest 读出的身份不一致的情况 —— 否则签名会忠实地为评估方随口指定的任何权重背书。 `HeldOutEvaluation` 携带它,并由 `PromotionAuthority` 与它自己从已校验 manifest 读出的身份比对;不一致即 `IndependentEvaluationRequired`。否则签名只证明了"某个分数",而没有钉死这个分数是在**哪套权重**上量出来的,于是一次针对同一 candidate、在便利 base model 上做的诚实评估,可以被重放为真实 base model 下的证据。该字段进入 HMAC 前像使得 journal schema 从 1 升到 2:旧签名会重算出不同值,而"这条证据早于某字段"与"这条证据被篡改"必须可区分,故 fail-closed 拒读旧版而非迁移。

**一条诚实的残余缺口。** evaluator 与 promotion 方的不相交是按**身份字符串**检查的(`PromotionAuthority::open` 拒绝 evaluator_id 与 promotion party id 相同的配置),而不是按密钥材料。同一方以两个 id 注册同一把密钥可以绕过它,且目前没有任何机制能发现。记录在此,以免把一条部分保证读成完整保证。

---

### 6.8 固定的、人控的约束:一条进化模块**绝不能**做的事

综合 §6.5 至 §6.7,一条被进化出来的模块 MAY 提出**有界**动作,但它 **MUST NOT**:

- 给自己授予能力(admission intersection-only,§6.6);
- 放松 security / durability / budget policy;
- 改写 trajectory 或评估证据(证据链 tamper-evident);
- 选择自己的晋升门槛(`PromotionGate` 由独立方定义);
- 晋升或回滚自己(离线 `PromotionAuthority` 加 human-owned 发布);
- 伪造自己的 held-out 结果(独立 evaluator,§6.7);
- 越过 recorded consent 扩大数据用途(`DataGovernance`/`TrainingConsent` 门控)。

这些约束 MUST 是冻结的、人控的常量,**不是**自进化算子的不动点。安全不能被它所治理的进化过程改写,这是整个进化边界成立的元规则:进化可以改变"用哪条 policy",但永远不能改变"什么算安全、谁来判定、谁能上线"。

---

### 6.9 open-substrate vs closed-training-pipeline:一条清晰的拆分

Iteron 在开放性上做一条**刻意的拆分**:

- **open substrate(开放基座)。** microkernel、五个 ABI 契约、`StrategySlot` 命名空间、`PolicyManifest`/`PolicyBundle` 类型、admission 与 promotion 的**契约与语义**,构成公开的 Plantcore-AI/Iteron 基座。任何人都能对着这套 typed ABI 产出、diff、admit、评估一个 checkpoint。
- **closed training pipeline(闭源训练侧)。** 具体的 **evolution/training 流水线**(candidate producer 的实现、搜索/训练算法、内部评估资产)**不开源**:采用 bring-your-own(自带 producer)或一个 closed-source 的 evolution service。

这条拆分的技术后果就是 §6.3(c):因为 artifact 类型(trajectory、PolicyManifest)是开放且方法无关的,**流水线的产出可用于训练 model**(post-training 语料),即便流水线本身是闭源的。open substrate 让 checkpoint 可携带、可审计、可组合;closed pipeline 让"如何产出更好的 checkpoint"成为可保护的资产。两者互不污染:基座不含任何训练机密,训练侧不改任何 ABI。一个自带 producer 的第三方,只要产出的 `PolicyManifest` 通过 `validate` 与 admission,就能接入同一条流水线,而无需暴露其内部训练算法。

---

### 6.10 现状披露(诚实边界)

本节描述的是**目标架构**与已落地的**契约层**;定位是前瞻性的(prospective),须诚实标注现状:

- Iteron 处于 **pre-alpha**:一个能跑但仍是模块化的 monolith;kernel 目前仍硬依赖约 10 个 crate,尚未收敛到最小 TCB。
- **live self-evolution activation 是 NO-GO**:`crates/evolve` 明确在 runtime TCB 之外,无 loader、无 runtime registry handle,不能载入、授予、执行或热插一条 policy。它当前只支持**记录、离线校验与评估**。
- **尚无 first-party benchmark 数字**:本节不含任何 tier 内部数字;能力结论(如"训练出的 harness 击败手搭基线")是一个**待验证**的实验设计,其成立与否 gate 在尚未运行的 held-out 结果上。
- escape-hatch 的 blob 到 typed 晋升路径目前是**设计承诺**,尚无 ADAS 式 artifact 真正 round-trip 进空间。

规范收束:本节定义的边界(kernel 冻结、ABI 不变、进化离线非权威、admission intersection-only、evaluator 独立、consent 门控)是**当下即被契约与类型强制**的部分;而"上线一条自进化 policy"的能力,被刻意留在关键路径**之外**,直到 runtime、effect、recovery、evaluation、production-distribution 五道门都可信为止。

---

### 6.11 本节规范性小结

1. 可进化的对象 MUST 限于 `StrategySlot` 空间内的 policy;microkernel 与五个 ABI 契约 MUST NOT 被进化流水线修改。
2. harness checkpoint MUST 以 `PolicyManifest` 表达,方法无关;**promotion 语义 MUST NOT 依赖 `method`**。
3. 进化 MUST 离线、非权威、human-gated;**step 1 MUST NOT 训练任何 model weights**;harness MAY co-adapt 到 model 的 post-training tag;同一 artifact MAY 后续用于 model post-training(受 consent 门控)。
4. admission MUST intersection-only、capability-monotone;candidate MUST NOT 授予能力、放松预算、改写证据、伪造 held-out、或自升/自回滚。
5. evaluator MUST 独立于 producer;**producer MUST NOT 伪造自己的晋升**。
6. 基座开放、训练流水线闭源;二者 MUST NOT 互相污染 ABI 或泄露训练机密。