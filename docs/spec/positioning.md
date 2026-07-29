# 1. 引言与定位 (Motivation & Positioning)

### 1.1 命题 (Thesis)

Core Code 的命题只有一句:

> **Transformer 是模型 (model) 的通用、可训练架构;Core Code 要成为 harness 的通用、可训练架构。**

这句话把两个通常被分开对待的东西并置。model 是被 train 出来的:它有一个通用架构 (Transformer)、一个可度量的目标函数、一套可复现的训练管线,于是"专精化一个 model"是一门系统工程,而不是手艺。harness (即承载一个 agent 去完成任务的那一整套非模型逻辑:路由、规划、上下文选择、记忆、调度、工具策略、校验、多 agent 协作) 今天却仍然靠直觉手工维护。本规范主张:harness 与 model 一样,存在一个**可形式化的边界**与一个**可被优化的策略面 (policy surface)**;因此 harness 的设计与优化,MUST 从启发式 (heuristic) 与直觉,升格为一门可度量、可复现、可优化的**系统工程与科学**。这个策略面不是自由文本或任意代码,而是一个 typed 空间 (见 §1.3 的 StrategySlot 与 §1.7 的稳定 typed ABI);正是"typed"这个性质,让"度量、复现、优化"从口号变成可执行的操作。

从这句命题派生出本文档所有后续设计的一条基线判断,它关于什么是 agent 系统里真正会增值的资产:

> **计算是一次性的;架构 (harness) 与上下文 (context) 才是会沉淀、增值的资产。**

一次 LLM 调用的算力开销花掉就没了;租来的 model 每个季度换代、可被替换。真正跨会话沉淀、随使用不断被校正而增值的,是 harness (承载任务的架构) 与 context (被反复修正的领域上下文)。一个 agent 系统的首要设计目标,MUST 是保护并放大这两类会增值的资产,而不是把专精化的成果绑死在一次性的计算或一个会被换掉的 model 上。这条判断在 §1.3 被具体化为"权重学先验、harness 学情境"的分工,并在 §1.7 被提升为对每个机制的评判标尺。

### 1.2 问题陈述:专精化今天寄居在权重里,或散落成"方法形状的碎屑"

把一个通用 coding agent 变成某个垂类 (vertical) 上真正好用的 agent (例如把它专精成一个"金融数据仓库的 SQL 迁移 agent",能理解该垂类的 schema 约定、常见反模式、回归测试口径、以及"什么样的改动需要人工复核") 这件事今天可以做到,而且确实产生了价值。问题不在于做不到,而在于**做出来的专精化成果没有一个可管理的载体**。它只会落到两个地方之一:

**(a) 寄居在权重里 (in weights)。** 把领域轨迹拿去 fine-tune,专精化被编码进 model 的参数。这有真实效果,但代价是:成果不可读、不可 diff、不可单独回滚;它与那一个具体 base model 绑死,base model 一换代,专精化要重来;而且领域事实与领域 verifier 本就在任何 base model 的分布之外,单靠改权重既昂贵又未必学得进去。具体失败模式包括:两处独立的领域修正被平均进同一批权重后互相稀释,无法分别回退;一个错误的领域事实一旦被编码,除了再训练没有干净的撤销路径;以及权重里学到的东西无法回答"它到底学到了什么规则"这类可审计的问题。

**(b) 散落成"方法形状的碎屑" (method-shaped debris)。** 更常见的是,专精化被拆散、以"产生它的那个方法的原生形状"散落在工程各处:一版手调的 prompt 模板;几个硬编码在脚本里的 few-shot 范例;一段检索启发式;一张由某个 workflow 搜索 (如 ADAS/AFlow 一类方法) 产出的拓扑图,存成 JSON;一个 DSPy 编译出来的 program;一叠散落在 notebook 里的评测口径。每一块都是真实的专精化,但它们各自被锁在不同方法的原生格式里,**合起来不构成任何一个可以被 diff、被评审、被作为一个整体晋升或回滚、被携带到下一个 model 上去的单一制品**。当负责它的工程师离开、或 base model 换代时,这些碎屑的价值大部分会流失。其失败模式是渐进而隐蔽的:没有单一版本号,没有单一 owner,任意一块被悄悄改动都不会触发一次可见的"发布",也无法在一次评估里被整体打分。

两条路的共同病灶是一样的:**专精化是真实的,但它没有一个一等的、方法无关的、可版本化的表达**。于是它无法像一次软件发布那样被治理。本规范存在的理由,就是给这个"本可被优化、却尚未被形式化"的对象一个正式的载体和一门可复现的学科;这个载体在 §1.3 被命名为 PolicyManifest。

### 1.3 核心论点:专精化 agent = 训练 harness,而其产物是"harness checkpoint"

本规范把上述问题收敛为一个明确的立场,它贯穿全文:

> **专精化一个 agent,意味着训练它的 harness,而不是训练那个 model。**

更精确地:除 microkernel (见 §1.6 与 §1.7,以及后续章节) 之外,一个 agent 的每一个非内核决策 (用哪个 router、如何 plan、选什么 context、留存什么 memory、如何 schedule、用什么 tool policy、如何 verify、如何在多个 model 之间路由、如何组织多 agent 协作) 都是**同一个 typed 策略空间**里的一个 policy。这个策略空间的元素叫 **StrategySlot**;9 个众所周知的核心 slot 是 `core/router`、`core/planner`、`core/context`、`core/memory`、`core/scheduler`、`core/tool_policy`、`core/verifier`、`core/model_router`、`core/collaboration` (crates/evolve/src/lib.rs:156-182)。

StrategySlot 是一个**开放的、命名字符串型 (open namespaced-string)** 类型,而不是一个封闭枚举。可扩展性正由这个开放命名空间保证:一个垂类包 (vertical pack) MAY 增加自己的 slot,只要它落在自己的命名空间前缀下 (例如数据库垂类的 `db/query_planner`、客服垂类的 `support/escalation_router`),而**完全不触碰 microkernel**。命名约定 MUST 为 `<domain>/<role>`:跨接缝的 `SlotId` 文法强制恰好一个 `/` (crates/protocol/src/slot.rs:68-87),因此「无前缀的保留名」根本不是一个可构造的 slot 身份。9 个核心 slot 占用 `core/` 这个域;垂类自加的 slot MUST 带自己的 vertical 域前缀,以免与 `core/` 或其它垂类相撞。本文其余段落为行文简洁,有时只写核心 slot 的 `<role>` 半段 (如「`verifier` slot」),其完整身份始终是 `core/<role>`。一个未知前缀的 slot 对 microkernel 是不透明的:内核既不解释它,也不因它而改变行为,内核只中介它经由 ABI 发出的提议 (见 §1.7)。

一套 harness 在某个垂类上被训练出来的状态,被封装成一个一等制品,本规范称之为 **harness checkpoint**,其正式名字是 **PolicyManifest**。它是:

- **方法无关的 (method-agnostic)**:无论专精化是由搜索 (如 GEPA)、SFT、偏好优化 (preference)、GRPO 还是 RL 产出的,它们 MUST 发射出**同一种**制品类型:PolicyManifest。产生它的方法不改变它的形状。
- **可版本化、可 diff 的 (versioned & diffable)**:它有 checkpoint 代数,包含 diff、merge、restrict、retire、transfer 这些算子,因此可以像软件发布一样被比较、组合、收窄、退役、迁移。语义约定为:`diff` 按 slot 给出逐槽变更集;`merge` 在两个 manifest 无冲突时并槽,冲突槽 MUST 报错而非静默择一;`restrict` 只能收窄能力上限,MUST NOT 放宽 (见 §1.5 的 capability admission);`retire` 把一个版本标记为不可再被晋升为 active;`transfer` 把同一制品套到另一个被冻结的 base model 上。
- **被独立评估的 (independently evaluated)**:一个 candidate PolicyManifest MUST 由一个**独立的 evaluator**,在**垂类拥有的、留出的 (held-out) 目标**上打分。候选者不能自评、不能伪造自己的 held-out 结果、不能改写证据。
- **像发布一样被晋升/回滚的 (promoted/rolled-back like a release)**:它经过 admission、held-out 评估、shadow、canary,才成为 active,并且带确定性回滚 (deterministic rollback)。
- **可跨冻结 base model 携带的 (carried across frozen base models)**:同一个 PolicyManifest 可以套到不同的、被冻结的 base model 上,而无需重训权重。

一句话概括这条分工:**权重学的是先验 (the prior),harness 学的是情境 (the situation)。** 领域信号 (轨迹、verifier 反馈、人类修正) 本就在任何通用 model 的分布之外,而"修正带宽"远高于一个标量 reward。这些信号无法被通用参数编码,只能被 train 进一个属于该垂类的 harness checkpoint 里。

> **worked example (SQL 迁移垂类)。** 把"金融数据仓库 SQL 迁移 agent"专精化的成果,不再散落成一版 prompt 加一段检索代码加一张搜索出的拓扑图。它 MUST 表达为一个 PolicyManifest,例如其中:`context` slot 学到"迁移任务优先注入目标方言的 schema 约定与最近三次回归失败";`db/query_planner` (垂类自加的 slot,带 `db/` 前缀) 学到该仓库的分区键反模式;`verifier` slot 学到"用垂类拥有的回归测试集判定通过,而非 model 自评";`tool_policy` slot 学到"跨 schema 的 DDL 变更必须先产 dry-run diff"。这一个制品可以被 diff (和上一版比,`diff` 报出只有 `verifier` 槽变了)、被独立评估 (在该垂类留出的迁移用例集上打分)、被晋升 (shadow -> canary -> active)、被回滚 (确定性退回上一版)、并在 base model 换代后经 `transfer` 原样套上去。
>
> **worked example (工具边界)。** 注意 `tool_policy` 槽里"DDL 变更先产 dry-run diff"这条规则,它决定的是"选哪个 tool、按什么参数、按垂类如何调";而"这个 DDL 变更被允许真正落到数据库上"这件事的**权威**不在该槽,而在 microkernel 的 effect broker 与 capability admission (见 §1.7)。同一条 bash 调用,其"是否被允许"由内核裁决,其"要不要在此处调、怎么调"由可进化的 `tool_policy` 槽决定;两者分属两个平面。

### 1.4 这不是什么:不是 AutoML/AutoAgent 平台,而是一个可训练的**substrate**

一个自然的误读是把 Core Code 当作一个 "AutoML / AutoAgent" 平台,即一个"喂进任务、自动帮你搭出一个 agent"的黑箱优化器。**它不是。** 本规范在此把区别钉死,因为它决定了全文的框架:

| 维度 | AutoML / AutoAgent 式框架 | Core Code (可训练 substrate) |
|---|---|---|
| 交付物 | 一个"最优 agent"或一段自动搭好的流水线 | 一个稳定的 typed ABI 加一个可被任意方法训练的策略空间 |
| 优化方法 | 平台自带、内置、通常单一的搜索/优化器 | **不绑定方法**;bring-your-own (搜索/SFT/偏好/GRPO/RL 皆可),都发射同一种 PolicyManifest |
| 产物形态 | 常是"方法形状的碎屑"或一个不可移植的封装 | 单一、方法无关、可 diff、可版本化、可跨 model 携带的 harness checkpoint |
| 权威边界 | 通常无明确的、被冻结的信任边界 | microkernel (身份、权限、证据、预算、副作用中枢) 被**冻结**,不参与优化 |
| 安全 | 常是事后附加 | 安全 MUST NOT 是自进化算子的不动点;deny-by-default 内建 |
| 评估 | 常由优化器自身闭环 | 由**独立 evaluator** 在**垂类拥有的 held-out 目标**上打分,候选者不能自评/自晋升 |

关键差别在"substrate"这个词。Transformer 不是一个"帮你自动造模型"的平台;它是一个**通用的、可训练的架构**,一个稳定的基座,你带着数据和训练管线来,得到你的 model。Core Code 的定位与之同构:它提供一个稳定的、厂商中立的可训练**基座**,你带着垂类数据和 (你自己的) 训练管线来,得到你的垂类 harness。**方法是你带的,基座是中立的;被优化的是策略,被冻结的是权威。** 这也直接回答"这算是一个工程/AutoML 平台吗":它是一个工程学科的基座 (substrate),不是一个替你做决定的自动化产品。

需要同样明确的一点:Core Code 的**进化/训练管线本身不属于本开源基座**。本规范开源的是 runtime 基座、稳定 ABI、以及 PolicyManifest 制品格式;产生 candidate 的训练管线是 bring-your-own,或由一个闭源的进化服务提供。开源的是"harness 的通用可训练架构"这个基座,不是某一家的训练方法 (与 §1.6 的开源范围一致)。

### 1.5 为什么必须可进化 (evolvable)

不存在一套对所有垂类都最优的通用 harness。每个垂类有各自的任务分布、工具集、verifier、成本与风险约束、以及领域上下文;而领域事实与领域 verifier 本就落在任何 base model 的分布之外。因此**最优性是垂类专属的**,harness MUST 能按垂类进化,而不是靠一套通用配置强行覆盖所有场景。

"可进化"在本规范里有精确含义,它不是"让 agent 在线自我改写自己":

- **进化是离线的、非权威的、人类把关的 (offline, non-authoritative, human-gated)。** 它是一条流水线:trajectory -> 受治理的数据集 (governed dataset) -> candidate producer -> PolicyManifest -> admission -> 独立 held-out 评估 -> shadow -> canary -> active,带确定性回滚。各阶段的职责与失败处置约定如下:`trajectory` 收集运行轨迹作为原料;`governed dataset` 施加数据同意与去敏治理,未获同意的数据 MUST NOT 进入;`candidate producer` 是 bring-your-own 的训练方法,产出 immutable candidate;`admission` 做 capability 准入检查,不通过即拒绝入库;`held-out 评估`由独立 evaluator 打分,分数不达门槛即淘汰;`shadow` 让 candidate 只旁路观察不产生副作用;`canary` 让它承接一小部分真实流量;`active` 是全量启用。任一阶段失败,系统 MUST 停在该阶段并保留上一个 active 版本;运行时的 microkernel 不参与产生或激活 policy。
- **进化不能自我授权。** capability admission 强制 candidate 的授权等于 subset(该 slot 的 ceiling  INTERSECT  其确切父辈的 ceiling),**只做交集,永不做并集 ("never union")**。一个 candidate 可以*提议*,但不能*授予*能力、不能改写证据、不能放松预算、不能伪造自己的 held-out 结果、不能自我晋升。举例:若某 slot 的 ceiling 允许"读工作区文件"而其父辈 ceiling 不允许"发起网络出站",则交集里没有网络出站,candidate 无论怎样提议都拿不到它。
- **进化包不包括"选内核"或"跑一个 agent 步骤"?不。** 进化选的是策略 (StrategySlot 的取值),不是内核;microkernel 的接口在进化过程中**不变**。进化产生的是一个静态制品 (PolicyManifest),不是一次 agent 运行。
- **进化涉不涉及训练 model?默认不。** 主路径是在**不训练 model** 的前提下进化 harness,以求得 co-design 之效 (可移植、model-agnostic)。当确需改权重时,把 curated 轨迹经 SFT/偏好/RL 回流,并 MUST 经过**同一道** admission 与评测门再入。即训练可以发生在两侧,但 harness 是那个恒可用、可移植、model 无关的一侧。

由此也澄清一个常见问题:"这个平台的产物能不能拿去训练 model?"可以:curated 的轨迹与 harness checkpoint 是极好的 post-training 语料,但那属于 model 一侧的、可选的回流路径,且必须重新过评测门;它不是 Core Code 的主张,主张是**在冻结 model 的前提下进化 harness**。

### 1.6 为什么必须开源 (open)

Core Code 的参考基座 MUST 开源,理由有两层,都不是姿态而是工程必需:

**(a) 可信边界只能被验证,不能被声明。** 当一个系统能自主提交副作用 (side-effects),包括写文件、调外部服务、执行命令,信任就不能靠"我们保证很安全"来建立,只能靠一条**可审计、可阅读的边界**来验证。因此开源是正确性与安全性的**前置条件**,而不是一个营销选项:microkernel 那条"内核绝不做什么"的负空间 (negative space,见 §1.7),必须是任何人都能读到、能核对的。

**(b) 学科需要一个中立、厂商无关的公共基座。** 正如 Transformer 因开放而成为一切 model 的公共基座,harness 要从手艺变成一门可复现、可比较的科学,同样需要一个开放、中立、可复用的参考架构。只有当"harness A 在垂类 X 上优于 harness B"这类命题能在一个共享的基座与共享的 ABI 上被复现和比较时,harness 优化才真正成为科学而非各家私货。

需要与 (a) 一致地说明范围:开源的是 runtime 基座、稳定 ABI、PolicyManifest 格式与那条可读的权威边界;**训练/进化管线不开源** (bring-your-own 或闭源进化服务)。这两件事不矛盾:公共的是"可信基座与制品格式",私有的是"你怎么训"。

### 1.7 全文框架:五条不变式与三层结构

本节确立整份规范的评判框架;后续每一章设计的每一个机制,MUST 用同一套标尺来衡量。

**五条不变式 (Five Invariants)。** 本规范中的任何机制,MUST 同时满足:

1. **Bounded** (有界):预算、deadline、可取消,任何执行不得无界扩张。预算 MUST 是带上限的数值:v1 冻结的 `Budget` 恰好是 `max_turns`、`max_usd: Option<f64>`、`max_wall_secs`、`max_consecutive_tool_errors` 四条轴 (crates/protocol/src/lib.rs:240-248),其中**没有 token 轴**,token 轴按 §4.3(b)3 属于事后可无损追加的字段。deadline MUST 是一个带上限的时长而不是一个可比较的时间点:协议里没有名为 deadline 的字段,它就是秒级的 `max_wall_secs` 这条墙钟轴。取消 MUST 能在有界步数内生效。
2. **Recoverable** (可恢复):任何晋升都能确定性回滚到已知良好状态。回滚 MUST NOT 依赖于外部状态是否"恰好还在",而是从记录里可确定重建。
3. **Reproducible** (可复现):同一输入加同一 pinned policy bundle 产生同一结果;记录可 replay。此处 pinned 指 policy bundle 的版本被钉死且不可变。
4. **Observable** (可观测):决策与副作用留下可审计的证据 (SHA-256 hash-chained、防篡改),任一记录被改动都会破坏链上后续哈希。
5. **Security-bounded** (安全有界):deny-by-default,能力只做交集不做并集,权威边界不可被优化掉。

**三层结构 (Three Planes)。** 整个系统被切成三个平面,本文档的其余章节沿此展开:

- **固定的 microkernel (fixed TCB / trusted computing base)**:被冻结、不参与优化的最小可信基。它拥有:身份与信任 (identity & trust);capability admission (5 个互相独立的 capability class 构成的一个**集合** `CapabilitySet`,只做交集、capability-monotone;它不是一条可按 `<=` 比较的层级阶梯,见 crates/protocol/src/tool.rs:26-39 与 crates/protocol/src/capability_set.rs:1-19);唯一的 effect broker;确定性状态归约 (一个纯 reducer);canonical record/checkpoint/replay (SHA-256 hash-chained、防篡改);预算/deadline/取消;version registry;kill/rollback;以及那个执行 reducer 所产出 action requests 的、有界的 agent-loop **driver**。它的**负空间**同样是规范的一部分,内核 MUST NOT:读文件或环境变量、调 provider、构造 prompt、选 context、spawn 进程、解析 MCP、渲染 UI、或训练/激活一个 policy。关于 bash 的一条明确裁决:内核只拥有 effect broker 加 capability admission,即"任何 tool (包括 bash) 被允许做什么"的**权威**;而"选哪个 tool、用什么参数、按垂类如何调"是可进化的 `tool_policy` slot (见 §1.3)。**bash 是一个其副作用被内核中介与准入的 tool,而不是内核内部的逻辑。**
- **可替换的 strategy 与 world 模块 (replaceable strategy & world modules)**:即 §1.3 的 StrategySlot 们,活在 TCB 之外,躲在稳定 typed ABI 之后。它们返回有界的**提议 (proposals)**、收到能力受限的结果;它们**不持有** ambient authority。
- **进化控制平面 (evolution control plane)**:§1.5 描述的那条离线、人类把关的流水线,产出 immutable 的 candidate PolicyManifest。安全策略、权限、耐久性、证据完整性、预算、数据同意、晋升授权,MUST 保持人类控制,不可被优化掉。

**稳定 typed ABI (stable typed ABI)。** 模块与内核之间、模块与模块之间,MUST 只经由五个契约通信:**TaskEnvelope、ContextRequest、ToolIntent、EffectProposal、ArtifactRef**。它们各自承担一件事:

- **TaskEnvelope**:一个待办任务的 typed 入口,携带 `input` (任务本体)、`trust` (输入的信任来源)、`acceptance` (怎么算做完)、`budget` 与 `ceiling` (crates/protocol/src/task.rs:116-135)。它是不变式 1 (Bounded) 在 ABI 层的落点,因为预算与 deadline 从入口就被显式携带:deadline 不是一个独立字段,而是 `budget.max_wall_secs` 这条轴 (crates/protocol/src/lib.rs:240-248)。v1 冻结形状**不携带垂类标识**:`profile_ref` 在 §4.2.1 打印的结构体里被显式注释掉,并被同节的规范性约束指名为该结构里唯一可事后无损追加的字段。
- **ContextRequest**:一个 strategy 模块 (通常是 `context` slot) 发起的、有界的上下文检索提议,声明"想要什么、要多少",而不直接触碰存储。
- **ToolIntent**:一个"想调用某个 tool"的声明 (tool 标识加参数),尚未获得副作用授权,由 `tool_policy` slot 产出。
- **EffectProposal**:一个待内核 effect broker 准入的副作用提议 (写文件、调外部服务、执行命令);它是唯一能让副作用真正发生的路径,MUST 经 capability admission 裁决。
- **ArtifactRef**:对一个不可变产物 (record、checkpoint、评估结果) 的内容寻址引用 (SHA-256),它把不变式 3 (Reproducible) 与 4 (Observable) 串起来。

这五个契约的稳定性,就是"可扩展性"的保证:一个垂类包能加 slot、能换 model、能重训策略,只要它仍然只说这五种话,microkernel 就无需改动。ABI 的细化定义与其在代码中的种子 (seeds),见后续章节。

> **架构不变式,一句话。** 除 microkernel 外,每一个模块都是稳定 typed ABI 之后可调、可训、可进化的策略,这是"机制与策略分离"被赋予了可学习性;而 microkernel (身份、权限、证据、预算、副作用中枢) 必须被**冻结**:**安全不能是一个自进化算子的不动点。**

### 1.8 现状诚实声明 (Status)

本规范描述的是 Core Code 的**目标契约 (target contract)**,而非一份已达成一致性 (conformance) 的现状声明。为避免任何过度承诺,现状如实陈述如下:

- Core Code 目前是 **pre-alpha**:一个能运行、但仍是**模块化单体 (modular monolith)** 的系统。它已被切分为受机器校验的开发边界 (protocol / record / observability / provider / tools / sandbox / context / verification / MCP / scheduling / agents / kernel / CLI / evaluation / evolution-contract 等 crate),但 kernel 仍**硬依赖若干具体实现**,CLI/TUI 仍参与运行时组装。**因此 Core Code 目前尚不宣称 microkernel 一致性。** 上述模块边界是"人的开发边界",不等于运行时隔离 (即 §1.7 三层结构目前是目标形态,尚未完全落地)。
- 活体的自我进化激活 (live self-evolution activation) 目前是 **NO-GO**:进化控制平面被描述为**未来的、隔离的**平面 (对照 §1.5 的离线、人类把关流水线,它是那条流水线的成熟形态,而非早期切片的既有能力)。
- 目前**没有第一方基准数字 (no first-party benchmark number)**。本节所述的定位与分层是**前瞻性的 (prospective)**,是本规范要去建立的目标,而不是已经测得的既成事实。

诚实地陈述现状,不削弱本命题;恰恰相反:"今日 harness 仍以直觉手工维护"这一事实本身,正是本规范的论据,它证明存在一个尚未被形式化、却本可被优化的对象。本文档的其余部分,就是把这个对象形式化,并给出把它从直觉与启发式,变成一门系统工程与科学的完整契约:**冻结权威,进化策略,令每个 model 可替换;进化与学习的单位,是 harness,而不是模型权重。**