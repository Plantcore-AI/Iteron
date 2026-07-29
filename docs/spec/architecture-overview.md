# 2. 体系结构总览 (Architecture Overview)

本节给出 Core Code 的整体图景:系统由哪几个平面构成、它们通过什么互相连接、以及每一处机制被同一套判据约束。后续各节(microkernel 组件见 §3、ABI 契约见 §4、strategy slot 见 §5、evolution pipeline 见 §6、评测见 §7)都是本节这张地图上某一块的展开;读本节的目的,是在进入细节前先建立"哪一部分是冻结的、哪一部分是可进化的、二者以什么为界"的全局判断。

Core Code 的定位是**"harness 的可训练基座"**:把一个 agent 专门化(specialize)到某个垂类,指的是**训练 harness,而不是训练 model**。除 microkernel 外,系统里每一个非内核决策都是**一个 typed policy space 里的策略**;它被训练后的状态是一等公民工件,即 **PolicyManifest(即 harness checkpoint)**。权重学的是先验(prior),harness 学的是具体处境(situation)。这一定位决定了整个体系结构必须回答一个结构性问题:**哪些东西可以被自我改进的算子(self-improving operator)改写,哪些绝对不能。** 答案就是下面的三平面切分。

### 2.1 三个平面 (three planes)

Core Code 在结构上 **MUST** 划分为三个平面,边界即信任边界:

1. **Plane A: 固定运行时可信基 (Fixed runtime TCB)。** 一个冻结的 **microkernel**,是系统里唯一拥有环境权限(ambient authority)的部分,承载全部不可谈判的机制:identity & trust、capability admission(五个彼此独立的 capability class,授权恒以集合 `CapabilitySet` 承载,只取交不取并;`crates/protocol/src/capability_set.rs:1-19` 说明为何 MUST NOT 表示为某个序上的一个点)、唯一的 effect broker、确定性状态归约(一个 pure reducer)、canonical record/checkpoint/replay(SHA-256 hash-chained、tamper-evident)、budgets/deadlines/cancellation、version registry、kill/rollback,以及运行 reducer 所产出 action request 的 **bounded agent-loop driver**。它的形态被一份**否定清单(negative space)**同等地定义:microkernel **MUST NOT** 读取文件或环境变量、**MUST NOT** 调用任何 provider、**MUST NOT** 组装 prompt、**MUST NOT** 选择 context、**MUST NOT** spawn 进程、**MUST NOT** 解析 MCP、**MUST NOT** 渲染 UI、**MUST NOT** 训练或激活任何 policy。这份否定清单不是风格建议,而是可被机器校验的边界:任一条被违反,即视为 microkernel 一致性缺失(honest status 见 §2.7)。

2. **Plane B: 可替换的 strategy 与 world 模块 (Replaceable strategy & world modules)。** 系统里一切"多样、有品味、随垂类而变"的决策都在这里:`core/router`、`core/planner`、`core/context`、`core/memory`、`core/scheduler`、`core/tool_policy`、`core/verifier`、`core/model_router`、`core/collaboration`(`crates/evolve/src/lib.rs:156-182`;`SlotId` 文法强制恰好一个 `/`,见 `crates/protocol/src/slot.rs:68-87`)。它们是**可 tune / train / 进化的 slot**,向 microkernel **只返回 bounded 的 typed proposal**,并**只收到 capability-scoped 的结果**;它们 **MUST NOT** 获得任何 ambient authority。一个 slot 若尝试直接触达文件、进程或 provider(即绕过 ABI 自行取权),该行为 **MUST** 在 admission 处被 deny-by-default 截停,而不是在事后审计里被发现。model 与外部世界(sandbox、repo、browser、db、MCP 工具)通过 conformance-gated adapter 挂接在这一平面之外沿;adapter 本身**MUST NOT** 携带 ambient authority,它只是把 typed proposal 翻译成受 capability 约束的具体调用。

3. **Plane C: 离线进化控制平面 (Offline evolution control plane)。** 一个**离线、非权威、人工门控**的流水线,负责生产、评审、晋升 Plane B 的候选策略。它以 `trajectory -> governed dataset -> candidate producer -> PolicyManifest -> admission -> 独立 held-out 评测 -> shadow -> canary -> active` 推进,并配确定性 rollback。它**产出并晋升** PolicyManifest,但 **MUST NOT** 在运行时直接行使任何权限:safety policy、permission、durability、evidence integrity、budget、data consent、promotion authority 全部保持人工控制,**不可被优化掉**。这一平面对运行时是只读观察者:它读 trajectory,写 PolicyManifest,但绝不在 Plane A 里注入一个可执行步骤。

这三个平面之间的关系可以用一句话锚定:**Plane C 生产工件、Plane B 消费工件并提出请求、Plane A 是唯一的权威裁决者。** 一个策略候选**可以提议(propose),但永远不能授予(grant)**:这是三平面切分要保护的核心不变式。

> **关于 bash 与工具的口径(一处常见误解的澄清)。** microkernel **只**拥有 effect broker 与 capability admission,即"任何工具(bash 也在内)被允许做什么"的**权威**。至于**选哪个工具、用什么参数、按垂类如何调**,那是 Plane B 里可进化的 **tool_policy** slot。因此 bash 是"一个 effect 被内核中介并 admit 的工具",**而不是**"内核里的一段逻辑"。凡涉及"某个工具的选择与策略",一律在 Plane B;凡涉及"这个 effect 是否被允许发生",一律在 Plane A。举例:tool_policy 决定"对这个垂类的任务用 `rg` 而非 `grep`、并把超时设为 5s",这是 Plane B 的可进化决策;而"这次 `rg` 调用是否被允许读该路径、是否在 budget 内、其 effect 如何被 hash-chained 记录",这是 Plane A 的裁决。二者的边界即典型的 tool_policy 与 effect broker 分界。

### 2.2 中心工件:harness checkpoint (PolicyManifest)

三个平面在结构上围绕**一个中心工件**咬合:**PolicyManifest**,即 harness checkpoint。它是理解"这套体系如何连起来"的枢纽,因此在总览层就必须讲清。

PolicyManifest 是一个 **method-agnostic、versioned、diffable** 的工件,定义在 StrategySlot 这一策略空间之上(§5;此处指槽的**身份**,即 `core_evolve::StrategySlot` 这个 newtype(`crates/evolve/src/lib.rs:131`),不是同名的 `core_protocol::slot::StrategySlot` trait(`crates/protocol/src/slot.rs:140-150`))。已冻结的 `PolicyManifest` 形如 `{ schema_version, policy: PolicyRef, artifact_kind, artifact_locator, parent: Option<PolicyRef>, method, protocol: ProtocolRange, required_capabilities: BTreeSet<Capability>, training_dataset_digest: Option<String>, evaluation_suite_digest, base_model }`(crates/evolve/src/lib.rs:448-465;冻结快照见 crates/evolve/tests/policy_manifest_freeze.rs)。几处容易读错的地方:身份与版本不在顶层,而在 `policy: PolicyRef { slot, policy_id, version, digest }`(lib.rs:422-428),其中 `digest` 是工件字节的摘要而非可变 URL;把多个 slot 绑成一束是另一个契约 `PolicyBundle.policies: Vec<PolicyRef>`(lib.rs:526-531),不是 manifest 上的字段;权限一侧的字段是 `required_capabilities`,它是候选**所申请**的能力集合,方向与"上界"相反,天花板由 admission 侧的 slot 天花板与精确父天花板给出,候选只能声明、不能授予(见 §6.6);血缘由 `parent: Option<PolicyRef>` 加 `training_dataset_digest` / `evaluation_suite_digest` 两个摘要承载,而不是一份自由形态的 `provenance`。它的关键性质:

- **方法无关(method-agnostic)。** 无论候选是由 search/GEPA、SFT、preference optimization、GRPO 还是 offline RL 产生的,产出的**都是同一种 PolicyManifest**。训练方法可以任意替换,工件形态不变:这正是"harness checkpoint"这个名字的含义,它对 harness 而言,就像 model checkpoint 对权重而言。
- **像 release 一样被治理。** 它被一个**独立的 evaluator** 在**垂类自持的 held-out objective** 上打分,然后像发布一个版本一样被 promote / rollback。promotion 的每一跳(shadow -> canary -> active)都是人工门控的,且每一跳都保留确定性 rollback 到上一个已知点。
- **可跨冻结 base model 携带。** 同一份被调好的 harness checkpoint **MUST** 能在 >=2 个不同的冻结 model 上经 adapter+conformance seam 生效,不训练任何 model 权重。这就是"weights learn the prior; the harness learns the situation"在工件层的体现。失败模式是明确的:若某个 checkpoint 只在单一 model 上可用,它 **MUST NOT** 被标注为可迁移,transfer 算子在该情形下 **MUST** 拒绝生成迁移结果而非静默降级。
- **带 checkpoint 代数(checkpoint algebra)。** 对 PolicyManifest 定义了 `diff`、`merge`、`restrict`、`retire`、`transfer` 五个算子。它们的语义是:`diff(a, b)` 产出两份 manifest 的 slot 级差异集;`merge(a, b)` 在无冲突 slot 上合并两份 manifest,冲突 slot **MUST** 上报而非任意择一;`restrict(a, ceiling)` 收窄一份 manifest 的 `required_capabilities`,结果 **MUST** 是原集合与给定 ceiling 的交集(只减不增);`retire(a)` 把一份 manifest 标记为退役,使其 **MUST NOT** 再被 activate;`transfer(a, model)` 把一份 manifest 迁移到另一个冻结 model 的 adapter seam 上。这五个算子让 harness 的演化像代码/发布一样可 diff、可合并、可收窄权限、可退役、可跨环境迁移。

一句话概括这套体系的资产观:**"计算是一次性的;架构(harness)与上下文(context)才是会沉淀、增值的资产。"** PolicyManifest 就是这份沉淀资产的载体。harness 优化因此是一门**系统工程学科**,即一个在 typed policy space 上、针对 held-out objective 的优化问题,**而不是**启发式手艺(heuristic craft)。

### 2.3 稳定 typed ABI:三平面之间的唯一接缝

三个平面之间 **MUST** 只通过一套**稳定的 typed ABI** 通信;正是这套 ABI 把"几个分开的 crate"变成"可互换的 module",也是**可扩展性的保证机制**。ABI 由五个契约构成(各契约的完整字段与校验规则见 §4):

| ABI 契约 | 语义 | 方向 |
|---|---|---|
| `TaskEnvelope` | 进入 runtime 的一个 task + 其验收契约 | 外部/Plane C -> 系统 |
| `ContextRequest` | 一个 module 对**已授权** context 的一次 typed 请求 | Plane B -> Plane A |
| `ToolIntent` | 一次被提议的工具调用,按 purity/capability 定型 | Plane B -> Plane A |
| `EffectProposal` | 一个被提议的、对外可见的 effect,带 durable id | Plane A 内部:kernel gate <-> broker(gate 求交后由内核铸造,见 abi.md §4.1 契约总表) |
| `ArtifactRef` | 一个工件的 hash · schema · producer · provenance · permissions | 双向(结果与证据) |

这五个契约构成一个 typed 边界:任何跨平面的信息流,若不能被归约成这五种之一,即 **MUST NOT** 跨越平面。例如一个 planner slot 想获得仓库结构轮廓或项目指令,它 **MUST** 发出一个 `ContextRequest`(以 `selectors` 声明它请求哪一类已授权 context;可用的 selector 只有 `repo_outline` / `instructions` / `memory_keys` / `transcript` / `environment_facts` 五种,外加一个降级用的 `Unknown`,crates/protocol/src/context.rs:134-153),而 **MUST NOT** 直接持有文件句柄;读取某个具体文件不是任何 selector 能表达的,它与写盘一样走 `ToolIntent`(abi.md §4.4 步骤 2)。它想执行一次写盘,则 **MUST** 提出一个 `ToolIntent`,其 `admitted` 以空集起手(deny-by-default 构造,crates/protocol/src/intent.rs:70),交由 capability gate 求交裁决;带 durable `id` 的 `EffectProposal` 由内核在 gate 之后铸造(crates/protocol/src/effect.rs:58-60、abi.md §4.2.4),strategy module **MUST NOT** 自行铸造它,broker 再据此把 effect 落地。

可扩展性由两条规则保证,二者都**不触碰 microkernel**:

1. **StrategySlot 是开放的命名空间字符串类型,不是封闭 enum。** 除 9 个 well-known 的 core slot(`core/router`、`core/planner`、`core/context`、`core/memory`、`core/scheduler`、`core/tool_policy`、`core/verifier`、`core/model_router`、`core/collaboration`,crates/evolve/src/lib.rs:156-182)外,一个垂类 pack **MAY** 新增 slot(例如 `db/query_planner`、`support/escalation_router`)而无需改动内核。因为 slot 名是开放命名空间字符串而非 enum 变体,新增一个 slot 不需要重编译内核、不需要改 ABI、不需要一次内核发版:"加一个 slot"是一条贡献者路径,不是一次内核发版。命名空间不是约定而是强制文法:跨接缝的 slot 身份 `SlotId::validate` 要求恰好一个 `/`,即 `<domain>/<role>`(crates/protocol/src/slot.rs:68-87),一个无前缀的名字不是可构造的 slot 身份;一个未被任何 PolicyManifest 绑定的 slot 名对内核而言是无操作,内核不因存在未知 slot 名而改变行为。
2. **存在一个 code-valued 的 escape-hatch slot,带一条 `blob -> typed` 的晋升路径。** 这让 ADAS 式的自由形式发现(free-form discovery)能被**编译进**这套 typed 空间:先以 code blob 形态被发现,再经晋升路径变成一个受 ABI 约束的 typed slot。晋升路径 **MUST** 在晋升点强制该 blob 只能通过五个 ABI 契约与内核交互,即自由度不越过类型边界:一个尚未晋升的 code blob 在运行时 **MUST** 受与任何 typed slot 完全相同的 capability admission 约束,它不因"是自由形式的"而获得任何额外权限。

**微内核接口在进化过程中是否改变?** 不改变。ABI 与 microkernel 表面是**冻结的承重面**;evolution 只在 Plane B 的 slot 内替换实现、在 Plane C 里生产工件。一个新 PolicyManifest 上线,**MUST** 不引起 microkernel 字节变化,也 **MUST** 不引起 ABI 破坏性变更。ABI 的兼容性演进(新增可选字段、未知项优雅退化)走独立的、人工评审的 compat-negotiation 通道,与自我改进算子完全隔离:自我改进算子 **MUST NOT** 拥有触达该通道的能力。

### 2.4 架构总图 (Architecture diagram)

下图是三平面 + 中心工件 + ABI 接缝的整体视图。竖直向下的 `v` 表示"提议/激活/结果向下流",向右的 `>` 表示同一平面内的阶段推进。内核向上的 capability-scoped 返回路径见图后说明。

```text
+--------------------------------------------------------------+

|  Plane C: Evolution control plane   (offline, human-gated)   |
|                                                              |
|  trajectory > governed dataset > candidate producer >        |
|  admission > INDEPENDENT held-out eval > shadow > canary >   |
|  active           (+ deterministic rollback at every arrow)  |
+------------------------------+-------------------------------+
                               |  emits / promotes
                               v
                  +-------------------------------+
                  |  PolicyManifest               |
                  |  the HARNESS CHECKPOINT        |
                  |  typed | versioned | diffable  |
                  |  algebra: diff merge restrict  |
                  |          retire transfer       |
                  +---------------+---------------+
                                  |  activates (exact bundle pinned per run)
                                  v
+--------------------------------------------------------------+

|  Plane B: Strategy + world modules   (replaceable slots)     |
|                                                              |
|  router | planner | context | memory | scheduler |           |
|  tool_policy | verifier | model_router | collaboration       |
|  + vertical-added slots   + code-valued escape hatch         |
+------------------------------+-------------------------------+
                               |  typed proposals  (STABLE ABI)
                               |  TaskEnvelope | ContextRequest | ToolIntent
                               |  (EffectProposal 由内核准入后铸出,
                               |   ArtifactRef 是回流的证据句柄)
                               v
+--------------------------------------------------------------+

|  Plane A: Fixed MICROKERNEL / TCB   (frozen authority)        |
|                                                              |
|  identity + trust  |  capability admission (CapabilitySet,    |
|  intersection-only, capability-monotone)  |  single effect    |
|  broker  |  pure reducer  |  record / checkpoint / replay     |
|  (SHA-256 hash-chained, tamper-evident)  |  budgets /         |
|  deadlines / cancellation  |  version registry  |            |
|  kill / rollback  |  bounded agent-loop DRIVER                |
|                                                              |
|  MUST NOT: read files/env | call providers | build prompts | |
|  select context | spawn procs | parse MCP | render UI |      |
|  train or activate a policy                                  |
+------------------------------+-------------------------------+
                               |  capability-scoped effects only
                               v
+--------------------------------------------------------------+

|  Adapters (conformance-gated, NO ambient authority)          |
|  frozen model A | frozen model B | frontier API              |
|  ||  sandbox | repo | browser | db | MCP tools               |
+--------------------------------------------------------------+
```

图的读法与两条未在图中画出的返回边:

- **向下 = 提议与激活。** Plane C 向下**产出/晋升** PolicyManifest;PolicyManifest 向下**激活**成 Plane B 当前生效的 slot 配置(每次 run 精确 pin 一个 bundle);Plane B 向下经 ABI 向内核**提议** effect/tool/context;内核向下经 adapter 施加 capability-scoped 的 effect。
- **返回边一(内核 -> module)。** 内核对每个提议的裁决与结果**只以 capability-scoped 的形式**回给 module,绝不回传 ambient authority。即使一个提议被 admit,module 拿到的也只是"这次被授权做这件具体事"的结果,而非一份可复用的权限。
- **返回边二(运行时 -> Plane C)。** 内核 record 出的 hash-chained trajectory 是 Plane C 的**唯一**输入来源;Plane C 拿到的是**被治理、去授权**的证据,而非活的权限。这条边把"运行"与"进化"在数据上单向解耦:进化能观察历史,但不能反手拿到运行时权力。

一个贯穿全图的 worked example,展示一次"提议到证据"的完整往返:某个 tool_policy slot 决定对一个 coding 任务执行一次文件写。(1) 该 slot 提出一个 `ToolIntent`:`proposed_by` 是它自己,`call` 是模型请求的原文,`admitted` 以空集起手(deny-by-default 构造,crates/protocol/src/intent.rs:48-63、intent.rs:70);(2) 该 intent 经 stable ABI 下行至 Plane A;(3) capability gate 按 `call.name` 取该工具在注册表里声明的 `Capability`,与本次 run 的 ceiling 求交(`CapabilitySet::intersect`,crates/protocol/src/capability_set.rs:82),收窄出 `admitted`,交集为空即 deny-by-default;**求交之后,内核才把这次 effect 铸成 `EffectProposal`**,其 `id` 是 harness 铸造的 durable id(crates/protocol/src/effect.rs:58-60、abi.md §4.2.4 与 §4.4 步骤 4)。该 proposal 上既没有目标路径字段也没有内容 hash 字段(它只有一个 `workspace` 作用域根,crates/protocol/src/effect.rs:76-77):目标路径只作为 `arguments` 里那份脱敏、bounded 的审计投影出现(effect.rs:74-75),内容 hash 只出现在回流的 `ArtifactRef.hash` 上(crates/protocol/src/artifact.rs:312-315);(4) admit 后,唯一的 effect broker 通过一个 conformance-gated 的 repo adapter 施加这次写,并把该 effect 追加进 SHA-256 hash-chained journal;(5) 内核以 capability-scoped 结果(成功/失败 + 新的 ArtifactRef)回给该 slot,而不回传任何可复用权限;(6) 这条被记录的 effect 日后作为去授权证据进入 Plane C 的 trajectory 输入。整条链条中,slot 从未持有 ambient authority,权限只在内核内部、只针对这一次 effect 存在。

### 2.5 五个不变式 (five invariants)

体系里**每一个机制**,无论在哪个平面,都 **MUST** 被同一套五条不变式判定。它们是本规范用来判断"这个设计对不对"的统一标尺,后续各节的验收门都是这五条的具体化:

| 不变式 | 含义 | 结构后果 |
|---|---|---|
| **Bounded** | 每次执行都在显式的 budget / deadline / cancellation 之内 | budget 属于内核,module 不能放松它 |
| **Recoverable** | 任何状态都能被确定性地 rollback 到已知点 | checkpoint/replay + kill/rollback 属于内核 |
| **Reproducible** | 同一 pinned bundle + 同一输入 -> 同一结果 | pure reducer 无 I/O;per-run 精确 pin policy bundle |
| **Observable** | 每个 effect 都留下 tamper-evident 的证据 | SHA-256 hash-chained record,单一 effect broker journal |
| **Security-bounded** | deny-by-default;权限只能取交、不能取并 | 五个独立 capability class + `CapabilitySet` 上限,intersection-only,capability-monotone |

一条贯穿性的安全命题:**安全不能是自我改进算子的一个不动点(Safety cannot be a fixed point of the self-improving operator)。** 也就是说,进化循环 **MUST NOT** 有能力把上面任何一条不变式优化掉。落到 admission 上,这被写成一条硬规则:候选的 authority **MUST** 满足 `authority = subset( slot-ceiling INTERSECT exact-parent-ceiling )`,**intersection-only("never union")**;一个候选**可以提议,但 MUST NOT** 授予 capability、改写 evidence、放松 budget、伪造自己的 held-out 结果、或自我晋升(self-promote)。这条规则把"自我改进"限制在一个**权限只减不增**的格子里流动,因此再多轮进化也不会突破人工设定的安全天花板。

举一个具体的失败尝试与预期结果:某个候选 PolicyManifest 在训练中"发现"若把某 slot 的 authority 与 parent-ceiling 取并可提升 held-out 分数。按上述规则,该候选在 admission 处 **MUST** 被拒:`INTERSECT` 语义使任何"取并"的意图在数学上不可表达,candidate 在 `required_capabilities` 里申请的能力集合若超出交集,admission **MUST** 将其收窄回交集或整体拒绝,而 **MUST NOT** 授予其请求的更宽权限。同理,一个试图改写既有 hash-chained journal 条目以"掩盖"某次越权的候选,会因 record 是 tamper-evident(任一条目篡改都会破坏后继 hash 链)而被 Observable 不变式当场暴露。

### 2.6 内核"只做一件事" vs 系统"处理多样性"

一个自然的疑问是:一个 agent 要处理路由、规划、上下文、记忆、调度、工具、验证、协作等如此多样的决策,凭什么说内核"只做一件事"?本体系结构的回答是把这两个层次**刻意分开**:

- **microkernel 只做一件事:当那个不可谈判的权威。** 它不关心"怎么规划得更好"或"该选哪个工具",那些是会随垂类、随任务、随时间变的**品味问题**。内核只回答一个**同质**的问题:"这个被提议的 effect,在当前 identity、`CapabilitySet` 上限、budget、版本约束下,是否被允许发生,允许发生成什么样,并被如何不可篡改地记录。" 无论上面提议的是一次文件写、一次 provider 调用、还是一次 subagent fan-out,内核用**同一条**受审边界处理它们。多样性在内核眼里被 ABI 归一成了五种 typed proposal,于是"处理多样性"退化成"对五种契约做同一件事"。
- **多样性全部外移到 Plane B 的 slot。** 正因为把"品味"从内核里剥出去,系统才能承载无限多样、且**持续进化**的策略:router 可以有一百种、planner 可以按垂类换、tool_policy 可以被搜索。多样性越丰富,越需要一个**小而不变**的核来保证它们都在同一套 budget/authority/evidence 约束下运行。**内核的"小"与"单一",正是上层"大"与"多样"的前提,而不是它的对立面。**

因此这**不是**一个把内核也做成万能选择器的 AutoML 平台,而是一个**冻结核 + 可进化外壳**的 agent substrate:**evolution 只调 module/profile,永不做"内核选择",也不在运行时插入一个 agent 步骤去改内核。** 进化确实可以涉及 model 侧:存在一条可选的、经**同一个 conformance gate** 的 post-training 回流路径(curated data -> SFT/pref/RL -> 回流),且本平台产出的 governed trajectory **可以**被用作训练 model 的数据来源,但这些都发生在离线、人工门控的 Plane C 内,与运行时 TCB 严格隔离。至于**为什么从头写而不是复用现有 agent 源码**:业界成熟 coding agent 的架构大多把 authority、prompt 组装、context 选择、tool dispatch 与"内核"揉在一起,其"策略"以硬编码启发式散落各处,既不可 diff 也不可独立评测;要让"除内核外一切可进化、且安全不可被优化掉"成立,**冻结核 + typed ABI + 可 checkpoint 的策略空间**必须是**地基**而非事后改造,这正是本体系需要从结构上重新组织、而非在既有实现上打补丁的原因。

### 2.7 现状口径 (honest status)

本节描述的三平面契约是**目标契约(target contract),不是已达成的一致性声明(conformance claim)。** Core Code 目前处于 **pre-alpha**:它是一个**可运行但仍为模块化单体(modular monolith)**的系统;工作区已按 protocol / record / observability / provider / tools / sandbox / context / verification / MCP / scheduling / agents / kernel / CLI / evaluation / evolution-contract 等边界切分,且这些边界受机器校验(唯一路径责任、Cargo 依赖漂移检测),但**内核目前仍硬依赖约 10 个具体 crate**,CLI/TUI 仍参与运行时组装。因此 Core Code **尚未**声称 microkernel 一致性。**运行时的自我进化(live self-evolution)激活为 NO-GO**,全部进化循环停留在离线、人工门控的路径内;本规范**不含任何首方基准数字**。

成熟形态(mature form)的目标是一个体量与业界生产级 coding agent 相当的完整系统;但本节所述的规模与广度是**前瞻性的定位**,**MUST NOT** 被用来描述任何早期演示切片的范围。换言之,读者 **MUST** 把"成熟形态"的每一处描述读作目标契约,而 **MUST NOT** 据此推断当前切片已具备该规模;凡本节陈述与当前实现不符处,以本节所标 pre-alpha 现状为准。从当前模块化单体走向目标契约的抽取路径是明确的:(1) versioned canonical command/event envelope;(2) 产出 action request 的 pure state reducer;(3) 唯一的 capability + effect broker;(4) 注入式的 provider / world / context / verification / scheduler port;(5) 带 bounded flow control 的长驻 session runtime;(6) 供 CLI/TUI 及未来客户端使用的 versioned App Server。后续各节即沿这条路径逐块展开。