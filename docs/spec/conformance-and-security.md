# 14. 一致性 (Conformance)

一个实现声称「符合本规范」（a conformant Core Code implementation），**MUST** 同时满足以下条件；未满足任一「MUST」即为不符合。本节是 §0.1 规范性语言的汇总落地。

**C1（微内核边界）。** 存在一个可识别的微内核 TCB，其职责集合是 §3 所列职责的子集或全集，且它 **MUST** 遵守 §3 的负空间：不读文件/环境变量、不调用 provider、不构造 prompt、不选择 context、不 spawn 进程、不解析 MCP、不渲染 UI、不训练或激活 policy。

**C2（唯一副作用出口）。** 一切外部可见副作用 **MUST** 经由唯一的 effect broker，并被赋予持久身份与终态；一个未知终态 **MUST NOT** 被跨崩溃自动重放。

**C3（能力单调）。** 能力准入 **MUST** 实现交集规则（授权 = subset(slot ceiling  INTERSECT  父辈 ceiling)），**MUST NOT** 出现并集式扩权；任一 candidate **MUST NOT** 授予自身能力、改写证据、放松预算或自我晋升。

**C4（稳定 ABI）。** 策略模块与微内核之间的一切通信 **MUST** 只经由 §4 的五个 ABI 契约；ABI 形状 **MUST NOT** 在运行内或进化过程中改变，只走 §16 的版本化演进。

**C5（策略空间）。** 除微内核外的每一个非内核决策 **MUST** 表达为某个 StrategySlot 的 policy；StrategySlot 命名空间 **MUST** 是开放的，允许垂类扩展槽而不改微内核。

**C6（进化非权威）。** 若实现提供进化能力，则该进化 **MUST** 是离线、非权威、人类把关的，产出 **MUST** 是一个经 admission 与独立 held-out 评估的 PolicyManifest；producer **MUST NOT** 能伪造其晋升信号。运行时微内核 **MUST NOT** 参与产生或激活 policy。

**C7（五条不变量）。** 实现的每一机制 **MUST** 可被 Bounded / Recoverable / Reproducible / Observable / Security-bounded 五条不变量逐条检验，并 **SHOULD** 附带证明该检验的测试或证据。

**C8（诚实门）。** 实现 **MUST NOT** 声称尚未达成的一致性等级；未实现的部分 **MUST** 以「typed 契约 + 基线 + 抽取路径」如实表述，而非表述为已实现（对齐 §0 诚实门与 pre-alpha 现状）。

> **当前实现的一致性自评（pre-alpha）。** 现状**部分满足** C1 至 C5 的类型契约，但微内核仍硬依赖 3 个具体 crate（`core-protocol`/`core-record`/`core-obs`；此前所记的「约 10 个」已不再成立，C1 的抽取已在收尾但尚未完成）、Bounded 不变量仅部分强制（若干内部通道尚未有界）；C6 的进化管线以 typed 契约 + 一个离线 producer + 独立评估器契约存在，但线上激活为 NO-GO。故当前 Core Code 应表述为「一个可运行的模块化单体 + 一条明确的抽取路径」，而非「已符合微内核规范的实现」。

---

## 15. 安全与威胁模型 (Security & Threat Model)

本节把散落于 §3（负空间与准入）、§6（能力单调准入与独立评估）、§4/§0.3 的安全断言汇总为一个统一的威胁模型，明确**证明了什么、结构上防御了什么、以及什么被显式置于范围之外**。核心立场：**安全 MUST NOT 是自进化算子的不动点**：一个能自我改进的算子，不得放松它本应受其约束的边界。

**信任模型与假设。** 被信任的根是：微内核的代码与其冻结的边界、independent evaluator 的签名密钥、被钉住的 held-out 评测集摘要、以及人类掌握的晋升权威（「不可被优化掉」）。被视为**不可信输入**的是：模型输出、仓库文件、Web 页面、工具输出、MCP 描述、项目指令、以及任一 candidate PolicyManifest：它们带显式的信任出处，可以指导任务，但**不因含有祈使语气而获得操作者权威**。

**被证明的（machine-checkable）。** (a) 晋升下授权单调不增（交集准入，"never union"）；(b) 无自我晋升（晋升权威与 candidate producer 分离）。

**被结构性防御的（契约设计，尚待 live red-team）。** producer 无法伪造其晋升信号：independent evaluator 是一个 producer 无法冒充的独立签名身份，且 producer 无 eval/activation 句柄。这正是防「自进化算子攻击自己的 verifier」这一已知失效模式的结构性修复。

**被显式置于范围之外（命名的残余攻击面）。** 以下 **不在**本规范的安全断言内，实现方 **MUST** 单独处理并 **SHOULD** 红队检验：一个**不诚实或被攻陷的 evaluator**；一个被污染或可被博弈的 held-out 评测集；**在授权内**的 reward-hacking（准入不阻止「合法权限内」的坏行为）；下一代 candidate 的**数据集投毒**；以及一切**语义安全**（「中介不等于语义安全」：端到端论证：把副作用统一中介，并不保证副作用在语义上是「好」的）。本规范只声称**权威爆炸半径**的有界，不声称语义正确。

**同意与轨迹回流治理 (consent regime)。** 轨迹、修正与 held-out 数据是敏感资产。任何将轨迹回流用于（可选的）model post-training 的路径 **MUST** 以记录在案的同意 (recorded consent) 为前提，且 **MUST NOT** 超出该同意所覆盖的数据用途；数据面**永不**因被回流而获得权威。删除/撤销 **MUST** 传播到未来的上下文与数据集（记录本身的防篡改性不等于其内容为真，故内容级撤销走 record 的 tombstone 机制，而非改链）。

**deny-by-default。** 权限模式构成一张覆盖能力格的策略表；plan 模式为硬只读叠加；trust-mutating 与 irreversible-external 两类动作 **MUST NOT** 被任何模式或会话规则自动批准。仓库配置只能**收紧**一个已授予的信任或预算，**MUST NOT** 凭空铸造代码执行、provider 路由、MCP 进程或生命周期 hook。

---

## 16. 变更控制 (Change Control)

**本规范文档的变更控制。** 本文档以本文档的版本字段管理；每次实质修订递增版本并在此登记「变更了什么意图/范围以及为什么」。§0.3 的两条规范性正本（R1、R2）与两条 canonical 结论一经变更，**MUST** 在此显式记录，并检查全文引用一致性。

**稳定类型 ABI 的版本演进。** ABI（§4）是产品的长期兼容面，其演进 **MUST** 遵守：
- 每个 envelope 携带版本；未知字段/变体走前向兼容降级（如 `#[serde(other)]`）而非硬失败。
- 破坏性变更 **MUST** 走一次显式的 `PROTOCOL_VERSION` 跃迁（`crates/protocol/src/wire.rs:40`，现值 `1`），并附一致性测试；是否构成破坏性变更由受信基线的 surface 集比对机器判定，见 `governance/schema-compatibility.json` 与 `core-xtask boundaries check-base` / `check-pr`（§4.3(a)）。**不存在**兼容性协商：一次 run 只钉死并只接受恰好一个 `PROTOCOL_VERSION` 的消息，版本 skew 由 `SqEnvelope::into_current` 硬拒为 `ProtocolVersionError`（`crates/protocol/src/wire.rs:93-96`），既无 min/supported 版本协商，也无能力交换。
- 一个 PolicyManifest **MUST** 声明其所依赖的 ABI 版本；跨 ABI 版本的 checkpoint 迁移 **MUST** 经 §6 的同一道评测门再入。

**PolicyManifest 的版本与晋升。** 每个 candidate PolicyManifest 有不可变身份与血缘 (lineage)；晋升/回滚是对「已认证、定形的离线发布记录 + active-bundle 指针」的推进，**MUST** 保持确定性回滚能力。

**弃用策略。** 面向公众的接口（CLI、配置、记录格式、ABI）的弃用 **MUST** 有一个由一致性测试支撑的、可读的弃用窗口；不得静默破坏既有配置或记录。
