# 技术规格 (Specification)

本节是 Core Code 的**完整技术规格**：一份自包含、正式的规范性文档，定义了这套可训练 Agent-Harness 基座的体系结构、接口与进化边界。它比 *Concepts* 章节更完整、更规范（带 RFC-2119 的 MUST/SHOULD/MAY 约定），面向要实现、扩展或评审本系统的工程师。

## 命题

> **Transformer 是模型的通用、可训练架构；Core Code 要成为 harness 的通用、可训练架构。**

专精化一个 agent，意味着训练它的 **harness**，而不是训练那个 model。除**微内核 (microkernel)** 外，一个 agent 的每一个非内核决策：路由、规划、上下文、记忆、调度、工具策略、校验、模型路由、多 agent 协作：都是同一个 typed 策略空间里的一个 policy；其被训练出来的状态被封装为一个一等制品：**harness checkpoint (PolicyManifest)**。*权重学的是先验，harness 学的是情境。*

## 如何阅读本规格

| 章节 | 内容 |
|---|---|
| [约定与术语](conventions.md) | 规范性语言 (RFC-2119)、术语表、两条贯穿全文的规范性结论 |
| [引言与定位](positioning.md) | 命题、问题陈述、为什么开源、为什么可进化 |
| [体系结构总览](architecture-overview.md) | 三个平面、五条不变量、以 harness checkpoint 为中心 |
| [微内核规格](microkernel.md) | 固定 TCB 的精确职责与负空间（含 bash 归属：R1） |
| [稳定类型 ABI](abi.md) | 五个契约与一次端到端往返；接口在进化下不变 |
| [策略模块与可进化槽](strategy-modules.md) | 9 个核心 StrategySlot：可调什么、基本形态、如何与内核交互 |
| [进化边界与 PolicyManifest](evolution.md) | 离线、非权威、人工门控的进化管线；能力单调准入；独立评估 |
| [通用能力映射](capability-mapping.md) | 生产级编码 Agent 的每项能力落在哪：内核 / 策略槽 / 世界模块 |
| [一致性与安全模型](conformance-and-security.md) | 符合本规范的条件；统一的威胁模型；变更控制 |

> **成熟度声明。** Core Code 目前为 pre-alpha：可编译、可运行，但仍是模块化单体，线上自进化激活为 NO-GO。本规格描述的是**目标契约**与一条明确的抽取路径；一切定位性论断为前瞻性。
