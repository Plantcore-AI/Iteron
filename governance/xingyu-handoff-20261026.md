# Iteron 全面接管与 0.0.31 发布交接

更新日期：2026-10-26。接管负责人：Xingyu Zhou（[@XZhouuuu](https://github.com/XZhouuuu)）。

**本文是当前执行与交接入口，不要求新 issue 或 PR。** [#443](https://github.com/Plantcore-AI/Iteron/issues/443)、[#445](https://github.com/Plantcore-AI/Iteron/issues/445)、[PR #444](https://github.com/Plantcore-AI/Iteron/pull/444) 和 [PR #446](https://github.com/Plantcore-AI/Iteron/pull/446) 按用户要求退役为历史追踪，由执行主线完成关闭并读回状态；本文不提前宣称关闭已完成。退役不等于其中的问题已解决。后续以本文、精确源码提交及新交接包中的执行收据为准。

Jamal 明确要求移交 Iteron 的代码所有权、未认领边界、审查协调、仓库权限和剩余工作；**0.0.31 由 Xingyu 负责发布**。本文不是 Xingyu 本人的接受声明、独立人工批准或发布证明。历史作者不改写；agent 不代人签收或 approve，不创建版本 tag，也不放宽发布门禁。

### 本次一次性直接落 main 的授权范围

Jamal 明确授权从 `c9245e5b88073f9d1cd32fdacf1698983264a444` 快进，纳入 `70541eb93ea234a79be88b6afadc0a61db72fe21` 的工程和运行时修复、`5cc99c2dc7c1ab76dd3b471f1ec8edde7b424dd7` 的所有权交接，以及本次文档收尾。前者包含真实 pre-dispatch deadline、host/CLI 与验证修复，**不是纯文档或单纯改负责人**。

临时 scoped Jamal bypass 仅限这一次快进；执行后必须移除该例外、恢复原保护并读回核验。这里只记录授权及要求，不声称推送或恢复已经完成；远端前后 HEAD、精确提交范围和保护恢复结果记录在新交接包。授权不等于独立 human review、测试全绿或 Xingyu 签收，也不是未来直接推送或绕过发布门的长期授权。官方 v0.0.30 tag 和发布资产保持原样；不把本次源码落 main 当成 v0.0.31 发布。

## 1. 已迁权限与源码生效条件

| 项目 | 本次已核实状态 | 不代表什么 |
| --- | --- | --- |
| 仓库权限 | `XZhouuuu`，user ID `81467490`，已有 Iteron ADMIN；无待接受邀请 | 不等于全部组织、云账号或个人身份转让 |
| main 规则 | 一次性例外前，个人 PR-only Owner bypass 已转 Xingyu 并读回；required checks、CODEOWNER、最新 push 人类批准、禁止强推/删除保留；本次例外及恢复须另有读回收据 | 不允许把 bypass 当正常审查通过或默认长期权限 |
| 版本创建 | `v* owner-created releases` 的个人创建权已转 Xingyu并读回 | 不允许提前消耗新版本号 |
| 发布审批 | `release` environment reviewer 已转 Xingyu并读回；其他开关、tag 部署限制保留 | 不等于候选 preflight 已通过 |
| 不可变保护 | immutable release 与版本 tag 禁更新/删除规则保持 | 不移动或删除既有 tag，不替换旧发布资产 |
| Mac runner | 既有进程恢复，GitHub 已显示 online | 不是新版本 native 构建或验收 PASS |
| Linux runner | 同一既有 ARM64 runner 已添加并读回两个 release 标签，原标签保留 | ARM64 与 x86 cross/QEMU 串行，不是两台 runner 或原生 x86 |
| 源码 Owner | 本交接提交的 registry 为 `xingyu-owner`；763 条生成 CODEOWNERS 均指向 Xingyu；以快进后的远端 HEAD 读回确认 main 生效 | 提交中的配置不是已完成推送或真人签收的证明 |
| 历史 issue/PR 移交 | 退役操作前已读回 25 个 open issue、12 个原有 open PR 均含 Xingyu，既有执行人保留；该数量是当时快照 | 本次只退役指定追踪，不把关闭计为实施或验收，不自动关闭其他未完成事项 |

权限移交仅限 Iteron。旧账号既有组织/仓库 Admin 不在尚未签收时盲目删除；接管后由新 Owner 复核访问清单。凭据只通过授权管理入口交接或轮换，不进入源码、issue、日志或本文。

## 2. 任务总数与计数口径

| 类别 | 总数 | 当前状态 | 下一门 |
| --- | ---: | --- | --- |
| 主边界 | 42 | 23 个非 critical `active`；19 个 critical `open` | 新 Owner 接受任命；critical 需真人独立 reviewer 与激活证据 |
| 跨边界 invariant overlays | 13 | 全部 `open`，要求独立审查 | Xingyu 安排真实审查人和任务证据 |
| 优化不变量审查 packet | 1,359 项 / 33 批 | source-current packet，人工批准 0 | 每批由责任真人审查，验证证据后记入 ledger |
| 生成 CODEOWNERS | 763 条 | 本交接提交中的所有权配置 | 快进后读回 main 精确提交；远端权限和 canary 另验 |

旧 packet 的 830 项 / 32 批已过时，不可重用其 token。新 token、生成 freeze、或修改 Owner 都不代表批准。`bootstrap` 保留，不能把上述 23 个登记为 active 的边界解读成整个治理系统或产品已经验收。

### 2.1 42 个主边界逐项交接

以下每一项的接手协调负责人均为 **@XZhouuuu**。表中 `active` 只描述本交接提交中的 registry 配置；`open` 的 primary 尚未正式激活，由新 Owner fallback 承担协调责任。所有路径和依赖以 [boundaries.json](boundaries.json) 为准，远端是否已采用该提交以执行收据为准。

| # | 精确 boundary ID | 职责 | 登记状态与下一任务 |
| ---: | --- | --- | --- |
| 1 | `project-governance` | 人类所有权、规则与治理 | critical/open；安排独立 reviewer、完成激活 |
| 2 | `community-entry` | 社区入口与贡献流程 | active；确认接管、维护入口与响应 |
| 3 | `security-policy` | 安全策略与漏洞流程 | critical/open；安排独立 reviewer、完成激活 |
| 4 | `architecture-roadmap` | 架构与路线图 | active；核对路线图与实际实现 |
| 5 | `documentation-site` | 文档站点 | active；保持严格构建、导航和事实一致 |
| 6 | `build-release` | 构建与发布 | critical/open；安排独立 reviewer、完成发布门 |
| 7 | `protocol-compat` | 协议兼容 | critical/open；安排独立 reviewer、验历史兼容 |
| 8 | `kernel-reduction` | Kernel reducer/driver | critical/open；安排独立 reviewer、验归约契约 |
| 9 | `kernel-runtime` | Kernel 运行时 | critical/open；安排独立 reviewer、验运行时不变量 |
| 10 | `kernel-effects` | 效果准入与确定性 | critical/open；安排独立 reviewer、验 effect 门 |
| 11 | `telemetry-export` | 遥测导出 | critical/open；安排独立 reviewer、验边界与泄漏防护 |
| 12 | `kernel-hooks` | 生命周期 hooks | critical/open；安排独立 reviewer、验权限与顺序 |
| 13 | `record-core` | 持久记录核心 | critical/open；安排独立 reviewer、验持久化与恢复 |
| 14 | `record-sessions` | Session 索引与会话管理 | active；维护恢复、索引和会话证据 |
| 15 | `observability` | 可观测性 | active；维护有效事件、指标和界限 |
| 16 | `scheduler` | 调度 | active；维护有界准入和公平性证据 |
| 17 | `provider-core` | 模型提供方核心 | active；维护调用、错误与预算契约 |
| 18 | `provider-adapters` | 模型提供方适配 | active；维护各 adapter 独立兼容证据 |
| 19 | `mcp-interop` | MCP 互操作 | critical/open；安排独立 reviewer、验真实互操作 |
| 20 | `language-server-lifecycle` | LSP 生命周期 | active；维护启动、取消和回收 |
| 21 | `workspace-change-set` | 工作区变更集合 | active；维护预像、应用和回退 |
| 22 | `status-surface` | 状态展示 | active；保持状态来源和实际执行一致 |
| 23 | `support-bundle` | 支持材料与诊断包 | critical/open；安排独立 reviewer、验脱敏边界 |
| 24 | `plugin-marketplace` | 插件市场 | critical/open；安排独立 reviewer、验信任和安装 |
| 25 | `context-core` | 上下文核心 | active；维护上下文预算和恢复契约 |
| 26 | `context-knowledge` | 知识与记忆上下文 | active；维护知识来源和可回溯性 |
| 27 | `agent-catalog` | Agent 定义目录 | active；维护定义、模型能力和配置 |
| 28 | `agent-controller` | 持久 Agent 控制器 | critical/open；安排独立 reviewer、验控制权与恢复 |
| 29 | `agent-orchestration` | Agent 编排 | active；维护消息、子任务与生命周期 |
| 30 | `evolution-control` | Evolution 控制 | critical/open；安排独立 reviewer、验提升权限 |
| 31 | `sandbox` | 沙箱 | critical/open；安排独立 reviewer、验真实平台隔离 |
| 32 | `tools-core` | 工具核心 | critical/open；安排独立 reviewer、验工具授权 |
| 33 | `tools-execution` | 工具执行 | critical/open；安排独立 reviewer、验进程/effect 回收 |
| 34 | `tools-context` | 工具上下文 | active；维护工具描述和上下文约束 |
| 35 | `verification` | 结果验证 | active；维护结果判定及证据来源 |
| 36 | `workflow-engine` | 工作流引擎 | active；维护动态工作流和有界执行 |
| 37 | `evaluation` | 评测 | active；维护真实基线、数据与复现 |
| 38 | `tunability-registry` | 可调参数及纯解析器 | active；维护精确声明、生成与校验 |
| 39 | `cli-host` | CLI 共用后端 | critical/open；安排独立 reviewer、验运行时集成 |
| 40 | `cli-tui` | 终端交互 | active；维护语义与真实 PTY 双重证据 |
| 41 | `cli-render` | 终端渲染 | active；维护布局、刷新和终端恢复 |
| 42 | `cli-output` | CLI 机器输出 | active；维护终局、版本和机器契约 |

### 2.2 13 个 overlay 的独立审查任务

每项协调负责人均为 **@XZhouuuu**；当前全部 `open`。独立 reviewer 必须是真人且满足项目独立性规则，不能由一个人同时充当 primary 和唯一独立审查人。下表是任务，不是已批准记录。

| # | 精确 overlay ID | 待安排的审查 |
| ---: | --- | --- |
| 1 | `governance-enforcement` | registry、可信校验器、生成视图与 CI 拦截 |
| 2 | `public-compatibility` | 公共 DTO/trait/schema 与消费者兼容 |
| 3 | `tcb-authority` | 权限、信任、effects、沙箱与外部进程权威 |
| 4 | `durability-replay` | 持久提交、恢复、重放及不确定效果 |
| 5 | `secrets-redaction` | 凭据处理、诊断与导出脱敏 |
| 6 | `boundedness` | 时间、队列、内存、输出、重试和并发界限 |
| 7 | `provider-routing` | provider 路由、回退及经济约束 |
| 8 | `frontend-contract` | CLI/TUI/AppServer 的实际交互契约 |
| 9 | `cost-accounting` | 成本、预算预留与使用量记账 |
| 10 | `eval-ground-truth` | 评测真值、数据隔离和可复现性 |
| 11 | `evolution-promotion` | 策略评估、批准与提升边界 |
| 12 | `release-supply` | 依赖、锁文件、工具链、发布与供应链 |
| 13 | `public-truth` | 架构、性能、安全和产品声明的证据 |

## 3. 按顺序完成接管和发布

### P0：真人接管、审查与治理

- [ ] Xingyu 亲自确认权限、边界、发布和 on-call 范围，补充可核对的接受记录；本文和交接收据是入口，不要求新建 issue 或 PR。
- [ ] 核对本次快进执行收据、main 精确 HEAD、registry 与生成 CODEOWNERS 一致性，以及临时 bypass 已移除、原保护已恢复的读回证据。不要直接手改生成文件。
- [ ] 复核 `70541eb9` 修复与本次交接的跨边界影响、实际 CI 和下述未解释测试失败；直接落 main 的授权不代替独立审查或失败归因。
- [ ] 为 19 个 critical 边界和 13 个 overlays 安排独立真人；逐项记录审查和激活条件。
- [ ] 审查最新 1,359 项 / 33 批不变量 packet；approval ledger 目前为 0，不重用旧 packet/token。
- [ ] 用非 bypass canary 证明错误声明、缺批准、过期批准、失败检查都会阻止 merge；保留失败证据。
- [x] 已读回历史 open issue/PR 的协调人移交快照。保留 #416 的 @gomnitrix 等已有执行人；指定追踪退役后的状态另以读回收据记录，不自动关闭其他未完成事项。

### P1：0.0.31 正式发布，先全部预检再打 tag

- [ ] 以本文的发布清单和精确收据为总账，先修当前依赖安全门。核对 rustls 公告、当前漏洞库及可复用更新候选（[PR #432](https://github.com/Plantcore-AI/Iteron/pull/432) 仅作参考）；`0.23.43` 至至少 `0.23.45` 的修复不能用旧漏洞库 PASS 代替。
- [ ] 按精确锁文件独立审查 MCP 测试依赖告警和可复用修复；不把测试供应链告警误计为 Rust runtime 漏洞，也不盲用批量更新。
- [ ] 使用真正旧 v0.0.30 validator 验最终候选。旧检查要求 `drive(launch)/serve(launch)`，Box 转发使用 `drive(*launch)/serve(*launch)`；如需兼容桥，限定精确范围、人工 review、保留负例。新 validator 自检不是 predecessor 验证。
- [ ] 审查 [v0.0.31-preparation.patch](v0.0.31-preparation.patch)：仅 `Cargo.toml`、`Cargo.lock`、`CHANGELOG.md`、`governance/schema-compatibility.json` 四文件的独立准备补丁，以 `70541eb9` 为应用基线。补丁采用零上下文；确认四文件仍与该基线一致后运行 `git apply --check --unidiff-zero governance/v0.0.31-preparation.patch`，再由负责人决定应用；基线有变先重新审查生成，不盲套。本交接未应用补丁，也不存在由此自动获得的 `.31` binary/测试收据。
- [ ] 冻结 workspace/version/lock/CHANGELOG/schema ordinal 和精确源码提交，重新运行受影响验证；保留历史契约字段，不把 `.30` 短版本二进制改标签。
- [ ] 让 Mac ARM64、Linux ARM64、Linux x86 cross/QEMU、Windows x86_64 实际取得任务并通过构建、native/明确 emulated 检查和包验收。runner online/标签读回不是 PASS；两个 Linux 目标使用同一 runner，按串行能力安排时间。
- [ ] 最终 protected-main 精确提交 CI 与无 tag 的完整 release preflight 全绿；许可证、SBOM、provenance、四平台包、三可执行文件同版本/commit、安装和回退均有收据。
- [ ] Xingyu 用自己的身份完成发布审批演练与 Owner gate，再经既有 `release-tools/create_release_tag.sh` 创建唯一 annotated `v0.0.31`。不绕前置门，不手动发布旧资产，不重蹈 `.28/.29` 手工补包路径。
- [ ] 发布后核对 immutable、完整资产 digest/attestation，实际下载资产执行固定版和 latest 安装 canary；最后从真正 `.31` 资产重做中文交接包。

### P2：真人恢复演练与签收

- [ ] 在授权的私有隔离位置选择真实备份：停止写者、完整备份、恢复副本、校验历史/对象/权限、执行恢复后的下一轮；记录恢复点和耗时，不公开备份内容。
- [ ] 回退使用旧 binary 加迁移前备份；禁止旧 binary 打开已升级 store。`UNKNOWN` effect 不自动重放，不用合成恢复测试冒充真实演练。
- [ ] 新 Owner 核验 runner、签名和发布 secret 的授权管理入口及轮换责任；不复制秘密值到 GitHub。
- [ ] Xingyu 亲自签收精确版本、代码/资产、已接受限制、恢复/回退收据、on-call 和旧权限复核清单。未签收前不宣称全面接管验收完成。

## 4. 可以复用的证据及明确限制

历史修复候选提交为 `70541eb93ea234a79be88b6afadc0a61db72fe21`，基线是官方 v0.0.30 的 `c9245e5b88073f9d1cd32fdacf1698983264a444`。该提交已有收据：14 个本地源码门通过；all-target 累计 5,220 passed、0 failed、8 ignored（非去重，ignored 不算 PASS）；Mac ARM64 optimized 5 项黑盒和 2 项签名/真实 PTY、Linux ARM64 dev 5 项通过；两个真实 provider 场景通过；MCP 1,534 checks 和 4 unsupported；发布工具 122 tests、19 条合成安装旅程通过。已退役追踪中的摘要只是历史索引，不是当前执行入口。

**本轮 `5cc99c2d` 全量测试没有全绿：host 套件为 1,427 PASS / 1 FAILED；失败项使用同一 binary 精确复跑为 1 PASS，但根因未证实，不能据此抹掉首次失败或宣称已修。后续 target 未运行。** 新交接包应同时保留失败与精确复跑收据，后续仍需定位原因并完成剩余门。`70541eb9` 的历史 5,220 条通过记录不覆盖这轮提交与执行。

这些证据可帮助审查已做修复，**不能改称 0.0.31 新二进制、GitHub CI 全绿、全平台验收、任意模型兼容、P95、Apple notarization、真实备份恢复或真人批准**。旧失败收据和旧发布资产继续保留。每一项未完成工作都应在本文及交接收据中留下负责人、精确源码/资产身份、验证结果与下一门；不要求继续使用已退役 issue/PR，转交与追踪关闭均不等于完成。
