# Issue #344 执行计划：Windows lane 与 release gate

> 跟踪 issue: [https://github.com/Plantcore-AI/Iteron/issues/344](https://github.com/Plantcore-AI/Iteron/issues/344)
> 范围、授权与非阻塞约定以 issue 为准。本计划只描述如何落地，不覆盖 issue 已有内容。

---

## 1. 最终目标

让 Iteron 正式发布一个包含 Windows 归档（`x86_64-pc-windows-msvc`）的 release，并证明它在干净的 Windows 机器上可用。

## 2. 完成标准

- [x] 主干上的 Windows 检查为绿色，耗时是真实编译时间，而不是测试超时。
- [ ] `release / validate` 在 `workflow_dispatch` 排练中完整通过。
- [ ] 存在一个 tag push 触发的 release，产物列表中包含 Windows 归档。
- [ ] 有一份可重跑的 Windows 安装验证记录：在从未安装过 Iteron 的 Windows 机器上下载归档、校验 digest、解压、运行 `iteron.exe --version`。
- [ ] `docs/reference/platforms.md` 与 Windows 实际状态一致。
- [ ] 有一份书面的 Windows sandbox 决策声明。

## 3. 前置约定

- 任何 release tag 必须是 annotated tag（见 `docs/development/releasing.md`）。
- 在打正式 tag 前，同一 commit 必须先通过 `workflow_dispatch` 从分支完整跑通 `release.yml`。
- `plantcore-win` 是团队共用机器，使用时需隔离 target dir、控制运行时长、事后清理。

---

## 4. 阶段计划

### 阶段 0：ConPTY 挂起测试排查

**目标**：定位并修复 `crates/cli/tests/windows_conpty.rs::native_conpty_conhost_signal_degrades_links_notifications_and_keyboard` 挂起。

1. 在 `plantcore-win` 上 clone/checkout 代码到独立目录。
2. 设置独立 `CARGO_TARGET_DIR`，例如 `C:\\iteron-ci-target\\bowei-debug`。
3. 单独运行该测试，确认是否必现：
  ```powershell
   cargo test -p iteron-cli --test windows_conpty native_conpty_conhost_signal_degrades_links_notifications_and_keyboard
  ```
4. 读取 `windows_conpty.rs` 源码，理解测试等待的事件链。
5. 在关键 `await`/`recv` 点加 `eprintln!` 或 `tracing` 日志，定位最后停在哪一行。
6. 逐步简化测试，保留最小失败用例。
7. 修复后清理日志，确保主干 Windows lane 变绿。

**验收**：该测试在 CI 和 `plantcore-win` 上都能在合理时间内完成，不再触发 15 分钟 action timeout。

---

### 阶段 1：release/validate 可诊断化

**目标**：把 `release.yml` 中 `release / validate` 的静默断言改成会说话的断言。

1. 通读 `.github/workflows/release.yml` 的 `release / validate` job。
2. 列出所有裸 `test`、`[[ ... ]]` 等断言。
3. 为每个断言添加失败输出：
  - 正在检查什么
  - 期望值
  - 实际值
4. 保持原有逻辑不变，只增加诊断信息。
5. 重点处理 tag 类型检查：如果是 lightweight tag，输出明确错误和操作命令：
  ```text
   Tag vX.Y.Z is a lightweight tag; releases require an annotated tag.
   Run: git tag -a vX.Y.Z -m "Iteron X.Y.Z" && git push origin vX.Y.Z
  ```
6. 在临时分支 `rehearse/release-validate` 上通过 `workflow_dispatch` 触发 release，验证诊断信息有效。

**验收**：故意构造失败场景时，日志能直接指出失败点和对比值。

---

### 阶段 2：逐个打通 release/validate 关卡

**目标**：让 `release / validate` 在分支 dispatch 上完整通过。

已知需要面对的关卡包括：

- protected CI evidence
- immutable schema-compatibility predecessor
- version/source-commit contract（含 annotated-tag 要求）

步骤：

1. 在 `rehearse/release-validate` 分支上 dispatch `release.yml`。
2. 记录失败步骤和诊断输出。
3. 修复失败原因（每次只修一个，保持改动小）。
4. 重新 dispatch，直到 `release / validate` 通过。
5. 确认 `release / ${{ matrix.target }}` 中的 Windows leg 能实际执行。

**验收**：同一 commit 在 `workflow_dispatch` 下完整跑通 release 流程。

---

### 阶段 3：规范 tag 创建流程

**目标**：防止未来再次出现 lightweight tag 烧毁版本号。

1. 新建 `release-tools/create_release_tag.sh`：
  - 强制使用 `git tag -a`。
  - 检查工作区干净。
  - 检查当前分支为 `main`。
  - 检查版本号与 workspace manifest 一致。
  - 使用 `gh api` 查询当前 commit 是否有成功的 `workflow_dispatch` release run；找不到则拒绝。
  - 没有 `gh` CLI 或有效 token 时直接失败。
  - 输出创建的 tag 信息，push 前要求确认。
2. 可选：在 `.githooks/pre-push` 提供 hook 模板，拦截 lightweight tag push（需开发者手动安装）。
3. 更新 `docs/development/releasing.md`，把"必须使用 `release-tools/create_release_tag.sh`"写入流程。

**验收**：

- 用 lightweight tag 调用脚本会被拒绝。
- 没有成功 branch dispatch 的 commit 调用脚本会被拒绝。
- 正常流程下能创建并推送 annotated tag。

---

### 阶段 4：文档与 sandbox 声明

**目标**：让公开文档与 Windows 实际状态一致。

1. 读取 `docs/reference/platforms.md`。
2. 更新其中关于 Windows 的描述，明确：
  - 支持的目标 triplet。
  - 当前不提供 sandbox/confinement。
  - 安装方式和限制。
3. 撰写 Windows sandbox 决策声明，放在 `docs/reference/platforms.md` 或相邻位置：
  - Windows 当前未实现 sandbox/confinement。
  - 在 Windows 上运行等同于在主机上直接运行，没有额外隔离。
  - 不建议在不可信输入或多租户场景下使用 Windows 版 Iteron。
  - 实现 Windows sandbox backend 不在当前 scope。

**验收**：`docs/reference/platforms.md` 反映真实状态，读者不会因文档产生错误预期。

**注意**：本阶段的文档改动必须作为同一个 PR 的一部分，与阶段 0–3 的代码改动一起合入 `main`，而不是等到 release 发布后再补。

---

### 阶段 5：正式发布并验证 Windows 归档

**目标**：发布一个带 Windows 归档的 release，并录制安装验证。

1. 阶段 0–4 的改动完成后，将同一 commit push 到 `rehearse/release-validate`。
2. 在 `rehearse/release-validate` 上通过 `workflow_dispatch` 完整跑通 `release.yml`。
 这是 PR 合入前的强制前提：没跑通就不合入。
3. 发起 PR，将验证通过的 commit 合入 `main`。
4. 合入后，在 `main` 上再次通过 `workflow_dispatch` 完整跑通 `release.yml`，确认合并后的状态仍然 green。
5. 确认目标 commit green 后，使用 `release-tools/create_release_tag.sh` 在 `main` 上创建并推送 annotated tag（例如 `v0.0.14`）。
6. 等待 tag push 触发 `release.yml` 并完整跑通。
7. 在 `plantcore-win` 上（或另一台干净 Windows 机器）录制以下过程：
  - 从 GitHub Release 下载 Windows 归档。
  - 校验 SHA-256 digest（与 release 页面/SHA256SUMS 对比）。
  - 解压归档。
  - 用绝对路径运行 `iteron.exe --version`，确认版本号正确。
  - 可选：验证篡改后的归档会被拒绝。
8. 把记录保存为可重跑的 transcript（命令 + 输出），作为交付物。

**验收**：

- Release 产物列表包含 `iteron-X.Y.Z-x86_64-pc-windows-msvc.zip`。
- transcript 可由他人照着重跑。

---

## 5. 决策记录


| 决策                    | 选择                                                               | 原因                            |
| --------------------- | ---------------------------------------------------------------- | ----------------------------- |
| release/validate 改造顺序 | A（annotated tag 检测）→ B（全局断言诊断化）                                  | 先堵住已知的版本号烧毁风险，再照亮其他潜在问题       |
| tag 创建方式              | `release-tools/create_release_tag.sh` + CI 兜底 + 可选 pre-push hook | 无法强制所有开发者使用 hook，CI 兜底是唯一强制防线 |
| 脚本严格程度                | 最严格：检查工作区干净、main 分支、版本号一致、branch dispatch 已通过                    | 防止再次烧毁版本号                     |
| 排练分支                  | `rehearse/release-validate`                                      | 干净、可删、不影响长期分支                 |
| Windows 复现环境          | `plantcore-win`，独立 `CARGO_TARGET_DIR`                            | 团队共用机器，必须隔离和清理                |
| 安装验证记录                | 用绝对路径运行刚解压的 `iteron.exe --version`                               | 避免 PATH 中残留旧版本干扰              |
| sandbox 声明            | A+B+C 结合：诚实说明 + 风险警示 + roadmap                                   | 既要准确，也要保护用户安全预期               |
| 文件级 allow 清理       | 移除全部 11 个文件级 `allow`；对仅用于 unix-only 测试的 helper 改用精确 `#[cfg(all(test, unix))]` / `#[cfg(unix)]`；其余 Windows clippy 警告保留 | Windows CI/release 不强制 clippy，清理到不影响 CI 即可；完全消除警告会引入大量非 issue 范围的改动 |


---

## 6. 风险与注意事项

- **ConPTY 挂起可能难定位**：如果根因是 Windows API 行为或 runner 环境特殊，可能需要多次迭代。
- **攒大步排练可能连环失败**：阶段 2 一次性跑 validate，可能同时暴露多个问题。如果失败点太多，再拆成小步处理。
- **plantcore-win 是共享资源**：测试需设置超时，避免长时间占用；测试后清理 target dir 和临时文件。
- **tag 脚本依赖 GitHub API**：API 延迟、token 权限、rate limit 都可能影响脚本。首次使用前先在本地测试查询逻辑。
- **annotated tag 与 lightweight tag 的区别**：所有参与者必须理解，不能用手动 `git tag vX.Y.Z`。
- **不要修改现有 runner 注册**：新增 pool/label 时，不要碰 `izrt4daujljimgz-iteron` 和 `izrt4daujljimgz-desktop`。

---

## 7. 附录：Windows 安装验证记录模板

```text
# Iteron Windows 安装验证记录

环境：
- 机器：plantcore-win / 其他干净 Windows 机器
- 用户：从未安装过 Iteron
- 时间：YYYY-MM-DD

步骤：

1. 从 GitHub Release 下载 Windows 归档
   URL: https://github.com/Plantcore-AI/Iteron/releases/download/vX.Y.Z/iteron-X.Y.Z-x86_64-pc-windows-msvc.zip

2. 校验 SHA-256
   预期 digest: <粘贴 SHA256SUMS 中的值>
   实际 digest: <PowerShell: Get-FileHash ...>
   结果: 匹配 / 不匹配

3. 解压归档
   命令: Expand-Archive -Path iteron-X.Y.Z-x86_64-pc-windows-msvc.zip -DestinationPath C:\iteron-test
   结果: 成功

4. 用绝对路径运行版本命令
   命令: C:\iteron-test\iteron-X.Y.Z-x86_64-pc-windows-msvc\iteron.exe --version
   输出: iteron X.Y.Z

5. （可选）篡改归档验证
   修改 zip 中某个字节后重新校验 digest，确认被拒绝。

结论: Windows 归档可下载、可校验、可运行。
```

---

## 8. 参考

- Issue #344: [https://github.com/Plantcore-AI/Iteron/issues/344](https://github.com/Plantcore-AI/Iteron/issues/344)
- `docs/development/releasing.md`
- `.github/workflows/release.yml`
- `.github/workflows/windows.yml`

