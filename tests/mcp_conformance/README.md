# Iteron MCP conformance

本目录把官方 MCP client conformance 固定到 commit
`49103de6ed70804e940637bf3e9e29e4a3f54e64`。`package-lock.json` 是依赖锁；CI 和本地
运行都必须使用 `npm ci`，不得使用浮动的 `npx` 包版本。

`iteron_adapter.py` 只把官方 runner 给出的 localhost URL 交给
`crates/mcp/examples/conformance_client.rs`。它不使用 Codex app-server、Codex 配置格式或
复制出来的控制层。

```bash
npm ci
python3 -m unittest test_runner.py
cargo build --locked -p iteron-mcp --example conformance_client
python3 run.py ../../target/debug/examples/conformance_client \
  --baseline-report regression-baseline-v1.json \
  --report /tmp/iteron-mcp-conformance.json
```

报告中的每个 check 包含版本、传输、场景、check id、同名出现序号和四态状态。报告内的
`compatibilityMatrix` 由本次实际执行结果生成，覆盖三个版本与 stdio/HTTP 六个组合；仓库
不维护脱离执行结果的静态“最新报告”。

紧凑基线同时保存全部预期通过项和已知失败项。门禁拒绝场景或既有通过项消失、runner
异常退出、`checks.json` 缺失/重复、新增失败、额外未审核检查和基线摘要变化。官方 runner
因已知断言失败返回 1 时，只有报告中的失败项全部经过基线审核才可通过。

审核一次完整报告后生成候选基线：

```bash
python3 review_baseline.py /tmp/iteron-mcp-conformance.json regression-baseline-v1.json
sha256sum regression-baseline-v1.json
```

维护者必须检查通过/失败身份变化，并把审核后的 SHA-256 同步到 `run.py`；CI 不会自行
接受或改写基线。
