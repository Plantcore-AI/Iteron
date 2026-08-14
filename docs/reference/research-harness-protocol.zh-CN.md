# Research harness 协议（中文版）

[English](research-harness-protocol.md)

`iteron-research/1` 是外部研究 harness 与 Iteron 优化面之间的 benchmark-neutral、
language-neutral 协议。它接收与原生 tuner 相同的 Candidate Graph，并构造有界执行计划；
它不导入 `iteron-evolve`，不选择 winner，不自动 promotion，也不扩大运行权限。

`iteron-harness` 仅是仓库内的研究可执行程序，不是 Iteron release 命令。release archive
与 installer 都不包含它，release CI 也不会打包或安装它。请从经过审查的 checkout 显式构建：

```sh
cargo build --locked -p iteron-eval --bin iteron-harness
```

跨语言接入以仓库内的
[JSON Schema](https://github.com/Plantcore-AI/Iteron/blob/main/crates/eval/schemas/iteron-research-1.schema.json)、
[纯标准库 Python client](https://github.com/Plantcore-AI/Iteron/blob/main/crates/eval/harbor/iteron_research_client.py)和
[无凭据 fixture optimizer](https://github.com/Plantcore-AI/Iteron/blob/main/crates/eval/harbor/fixture_optimizer.py)为准；Rust runtime
validator 仍是最终权威，并额外拒绝重复 JSON key 与跨字段身份不一致。

## 封闭 envelope

每个请求都是一个封闭 JSON object：

```json
{
  "protocol": "iteron-research/1",
  "request_id": "caller-unique-id",
  "payload": {
    "operation": "surface",
    "adapter": {
      "benchmark_id": "iteron-cli",
      "benchmark_version": "1"
    }
  }
}
```

响应必须重复相同的 `protocol` 与 `request_id`。未知字段、重复 key、未知协议、非法 ID、
未固定的 adapter 版本、超限文档、无界路径或预算，以及不一致的 response correlation
都会 fail closed。

## Candidate Graph 与五类可优化输入

schema-v3 Candidate Graph 用一个不可变身份同时表达：

- unified-profile 值；
- direct-config patch；
- caller-input patch；
- implementation binding；
- topology、lineage 与 experiment identity。

`candidate_sha256` 是完整 candidate 的原生 tuner 内容身份，格式为
`sha256:` 加 64 位小写十六进制；`profile_sha256` 是 canonical rendered profile 的裸
64 位 SHA-256。两者不能互换。实现绑定接受 stateless 的
`iteron-implementation/1` 与支持 state migration 的 `iteron-implementation/2`。

## 操作

- `surface`：返回 tunables surface、adapter registry、候选 schema/capability 及其摘要。
- `candidate_validate`：校验完整 candidate、materialize profile，并按需生成 create-new、
  no-follow 的 implementation activation 与 native patch materialization。
- `run`：只接受同一 persistent session 已校验的 candidate，并再次绑定 adapter、candidate、
  profile、activation、Candidate Graph 与 run 身份。
- `cancel`、`result`、`evidence`：使用同一组不可变身份定位 run，不能把 run 重新绑定到另一
  candidate 或 implementation set。

内置 registry 有三个固定入口：

- `iteron-cli/1`：普通 Iteron CLI execution；
- `iteron-native-adapter/2`：消费 combined Candidate Graph materialization 并逐节点返回
  consumption evidence 的 operator-pinned process；
- `terminal-bench/2.1`：严格 Terminal-Bench 2.1 wrapper，不提供隐式默认版本，也不会放宽
  原协议。

## CLI

单次模式从 stdin 读取一个请求，从 stdout 写一个响应：

```sh
target/debug/iteron-harness surface < request.json
target/debug/iteron-harness candidate-validate < candidate-request.json
```

`serve` 是 persistent NDJSON。默认是 dry-run；真实执行必须由本机 operator 在进程启动时
显式固定 executable，不能由不可信 request 远程开启：

```sh
target/debug/iteron-harness serve
target/debug/iteron-harness serve --execute --iteron-cli /absolute/path/to/iteron
target/debug/iteron-harness serve --execute --native-adapter /absolute/path/to/adapter
```

execute supervisor 清空 ambient environment，只安装固定的公共环境；operator 明确
allowlist 的 credential name 可以继承，但 credential value 永不进入 argv、协议响应、
session state 或 evidence metadata。wall time、stdout、stderr、evidence 与 address space
都有独立上限；cancel、timeout、overflow、EOF 与 drop 都会终止并 reap 子进程树。

一个进程返回成功并不等于 candidate 被消费。implementation run 必须产生完全关联的
`iteron-implementation-consumption/1` receipt；native combined run 必须产生
`iteron-candidate-materialization-consumption/2` receipt，并对每个 production-plan node、
implementation binding 与 patch 逐项证明 dependency、condition、lifecycle、load、apply 与
observation。缺失、过期、重排、部分、重复或 digest rebound 都会把表面成功转换为 failed。

## 无凭据 dry-run

下面的命令不读取 provider credential，也不运行 benchmark campaign：

```sh
cargo build --locked -p iteron-eval --bin iteron-harness
python3 crates/eval/harbor/fixture_optimizer.py \
  --harness "$(pwd)/target/debug/iteron-harness"
```

它只验证匿名 surface handshake。添加 `--candidate PATH` 时会额外校验精确 Candidate
Graph；fixture 始终不会 execute、select、promote，也不产生性能结论。

仓库内的三个工程 fixture 也使用同一可执行程序：

```sh
target/debug/iteron-harness scoreboard \
  crates/eval/fixtures/evidence-bundle-v1 \
  fd1724385aa0c75b64fb78cd602fa1d991fdebf76b13c58ed702eac835e9f618
target/debug/iteron-harness hermetic-fixture --output /absolute/create-new-receipt.json
target/debug/iteron-harness synthetic-cycle \
  --authorization "$(pwd)/crates/eval/tests/fixtures/synthetic-cycle-authorization-v1.json" \
  --output /absolute/create-new-cycle-directory
```

`scoreboard` 只接收经过签名验证的 Evidence Bundle v1，并从证据推导分母、终态分解和
区间。提交的 bundle 带 `synthetic_fixture` 标记，因此 board 恒定输出
`publishable_measured_result: false`。`hermetic-fixture` 验证确定性 manifest 与 physical
attempt identity，但不生成真实 score。`synthetic-cycle` 消费独立授权 artifact，跑通冻结
model、零 provider 的工程链路并精确 rollback；它同样不声称真实性能结果。

## Claim 边界

dry-run 只证明协议兼容和 validation-time identity。execute 只有在精确 consumption
receipt 也通过时，才证明一次有界、相关的进程执行。该协议不比较 candidate、不选择 winner、
不调用 `iteron-evolve`、不自动 promotion、不训练 model，也不证明 benchmark 性能提升。
