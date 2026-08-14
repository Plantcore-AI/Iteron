# 无凭据 Provider 诊断

创建、轮换或粘贴 API key 之前，先执行以下步骤。它们不读取凭据值，只验证本机安装与配置事实。

## 1. 验证可执行文件与版本

```sh
command -v iteron
iteron --version
```

第一条命令必须输出预期安装路径，第二条必须成功退出。若无法解析，把安装目录（通常是
`$HOME/.local/bin`）加入 `PATH`，新开 shell 后重试。若先命中旧版本，应调整 `PATH`
顺序，或直接使用目标二进制的绝对路径。

## 2. 只检查非秘密配置

运行 `iteron --help`，并对照 [provider 配置](../reference/providers.md)检查 provider
名称、model id、endpoint 与 CLI 参数。可以确认预期的凭据**变量名**，但绝不输出其值。
仓库配置不能授予 provider 权威；路由由可信用户配置、CLI 输入与进程环境控制。

## 3. 区分目录状态与认证状态

在没有 key 的情况下启动 Iteron，查看 `/status` 与 `/model`。unavailable 或 unknown
是正常的诊断状态。model 出现在内置目录中，不代表账号有权限、endpoint 可达或凭据有效。
不要把真实模型请求当作第一项安装测试。

## 4. 在不发送认证信息的情况下检查 endpoint

若网络诊断符合本机策略，可解析配置的主机名，并发起一个有界、无 Authorization header
的 HTTPS 请求。`401` 或 `403` 仍可证明 DNS、TLS 与 HTTP 可达，但不证明账号权限。
不要把 token 写入命令历史、URL、issue 或仓库文件。

## 5. 本机检查通过后再加载凭据

使用 `iteron setup --byok PROVIDER` 或文档规定的环境变量，然后重启 Iteron，使新进程
继承更新后的环境。再次检查 `/status`；只有明确需要时才重试某个 model。提交 bug 时须
删除 header、账号标识、request body 与 session record。

以上步骤只诊断安装、`PATH`、配置归属、目录状态与网络可达性；不对 provider 在线状态、
账号权限、计费或 model 可用性作任何承诺。
