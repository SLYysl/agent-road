<img src="docs/assets/mac-lifebuoy.png" alt="坐在红白救生圈上的经典 Mac" width="180" align="right" />

# Agent Road

**让 Mac 上已有的 AI Agent，去你的 Windows 电脑上做事。**

不用在两台电脑之间反复复制命令和结果：你继续和 Mac 上的 Agent 对话，它通过 Agent Road 在 Windows 上执行任务，再把输出和文件带回来。Windows 不需要再运行一个模型。

[English](README.md) · [网站与演示](https://agent-road.brahma-technologies.com/) · [给 Agent 的中文指南](docs/agent-guide-zh.md)

> 免费 Alpha，目前重点验证 Mac → Windows。此仓库仍是私有开源准备版，许可证待确定，Windows 原生安装器尚未公开发布。已经接入的设备可以继续使用；新用户请按收到的内测包操作。

## 能做什么

- 在 Mac 上让 Agent 检查 Windows 项目、运行经授权的测试并拿回结果。
- 传输脚本、下载报告，并核对文件完整性。
- 启动后台任务，保存任务 ID，断开当前连接后再查询同一任务的状态和日志。任务不能跨 Windows 重启继续运行。

例如：“看看我 Windows 上有没有 Python，经我同意运行这个脚本，然后把报告拿回来。”先检查已有工具，再决定是否需要安装。

```text
Mac：你 + 已有 Agent → Agent Road → Tailscale + SSH → Windows：执行任务
                         ↑                             ↓
                         └──────── 输出与文件 ──────────┘
```

## 第一次使用

1. 准备 Mac、有终端权限的 Agent，以及一台你有权管理的 Windows 电脑。两端联网，Windows 主人能批准管理员操作。当前重点测试 Apple Silicon Mac → Windows 11 x64。
2. 把下面的提示词交给 Mac 上的 Agent。收到内测包就按包内版本操作；不要把网站旧版流程混进来。
3. 由你完成浏览器账号授权和两端接入确认。账号授权不等于 Tailscale 网络已经配置好。
4. 先验证一条输出 `Hello from Windows` 的命令，再分别验证文件往返和后台任务。

```text
请帮我用 Agent Road，让这台 Mac 上的 Agent 操作我授权的 Windows 电脑。
开始前完整阅读此仓库的 docs/agent-guide-zh.md、docs/onboarding-status.json
和 docs/agent-interface.md。先只读检查已有环境，保留现有工具和控制器状态。
如果我提供内测包，按包内固定版本说明和 manifest 操作；公开安装器尚未发布时
明确报告阻塞，不猜下载链接，不自动退回旧流程。安装、管理员变更和重启先取得
我的授权。接入后先执行一条只读命令并核对输出，再分别验收文件往返和后台任务。
结果不明的写操作不要重试；密码、密钥和接入命令不要放进聊天或公开日志。
```

已经接入过？继续使用原控制器状态，先 `list` 和 `status`，不要重新配对。具体命令见 [English README](README.md) 和[命令契约](docs/agent-interface.md)。

## 它不是什么

它不替代 Claude Code、Codex 或其他 Agent，也不保证鼠标、桌面和浏览器控制。当前支持范围不包括 Mac 目标端或 Linux 目标端。完全断网、无法启动、BIOS 或 BitLocker 开机前问题，需要本地处理。

内部真机和 VM 已做过命令、中文文件往返、后台任务及其他 Agent 使用验证；一次 24 小时观察的 95 次采样正常，不等于永不断线。此前 SSH 停服根因、陌生设备首次接入和通用重启恢复仍有待验证。

## 反馈

请使用仓库的 Alpha 反馈模板，写清两端系统、Agent、版本、失败阶段和脱敏错误。不要提交密钥、token、原始状态文件或完整接入命令。安全问题按 [SECURITY.md](SECURITY.md) 私下报告。

[开源准备与验收边界](OPEN_SOURCE_PREPARATION.md) · [贡献说明](CONTRIBUTING.md)
