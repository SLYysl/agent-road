# Agent Road：给 Agent 的中文配置与使用指南

更新：2026-09-23。使用者：有终端访问权限、获得设备主人授权的 Agent。
开始前完整阅读本文、[发布状态](./onboarding-status.json)和[命令契约](./agent-interface.md)。本文不代替实际授权，不保证某台设备在线。

## 先判断用户要做什么

| 用户情况 | 下一步 |
| --- | --- |
| 已接入，想执行任务 | 使用原控制器状态，发现设备、核查能力、执行任务；不重新安装或配对 |
| 收到私人内测包 | 先读包内说明、manifest 和哈希，按那个固定版本的测试流程操作 |
| 从公开网站首次接入 | 检查当前公开发布状态；原生安装未发布时明确报告阻塞 |
| Mac→Mac 或 Windows→Windows | 目前仅环境检查，不假称支持接入 |

当前接入测试范围是 Mac→Windows 11 x64，网络使用 Tailscale。Mac arm64 有安装验收，Intel 尚无执行验收。Windows 主人不必注册 Agent Road 账号，但需要知道并同意远程管理变更。
公开 Windows 原生安装器尚未发布；一个新 Windows VM 上完成过原生配对、SSH、core 和文件往返，不代表陌生真机、受信任签名或自动重启恢复已通过。普通 `pair` 仍是受限旧流程，不能自动当作原生安装的替代。

## 公开安装与私人候选分开处理

读取 `/docs/onboarding-status.json`，要求 schemaVersion=1。核对 controller.status=AVAILABLE_ALPHA 与 `/downloads/controller-manifest.json`；公开下载要求 manifest.published=true。状态或 manifest 不一致时停止，不猜测当前版本。
原生公开接入要求 windows.nativeInstallerPublished=true；要描述为原生接入已验收，还需 freshNativeOnboardingAccepted=true 且 knownBlockers 为空。否则报告 NATIVE_INSTALLER_NOT_RELEASED 或具体未完成项。
私人候选仅限用户明确选择、具备对应固定哈希和操作说明的测试包。按包内版本操作，不猜测下载地址，不把私人候选改称公开正式版。公开指南不会给你授权安装陌生候选。已接入设备的正常使用不受“新安装尚未发布”阻塞。
旧流程仅在主人明确选择受限 legacy Alpha 后使用；原生失败不得自动降级。Defender 或其他系统保护阻止时保留错误、停止，不关闭保护或重放载荷。

## 配置前先只读检查两端

检查系统/架构、现有 CLI 的路径及 capabilities、Node/Git/Python、Tailscale/SSH、已有 Agent Road 状态与待重启项，按已有、缺失、冲突、未知报告。远端尚不可达时请目标主人或其 Agent 检查，不能把本机检测当成两端检测。访问受限不是缺失。
Mac 上已有 Node >=22 可以运行经过哈希核验并解压的 controller/src/cli.mjs，不需要 npm install。没有兼容 Node 时，经同意可用官方安装器安装私有 Node；不要替换全局工具。已有 Git、Node、Python 不重装，Windows core 接入不要求先装这些工具。
保留已有配置。新测试使用单独的私有 AGENT_ROAD_HOME，所有操作使用同一个值和确定的 CLI 路径。既有设备继续使用原来的 home，不能换成空目录后认为设备丢失。
已有 Windows SSH 配置、已登录的 Tailscale 身份、AgentRoad 账号/目录或旧 journal，需要诊断；当前原生候选不能无条件接管。不得删除这些内容来强行满足前置条件。

## 账号授权与网络是两件事

运行 `agent-road login`（不能自动打开浏览器时用 `login --no-browser`）。由主人登录、验证邮箱、对比终端和网页代码并批准，再用 whoami 确认账号。不要索取密码，也不要批准不认识的代码。停止终端等待不等于撤销服务器上的待批准请求。
Mac 需要测试者自己的 Tailscale 已登录、.ts.net 名称以及所需 Serve 权限。status、serve status 可用于检查；读取成功不证明能新建路由。不要自动切换尾网、清空 Serve 路由或修改网络策略。
私有 AGENT_ROAD_HOME 为 0700，pairing.json 和所引用的密钥文件为当前用户拥有的 0600 文件。账号模式的配置形状：
```json
{"origin":"https://agent-road.brahma-technologies.com","tailscaleAuthKeyFile":"/实际私有绝对路径/tailscale-auth-key"}
```
用户在自己的网络生成单次 tskey-auth-，通过本地隐藏输入保存，不经聊天、命令参数或日志。也可改为 tailscaleApiTokenFile 引用自己的 tskey-api-，两种字段只选一种，类型不可互换。不要复制开发者网络凭据；不需要共享 admin token，不使用 --config 绕过账号批准。

## 接入与验收

依照当前选定流程先准备 Windows，再生成短码；更新、慢速前置安装及获准的重启应在邀请开始计时前完成。接入会创建专用管理账号、配置 SSH/防火墙和网络，主人应知道这些变更。保留当前尝试的回执、验证代码和结果；短码过期或断连不表示远端什么都没发生。
不要仅凭 CONNECTED_SSH_ONLY 宣称 core 或桌面就绪；逐项检查：
1. list/status：本地登记状态，不能独立证明在线。
2. doctor、实际只读 exec：确认实时连接和命令结果。
3. runtime-status：核查 core 状态；未就绪时参照英文配置指南中的 readiness/baseline/recovery 流程。
4. put/get：在主人授权的唯一测试目录做文件往返，核对字节数与 SHA256。
5. job：只提交一次，保存 ID，查询终态和日志，检查脚本退出码。
6. GUI、网页端到端、重启恢复：独立验收；未测就写未测。宿主机 reset 或人工修复不是自动恢复成功。

## 日常命令速查

以下接在已核验的 `agent-road` 后，或 `node /绝对路径/controller/src/cli.mjs` 后。参数中的设备与路径必须来自本次任务，不照抄别人的 ID。每台设备一次一个控制器操作。

| 需求 | 参数 |
| --- | --- |
| 本地接口、设备登记 | capabilities / list / status <设备ID> |
| 实时诊断、core 状态 | doctor <设备ID> / runtime-status <设备ID> |
| 短脚本 | exec <设备ID> --script <绝对.ps1> --timeout-seconds 300 |
| 多脚本共享 SSH | session <设备ID> <绝对脚本1> <绝对脚本2> |
| 持久任务 | job start <设备ID> <绝对.ps1> 120 |
| 查询、取日志 | job status <设备ID> <任务ID> / job logs <设备ID> <任务ID> |
| 取消、注销终态调度定义 | job cancel <设备ID> <任务ID> / job remove <设备ID> <任务ID> |
| 文件上传、下载 | put <设备ID> <本地文件> <Windows文件> / get <设备ID> <Windows文件> <本地文件> |
| 检查现有工具 | base-inspect <设备ID> |
| 使用本次检查的工具 | base-exec <设备ID> <检查目录绝对路径> <绝对.ps1> node,python 300 |
| 测量执行开销 | measure-exec <设备ID> 3 |

远端文件使用反斜杠绝对路径，例如 C:\AgentRoad-Work\唯一任务目录\结果.txt，先按任务授权创建目录，不覆盖已有文件。put/get 为单文件操作，拒绝 C:\ProgramData\AgentRoad 保留目录、UNC 和通配符；不要修改校验来放行。
session 接受 1–20 个脚本，共享 SSH 而不共享 PowerShell 进程或变量，遇错停止。长任务用 job；job 不保证跨重启续跑。cancel 受理后仍需查询；remove 只移除终态调度定义，文件和结果保留。
base-exec 重新核验工具路径/哈希；脚本显式使用 `& $AgentRoadTools.node ...` 等调用。发现工具不等于已安装 managed base，缺工具也不是自动安装授权。

## 结果不确定时怎么做

exec/put/get 输出 JSON；job/session/base 等输出 JSON lines，逐行处理。及时保存首行操作 ID、job ID 与 capture。capture 是 Node os.tmpdir() 下目录名，内容可能敏感，不上传整个目录。
job 完整结果在 response.json；任务状态读 response.state.status，退出码读 response.state.exitCode，不读顶层 status 代替任务结果。控制器退出 0 不保证脚本成功。
logs 的 stdout/stderr 是 {offset,bytes,base64}，按 UTF-8 解码；offset 非零代表只拿到尾部。
DEVICE_BUSY 先等原操作结束；DEVICE_NOT_READY 先重查原状态，不能推断远端任务没执行。INTERRUPTED_OR_NOT_STARTED 也应检查原任务 ID 和日志。不确定的 start 不再次提交，session 不能整批重放。
身份、host-key 或安全校验冲突时停止，不绕过。保留原安装 journal 和错误；不要清空证据重新装。用户在游戏或要求后台工作时，不抢焦点、操控桌面或重启。

## 可复制的日常任务提示词

请先完整阅读 Agent Road 中文指南与命令契约，使用原控制器的 AGENT_ROAD_HOME 和已核验 CLI。根据 list 选择我指定的设备，实时确认本次任务需要的能力。按授权完成下面的任务，保留回执，取回并核验产物；结果不确定时查询原操作，不自动重放。不要重新配对、重装环境或调用另一个模型。用中文报告实际结果、失败和未验证项。
我的任务：<填写任务>

## 可复制的排障提示词

请对本次 Agent Road 失败先只读诊断。核对控制器路径、AGENT_ROAD_HOME、设备 ID、原操作或 job ID、有限错误与当前状态，区分网络不可达、身份冲突、任务失败和结果未知。不删除 journal，不自动重试安装或任务，不放宽 host-key、安全策略或防火墙。提出基于证据的最小修复，并在已有授权范围内继续。保留首次失败与修复后的结果，反馈时脱敏，不导出凭据。

更多参数及 core 恢复细节见 [英文配置指南](./agent-setup.md) 与 [命令契约](./agent-interface.md)。
