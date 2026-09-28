# 可续查的非重启闭环验收（Mac 控制器）

Python 3 标准库工具，通过本 checkout 的 Node CLI 调用已登记 Windows。
不安装依赖、不配对、不重启、不操作驱动或桌面。它仍会在 Windows 创建独立测试目录、
上传小文件和提交一次 15 秒后台任务；只有获得这些操作授权后才执行 `resume`。

```sh
# 以下 init / status 均只操作本地；父目录必须存在，trial 目录必须是新的。
python3 tools/acceptance/closed_loop.py init /absolute/private/trial --device dev_example
python3 tools/acceptance/closed_loop.py status /absolute/private/trial
# 下列命令会连接 Windows；用户正在游戏时暂缓实测。
python3 tools/acceptance/closed_loop.py resume /absolute/private/trial
```

隔离控制器需要在 init 和所有 resume 时设置同一 `AGENT_ROAD_HOME`。
默认采用 `~/.agent-road`；目录记录绑定设备、控制器路径、状态根路径和输入哈希。
不要编辑 trial.json、生成的脚本或步骤回执；上下文改变后会拒绝续查。
只在私有目录保存，不要提交 Git；目录可能包含设备 ID、路径、输出及 capture 指针。

## 执行与续查

每次 resume：实时 doctor → 创建独立目录（一次）→ put（一次）→ get/逐字节核对
→ job start（一次）→ 用原 job ID 执行一次 logs 并验证状态和完整中文/emoji 标记。
已经有成功回执的创建目录、上传和提交步骤直接复用；doctor、下载和日志重新观察。

- `PASSED`：本轮命令、core、文件往返和已完成 job/logs 已验证。
- `WAITING`：任务仍 SUBMITTED/RUNNING；本次结束。稍后再次 resume，只查原任务。
- `STOP_UNKNOWN`：写步骤已开始但没有成功回执。保留目录，核查原操作，不能重新建
  trial 或删除步骤目录来绕过不确定状态。本版没有自动消除不确定状态的命令。
- job start 即使中断，只要首行 job ID 已落盘，续查只查该 ID；没有 ID 就停止。
  JOB_NOT_FOUND 也不会重新 start。
- CLI 失败停止，不内置网络重试或无限轮询；DEVICE_BUSY 不会引发重启或删锁。
- Ctrl-C / SIGTERM 请求在当前 CLI 完成后停止，子进程单独进程组；强制 kill 或机器
  掉电仍可能留下 CLI 身份锁，按 docs/agent-interface.md 核查，不自动删除。

每次调用前以独占创建并 fsync 的 started.json 记录参数与上下文；原始 stdout/stderr、
退出码、验证成功回执分别保存。CLI 输出的 capture/job ID 及可用操作标识保留在原始
输出中；不保证每种 CLI 都公开 operation ID。私有 OS-temp capture 不自动归档，
如需底层 staging 证据，必须另行保留。脚本采用保守策略，started 落盘而尚未实际
派发时中断也会停止，不假定“没有执行”。

observer.lock 使用 macOS 文件锁避免同一 trial 双重运行；此锁不替代 CLI 的设备锁，
不要同时对同一设备启动多个 trial。控制器 SIGKILL 后遗留的子 CLI 仍需人工核查。

报告名含随机 ID，不按文件名排序判断最新报告；status 展示历史报告及步骤。PASSED
只代表对应检查时刻，不代表以后一直在线。系统 pendingReboot 单独记录；工具不处理
系统更新，也不把 core 验证通过当成重启恢复通过。

## 验证与限制

```sh
python3 -m unittest discover -s test -p acceptance_closed_loop_test.py -v
```

本地模拟覆盖完整流程、重复续查、提交后中断、ID 缺失、写操作不确定、只读失败、
日志错误、上下文/脚本变化、观察器互斥和纯本地状态查看。
2026-09-26 已在物理 Windows 验证 WAITING → PASSED，未重复提交；见
[实机记录](../../experiments/resumable-acceptance-20260926/README.md)。
原测试 VM 的 sshd 停服另行记录，未修复。没有新设备安装或重启恢复验收。Node 的 npm test 不包含
这些 Python 测试，需显式运行上面的命令。多轮验收使用新的独立目录，只有上一轮
结果已明确且获得新一轮任务授权时再创建。

2026-09-27：DeepSeek 经隔离 Hermes 独立操作本工具，完成 WAITING/PASSED/PASSED，
主代理核对原始回执通过，见 [独立 Agent 记录](../../experiments/deepseek-acceptance-20260927/README.md)。
