# Agent Road 流程优化 — 2026-09-26

本轮只在 Mac 修改和验证；没有连接 Windows、重启、操作驱动或前台窗口。
目标是减少控制器往返和 Agent 手工解析，同时保留身份校验与不重复执行约束。

| 阶段 | 建议顺序 | 依据与边界 |
| --- | --- | --- |
| 发现 | 先本地 capabilities、list/status，再按任务做一次实时检查 | 登记状态不证明在线；不要每条命令前重复 doctor |
| 首次接入 | 环境只读检查 → 账号授权/短码配对 → 必要安装 → core 验证 | 缺工具才安装；待重启必须服从用户当前限制，不自动重复配对 |
| 连续短任务 | 能组成一个脚本的只读检查合并；多个明确脚本用 session | 共用连接，不共享 PowerShell 状态；失败停止，不整批重放 |
| 长任务 | job start 一次，立即保留 job ID | 提交回执丢失也不再次 start |
| 取结果 | job logs ID --include-output | 一次响应同时含状态和日志，无需先 status 再 logs，也无需查临时目录 |
| 等待 | 按任务预期时长安排有限轮询；同设备串行 | 不高频轮询；只在明确的只读观察流程中处理瞬时连接错误 |
| 中断 | 等当前 CLI 完成后停止观察器 | DEVICE_BUSY 是本地锁问题；不当作 Windows 离线，不自动删锁 |
| 恢复验收 | 用户允许时才重启；比较启动时间和启动事件 ID，再查 core/文件/原 job | 已完成任务结果保留不等于运行进程跨重启续跑 |
| 交付 | 保存私有回执，导出脱敏汇总，最后独立 Agent 验收 | 接入成功、运行时就绪、恢复成功、全新设备验收分别记录 |

## 本轮落地

新增 `job logs <device-id> <job-id> --include-output`。默认仍隐藏日志；显式开启时，
第二行 JSON 包含原有 `state` 及 `{offset, bytes, base64}` 日志字段。尾部可能截断
UTF-8 字符，所以不强制转码；原始 response.json 仍保存。非零 offset 表示仅为尾部。
该选项仅改变控制器输出，Windows 控制脚本和 SSH 身份校验未变。

一次 logs 已带状态，能少一次 status 往返；这是调用次数减少，不是实测延迟保证。
已有 session 在 9 月 19 日十条短命令试验中总耗时降低 41.6%，属于历史单机测量，
不能直接推成今天游戏负载下的表现，详见 reused-sessions.md。

## 验证

本地 background-task、cli-work-commands、cli-remote-work 共 44 项测试通过；
涵盖默认日志隐藏、显式输出的原始字节保留、参数拒绝、隔离状态下的 CLI 路由
和既有远程命令兼容性。没有执行 Windows 实测或部署。

## 后续顺序

1. 物理 Windows 已验证新日志选项和 WAITING → PASSED：首次 6 次调用，续查 3 次，
   job start 仅一次；尚无匹配的前后性能基准。
2. 已实现本地版[可续查验收工具](../tools/acceptance/README.md)：独立保存步骤、
   CLI 原始回执和 job ID；不确定写操作停止，有 job ID 时只查原任务。
   12 项本地模拟及物理 Windows 非重启闭环通过；
   [实机记录](../experiments/resumable-acceptance-20260926/README.md)另记原 VM 的 SSH 故障。
3. 对已有四核 VM 故障继续匹配符号分析；单核只是已验收的绕行方案，不推广到普通真机。
4. 后续再做全新环境和网页流程验收；本轮不改冻结测试包、安装器或网站。
