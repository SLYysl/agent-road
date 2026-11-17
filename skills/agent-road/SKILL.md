---
name: agent-road
description: Operate an enrolled Windows PC from this Mac through the Agent Road controller CLI — run PowerShell scripts, start and query background jobs, upload or fetch a single file, and inspect or use tools already installed on Windows. Use when the user mentions Agent Road or asks for work on their connected Windows PC. Not for local Mac tasks, and not for remote desktop or GUI control.
---

# Agent Road

Agent Road lets the agent on this Mac run authorized work on a Windows PC that has
already been enrolled. This skill covers day-to-day use. It does not enroll devices,
install tools or widen what the user has authorized.

## Find the CLI

```sh
agent-road capabilities                                  # if the bin is on PATH
node "$AGENT_ROAD_ROOT/src/cli.mjs" capabilities         # otherwise, from the checkout
```

If neither works, ask the user where their Agent Road checkout is. Do not clone,
install or pair anything on your own. Needs Node.js 22 or newer.

`capabilities` describes the controller's interfaces. It does not contact Windows.
`list` and `status <device-id>` read the saved registry; a listed device is a recorded
fact and may be offline. Pick the device ID from `list` in this session — never reuse
one from an old transcript, and never put one in a file you commit.

Read `docs/agent-interface.md` in the checkout for exact arguments, result files and
limits before the first call. That guide is the source of truth; this file is a summary.

## Pick the command

| Need | Command |
| --- | --- |
| One short script | `exec <device-id> --script <local.ps1> [--timeout-seconds 300]` |
| Several scripts over one connection | `session <device-id> <absolute-first.ps1> <absolute-second.ps1>` |
| Work that must outlive the connection | `job start <device-id> <absolute.ps1> [timeout-seconds]` |
| Check a job, read its logs | `job status <device-id> <job-id>` / `job logs <device-id> <job-id> [--include-output]` |
| Stop a job, drop its finished schedule entry | `job cancel <device-id> <job-id>` / `job remove <device-id> <job-id>` |
| Upload one file | `put <device-id> <local-file> <absolute-windows-path> [--overwrite]` |
| Fetch one file | `get <device-id> <absolute-windows-path> <local-file> [--overwrite]` |
| See which of Git/Node/Python/rg exist | `base-inspect <device-id>` |
| Run a script with those inspected tools | `base-exec <device-id> <absolute-inspection-directory> <absolute.ps1> node,python [timeout-seconds]` |

Write the PowerShell to a local file and pass the path. Pass arguments as a process
argument array; do not build a shell string from task text.

- `session` shares the SSH connection only. Variables and the working directory do not
  carry over between scripts, and it stops at the first failure. For anything long, use `job`.
- Jobs do not survive a Windows reboot.
- On a non-English Windows, non-ASCII output arrives garbled unless the script starts
  with `[Console]::OutputEncoding = [System.Text.Encoding]::UTF8`.
- In `base-exec` scripts call tools explicitly, e.g. `& $AgentRoadTools.node script.js`.
  A missing tool is not permission to install it.
- Transfers are one file at a time. Windows paths must be absolute with a drive letter
  and backslashes. Put work files in their own folder such as `C:\AgentRoad-Work\<task>\`;
  `C:\ProgramData\AgentRoad\` is reserved and rejected by `put`/`get`.

## Read results correctly

- `exec`, `put`, `get` print one JSON object. `session`, `job`, `base-*` print JSON
  lines: parse each line on its own and keep the first line (it carries the capture
  name and, for `job start`, the job ID).
- A zero exit from the CLI means the control call worked, not that the task succeeded.
  For jobs read `state.status` and `state.exitCode` in the printed line (the same
  object is `response.state` in the capture's `response.json`).
- Job log streams are `{ offset, bytes, base64 }`. Decode the base64; a nonzero offset
  means you have the tail only.
- Capture directories hold device IDs, scripts and task output. Keep them out of Git
  and out of anything you share.

## When something is uncertain

- **Never replay a write whose result you do not know.** If `job start` printed a job
  ID and then the response was lost, query that ID; do not start again.
- `DEVICE_BUSY` means another controller call to the same device is still holding the
  local lock. Wait and query the original operation. It does not mean Windows is offline.
  Run one controller call per device at a time.
- `job cancel` accepted is not `job` stopped. Keep checking `job status`.
- Do not bypass host-key or identity checks, and do not fall back to raw SSH.

## Boundaries

Stay inside what the user authorized for this task. Ask before installing software,
making administrator changes or rebooting. If the user is using the Windows PC, keep to
background work: no foreground windows, input or restarts. There is no PTY, interactive
login, persistent shell, recursive sync or general desktop control.
