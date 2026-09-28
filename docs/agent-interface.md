# Agent-facing work interface

Use the same controller entry point from any agent with access to this Mac checkout:

```sh
node /absolute/path/to/agent-road/src/cli.mjs capabilities
node /absolute/path/to/agent-road/src/cli.mjs list
```

The installed `agent-road` bin resolves to that same CLI. No skill, browser harness,
model provider or global installation is needed for the interface. Use a process
argument array rather than constructing a shell command from untrusted task text.
Do not hardcode a device ID from another agent's transcript: select it from the
current registry. Registry status is a persisted fact, not a live network probe.

`capabilities` is local-only and returns schema version 1 JSON describing controller
interfaces. It does not contact Windows or claim that a particular device/tool is
currently ready. Ordinary exec, transfers, jobs and tool binding retain the same
host-key checks, device identity, limits and execution semantics as their existing
implementations. Controller transport remains serialized per device.

## Command selection

| Need | Command after `node src/cli.mjs` | Result |
| --- | --- | --- |
| Device discovery | `list`, `status <device-id>` | Private registry JSON |
| One short PowerShell task | `exec <device-id> --script <local.ps1> [--timeout-seconds 300]` | JSON with stdout, stderr and script exit code |
| Several scripts, reduced connection overhead | `session <device-id> <absolute-first.ps1> <absolute-second.ps1>` | JSON lines plus private completed results |
| Work that must outlive SSH | `job start <device-id> <absolute.ps1> [timeout-seconds]` | Job ID saved/printed before dispatch |
| Inspect an existing job | `job status <device-id> <job-id>` | JSON lines with persisted state and scheduler observation |
| Retrieve bounded logs | `job logs <device-id> <job-id>` | JSON lines; raw output in private capture |
| Request cancellation | `job cancel <device-id> <job-id>` | Request receipt; query status for termination |
| Remove a terminal scheduler definition | `job remove <device-id> <job-id>` | Files/results remain queryable |
| Upload/download one file | `put <device-id> <local-file> <absolute-windows-path>` / `get <device-id> <absolute-windows-path> <local-file>` | JSON including size/hash; optional `--overwrite` |
| Observe installed Git/Node/Python/rg | `base-inspect <device-id>` | Private inspection and summarized candidates |
| Execute with inspected tools | `base-exec <device-id> <absolute-inspection-directory> <absolute.ps1> node,python [timeout-seconds]` | Revalidated bound executables; private task result |
| Measure ordinary exec overhead | `measure-exec <device-id> [1-20 iterations]` | Sanitized JSON lines and timings; default 10 |

All commands are explicit. This interface does not install missing tools, select a
remote model, send prompts to Claude/Codex, reboot Windows or take desktop focus.
The script submitted by the caller can have its own effects and needs the user's
authorization. The CLI is not a sandbox for untrusted scripts.

Plan transferable artifacts outside the reserved `C:\ProgramData\AgentRoad\`
tree, for example in a unique `C:\AgentRoad-Work\<task>\` directory. Both put/get
reject the reserved root and all its descendants locally. Windows transfer paths
must use absolute drive-letter/backslash syntax, not forward slashes, UNC or globs;
create the intended parent directory as part of the authorized task. If a task's
own known report files were already generated under the reserved tree, an authorized
exec can copy those files to a fresh external task directory before get. Preserve
original results; do not rerun the task, export internal credentials or relax the
transfer validator.

Session accepts 1–20 scripts with a 300-second timeout per script. They share SSH,
not a PowerShell process; variables and cwd do not persist. It stops on the first
nonzero or uncertain result and requires the controller to remain running. Use
jobs for durable background work; jobs do not resume across a reboot.

Existing-tool bindings are called explicitly inside a PowerShell script:

```powershell
$value = & $AgentRoadTools.node -p '6*7'
if ($LASTEXITCODE -ne 0 -or $value -ne '42') { throw 'TASK_FAILED' }
```

Use the exact private inspection from `base-inspect` on that same device.
`base-exec` validates selected executable paths and hashes again before task code;
it does not implicitly resolve a replacement from PATH.

## Reading results and recovering uncertainty

For JSON-lines commands, parse each nonempty stdout line independently. The
`capture` field is a basename under the controller's Node `os.tmpdir()`. Preserve
the first line immediately, especially the job ID on start. The files below are
private and may contain device IDs, addresses, scripts or task output:

| Command | Result files in its capture directory |
| --- | --- |
| session | `request.json`, `results.json`; `stopped.json` on error |
| job | `request.json`, `execution.json`, `response.json`; `stopped.json` on error |
| base-inspect | `context.json`, `execution.json`, `assessment.json`, `state-after.json` |
| base-exec | `binding.json`, `execution.json` |
| measure-exec | `results.json` |

`job logs <device-id> <job-id> --include-output` explicitly includes bounded
stdout/stderr byte records in its second JSON line, alongside `state` and scheduler
observations. This avoids a separate status call and local capture lookup when
both results and logs are needed. Output may contain private task data; only opt
in when the calling agent needs it. The default remains metadata-only.

`job logs` leaves stdout/stderr byte records in `response.json`; the printed summary
omits them. Each stream is `{ offset, bytes, base64 }`, not a plain text string.
Decode `Buffer.from(response.stdout.base64, 'base64').toString('utf8')` for UTF-8
tasks. Preserve `offset`: a nonzero value means this is a tail, not the entire log.
Task status is nested: inspect `response.state.status` and `response.state.exitCode`.
For example, `response.state.status === 'SUCCEEDED'` confirms a successful terminal
receipt; top-level `response.status` is not the job state.
Session results contain each completed script's exact stdout/stderr/exit code.
Temporary captures are not permanent archives; preserve required evidence privately
before OS cleanup. Never commit captures or identity/auth files.

An inactive scheduler alone does not prove a job failed or never ran. If status
is `INTERRUPTED_OR_NOT_STARTED`, inspect the same job ID and its logs; do not
resubmit automatically. Completion can race with a scheduler observation.

Do not treat a zero controller exit as universal task success: `job status` can
successfully report a FAILED job. Inspect the returned state and original exit
code. A session script failure returns CLI exit 2 with `SESSION_SCRIPT_FAILED`;
`base-exec` returns 1 for a completed nonzero task and 2 for control failures.

No command automatically replays user work. For a lost `job start` response, use
the already printed/saved job ID with `job status`/`job logs`; do not start again.
For other uncertain execution, preserve the operation ID and receipts and inspect
the outcome before any new submission. `DEVICE_BUSY` means a local identity-lock
wait expired before dispatch. It is distinct from a remote connection failure
and from `DEVICE_NOT_READY`; do not classify it as Windows being offline or
restart Windows in response. Do not run controller calls concurrently to one device.

If an operation is active, let it finish. If a controller was forcibly interrupted,
a dead-owner file lock can remain: repeated waiting will not remove it. Stop the
poller and inspect only the lock metadata and owning process, without reading or
printing identity keys. Do not blindly delete locks or automatically replay work.
An operator must reconcile the interrupted operation and verify the exact lock
owner is dead before any narrowly scoped lock recovery. Retain the metadata and
receipts. Polling harnesses should stop cooperatively between completed CLI calls,
and report `DEVICE_BUSY` separately instead of retrying it as network downtime.

## Earlier work and present boundaries

- [Independent skill task](skill-task-acceptance.md): another agent generated a
  minute-long Windows resource report, retrieved it and completed cleanup.
- [Existing tools](existing-base.md): observation, binding and drift rejection.
- [Background tasks](background-tasks.md): process lifetime, cancellation and logs.
- [Reused sessions](reused-sessions.md): connection reuse, failure behavior and timing.
- [Single-exec optimization](remote-exec-latency.md): combined receipt/cleanup.
- [Remote agent experiment](remote-agent-handoff.md): Windows Claude generation,
  retrieval, review and repair through a temporary desktop-user task bridge.
- [Browser comparison](windows-browser-ablation.md): earlier CLI/browser GUI trials.
- [Gaming coexistence](windows-gaming-noise-check.md): background evidence and gaps.

The desktop/browser and remote-agent experiments have no supported generic command
in this interface. Their desktop-user bridge requires an active logged-in session
and shares foreground ownership. PTY, persistent shell state, general agent account
selection and recursive/resumable file synchronization remain outside this release.
A successful experiment does not make every Windows agent or browser profile callable.

## Compatibility and validation

The five historical `tools/*.mjs` entry points remain thin compatibility launchers
for the exact same modules as the main CLI. Existing arguments, JSON content,
private capture layout and exit codes are retained. Importing these implementation
modules performs no task; `run(argv, env, io)` is explicit and returns an exit code
without changing `process.argv` or `process.exitCode`. Environment routing including
`AGENT_ROAD_HOME` is passed to production dependencies.

Acceptance on 2026-09-19 covered canonical CLI execution on the enrolled Windows
machine: two-script reused session with exact Chinese/emoji output; job start,
SUCCEEDED/0 status, exact decoded logs and terminal definition removal; fresh
base inspection with unchanged managed state; bound Node calculation; and a
single ordinary-exec measurement. No foreground interaction or reboot occurred.
The smoke harness initially read job state at the wrong nesting level and expected
plain-text logs instead of Base64 byte records. Existing private receipts resolved
both harness mistakes; the same job ID was retained and no work was resubmitted.
The examples and capability metadata above document these actual result shapes.

Local checks cover both canonical and legacy rejection/exit behavior, local-only
capability discovery, module-name allowlisting, environment routing and retained
failure captures, alongside existing CLI/transport/job/tool regressions. Existing
execution logic was compared with its pre-extraction source after normalizing only
imports, argv/environment/IO plumbing and the exported function wrapper.

Final focused regression: 255 passed, zero failed; `npm run check` passed.

For the end-to-end sequence and optimization boundaries, see
[Workflow optimization](workflow-optimization.md).
