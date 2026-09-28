# Background tasks (explicit first version)

Use `agent-road job` for a trusted, noninteractive PowerShell script
which must outlive the initiating SSH connection. The main CLI and historical tool launcher share the same implementation;
runtime provisioning remains separate.

```sh
node src/cli.mjs job start <device-id> <absolute-task.ps1> [timeout-seconds]
node src/cli.mjs job status <device-id> <job-id>
node src/cli.mjs job logs <device-id> <job-id> [--include-output]
node src/cli.mjs job cancel <device-id> <job-id>
node src/cli.mjs job remove <device-id> <job-id>
```

The source limit is 64 KiB. The execution limit is 1–86400 seconds, default 3600;
this measures the child process, not initial scheduling/compilation. Scheduling has
an additional 120-second outer execution allowance. No package install or reboot
is required. Windows Task Scheduler, Windows PowerShell and C# Add-Type support
must already work for the enrolled account.

## Identity, persistence and results

Start saves and prints a random job ID and private capture basename **before**
remote mutation. It does not automatically retry. If the connection or response is
lost, query that ID; do not submit the script again to guess what happened.
Remote jobs live below `C:\ProgramData\AgentRoad\jobs\<job-id>` with access limited
to the creating account, SYSTEM and administrators. Start refuses an existing ID
or scheduled-task name. Reparse-point paths and unexpected ACL readers are rejected.

Each job gets a demand-only `AgentRoad-<job-id>` scheduled task, running as the
current enrolled Windows account with S4U and Limited run level. It does not run as
SYSTEM or require an interactive desktop. This logon does not supply reusable
network credentials or access to encrypted files; those tasks need a separately
reviewed logon method. See [S4U logon restrictions](https://learn.microsoft.com/en-us/windows/win32/taskschd/principal-logontype). There is no startup trigger or automatic
restart. An exclusive worker lock and persistent claim prevent the user script
from being rerun by a repeated worker launch. A crash after claiming but before
launch can therefore leave a task which never ran; do not infer exactly-once
completion from this at-most-once launch policy.

The worker atomically publishes status. `SUBMITTED` means a scheduling request was
accepted, not that the script ran. `RUNNING` includes worker setup. Final results
are `SUCCEEDED`, `FAILED`, `CANCELLED`, `TIMED_OUT`, or `OUTPUT_LIMIT`. Script failures
retain the exit code; a worker failure has null exit code and `JOB_WORKER_FAILED`.
`INTERRUPTED_OR_NOT_STARTED` means the scheduler is inactive without a final receipt;
it must not be treated as success or automatically replayed. Status also reports
the scheduler result code. A reboot is not a supported task-resumption mechanism.

Cancel creates a job-specific request. `CANCEL_REQUESTED` is not confirmation of
termination: query until a final state appears. The worker launches the script
suspended, assigns it to a native Windows Job Object, then resumes it. Cancellation
and timeout terminate that job; a final cancelled/timed-out receipt is written only
after its active process count reaches zero. Normal script exit also terminates
leftover descendants. Closing the worker's last job handle kills members if the
worker is interrupted. Abrupt failure between suspended process creation and job
assignment can leave a suspended process; this handoff is not crash-atomic. Failure to establish containment prevents script execution.
This manages ordinary descendants, not work handed to external services or brokers.

## Logs, environment and cleanup

Logs retrieves the last 64 KiB of each stream as base64 with byte offsets in
`response.json` inside the returned private OS-temp capture directory. It does not
print arbitrary script output to the control console by default. Explicit
`--include-output` adds these same bounded base64 byte records to the second JSON
line, with the task state; no extra remote query or decoding is performed. This preserves raw bytes,
even if a tail begins in the middle of a UTF-8 character. Full logs remain on Windows.
The worker checks combined output against 4 MiB about every 100 ms and on exit;
this is a stop threshold, **not a disk quota**: fast output can overshoot it.

The task uses PowerShell `-File`, preserving script-level parameter/directive
semantics. Use explicit encoding (for example `[Console]::OutputEncoding =
New-Object Text.UTF8Encoding($false)`) when needed. Working directory is the job
folder; there is no persistent shared shell. Existing-tool fingerprint bindings
are not implicitly selected by this tool. Use explicit task requirements and
executable paths or a separately generated existing-tool wrapper.

`remove` unregisters only a terminal, inactive scheduled-task definition and retains
all task files/results. It does not delete evidence or stop an active task. Retained
scripts and logs may contain private task data; there is no automatic retention
cleanup in this version. The task is trusted code, not a sandbox: it runs with the
account's access and can modify its own task data. ACL checks do not prove atomic
ancestor identity or protect against a malicious administrator.

## Physical acceptance (2026-09-19)

- Separate start/status/log connections observed running work and final success;
  Chinese/emoji stdout was recovered intact after the initiating connection ended.
- A task spawning a child was cancelled; final state was CANCELLED, the exact
  original child identity was absent and its delayed marker was absent.
- A 3-second limit stopped a 60-second task with TIMED_OUT.
- A script exiting 7 retained FAILED/7 and its expected stderr.
- A 5 MiB output burst triggered OUTPUT_LIMIT; log retrieval returned only the
  final 64 KiB with its nonzero byte offset. The threshold is intentionally soft.
- Test scheduler definitions were removed while script, state and log files were
  retained; subsequent queries still read completed results and logs.
- Duplicate start with the same job ID was rejected; restarting the completed
  worker left its prior receipt and log hash unchanged (no script replay).
- Initial worker state publication failed because PowerShell 5.1 marshalled a null
  backup path incorrectly for File.Replace; an isolated reproduction established
  this and an explicit backup path fixed the subsequent runs. Failed-run evidence
  was retained and its user script was never replayed.

Local regression: 37 tests passed across the new controller, existing-tool launcher
and remote execution. No power-loss/reboot, authenticated network access, arbitrary
GUI app or malicious-task containment claim is made.

Native design references: [Windows Job Objects](https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects)
and [scheduled-task principals](https://learn.microsoft.com/en-us/powershell/module/scheduledtasks/new-scheduledtaskprincipal).
Exact job IDs, transport receipts and scripts from live probes remain private.

## Local controller contention

`DEVICE_BUSY` means target loading timed out acquiring the local SSH identity lock
before remote dispatch. Wait for the current controller operation to finish, then
query the same job ID. This differs from `DEVICE_NOT_READY` identity/readiness
failures. This classification change adds no automatic task replay or concurrent
transport; uncertain submissions must still be resolved using their recorded ID.
