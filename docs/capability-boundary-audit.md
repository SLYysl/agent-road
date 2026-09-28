# Agent Road capability boundary audit

Controller session date: 2026-09-19; exact execution timestamps remain in private receipts.
User requested tests of ordinary tasks that do not work through current Agent Road.
Scope: normal `executeRemoteScript`, file transfer, existing-tool launcher contracts.
No installations, reboot, real credentials/clipboard inspection, or existing-project edits.

## Physical Windows observations

| Probe | Result | Practical boundary |
| --- | --- | --- |
| `Read-Host` in ordinary exec | Rejected immediately under `-NonInteractive` | No live terminal conversation, password prompt, or REPL input through this API. |
| Exec process versus Explorer | Session 0 versus desktop session 1 | Ordinary exec is not attached to the visible desktop. A separate interactive-session helper was needed for earlier screenshots. |
| Environment and working directory across two exec calls | Both absent/reset in second call | Each invocation is a separate process, not a persistent terminal session. |
| `Start-Job` followed by `Receive-Job -Wait` | Returned expected 42 | Bounded child work within one invocation is possible. |
| `Start-Job` writing a marker after 6 seconds; parent then exits | Marker absent after a later invocation waited another 8 seconds | This job did not survive as a useful detached task. Do not treat ordinary exec as a durable background-job service. This does not prove that all native detached processes fail. |
| Default `Write-Output`/JSON containing Chinese and emoji | Did not round-trip; console reported `gb2312` | Default non-ASCII console output is unreliable in this environment. |
| Same text after `[Console]::OutputEncoding = New-Object Text.UTF8Encoding($false)` | Exact round-trip | Explicit encoding fixes this tested output case; other input/file/native-program encodings remain task-specific. |

The previous development demo also reproduced PowerShell 5.1 treating native stderr
as an error when redirected with `2>&1` under `$ErrorActionPreference='Stop'`, even
though Python unittest was emitting ordinary progress. Its task runner was adapted
to stdout plus explicit exit-code checking. This is a Windows shell behavior exposed
by the task script, not evidence that Python tests cannot run remotely.

## Locally exercised API rejection boundaries

All eight requests below were rejected with `REMOTE_INPUT_INVALID` before any
transport call (an instrumented dependency counted zero transport calls per case):

1. Supplying `stdinText` to `executeRemoteScript` (unsupported API field).
2. A timeout of 1,800,001 ms (maximum accepted configuration is 30 minutes).
3. A script containing 1 MiB + 1 byte.
4. Uploading a zero-byte file.
5. Uploading a directory as a file.
6. Uploading a sparse test file of 256 MiB + 1 byte.
7. A UNC destination path.
8. A destination under `C:\ProgramData\AgentRoad` through ordinary file transfer.

The last restriction protects governed runtime state; it is not a Windows filesystem
inability. ZIP packaging already provides a demonstrated workaround for directory
transfer. Chunking/large-file transfers and empty-file transfer are not implemented
at the time of this audit (empty files are addressed below). No large payload was sent during these tests.

## Source-only limits (not stress-tested here)

- Ordinary exec defaults to 5 minutes; callers can request at most 30 minutes.
- Ordinary exec has a 4 MiB output bound (`src/remote/remote-exec.mjs`).
- The existing-tool task launcher has a 64 KiB task-source limit and a fixed 5-minute
  timeout (`tools/run-existing-task.mjs`, `src/runtime/existing-task.mjs`).
- The launcher rejects missing or ambiguous tool selections; this is stricter than
  a user manually choosing a binary. It does not install a missing capability.

Do not infer reliable child termination or durable resumption from a timeout. The
existing uncertain-execution rules still apply; this audit deliberately did not
force a timeout, disconnect, or reboot to avoid creating uncertain remote work.

## Conclusions and next candidates

This is a useful noninteractive development channel, not full desktop/terminal
parity. Direct limitations are interactive input, persistent sessions, durable job
management, file-transfer shape/size, and default output encoding. Visible GUI work
is possible with a separate logged-in-session helper, as prior screenshots proved.
GPU, Docker, WSL, audio/video, package installation, and arbitrary desktop apps remain
untested here; they must not be reported as failed or supported from this audit.

Possible follow-up fixes: default UTF-8 output; empty-file transfer; explicit job
start/status/logs/cancel; a supported interactive desktop adapter. None was implemented
in this audit. Runtime state compared equal before/after; ready profiles remain core.

Private evidence: OS-temp `agent-road-capabilities-*` contains per-process results,
`session-one-execution.json`, `session-two-execution.json`, `local-boundaries.json`,
and `summary.json`. Remote artifacts are confined to a newly created temporary
`agent-road-limits-*` directory. The sparse local size fixture was only used for
preflight rejection. Private identifiers and transport receipts are not committed.

## Follow-up improvements (2026-09-19)

The observations above describe the original audit checkpoint. Subsequent changes:

- Ordinary put/get now accept zero-byte files, including overwrite, with the same
  SHA-256, path, ownership, publication and cleanup checks. Empty scripts and
  provisioning artifacts still retain their nonempty requirement.
- The existing-tool launcher defaults console/pipeline output to UTF-8 and sets
  task-local Python output encoding. Ordinary exec retains its existing `-File`
  semantics and still needs explicit encoding when required. Python `-I`/`-E`
  ignore environment encoding settings; use `-X utf8` for that case.
- The launcher accepts an optional 1–1800 second execution timeout, default 300.
  This replaces its formerly fixed limit, not the existing uncertain-execution rules.

Interactive stdin, persistent terminal sessions and a supported desktop adapter
remain separate work. A subsequent explicit [background task controller](background-tasks.md)
now provides bounded start/status/logs/cancel across SSH connections, with no reboot
resumption or automatic replay. No install or reboot was needed.

Follow-up validation: 265 tests passed, 2 skipped across file transfer, local
publication/recovery, CLI, existing-tool launcher, exec and provisioning upload.
Physical main-CLI checks passed empty put/get, nonempty-over-empty and
empty-over-nonempty remote overwrite, and empty-over-nonempty local overwrite.
The launcher round-tripped Chinese and emoji from PowerShell and Python with a
90-second configured timeout. Private receipts are under `agent-road-usability-*`.
The first download probe was rejected because its Mac destination used a symlinked
temporary-directory alias; resolving the test directory's real path fixed the probe
without changing destination-path safeguards.

## Gaming-noise recheck (2026-09-19)

The [gaming-noise check](windows-gaming-noise-check.md) reconfirmed background
execution, exact UTF-8 log recovery, headless Edge and ordinary/empty Unicode-path
file transfers while the user reported gaming. Interactive stdin and persistent
shell state still failed by design. A [separate earlier browser comparison](windows-browser-ablation.md)
proved native GUI and Playwright control on a local fixture; it does not establish
independent foreground control while another person plays. The updated matrix
separates implementation gaps from GPU/WSL/Docker and other untested capabilities.
