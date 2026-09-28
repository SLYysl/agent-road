# Windows agent handoff acceptance

On 2026-09-19 the user explicitly authorized invoking their installed Windows
agents. The controller found Claude Code 2.1.198 and Codex CLI 0.130.0. Both version
commands worked. Claude's own auth-status command reported logged in; Codex was
not model-invoked or upgraded. The Claude result reported `claude-sonnet-5`.

## Invocation boundary

The installed agents belong to the logged-in desktop account; Agent Road's SSH
account is different. This test used a temporary, explicitly staged scheduled task
under the current desktop user's Interactive/Limited token. It reused the native
Job Object worker for bounded process lifetime. This was a one-off session bridge,
not the public background controller's default S4U principal and not a generic
agent-backend integration. It currently requires that desktop user to be logged in.
No authentication files were copied or manually read, and no CLI was installed or
updated. Auth-status output and exact user/device/task identifiers remain private.

A fresh demonstration workspace received a dependency-free telemetry-library task.
Claude was invoked in print mode with JSON results, a fixed built-in tool set,
`dontAsk`, explicit Read/Write/Edit/Glob/Grep permissions and the exact test command
`Bash(node test.cjs)`. MCP configuration was restricted to an empty explicit file.
No permission-bypass flag was used. One initial attempt to append an exit-code echo
to the shell command was denied; the agent then used the permitted exact command.
The repair result had no permission denials. Both invocations completed normally
within the worker's 480-second limit. Session persistence was disabled.

The invocation flags were checked against the installed CLI help and the
[official Claude Code CLI reference](https://code.claude.com/docs/en/cli-reference).
These are task permissions and process bounds, not a malicious-agent sandbox.

## Observed work and repair

1. Windows Claude authored `telemetry.cjs`, `test.cjs` and `README.md`, and reported
   running its 11 test cases. The controller retrieved the files through ordinary
   Agent Road get, reviewed their source and independently reran those tests.
2. Eight independently prepared acceptance cases passed. An additional review
   check with Number.MAX_VALUE exposed nonfinite means for a valid finite input.
3. The controller dispatched an explicit correction task to the same workspace.
   Claude changed mean calculation/rounding and added three regression cases.
4. The final 14 author tests and 11 independent acceptance cases passed on both
   Windows (Node 24.15.0) and the Mac controller. Three of the acceptance cases were
   added for the observed defect; this is not an unseen held-out evaluation.
5. Four file hashes matched between Windows, the received Mac copy and the archive.
   Temporary probe/initial/repair scheduler definitions were removed after terminal
   success; workspace files, logs and private receipts were retained.

The controller did not patch the generated implementation. The exact final files
and controller-authored acceptance harness are under
[`examples/windows-agent-relay`](../examples/windows-agent-relay/ORIGIN.md).
This establishes a bounded dispatch → generate/test → retrieve/review → repair →
revalidate loop. It does not establish universal agent parity, unattended desktop
login, automatic agent selection, or general correctness of generated programs.

## Local readiness error found during retrieval

A parallel result query failed with DEVICE_NOT_READY while a transfer was running.
The failure stack ended in the Mac's `loadRemoteTarget` identity-read catch, before
remote transport. A controlled check reproduced that exact public code by holding
only the local SSH identity lock and then loading the target, without contacting
Windows. Source inspection shows that `SshIdentityStore.getExisting` uses the
one-second default file-lock wait; pinned transport holds that same identity lock
for its session. At the time, `loadRemoteTarget` flattened identity failures to
DEVICE_NOT_READY.

Thus local lock contention is a demonstrated cause of this error; the other agent's
earlier occurrence cannot be labelled a network outage from the reported evidence.
Queries/transfers were serialized for the rest of that test.

The subsequent fix brands actual file-lock acquisition timeouts internally and maps
an identity-read acquisition timeout to `SSH_IDENTITY_BUSY`, then public
`DEVICE_BUSY` (CLI exit 2, no remote dispatch). Other identity validation failures
remain `DEVICE_NOT_READY`. Existing lock waits, key validation and transport
serialization are unchanged. A real held-lock check exercised the main CLI and
confirmed identity loading works after release; 106 focused tests passed.

Wait for the active controller operation to finish before a new query. This change
does not implement concurrent transport or automatic replay. For any execution with
an uncertain outcome, inspect its existing job ID instead of submitting it again.
The earlier report alone does not prove which transient condition occurred.
See [Windows browser comparison](windows-browser-ablation.md) for the next live trial.
