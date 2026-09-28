# Reuse existing Windows tools

The user chose to inspect and reuse existing tools before installing replacements.
This extends the earlier portable-only design with an explicit **existing-tool
assessment**. It does not change the signed managed-runtime catalog or treat an
external installation as an Agent Road generation.

## Inspect

```sh
node src/cli.mjs base-inspect <device-id>
```

The command uses the enrolled device's pinned SSH transport. It inspects SSH PATH
and a bounded set of normal machine/user-profile installation locations for Git,
Node.js, Python and ripgrep. Windows Store aliases are reported without executing
them. Reparse-point executables or ancestors are not accepted by this first version.
Scoop junctions may therefore require later explicit resolution and verification.
A `not-found` result means not found in this search scope, not absent from the disk.

The remote script runs version probes, a small Node expression, and an isolated
Python query for `venv`, `ensurepip`, and `pip` modules. It hashes each executable
before and after probing and rejects an observed change. It strips inherited Node
startup options and uses Python `-I -B`. Failed candidates retain finite reasons.
Each subprocess has a deadline; only its own timed-out probe process is terminated.
No install, shell profile edit, global PATH change, reboot, package installation,
or runtime activation is performed. The normal SSH transport still creates and
cleans its temporary script staging files.

The console report omits paths and hashes. A unique private OS-temp directory
(`agent-road-existing-base-*`, mode 0700) contains exclusive 0600 receipts and
`assessment.json` with exact paths and fingerprints. Treat these files as private.
This command does not persist a selected tool in device configuration.

## Assessment

| Action | Meaning |
| --- | --- |
| `reuse` | Exactly one candidate passed the basic probes (and Python module checks). |
| `select` | Multiple candidates passed; select an explicit path before task execution. |
| `review` | Candidates exist but none passed the required checks. |
| `not-found` | No candidate was found in the bounded search locations. |

`reuse` is a recommendation for basic task execution, not publisher authentication,
a whole-installation integrity proof, or a guarantee that a particular project
supports that version. Executable hashes do not cover DLLs or standard libraries.
The Python module-presence check is narrower than actually creating a virtual
environment or installing a package. Git/ripgrep checks establish version-command
execution only. An external tool can change after the observation: the task
launcher must revalidate the chosen absolute path and fingerprint and fail on drift,
then check the task's version/feature requirements. Never silently fall back to PATH.

`managedBaseReady` is always false in this report. Existing `core`/`base` runtime
state, signed manifest, receipts, and rollback remain on their current contract.
Do not send existing-tool assessment data to the provisioning state machine.

## Next integration

Use the selected absolute executables in a task-specific environment after fresh
validation; keep Python project virtual environments separate from the existing
interpreter. Add only capabilities the task actually needs and lacks. A missing
ripgrep alone does not require reinstalling Git, Node.js, or Python, or prevent a
task that does not need ripgrep. The explicit task launcher below binds this observation; automatic missing-tool
installation remains unimplemented.

## Execute with observed tools

```sh
node src/cli.mjs base-exec <device-id> <absolute-inspection-directory> <absolute-task.ps1> git,node,python [timeout-seconds]
```

Use the private directory returned by the inspection command (under the Mac's OS
temporary directory). The launcher requires owner-only inspection files and checks
that the observation belongs to the requested device. It selects exactly one usable
candidate for each requested tool; missing or ambiguous requirements fail locally.
A tool not requested by the task does not block execution.

In the PowerShell task, call the bound executable explicitly:

```powershell
$value = & $AgentRoadTools.node -p '6*7'
if ($LASTEXITCODE -ne 0 -or $value -ne '42') { throw 'TASK_FAILED' }
```

The remote wrapper validates every selected path and executable hash before any
task code runs. It rejects reparse-point paths and holds read handles denying normal
file write/delete replacement while the task runs. A mismatch, inaccessible file,
or incompatible lock fails with `EXISTING_TASK_TOOL_CHANGED` and exit 78, before
the task starts. It never resolves a replacement from PATH or automatically retries.
This is not an atomic proof of ancestor-directory identity, loaded dependencies,
or a security sandbox. The task is trusted user code and must use the supplied map;
an arbitrary script can choose to invoke something else.

Node startup overrides and Python home/path overrides are removed in the temporary
remote task process. The wrapper defaults PowerShell console input/output and native
pipeline encoding to UTF-8, and sets task-local `PYTHONIOENCODING=utf-8`. Python
`-I`/`-E` ignore that environment setting; use `-I -B -X utf8` when isolated Python
needs UTF-8 output. Other native tools can still have their own encoding settings.
This default applies to this launcher; ordinary `agent-road exec` keeps its existing
PowerShell `-File` execution semantics. No machine/user environment is edited. Project-specific versions, package dependencies, virtual environments,
and tool-specific options remain the task's responsibility.

The wrapper and raw task results are saved in a new private
`agent-road-existing-task-*` directory. The console exposes only a capture basename,
status, exit code, tool names, and output byte counts. Task stdout/stderr remain in
`execution.json`; treat the entire directory as sensitive. Execution is bounded by
the existing remote-exec timeout/recovery contract. The optional final argument is
an integer from 1 through 1800 seconds (default 300); it bounds the execution call,
not all transfer/cleanup phases. Longer timeouts do not provide durable jobs or
resumption. An uncertain invocation must
not be replayed. This command does not install missing tools or publish base READY.

Physical acceptance on 2026-09-19: the committed
[`existing-tools-task.ps1`](../test/fixtures/existing-tools-task.ps1) ran successfully
with existing Git, Node.js and Python. A separate private inspection copy with an
intentionally incorrect Git hash returned exit 78, exact finite drift error and no
task output; its sentinel task never ran. No installed executable was modified for
this negative test. Controller runtime state remained unchanged with only `core`
ready. Twelve local inspection/binding/CLI tests passed.
