# Task 9: local evidence after a lost inspect result

The physical inspect was invoked, but its execution-session result was lost.
`INSPECT_INVOKED_RESULT_UNCERTAIN` remains the controlling outcome. No later
local observation can reconstruct that Windows result or authorize a retry.

## Local observation

From this checkout, run:

```sh
node --input-type=module -e 'import { observeLocalRecoveryEvidence } from "./src/runtime/local-recovery-evidence.mjs"; console.log(JSON.stringify(await observeLocalRecoveryEvidence()));'
```

This reads the configured Mac state root, selects exactly one connected device,
and requires its validated state to be `FAILED/RUNTIME_COMPLETION_UNCERTAIN`.
It does not call the production CLI, acquire store locks, write state, load
credentials, or invoke SSH. Only finite constants, booleans, and counts leave
the module. Invalid, missing, oversized, or symlinked input fails closed with
`LOCAL_EVIDENCE_UNAVAILABLE`.

File presence is not proof validity. Entry counts include every regular file,
including incomplete or invalid records; legacy and current directories are
reported separately. A persistent lock file does not establish lock ownership,
a running process, or a stale lock. The report always denies retry authority.

The report is a sequence of local observations, not an atomic snapshot. The
state record is rechecked, but recovery directories can change independently.
Run with other Agent Road controllers stopped. Parent symlinks are rejected
when observed; this utility does not claim hostile concurrent path-swap safety.
It must never be used as an authorization input to apply, cleanup, or prepare.

## Observed on 2026-09-18

- Validated Mac state remains `FAILED/RUNTIME_COMPLETION_UNCERTAIN`.
- Operation directory and persistent recovery lock file are present.
- Boot observation and recovery commit files are absent.
- Current/legacy tickets, successors, and current/legacy attempts: zero entries.
- No Windows command was executed. The remote outcome remains unknown.

## Durable result capture

`src/runtime/recovery-inspect-capture.mjs` implements the following contract,
tested with synthetic CLI results and a real local child-process exit:

1. Exclusively create an owner-only local run directory; persist and fsync a
   started marker before invoking the command. Never auto-resume that invocation.
2. Invoke exactly once, await the promise, and bound captured output bytes.
   Project only the finite inspect results from the Phase A plan; never persist
   raw stdout, stderr, exceptions, device IDs, or credentials.
3. Atomically publish and fsync a redacted terminal receipt before writing the
   same result to the tool's stdout. The receipt must be available even if the
   surrounding execution-session handle is lost.
4. Readback must never invoke the CLI. A started marker without a valid terminal
   receipt means uncertain, including a crash between remote completion and
   receipt publication. Missing, corrupt, conflicting, or partial records stop.
5. Test lost stdout, output overflow, thrown CLI errors, duplicate invocation,
   interrupted publication, and successful receipt readback without reinvocation.

The trusted local harness API is `captureRecoveryInspect({ runDirectory, invoke,
stdout, diagnostics = false })`. Its `invoke({ stdout, stderr })` callback must
await the one operation and return the CLI exit code. This module does not import the CLI, select a device,
or contact Windows. The separate [inspect CLI adapter](task9-inspect-cli.md) now
provides explicit production invocation and local readback routes; production
inspection has not been executed during this integration.

The caller supplies a new absolute canonical run path under an existing owner-only
0700 directory. Each run uses a 0700 directory and 0600 records. The fsynced
`started.json` contains a random local run binding; `terminal.json` contains that
binding and only the finite redacted projection. A combined 64 KiB capture limit
covers stdout and stderr. Publication uses an exclusive temporary file and a
non-replacing hard link, then removes the temporary and fsyncs the directory.
Any retained run directory blocks reinvocation, including one without a marker.

`readRecoveryInspectCapture(runDirectory)` only reads the two records. Missing,
extra, corrupt, noncanonical, mismatched, permissive, or symlinked records return
uncertainty. A lost display sink leaves the durable receipt readable. Readback
does not import or accept an invocation callback. It neither repairs partial
publication nor releases locks, and a receipt grants no permission to act.

The callback and capture parent are trusted local inputs. The callback must not
keep writing after its promise settles. Its own operation timeout remains in
force; this wrapper does not race a timeout against an unfinished remote command.
Duplicate prevention is per retained run directory, not across newly chosen run
paths. No new path may be used to bypass an uncertain earlier invocation. The
records bind to a local run, not to an independently verified remote operation.
They are diagnostic evidence, not recovery tickets or authorization inputs.
The default schema 1 format is unchanged; the CLI opts into schema 2 with a
finite last-stage label. [Stage diagnostics](task9-inspect-stage-diagnostics.md)
describes compatibility and why missing terminal records still mean uncertainty.
Observed symlinks are rejected, but this module does not claim safety against a
hostile owner concurrently swapping parent directories or rewriting both records.
Process-exit testing does not establish hardware power-loss durability.

The [pre-CLI readiness record](task9-pre-cli-readiness.md) contains the completed
local review, filesystem fault evidence, and adapter contract. The later
[CLI integration](task9-inspect-cli.md) implements that contract. Before physical
use, review the adapter and invocation plan, then obtain separate physical authorization.
The historical inspect result cannot
be recovered by adding a receipt after the fact. Reboot, apply, doctor, baseline,
plan, and prepare remain outside this local capture scope.
