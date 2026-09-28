# Task 9: capture readiness before CLI integration

Historical checkpoint at `5543660`. The later [inspect CLI integration](task9-inspect-cli.md)
implements the adapter contract below; no physical inspection has been performed.

## Scope and decision

This checkpoint stops before production CLI integration. It covers the local
capture module, filesystem failure behavior, redacted readback, and the contract
for the future adapter. No target is selected and no Windows command is run.
No adapter, new CLI command, package dependency, or recovery permission is added.

The earlier physical inspect remains `INSPECT_INVOKED_RESULT_UNCERTAIN`. This
implementation cannot reconstruct its outcome or authorize a replacement call.

## Review findings

One finite-projection defect was reproduced and fixed: `Object.hasOwn` coerced
an array status such as `["RECOVERY_READY"]` into a permitted property name.
The new regression first returned `FINITE_RESULT` where `STOP_UNKNOWN` was
required. The projection now requires a string before checking the allowlist;
the same check protects capture and receipt readback.

The self-review also checked the ordering of exclusive directory creation,
started-marker synchronization, invocation, terminal-file synchronization,
non-replacing publication, directory synchronization, and display. The callback
is invoked only after the start record and directory have been synchronized.
Display occurs only after publication and its final directory synchronization.
No independent agent review was performed.

## Fault evidence

The capture tests exercise the actual module in disposable local processes.
Filesystem failures are injected into Node's filesystem calls inside each child;
no test hook or injectable filesystem was added to the production API.

| Boundary | Invocation count | Capture result | Later readback |
| --- | --- | --- | --- |
| Parent directory sync fails | 0 | BLOCKED | unknown |
| Started write or file/directory sync fails | 0 | BLOCKED | unknown |
| Terminal write or file sync fails | 1 | STOP_UNKNOWN | unknown |
| Terminal link or temporary unlink fails | 1 | STOP_UNKNOWN | unknown |
| Final directory sync fails after publication | 1 | STOP_UNKNOWN | finite if complete records remain visible |
| Process exits after started, before result | 1 | no returned result | unknown |
| Process exits during display | 1 | no returned result | finite in another process |

Every injected filesystem failure suppresses display and retains the run
directory, so a second capture against it is blocked. A visible complete receipt
after final-directory sync failure establishes only what can currently be read;
it does not prove the earlier sync succeeded or that bytes would survive power
loss. Partial publication is never repaired automatically.

Other coverage includes duplicate concurrent calls, strict result semantics,
all permitted success status/classification pairs, thrown/unknown errors,
corrupt/mismatched/extra-field receipts, private modes, symlinks, conflicting
endpoints, and a UTF-8 payload at exactly 65,536 bytes versus one byte over.
Raw private fields are absent from persisted projections.

## Future adapter contract — design only

1. Establish a single reviewed, controller-private device selection and retain a
   fixed local capture path before any invocation. Do not put device IDs, keys,
   addresses, tickets, or raw CLI output into logs or the path's label. The path
   must remain discoverable without the execution-session handle. Do not choose
   a fresh path automatically after a block, error, timeout, or uncertain result.
2. Use an existing canonical owner-only capture parent. Do not repurpose the
   runtime recovery directory, acquire its lock, or remove historical artifacts.
   Validate inputs locally before entering capture; do not run transport preflight
   or any other remote command as an implicit side effect of the adapter.
3. The sole invocation is an awaited call to the existing `main(argv, env, io)`
   interface. Its argv is exactly `['runtime-recover', selectedDeviceId, '--inspect']`
   for a separately reviewed fresh-inspect scope. Do not accept arbitrary commands,
   apply flags, prior tickets, default device fallback, or `latest` selectors.
4. Pass only the capture sinks to `io`; do not fall back to real stdout/stderr or
   invoke the command a second time to get an exit code. Retain the existing
   production timeout and SSH verification behavior. Do not race a new timeout
   against a still-running promise or launch a detached retry.
5. Translate the capture outcome at the outer boundary: `FINITE_RESULT` -> exit 0,
   `FINITE_STOP` -> exit 2, `BLOCKED` -> exit 3, `STOP_UNKNOWN` -> exit 4. All are
   terminal for that invocation; exit 0 and `actionable: true` do not authorize
   apply or any next command. A failed display may prevent observing this exit;
   retrieve the existing receipt instead of repeating capture.
6. Keep readback as a separate local-only route accepting the known capture path.
   Never import or invoke the CLI from readback. Missing or uncertain readback
   stops without repair, lock removal, reboot, or another inspect.

Future integration tests must use a stub `main` to verify the exact argv,
environment forwarding, capture sinks, awaited completion, one invocation,
finite exit mapping, and readback with zero invocations. Before a physical run,
review that adapter and the exact local run path and separately authorize the
single remote inspection. This checkpoint supplies no such authorization.

## Verification boundary

- Capture regression: 36 passed, 0 failed, including nine filesystem fault cases.
- Full suite: 1,244 tests; 1,236 passed, 0 failed, 8 skipped.
- Syntax and final checkpoint results are recorded in `CURRENT_STATE.md`.
- Production CLI integration, physical recovery, hardware power-loss behavior,
  and protection against a hostile owner replacing parent directories remain
  outside this checkpoint. Receipt UUIDs bind local files; they do not authenticate
  a remote operation. No findings here loosen pinned SSH, Tailnet, ACL, stderr,
  exit-code, or recovery authorization rules.
