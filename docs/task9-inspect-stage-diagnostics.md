# Inspect stage diagnostics

The capture adapter records the last diagnostic stage using a finite
`lastStage` string. It does not record exceptions, paths, device identifiers,
addresses, hashes, or raw remote output. Recovery decisions, validation rules,
dependency calls, transport timeouts, and retry behavior are unchanged.

## Labels and interpretation

| Label | Last boundary entered |
| --- | --- |
| NOT_REPORTED | No controller stage was recorded |
| INPUT_VALIDATION | Inspect input validation |
| DEPENDENCIES | Dependency construction and validation |
| STATE_READ | Initial state read and eligibility validation |
| TARGET_LOAD | Target loading and validation |
| RECOVERY_LOCK | Recovery operation lock acquisition |
| RECOVERY_SCOPE | Locked scope validation |
| STATE_RECHECK | State reread and consistency checks under the lock |
| BOOT_OBSERVATION_READ | Existing boot observation read |
| COMMIT_READ | Existing recovery commit read |
| RECOVERY_RECORDS | Record validation and recovery lineage decisions |
| REMOTE_INSPECT | Remote dependency invocation, including transport and parsing |
| REMOTE_RESULT_VALIDATION | Returned classification and proof handling |
| BOOT_OBSERVATION_PUBLISH | Observation creation and validation; includes expected reboot stop |
| TICKET_PUBLISH | Ticket creation and validation |

A label is diagnostic context, not an exception-origin guarantee. Lock cleanup
or subsequent CLI handling can fail after the last marker. `REMOTE_INSPECT` does
not prove that SSH or Windows was reached and does not distinguish a remote
rejection from transport or parser failures. `BOOT_OBSERVATION_PUBLISH` does not
prove publication completed. No label grants recovery authority or authorizes
reboot, apply, retries, or cleanup.

Validated inspect rejections can now replace the controller stage with a finite
`WINDOWS_*` label reported by the wrapper. See [Windows inspect diagnostics](task9-windows-inspect-diagnostics.md)
for the rejection protocol, label meanings, trust gate, and platform limits.

## Receipt compatibility and uncertainty

`captureRecoveryInspect` retains schema 1 by default. The separate inspect CLI
opts into `diagnostics: true`, producing schema 2 started and terminal records.
Schema 2 terminal projections include exactly one allowlisted string `lastStage`.
Readback requires matching record versions and run bindings, rejects extra or
invalid fields, and reads existing schema 1 receipts without adding a stage.
Untrusted stdout/stderr fields cannot supply the label.

An async-local recorder separates simultaneous calls and ignores callbacks after
its operation settles. Stages remain in memory until terminal publication; this
is not a per-stage crash journal. A crash before publication, invalid readback,
or failed publication returns the existing uncertain result without a fabricated
persisted stage. A lost display after publication can recover the saved stage
through local readback. The retained run directory still blocks reinvocation.

## Local evidence and next boundary

Synthetic controller tests produce the same `RUNTIME_STATE_UNSUPPORTED` at six
different boundaries and compare dependency call sequences with diagnostics on
and off. Two tests exercise the actual capture CLI, production CLI, and controller
with synthetic dependencies, distinguishing remote invocation from observation
publication and verifying receipt readback. Other tests cover concurrent capture,
late callbacks, output-field spoofing, malformed schema 2 receipts, schema 1
compatibility, lost display, and child-process exit before terminal publication.
These tests make no production Windows calls. The focused suite passed 110/110;
the full suite reported 1,275 tests, 1,267 passed, 8 skipped, and zero failures.
`npm run check` also passed.

This change cannot attribute the historical failure retroactively. The earlier
single physical authorization was consumed and its retained run remains occupied.
The executable source changed, so the earlier source binding is no longer a
review of this version. Any further physical investigation needs a fresh concrete
review and authorization that addresses the retained uncertain history; choosing
a new run path alone does not resolve it.
