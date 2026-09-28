# Core physical rollback diagnosis (2026-09-19)

The current production transaction remains `FAILED / RUNTIME_COMPLETION_UNCERTAIN`
on the Mac. Windows reports a terminal `rolled-back` journal. Neither an
installation retry nor a manual state reset has been performed.

## Reproduced defects and fixes

1. `Assert-AgentRoadZipEntry` rejected an empty mandatory `HashSet[string]` before
   the first ZIP entry could be checked. `AllowEmptyCollection` permits that
   initial state. A behavioral Windows fixture accepts the first ordinary entry
   and still rejects a case-insensitive duplicate. The actual staged archive's
   first entry also passes.
2. A validated target `RUNTIME_INTERNAL_ERROR` escaped the provision controller,
   but the orchestrator's finite provision/state vocabulary does not contain it.
   Such a result became `RUNTIME_COMPLETION_UNCERTAIN`. The provision controller
   now maps only a fully validated terminal internal error to the existing
   `RUNTIME_INSTALL_FAILED`. A mismatched result/exit pair remains uncertain.
   This reproduces a code path consistent with the historical failure; the old
   invocation's full transport output was not retained, so it does not establish
   that this was the only cause of its uncertain result.

## Physical evidence

- Full core installation in a fresh protected TEMP directory completed all nine
  forward phases, returned `committed`, and published its fixture active pointer.
- The fixture reads the existing signed capsule and archive. All installation
  writes and cleanup occur under its unique fixture root, with a distinct mutex.
- `test/fixtures/runtime-core-physical.mjs` is an explicitly invoked physical
  fixture, not an automatic test or production entry point. It requires an
  enrolled administrator session, an existing exact stage, and process-scoped
  script execution permission. Its generated file must be dot-sourced by the
  fixture loader so `$PSCommandPath` and the reporting scope both work.
- A separate production transport fixture delivered exact stdout, empty stderr,
  and exit code 2 through the actual staged-script/exit-receipt/cleanup path.
- A read-only check using production PowerShell validators confirmed the current
  journal's terminal rollback/succeeded phase, signed capsule and pinned key,
  operation/digest bindings, restored pointer snapshots, absent new generation
  and rollback tombstone, and the exact archive.

## Terminal confirmation implemented

The initial-core case now has a [durable terminal confirmation protocol](terminal-rollback-confirmation.md).
Two exact read-only observations, immutable evidence publication, and a
commit-gated local compare-and-swap resolved the historical uncertainty without
replaying installation or changing Windows files. The original uncertain state
and exact capsule/journal remain inside that commit. Ordinary state transitions
still cannot clear uncertainty directly.

A fresh approved core operation subsequently returned `READY`. Independent
inventory, baseline and no-op acceptance results are recorded in the live
checkpoint; the earlier isolated run alone was not production acceptance.

Private captures: `live-diagnostic-core-full-isolated-05`,
`live-diagnostic-core-zip-regression-01`, `live-diagnostic-terminal-rollback-precheck-01`,
and `exit-receipt-probe-*`. These names are pointers, not authority records.
