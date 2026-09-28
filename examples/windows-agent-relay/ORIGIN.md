# Windows agent relay provenance

These three deliverables (`telemetry.cjs`, `test.cjs`, `README.md`) were authored and
then repaired by the existing Windows Claude Code CLI on 2026-09-19, in a new demo
workspace, after explicit user authorization. Mac Astra dispatched both tasks via
Agent Road and retrieved the files using the normal pinned file-transfer path.
The Mac controller authored `acceptance.cjs`, this provenance note and the manifest.
No generated implementation was patched locally by the controller.

Observed CLI versions: Claude Code 2.1.198; Codex CLI 0.130.0. Claude's first result
reported model `claude-sonnet-5`. Codex was version-probed only, not model-invoked.

The original implementation passed its 11 tests and the first 8 independent cases.
An additional finite-number boundary check exposed overflow for Number.MAX_VALUE.
That failing example was sent back as a separate, explicit repair task in the same
workspace. Claude repaired running means/rounding and added 3 regressions.
Final validation: 14 author tests and 11 independent acceptance cases pass on Mac;
Windows validation is recorded in the handoff report. The final three independent
cases were informed by the discovered defect, not an unseen held-out evaluation.
This small demonstration does not establish general code correctness.

Reproduce from this directory:

```sh
node test.cjs
node acceptance.cjs "$(pwd)/telemetry.cjs"
```

`manifest.json` records SHA-256 of the exact final files, including the independently
supplied acceptance harness. Private device IDs, Windows user paths, auth-status
output and raw agent/transport receipts are not included.
