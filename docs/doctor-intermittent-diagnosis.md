# Doctor stdin blocking diagnosis and repair

The common Windows SSH bootstrap now reads framed input through a `FileStream`
over the native standard-input handle. It previously used `Console.In`, backed
by `ConsoleStream`. The handle is wrapped with `ownsHandle: false`; the ASCII
reader disables BOM detection. The frame format, chunk size, length/hash checks,
source limits, timeout budgets, pinned transport and finite errors are unchanged.
No automatic retry was added.

This is consistent with the distinction documented in the upstream
[PowerShell SSH input discussion](https://github.com/PowerShell/PowerShell/issues/14478)
and the author's [raw-pipe experiment](https://gist.github.com/jborean93/7d4cb107fa06251b080fa10ec844893e).
That external evidence guided a local experiment; it is not a claim that the
experimental remoting shim was installed or is supported by Microsoft.

## Physical evidence

Before the repair, the original full CLI ordering reproduced
`RUNTIME_INVENTORY_FAILED` after a successful `present` plan, identical READY
prepare, unchanged baseline and identical status. Separate instrumented attempts
captured 20-second preflight/verification timeouts and 120-second invoked
inventory timeouts. Cleanup completed, but invoked uncertainty remained
fail-closed. SSH debug showed authentication, exec acceptance and stdin EOF,
without remote output/exit. A marked read-result call reached bootstrap START
but not FRAME before timeout.

A first process check counted only `-File` task children and found zero. It did
**not** establish that launchers were gone: a later independent short-command
query found ten processes with exact production-bootstrap token hashes, some
over an hour old. The direct query's encoded token differed from the production
bootstrap. One authorized reboot cleared those launchers; changed boot identity,
running automatic sshd/Tailscale, and no old bootstrap matches were verified.

Wrapping `Console.OpenStandardInput()` in a `StreamReader` still timed out:
it retained the problematic underlying stream. A temporary native-handle reader
then completed six consecutive full doctor observations with verified generation.
The production change implements that narrower reader substitution; a proposed
smaller-chunk experiment was not run or shipped.

The native Windows fixture passed all six cases: fragmented open input, maximum
32 KiB source with input still open, and rejection of bad hash, bad length,
truncation, and a leading BOM. Invalid frames did not execute the payload.

The formerly failing full normal CLI sequence subsequently passed initial and
final doctor, baseline capture, fresh `present` plan, approved prepare returning
the identical READY record, unchanged baseline, identical final status and
unchanged enrollment registry. Core remained PowerShell 7.6.4. No installation
was replayed and retained transactions were not deleted. Six further observations
using final production code passed with unchanged local state; an independent
process query found zero matching bootstraps and only its own short diagnostic
PowerShell process. Diagnostic receipt permissions were verified as 0700/0600,
with no saved process argv.

The original finite inventory errors lacked underlying execution receipts, so
individual historical failures cannot all be retroactively assigned this cause.
These bounded observations do not establish universal first-attempt reliability.
Other fixed-length input loaders were not changed by this repair.

## Reusable diagnostics

```sh
node tools/diagnose-runtime-doctor.mjs <device-id> 3
```

The optional count is 1–6 (default 1). The tool uses the production pinned
transport and inventory parser, stops on the first error, and never retries a
failed observation. It does not provision or reboot. Transport still creates
and cleans its normal bounded Agent Road task staging. Successful sequences
compare local runtime state before/after; a mismatch exits with a finite conflict.

Receipts use a unique `agent-road-doctor-*` directory in Node's OS temporary
directory (0700), with exclusive 0600 files. The output gives its basename.
Keep receipts private: execution results contain identifiers and raw inventory.
Terminal output contains only the capture basename, attempt/validation flags,
and finite error/boundary labels. Receipts retain process timeouts, executable
basenames, timestamps, results, bounded partial output on failure, pre-parse
inventory execution, and the first failure. No SSH argv, private keys, or stdin
payloads are saved. Archive temporary receipts privately if needed.

Do not equate zero task-script processes with zero bootstrap processes. A
concurrent observer can also be blocked by the local identity lock; the observed
`DEVICE_NOT_READY` during one overlapping probe was not a Windows failure.
One early marker harness exceeded its own 16-byte read-result output budget;
that harness error was excluded from product evidence and its diagnostic budget
was corrected. Failed hypotheses and original receipts remain preserved under
private `doctor-transport-check-*` captures.
