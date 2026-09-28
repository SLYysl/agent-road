# Task 9: staged transaction diagnosis

Observed 2026-09-18 on the enrolled Windows machine, under the user's expanded
permission for continued connection, diagnosis, and verification. This supersedes
historical single-inspection limits for this session, but does not authorize a
new prepare/apply or deletion of the staged operation. Separate explicit user
approvals covered the one-file journal ACL repair and the single reboot below.

## Confirmed findings

1. Pinned SSH works. The actual production planning-inventory reader returned
   `RUNTIME_STATE_UNSUPPORTED` in 2.661 seconds. It stopped at the first observation;
   no second observation was made in that rejected call. After the fixes and
   authorized journal ACL repair, the same production reader completed both
   observations in 4.410 seconds. Both reported the expected pending operation,
   no verified generation, and unpinned runtime trust. They were semantically
   equal at a 1 GiB free-space threshold (a diagnostic comparison, not admission).
2. The failed operation is not empty. It contains one expected transaction
   directory, a capsule, and one staged archive. No work directory was observed.
   Consequently the existing **empty-operation** recovery protocol deliberately
   rejects it at `WINDOWS_CHILDREN`. Repeating that inspect cannot make this
   topology eligible.
3. A bounded independent read verified the capsule's RSA-SHA256 signature against
   the existing Mac controller public key, and matched the failed state's device,
   operation, manifest, and generation bindings. Archive size and SHA-256 matched
   the signed component. This proves matching staged material, not installation,
   runtime readiness, or completion of all inventory ACL/schema checks.
4. Windows PowerShell 5.1 throws `ArgumentException` for `@($list)` when the list
   is created with `New-Object Collections.Generic.List[object]`. Physical probes
   reproduced this for zero, one, and two elements. `.ToArray()` passed all three.
   Four affected inventory/provision return sites now use `.ToArray()`.
5. A default `[string]$ExpectedSha256 = $null` becomes an empty string. The old
   `$null -ne $ExpectedSha256` condition therefore required an empty digest even
   when the caller omitted the hash argument. Both file-node assertions now test
   `PSBoundParameters.ContainsKey`. Supplied empty and mismatching hashes remain
   rejected. Eight physical checks passed across both actual helper bodies;
   ACL/link checks were explicitly stubbed in those hash-semantics tests.
6. After these fixes, strict staged validation reached the bootstrap identity
   journal and rejected its ACL. The AgentRoad and bootstrap directories have
   the required protected, canonical Administrators-owned DACL. The journal has
   exactly the SYSTEM and Administrators FullControl rules, but both are inherited
   and its DACL is unprotected. The consumer requires explicit protected rules.
   The current stage-zero writer already protects the published journal; it does
   not retroactively repair this existing file.

7. After the journal repair, direct staged validation with the Mac controller key
   passed, but the whole snapshot rejected absent runtime trust. The two optional
   `[string]` key parameters converted null to an empty string and fabricated a
   pin. They now preserve null as an object value; the capsule reader rejects
   non-null non-string values. Five physical tests of the actual strict staged
   reader passed: absent/matching pins accepted; empty/wrong/non-string pins
   rejected. No signature or existing-pin comparison was weakened.
8. The resulting strict snapshot passes: matching capsule and artifact, expected
   pending operation, no work or temporary upload, zero managed artifacts, and
   no verified installed generation. A successful inventory is not readiness.
9. Current inventory reports pending reboot and an interactive session. All
   signed platform fields except Windows PowerShell version still match; that
   version differs. Therefore the old signed capsule cannot simply resume under
   the existing exact machine-precondition check, even though its bytes and
   signature are valid.

## Authorized journal repair completed

The reviewed one-file repair preflight passed: both parent ACLs, regular-file and
single-link checks, bounded canonical journal parsing, enrolled device binding,
and the exact existing inherited rules were checked. The user explicitly
approved fixing this file. `SetAccessRuleProtection($true, $true)` was applied to
its existing DACL, followed by `SetAccessControl` on that file only. Postchecks
confirmed strict journal validation, unchanged content, owner, principals, and
rights. No staged content was changed, deleted, or installed.

## Next boundary

The old empty-operation recovery still cannot act on this nonempty topology.
Its earlier design assumption that no capsule can be recovered is contradicted
by the physical observations above, but importing the capsule alone does not
solve its now-stale platform binding or authorize a fresh operation.

The user explicitly authorized one reboot and subsequent read-only checks. One
request was dispatched and acknowledged. The first follow-up still observed the
old boot marker, followed by connection timeouts while Windows updated. The user
confirmed the update/startup and asked to wait; checks were paused until cleared.
No reboot request was repeated.

After the user reported readiness, pinned SSH reconnected successfully. The
private CIM boot marker differs from the immediately preceding pre-reboot marker;
sshd and Tailscale are both running with automatic startup. The production
inventory reader completed both observations in 6.026 seconds. They are
semantically equal at the signed component's maximum-expanded-size plus 256 MiB
reserve. Pending reboot and interactive session are both false, the session is
elevated, and available disk space meets that threshold. Every signed platform
field except Windows PowerShell version still matches.

A further strict read using the existing Mac controller key confirmed the same
signed capsule, archive, and operation binding, with no work/temporary upload and
zero managed artifacts. Registry and local runtime-state bytes are unchanged.
This is successful reboot/reconnection and inspection, not runtime recovery or
installation. The private diagnostic boot comparison is not a production recovery
boot-observation record or an actionable empty-operation ticket.

Next, implement an explicit recovery for the verified obsolete staged
transaction before a new prepare. Preserve its signed evidence, bind any recovery
action to the failed state and exact topology, and address old-process fencing
and lost acknowledgements. Do not clear FAILED, remove locks, re-sign the old
operation, or repurpose empty-operation cleanup. New-install admission must use
fresh inventory and current source revisions.

## Verification and limits

- Related inventory, planning, provision, production-dependency, doctor, and
  stage-zero tests: 121 total, 116 passed, 5 Windows-only skips on macOS.
- `npm run check`: passed.
- New regression guards cover all four object-list return sites and both
  optional-hash conditions. A Windows-only behavioral test covers omitted,
  matching, explicitly empty, and mismatching hashes using a temporary file.
  A separate Windows-only test exercises the staged parameter binder and capsule
  trust check with absent, matching, empty, wrong, and non-string pins.
- Registry and runtime-state bytes still match the pre-diagnosis review. Local
  evidence remains FAILED / RUNTIME_COMPLETION_UNCERTAIN; no recovery ticket,
  attempt, successor, boot observation, or recovery commit was created.
- Earlier ad hoc diagnostic loaders using text/EOF reads stalled. Their results
  remain unknown rather than successful. Three exactly identified diagnostic
  processes were stopped; subsequent bounded exact-byte diagnostic transport
  returned normally. A final process query found zero remaining old diagnostic
  loaders. The production reader also returned normally, so no
  production transport change is justified by these diagnostic stalls.
- Private receipts retain raw details locally under `inspection-captures`.
  Device identifiers, addresses, key material, full digests, and capsule content
  are excluded from this document and Git.

The success criterion remains a supported recovery followed by a complete normal
prepare/readiness check, with failure handling verified. This diagnosis does not
claim that criterion has been met or that every remaining defect is excluded.
