# Local diagnosis of the finite inspect stop

## Finding

The authorized inspection returned `RUNTIME_STATE_UNSUPPORTED`. Its exact failed
check cannot be recovered from the finite receipt. Local investigation narrowed
the possibilities but did not establish a root cause. No further Windows command
was issued, and no real recovery lock, state record, or permission was changed.

## Evidence obtained locally

1. Metadata audit: the managed runtime directories are canonical, owner-owned
   0700 directories without extended ACL entries. The state file is a single-link
   0600 regular file; the persistent recovery lock is a single-link empty 0600
   regular file. Neither is a symlink and neither has extended ACL entries.
   Legacy ticket/attempt directories are absent, not merely empty.
2. All recovery eligibility predicates passed: schema 1, failed completion-uncertain
   state, core-only requested profile, no ready profiles, valid operation and
   manifest/generation formats, and successful canonical recovery-state digest
   validation. No private values or digests were emitted.
3. A bounded copy of the selected device's non-key runtime files was made in a
   canonical owner-only temporary directory. The production `RuntimeStateStore`
   read the copied state successfully and returned identical state data. The
   production `RuntimeRecoveryStore` acquired the copied operation lock and read
   absent boot-observation and recovery-commit records successfully. The copy was
   removed afterward. These operations never used the actual recovery lock or
   imported a transport invocation path.
4. The persisted capture timestamps span approximately 6.8 seconds. The selected
   known-hosts file's modification time falls inside that interval. The production
   trusted-SSH code rewrites that file after local key/fingerprint checks and
   before address probing. This is consistent with entering transport preparation;
   absent an exclusive historical trace, it is not proof of a particular SSH
   command, successful authentication, or a Windows response.
5. Controller and recovery-remote regression suites passed 60/60. The suites
   include an acknowledged Windows rejection carrying this same error code and
   a controller-side boot-observation validation failure carrying the same code.

The home directory has an extended ACL entry, but the existing-root state-read
path does not validate that home directory. This observation is not evidence
that the home ACL caused this failure and does not justify changing it.

## Why the remaining result is ambiguous

`inspectRuntimeRecovery` can return the same finite code at different boundaries:

| Boundary | Evidence / limitation |
| --- | --- |
| Local state or eligibility validation | Current predicates and isolated state-store read passed |
| Recovery operation lock or record reads | Passed on isolated copy; does not recreate historical contention or path races |
| Remote inspect rejection | `parseRuntimeRecoveryInspectProcess` preserves an acknowledged `RUNTIME_STATE_UNSUPPORTED` rejection |
| Returned-state or boot-observation handling | Controller checks and store publication can also produce the same code |

The generated Windows inspect wrapper itself maps multiple validation failures
to that one error code. Raw output was intentionally not retained, and the
receipt contains no source-stage field. Therefore neither an ACL mismatch, a
changed remote directory, a boot-marker problem, nor a specific local publication
failure can be named as the confirmed cause. No permissions were relaxed and no
cleanup or reboot was performed on the strength of this code.

Relevant code: `src/runtime/runtime-recovery.mjs` (`readEligibleState`,
`inspectRemote`, `inspectRuntimeRecovery`), `src/runtime/runtime-recovery-store.mjs`
(`withRecoveryOperationLock`), `src/runtime/runtime-recovery-remote.mjs`
(`parseRuntimeRecoveryInspectProcess`), and `src/ssh/trusted-ssh-session.mjs`
(`runSessionLocked`, `writeKnownHosts`).

## Next diagnostic boundary

Before another physical call, add narrowly scoped, finite stage attribution and
validate it against synthetic failures. Distinguish state read, recovery lock,
record reads, remote inspect, and boot-observation publication; keep only fixed
stage enums and existing finite codes, never raw exceptions, paths, or identifiers.
If the failure is established to originate in Windows, its internal checks will
need similarly bounded attribution before claiming a specific cause.

This is diagnostic work, not a reason to modify validation policy or repair
state speculatively. Any new capture/receipt format must retain crash uncertainty,
redaction, and no-retry behavior. The original fixed run remains occupied. This
local investigation authorizes no new inspect, reboot, apply, or cleanup.

The subsequent [local stage diagnostic implementation](task9-inspect-stage-diagnostics.md)
adds finite last-stage capture and synthetic failure tests. It does not identify
the historical cause or add information to the existing receipt. This source
change invalidates reuse of the earlier executable source binding for a new call.
