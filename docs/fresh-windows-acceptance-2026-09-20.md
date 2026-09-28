# Fresh Windows pairing acceptance — 2026-09-20

## Scope

Two independent VirtualBox Windows 11 Enterprise Evaluation environments on the
existing Windows host. Trial two is a full clone of the pre-enrollment snapshot,
not a clone of trial one's enrolled state. Both initial baselines report no
Agent Road root, no Tailscale service and no sshd service. Each has a separate VM
UUID, virtual NIC and disk. This validates fresh application/device identity;
it is not a second Windows installation from ISO or a test across separate ISPs.

The public HTTPS pairing service and automatic single-use Tailscale key mode are
used. Credentials, verification screenshots and raw captures stay outside Git.
The inspected-file loader route is described in `short-pairing.md`; the host
Defender interception of injected `irm | iex` remains a separate limitation.

## Trial one: exploration and repair

- Initial enrollment exceeded the old ten-minute controller budget while Windows
  Update was still installing OpenSSH. The remote bootstrap later reached
  completion-pending. Its terminal result was inspected before a new enrollment.
- A second enrollment completed pinned SSH verification. Pending Windows file
  renames required one guest reboot before core provisioning.
- The first formal core attempt failed and completed rollback. Long staging
  paths exceeded the fresh guest's path handling with `LongPathsEnabled=0`.
- A shortened work directory passed the isolated complete-core fixture. A real
  Windows filesystem fixture also checked legacy selection and rejection when
  both old and new work directories exist.
- A new approved formal core plan then reached `READY`. Protected baseline
  comparison reported `UNCHANGED`, with no changed surfaces.
- Administrative execution and SSH after reboot passed. An 81-byte UTF-8 input
  containing Chinese and emoji was uploaded, read by Windows, and returned with
  a hostname suffix; the downloaded bytes matched the expected result exactly.
- Both enrollment auth keys have revocation receipts. Temporary diagnostic roots
  were removed by exact path. Defender remained active and LongPathsEnabled stayed 0.

## Validation

Full `npm test`: 1,506 passed, 18 skipped, zero failed (1,524 total).
`npm run check` and `git diff --check` passed. Windows-only fixture results are
recorded separately from the locally skipped tests. No public deployment was
needed for these controller-delivered bootstrap/runtime fixes.

## Trial two

The sole pairing attempt reached pinned `CONNECTED_SSH_ONLY` in 11m33s
(controller registration at 00:33:26.940Z, verified at 00:45:00.098Z). Its SSH
host fingerprint and Tailscale identity differ from trial one. The one-use auth
key has a revocation receipt with no uncertain cleanup.

The automatic core handoff returned `RUNTIME_REBOOT_REQUIRED`, so the `pair`
process exited 2 despite successful enrollment. One pending temporary-file rename
was present; CBS and Windows Update reboot flags were false. One guest reboot was
scheduled, and SSH/admin/services were verified again after boot. The first
reconnect probe arrived during boot and failed; the subsequent read-only probe
succeeded. No second enrollment or repeated restart was issued.

The first formal core provisioning attempt after reboot reached `READY`, and
executing its private PowerShell binary returned version 7.6.4. LongPathsEnabled
remained 0. The UTF-8 upload/execute/download roundtrip passed exact byte comparison.
No core reinstall or second enrollment was needed.

The first post-core baseline read returned `RUNTIME_INVENTORY_FAILED`; its exact
underlying cause was not retained and is not claimed fixed. A subsequent instrumented
read succeeded. It ran after the first file upload and reported only
`external-sentinel-acls` changed. The upload had created the previously absent
`C:\ProgramData\AgentRoad\transfers` directory. Read-only diagnostic recomputation
using the original baseline key and current eight ACL records, substituting only
that path's original `missing` record, exactly matched the original surface MAC.
Other surfaces were unchanged. The actual comparison remains recorded as `CHANGED`;
it was not overwritten or relabeled as unchanged. The diagnostic key-bearing local
script was removed after verification, and no actual Windows ACL was changed.

Both trials therefore reached SSH, core and file-transfer acceptance. Trial two
used one enrollment attempt and one successful core provisioning attempt, with
one intervening Windows reboot. It is not an uninterrupted, zero-reboot `pair`
command returning zero: reboot continuation remains a separate controller step.
Trial one is saved; trial two is left running. Both environments are retained.
