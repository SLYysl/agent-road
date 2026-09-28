# Agent Road Remote Work Layer Design

> Date: 2026-07-28  
> Status: approved for implementation  
> Base: `feature/windows-bootstrap` at `808413b`

## 1. Objective

Add the first usable Mac-to-Windows work surface on top of the physically accepted Tailscale and pinned-host-key OpenSSH channel. A Mac-side Agent must be able to run a local PowerShell script on an explicitly named Windows device, upload one file, and download one file without touching the Windows desktop.

The target still runs no model and no general Agent Road daemon. The implementation uses Windows PowerShell 5.1, OpenSSH, and the existing dedicated `AgentRoad` administrator account.

## 2. Scope

This slice adds exactly three CLI operations:

```text
agent-road exec <device-id> --script <local.ps1> [--timeout-seconds <1-1800>]
agent-road put <device-id> <local-file> <absolute-windows-path> [--overwrite]
agent-road get <device-id> <absolute-windows-path> <local-file> [--overwrite]
```

It also extracts a reusable trusted SSH session boundary from the current verifier so enrollment verification and normal operations cannot drift to different SSH trust policies.

This slice does not add inline PowerShell, an interactive shell, directory recursion, GUI/browser control, Windows-MCP, RustDesk, other VPNs, a target daemon, a persistent task queue, automatic development-tool installation, or automatic retry of an uncertain remote mutation.

## 3. Preconditions

Every operation names one device ID explicitly. The controller loads that device from the existing registry and requires:

- status `CONNECTED_SSH_ONLY` or `READY`;
- capabilities `ssh`, `sftp`, and `admin-powershell` as required by the operation;
- target platform `windows`;
- the dedicated SSH username `AgentRoad`;
- at least one registered Tailscale address;
- the registered Ed25519 host keys and fingerprints;
- the existing per-device private identity and known-hosts locations.

Missing, malformed, or non-ready state fails before any network process starts.

## 4. Architecture

### 4.1 Trusted SSH session

A focused internal SSH session module owns all security-sensitive connection construction:

- `/usr/bin/ssh`, `/usr/bin/scp`, and `/usr/bin/ssh-keygen` are absolute paths;
- the registered host keys and fingerprints are validated before use;
- the private key and known-hosts data are opened, snapshotted, and revalidated before and after every child process;
- password, keyboard-interactive authentication, ssh-agent, proxy command, ProxyJump, ControlMaster, DNS host-key verification, and host-key updates remain disabled;
- `StrictHostKeyChecking=yes`, `IdentitiesOnly=yes`, and the session snapshots remain mandatory;
- Tailscale addresses are selected only from the frozen device record;
- one per-device lock serializes v1 operations.

The current enrollment verifier is changed only enough to consume this same internal boundary. Its probe, file round-trip, error behavior, and acceptance result remain unchanged.

Every non-fixed PowerShell value, including a user-facing path, is carried in a bounded canonical JSON payload encoded as Base64. It is decoded and schema-validated by the fixed remote wrapper; arbitrary values are never interpolated into PowerShell source or an SSH argument.

The fixed wrapper source is transported through an integrity-checked line frame over pinned-host-key authenticated SSH rather than one large stdin line. A single short `-EncodedCommand` bootstrap starts by setting `$ProgressPreference='SilentlyContinue'`, then reads only the exact `AGENT_ROAD_STDIN_V1` header, canonical ASCII byte length, uppercase SHA-256, derived chunk count, Base64 chunks of at most 2,048 characters, and `END`. It rejects truncation, noncanonical lengths/counts/Base64, padding in nonfinal chunks, non-ASCII or NUL source bytes, and length/hash mismatches before `ScriptBlock::Create`. The source is capped at 32 KiB so the complete frame remains below the trusted session's 64 KiB stdin limit. The controller emits no bytes after `END`, while the bootstrap deliberately executes without waiting for EOF. Only integrity-checked chunk bytes before `END` are recovered as wrapper source; this does not claim that a subsequently invoked script could never read separately supplied trailing stdin.

### 4.2 Operation modules

The runtime is split into small units:

- `trusted-ssh-session`: trust material, address probing, locked process invocation, and cleanup invocation;
- `remote-exec`: script validation, staging, execution, bounded result parsing, and cleanup;
- `remote-file-transfer`: upload/download validation, staging, SHA-256 integrity, atomic publication, and cleanup;
- CLI adapters: argument parsing, device lookup, stable output, and process exit code mapping.

No operation builds an independent list of SSH options.

## 5. Address selection and retry semantics

Before a mutation, the trusted session runs a bounded no-op administrative PowerShell probe against registered addresses in order. It selects the first address that passes the pinned-host-key connection and administrator check.

After staging or execution begins, the operation stays on that address and is attempted exactly once. A connection loss after this boundary returns an uncertain result. It never changes address and repeats the script, publication, or replacement because the first mutation may already have completed.

Read-only address probing may retry. Remote mutations may not.

## 6. `exec` data flow

### 6.1 Input

The local script must be an existing regular file with one hard link, not a symlink, from 1 byte through 1 MiB. It must contain valid UTF-8 text without NUL characters. The controller snapshots it into an owner-only temporary directory, converts it to UTF-16LE with a BOM for deterministic Windows PowerShell 5.1 decoding, and computes SHA-256 over the staged bytes.

The default timeout is 300 seconds. The accepted range is 1 through 1800 seconds. Combined captured stdout and stderr are bounded to 4 MiB.

### 6.2 Remote staging and execution

The controller uploads the prepared script to a random path below:

```text
C:\ProgramData\AgentRoad\tasks\<operation-id>.ps1
```

The operation ID is generated by the controller and restricted to a fixed lowercase hexadecimal form. Before upload, a fixed preflight creates or validates the internal task directory with the existing Agent Road trusted-directory policy. A small fixed wrapper:

1. verifies that the path is below the task root and is a regular non-reparse file;
2. verifies the remote SHA-256 equals the controller snapshot;
3. executes it with Windows PowerShell 5.1, `-NoLogo`, `-NoProfile`, and `-NonInteractive`;
4. propagates the script exit code;
5. produces no additional success text on stdout or stderr.

The script body is never interpolated into an SSH command line.

### 6.3 Result

Successful transport writes one JSON object to controller stdout:

```json
{
  "schemaVersion": 1,
  "operation": "exec",
  "deviceId": "dev_example",
  "address": "100.64.0.1",
  "exitCode": 0,
  "stdout": "",
  "stderr": "",
  "startedAt": "2026-07-28T00:00:00.000Z",
  "finishedAt": "2026-07-28T00:00:01.000Z"
}
```

The CLI exits `0` when the remote exit code is zero and `1` when transport succeeded but the remote script returned nonzero. Infrastructure, validation, trust, timeout, output-limit, or cleanup failures exit `2` and print only a stable code to controller stderr.

The temporary script is removed after success or failure. If the controller cannot prove removal after staging began, the final result is `REMOTE_CLEANUP_UNCERTAIN`, even when the script result was otherwise available.

Timeout or output overflow after remote execution may have started is reported as `REMOTE_EXECUTION_UNCERTAIN`; it is never simplified to a retryable timeout. `REMOTE_OUTPUT_LIMIT` is limited to a pre-mutation probe that exceeded its output contract.

## 7. File transfer data flow

### 7.1 Common path rules

V1 remote paths must be absolute drive paths such as `C:\...` or `D:\...`. UNC paths, device paths, alternate data streams, relative paths, wildcards, and control characters are rejected. Windows canonicalizes the path and must obtain the same intended absolute drive path before use.

User-facing `put/get` cannot directly access the internal `%ProgramData%\AgentRoad` tree. The internal transport code may use only its fixed random staging children there.

Each transferred file is bounded to 256 MiB.

### 7.2 `put`

The local source must be a stable regular non-symlink file with one hard link. The controller snapshots it into an owner-only local temporary directory and computes SHA-256.

The file is uploaded to a random internal remote staging path. A fixed PowerShell publisher verifies the staged file type, size, and SHA-256, validates that the destination parent already exists and is not a reparse point, and then publishes within the destination volume.

An existing destination is rejected unless `--overwrite` is present. Overwrite accepts only an existing regular non-reparse file. Publication uses a same-directory temporary file and an atomic move or replacement so a failed transfer does not expose a partial destination.

Success returns one bounded JSON object containing schema version, operation, device ID, selected address, byte count, SHA-256, destination path, and timestamps.

### 7.3 `get`

A fixed PowerShell preparer validates the remote source as a regular non-reparse file within the size limit, copies a stable snapshot to a random internal staging path, and returns its exact byte count and SHA-256. SCP downloads only that internal staging file.

The controller writes to an owner-only local temporary file, verifies size and SHA-256, then atomically publishes it. An existing local destination is rejected unless `--overwrite` is present; an overwrite target must be a regular non-symlink file with one hard link.

Success returns one bounded JSON object containing schema version, operation, device ID, selected address, byte count, SHA-256, source path, local destination, and timestamps.

All local and remote staging paths are cleaned. An unverified remote cleanup becomes `REMOTE_CLEANUP_UNCERTAIN`; an unverified local cleanup becomes `LOCAL_CLEANUP_FAILED`.

## 8. Stable failures

The first implementation exposes only these operation-level failure codes:

```text
DEVICE_NOT_FOUND
DEVICE_NOT_READY
REMOTE_INPUT_INVALID
REMOTE_CONNECTION_FAILED
REMOTE_EXECUTION_UNCERTAIN
REMOTE_OUTPUT_LIMIT
REMOTE_CLEANUP_UNCERTAIN
FILE_TRANSFER_FAILED
FILE_TRANSFER_UNCERTAIN
FILE_INTEGRITY_FAILED
LOCAL_CLEANUP_FAILED
```

Errors do not echo the script, arbitrary paths, raw child-process messages, SSH arguments, private-key paths, or captured remote output. Remote script stdout/stderr are returned only in the structured result for a completed transport.

A primary failure is never discarded when cleanup also fails. The CLI prints the stable primary code with the stable cleanup suffix, for example `REMOTE_EXECUTION_UNCERTAIN:REMOTE_CLEANUP_UNCERTAIN`. With no primary failure, cleanup uncertainty is the primary code. The same rule applies to local cleanup.

## 9. Testing

Implementation follows red-green-refactor. Tests use injected process runners and real local filesystem fixtures rather than a live target except for physical acceptance.

Automated coverage includes:

- CLI help, strict argument parsing, exit-code mapping, and one-object stdout;
- device status, platform, capability, and transport rejection before spawn;
- one shared SSH option source with no password, agent, proxy, or host-key fallback;
- private-key and known-hosts mutation detection before and after each process;
- address probing before mutation and no retry after staging begins;
- UTF-8 validation, deterministic UTF-16LE staging, script size, timeout, and output bounds;
- remote zero and nonzero exit codes;
- timeout, output overflow, disconnection, primary-plus-cleanup failure precedence, and uncertain cleanup;
- absolute Windows path rules and reserved internal-tree rejection;
- local symlink, hardlink, remote reparse point, missing parent, and overwrite rejection;
- upload/download size and SHA-256 integrity;
- atomic publication and preservation of an existing destination on failure;
- cleanup of every local and remote temporary path;
- unchanged enrollment verifier behavior and the full existing suite.

## 10. Physical acceptance

The existing Windows 11 Home device is used for the first operational acceptance. The Windows keyboard and desktop are not touched during the task.

1. The Mac creates an isolated website fixture.
2. `exec` creates an isolated Windows workspace.
3. `put` uploads the website source files individually.
4. `exec` inventories Git and Node without changing them; an existing supported installation may be used, while a missing tool is reported rather than installed in this slice.
5. `exec` builds the website and starts a temporary server bound only to `127.0.0.1`.
6. Windows validates the page through `Invoke-WebRequest`, then stops the server.
7. `get` downloads a build artifact and the Mac verifies its SHA-256.
8. The test proves all operation scripts, staging files, and temporary processes are gone.
9. The existing SSH listener, firewall rule, Tailscale Serve/Funnel state, and pinned trust material are unchanged.

The operational slice is accepted only when the full automated suite passes and this physical task completes from the Mac without local Windows interaction.

## 11. Deferred work

- inline PowerShell and interactive shells;
- recursive directory synchronization;
- resumable or queued tasks;
- automatic Git, Node.js, Python, or package-manager installation;
- reboot orchestration from the runtime CLI;
- desktop, browser, mouse, keyboard, Windows-MCP, or RustDesk control;
- alternate transports, VPNs, relays, or public listeners;
- Windows 10/11 Home/Pro near-bare compatibility claims beyond tested evidence.
