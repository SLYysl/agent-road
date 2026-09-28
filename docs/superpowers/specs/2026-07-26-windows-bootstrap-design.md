# Agent Road Windows Bootstrap Design

> Date: 2026-07-26
> Status: automated implementation complete, physical Windows acceptance pending

## 1. Purpose

This phase turns the existing Mac controller foundation into a usable first remote-entry path for a normally booted Windows computer. The user performs one intentional local action: open an elevated Windows PowerShell session and paste one generated command. Windows does not need Git, Node.js, Python, a package manager, or a local model.

The phase is complete when a supported Windows computer joins the same Tailnet after one browser confirmation, installs a preserved and key-only OpenSSH path, and the Mac verifies an administrative SSH command using a pinned host key.

This phase does not implement Windows-MCP, RustDesk, browser control, interactive desktop control, a watchdog, WinRE, BIOS, BitLocker pre-boot recovery, VPS relays, V2Box-specific routing, or alternative VPN transports.

## 2. Supported systems

- Windows 10 build 1809 or newer.
- Windows 11.
- Home, Pro, Enterprise, and Education editions are detected automatically.
- Windows PowerShell 5.1 or newer.
- An elevated local PowerShell session and working internet access.
- A Mac already signed in to the Tailnet and able to run the Tailscale CLI.

Home and Pro use the same bootstrap path in this phase. Edition differences matter later for desktop-session strategies, not for Tailscale, OpenSSH, command execution, or file transfer.

Unsupported Windows builds stop before persistent system changes with `UNSUPPORTED_WINDOWS_BUILD`. A non-elevated shell stops with `ADMIN_REQUIRED`.

## 3. Selected architecture

The Mac runs a Node.js enrollment receiver bound only to `127.0.0.1` on an ephemeral port. Tailscale Serve publishes that local receiver over Tailnet-only HTTPS. Agent Road must invoke `tailscale serve`, never `tailscale funnel`; if Tailnet HTTPS or Serve requires owner consent, the controller stops with `TAILSCALE_SERVE_AUTH_REQUIRED` and shows the Tailscale consent URL.

The Mac generates a device-specific Ed25519 SSH key pair before issuing the enrollment command. The private key remains on the Mac with owner-only permissions. The Windows command contains the short-lived enrollment token and controller URL, but not the SSH private key.

The generated `-EncodedCommand` carries a bounded stage-zero PowerShell loader rather than the complete installer. Stage zero uses only built-in Windows facilities to perform preflight, install or reuse Tailscale, complete interactive Tailnet login, and contact the controller. After authenticated exchange it downloads the larger stage-one bootstrap from the Mac, verifies its pinned SHA-256 digest and controller signature, and only then executes it. This keeps the command below Windows command-line limits without requiring a public Agent Road artifact host.

The controller owns a persistent RSA-3072 bootstrap-signing key separate from device SSH keys. Stage zero embeds only its public modulus and exponent and verifies RSA PKCS#1 v1.5 signatures with SHA-256 using APIs available to Windows PowerShell 5.1. The signing private key stays on the Mac with owner-only permissions. Device SSH identities continue to use Ed25519. Third-party installers are accepted only when they match pinned release metadata and pass cryptographic verification.

## 4. Identity model

The bootstrap creates a dedicated local administrator named `AgentRoad`. It does not change the current user's password, login method, profile, SSH keys, or browser credentials.

The account is the system-management and recovery identity. It receives only the device-specific public SSH key. SSH password authentication is disabled for this account. Existing users and their SSH access remain unchanged.

Agent Road must not place its key in the shared `administrators_authorized_keys` file, because that can make one key applicable to multiple administrator identities. It uses an Agent Road-owned key file and an account-specific `Match User AgentRoad` rule positioned before any generic administrator-group rule. Before service startup, Agent Road verifies the exact owned block, rejects conflicting user/group allowlists, user-specific matches, includes, key-command sources, trusted user CAs, and authorized-principal sources, and runs `sshd -t`. Win32-OpenSSH cannot reliably evaluate another local administrator's group token from an interactive administrator process, so the verified LocalSystem service definition and startup plus the Mac's pinned-host-key SSH probe are the authoritative runtime checks.

Ordinary unencrypted files remain manageable through administrative command and file channels. EFS data, DPAPI-protected secrets, browser cookies, saved passwords, MFA, hardware keys, and other identity-bound material are not made accessible by changing ownership or permissions. Agent Road must not recursively take ownership of an existing user profile.

A later interactive-session helper will run inside the user's existing desktop session for browser and GUI work. It is not part of this phase.

## 5. Enrollment flow

### 5.1 Mac preparation

1. Verify the Tailscale CLI exists and the Mac is in `Running` state.
2. Start the enrollment receiver on an ephemeral localhost port.
3. Configure a temporary Tailscale Serve HTTPS route to that port.
4. Read back and validate the resulting `https://*.ts.net/` URL.
5. Generate an Ed25519 key pair dedicated to the device.
6. Create the single-use enrollment token and device record using the selected enrollment-session lifetime.
7. Print exactly one PowerShell command to stdout. Diagnostics go to stderr.

The receiver route is temporary. After SSH verification, Agent Road removes Serve, reads back Serve and Funnel status to verify the owned path is absent, and closes the receiver before publishing `CONNECTED_SSH_ONLY`; successful cleanup is a publication barrier. If cleanup or its status verification fails, Agent Road records `BOOTSTRAP_FAILED` rather than a false connected state. The route is also removed on explicit cancellation or timeout. This release checks both Serve and Funnel status first and fails closed if either has any pre-existing configuration; it never takes over or deletes unrelated routes.

Tailscale Serve requires Tailnet HTTPS to be enabled. If it is not enabled, the Tailnet owner may need to approve it once on the Mac before the first device enrollment. That controller prerequisite is separate from the per-Windows-device action. Agent Road never enables Funnel.

The CLI selects one bounded enrollment-session lifetime from 5 through 30 minutes, defaulting to 10. That same lifetime governs the enrollment token, completion ticket, and Mac completion wait so no credential expires earlier than the session it authorizes.

### 5.2 Windows preflight

The PowerShell bootstrap:

1. requires an elevated administrator token;
2. detects Windows version, build, edition, architecture, and PowerShell version;
3. creates `C:\ProgramData\AgentRoad\bootstrap` with administrator-only ACLs;
4. acquires a local bootstrap lock;
5. creates a journal before the first persistent mutation;
6. inventories existing Tailscale, OpenSSH, `sshd`, firewall, account, and SSH configuration state.

Re-running a newly generated command resumes completed checkpoints when their recorded postconditions still hold. A concurrent bootstrap stops with `BOOTSTRAP_ALREADY_RUNNING`.

### 5.3 Tailscale installation and login

- A valid existing Tailscale installation is preserved and reused.
- Otherwise the bootstrap downloads the pinned official Windows installer from the manifest embedded by the controller.
- The download must match the pinned SHA-256 digest and a valid Authenticode signature whose signer is allowlisted for Tailscale. Verification happens before execution.
- The installer runs unattended, but Tailnet enrollment does not use a stored administrator key.
- For a fresh installation, the bootstrap invokes Tailscale with the device-specific hostname `agent-road-<device-suffix>` and unattended mode, then opens the interactive login URL. A valid existing Tailscale identity keeps its hostname and other preferences; Agent Road enables unattended mode without resetting unspecified settings.
- The user completes one browser login. The bootstrap waits with a bounded timeout for `Running` state and at least one Tailscale IP.

Failure to log in returns `TAILSCALE_LOGIN_REQUIRED` without proceeding to SSH configuration. Existing Tailscale preferences are not reset or replaced.

### 5.4 Authenticated controller exchange

After Tailscale reaches `Running`, Windows posts the enrollment token and device ID to the Tailnet-only HTTPS receiver. The receiver atomically consumes the token and returns an allowlisted response containing:

- the expected device ID;
- the device-specific SSH public key;
- the signed stage-one bootstrap and its SHA-256 digest;
- a short-lived, single-use completion ticket;
- a bootstrap protocol version;
- non-secret configuration bounds.

The response contains no private SSH key, Windows password, Tailnet administrator credential, or reusable enrollment credential. A consumed, expired, unknown, or mismatched token fails closed. The receiver retains only a hash of the completion ticket in memory. The ticket is consumed and completion state is published once. After the first response has settled, an exact transport replay may receive the same acknowledgement without consuming the ticket or publishing completion again; altered or concurrent pre-settlement replays fail closed. Windows removes its raw ticket after completion or failure; it is never written to the bootstrap journal.

Stage zero verifies the returned device ID and protocol version, hashes the stage-one bytes, and verifies the RSA-SHA256 signature with its embedded controller public key before execution. Any mismatch stops with `BOOTSTRAP_SIGNATURE_INVALID` before OpenSSH, accounts, services, or firewall state are changed.

### 5.5 OpenSSH and account configuration

1. Preserve a valid existing Windows OpenSSH Server installation.
2. Otherwise install `OpenSSH.Server~~~~0.0.1.0` through Windows Feature on Demand.
3. Back up files that Agent Road will change, including relevant `sshd_config` and authorized-key files.
4. Create the `AgentRoad` local account if absent, using a cryptographically random local password that is not printed or returned in this phase. A pre-existing same-name account is reused only when the protected journal proves Agent Road created it or a healthy completion-pending transaction is being superseded; otherwise enrollment fails closed before adding administrator membership.
5. Add the account to the local Administrators group without changing other group memberships.
6. Install the device-specific public key in an Agent Road-owned administrator-readable key file with the ACL required by Windows OpenSSH.
7. Add an Agent Road-owned `Match User AgentRoad` policy that selects only that key file, requires public-key authentication, and denies password and keyboard-interactive authentication for that account.
8. Validate the exact owned SSH block and candidate syntax before restarting or enabling `sshd`; do not claim an interactive `sshd -T -C` surrogate is equivalent to the real account's SYSTEM-evaluated policy.
9. Verify that the `sshd` service runs as `LocalSystem` from `%SystemRoot%\System32\OpenSSH\sshd.exe`, configure it for automatic startup, and start it.
10. Create or update only an Agent Road-owned firewall rule for TCP 22, scoped to the machine's current Tailscale local addresses, Tailnet source ranges, and the verified Microsoft `sshd` program/service. After that rule is verified, transactionally disable only the exact Microsoft `OpenSSH-Server-In-TCP` broad inbound rule and restore it on rollback. Fail closed on explicit third-party SSH program/service or TCP-22 allow rules, weak-host receive or forwarding on any non-Tailscale interface, a TCP-22 port proxy, or a TCP-22 static NAT mapping. Do not infer SSH exposure from AppContainer/ServerCapability rules that expose only `Program=Any`, an empty package filter, and `Port=Any`; their additional application-isolation conditions are not represented by that projection. If an earlier rollback step fails, the broad Microsoft rule remains disabled and rollback is reported incomplete.

If validation or service startup fails, restore Agent Road's backups and prior service state, then return a stable error code. Existing unrelated SSH configuration is never replaced wholesale.

Reusing a valid OpenSSH installation does not preserve the Microsoft broad SSH rule. Successful enrollment combines exact Tailscale-only `ListenAddress` entries, the scoped Agent Road rule, transport-isolation checks, targeted SSH-rule conflict checks, and a post-start assertion that every TCP-22 listener address and owning PID belongs to the verified `sshd` service. Existing unrelated account, SSH configuration, and application-capability firewall state remains preserved. A listener mismatch stops `sshd` immediately before ordinary rollback continues.

### 5.6 Completion and Mac verification

Windows collects its Tailscale addresses, SSH host public keys and fingerprints, OS metadata, and completed checkpoint list. It durably marks completion pending, then posts these non-secret facts plus the single-use completion ticket to the receiver. The receiver consumes the ticket before accepting completion. Windows may retry the identical request to reconcile a lost response; a definite HTTP rejection remains recoverable, while transport uncertainty must not trigger destructive rollback of already-working SSH state.

If those retries end in `COMPLETION_UNCERTAIN`, the healthy pending SSH/account/firewall state may be safely superseded by a newly generated enrollment command and its new device key. Supersession first verifies the exact expected baseline; any missing, altered, or unsafe state fails closed rather than reusing or overwriting it.

The Mac checks that the reported device ID matches, stores the host-key fingerprints, and performs a strict host-key-pinned SSH probe using the device private key. The probe must prove:

- it reached the expected Tailnet address;
- host-key verification succeeded without `StrictHostKeyChecking=no`;
- the remote identity is `AgentRoad`;
- the session has administrative membership;
- PowerShell can execute a structured probe and return exit status, stdout, and stderr.

Only then does the device move to `CONNECTED_SSH_ONLY`. A completed Windows bootstrap without a successful Mac probe remains `SSH_VERIFY_FAILED` and preserves enough diagnostics for repair.

## 6. Controller interfaces

The existing `enroll` command becomes the user-facing bootstrap entry and manages receiver lifetime. It accepts a device display name and may accept explicit test-only overrides for injected process runners and release manifests; production CLI use does not accept arbitrary installer URLs or hashes.

Controller modules remain separated by responsibility:

- Tailscale CLI adapter: status, Serve route lifecycle, and Tailnet address discovery.
- Enrollment receiver: localhost HTTP protocol, token consumption, and completion state.
- SSH identity store: key generation and restrictive persistence.
- Windows bootstrap builder: deterministic PowerShell payload generation.
- SSH verifier: pinned-host-key connection and structured probe.
- Enrollment orchestrator: state transitions, compensation, and user-facing result.

The receiver is not a general-purpose HTTP API. It exposes only versioned enrollment endpoints, enforces request size and time limits, uses exact allowlisted schemas, and redacts tokens from logs and errors.

## 7. State and checkpoints

Controller state records non-secret facts only: device ID, display name, platform, edition/build, capabilities, Tailscale addresses, SSH username, pinned host-key fingerprints, status, timestamps, and stable error codes.

Raw enrollment tokens and Windows passwords are never persisted. SSH private keys are stored separately from the device registry with owner-only filesystem permissions. Keychain wrapping may be added later without changing the transport interface.

Windows stores a restricted bootstrap journal containing step names, timestamps, backup paths, non-secret detected state, and validation results. It never stores the raw enrollment token, Mac private key, Tailnet administrator key, or plaintext operational password in the journal.

## 8. Failure behavior

Stable failures include:

- `ADMIN_REQUIRED`
- `UNSUPPORTED_WINDOWS_BUILD`
- `TAILSCALE_NOT_AVAILABLE_ON_MAC`
- `TAILSCALE_NOT_RUNNING_ON_MAC`
- `TAILSCALE_SERVE_AUTH_REQUIRED`
- `TAILSCALE_DOWNLOAD_INVALID`
- `TAILSCALE_LOGIN_REQUIRED`
- `ENROLLMENT_TOKEN_INVALID`
- `BOOTSTRAP_SIGNATURE_INVALID`
- `OPENSSH_INSTALL_FAILED`
- `SSHD_CONFIG_INVALID`
- `SSHD_START_FAILED`
- `FIREWALL_CONFIG_FAILED`
- `SSH_VERIFY_FAILED`
- `BOOTSTRAP_ALREADY_RUNNING`

Errors identify the failed stage without printing enrollment tokens, passwords, private keys, full response bodies, or sensitive command lines. Network loss pauses or fails the current stage; it does not trigger unguarded firewall, routing, or VPN changes.

## 9. Testing

Automated tests run on the Mac with Node's built-in test runner and injected adapters. They cover:

- OS/build/edition and elevation decisions;
- deterministic PowerShell encoding and strict input bounds;
- installer hash and signer-verification commands;
- checkpoint resume and lock behavior;
- preservation of existing Tailscale and OpenSSH state;
- exact account, ACL, SSH policy, service, and firewall mutations;
- rollback after each mutable stage;
- single-use receiver protocol and schema rejection;
- rejection of any pre-existing Serve or Funnel configuration, plus exact cleanup of only the route created by Agent Road;
- SSH host-key pinning and state transitions;
- secret-pattern scans of registry, journal, logs, and command output.

The first physical acceptance run requires a supported Windows 10 or 11 machine. It records preflight output, Tailscale login, OpenSSH installation, first SSH probe, a small bidirectional file-transfer test, and a Windows reboot followed by SSH reconnection. Desktop and browser control are explicitly excluded from this acceptance run.

## 10. Completion criteria

This phase is complete only when:

1. the Mac prints one elevated PowerShell command;
2. a near-bare supported Windows machine needs no development runtime;
3. after the one-time Mac Serve prerequisite, the only additional per-device user action is Windows Tailscale browser authentication when required;
4. existing Tailscale, valid OpenSSH installation/configuration, user accounts, and user-file ownership are preserved, except that the exact Microsoft broad SSH firewall rule is intentionally disabled in favor of the Tailnet-only rule;
5. Windows reports a pinned SSH identity through the authenticated Tailnet-only exchange;
6. the Mac executes an administrative PowerShell probe with strict SSH host-key verification;
7. bidirectional file transfer succeeds;
8. Windows reboot preserves Tailscale and SSH access;
9. automated tests and secret scans pass;
10. `CURRENT_STATE.md` records the final commit, verification evidence, remaining desktop-control work, and the exact next action for a remote-session user.
