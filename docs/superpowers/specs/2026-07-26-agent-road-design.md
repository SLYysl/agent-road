# Agent Road — Design Specification

> Date: 2026-07-26
> Status: Approved design, pending implementation plan

## 1. Objective

Agent Road lets an Agent running on a Mac take over a normally booted, networked Windows computer after one intentional local bootstrap action: the user opens an elevated PowerShell window and pastes one enrollment command.

After enrollment, the Mac Agent can configure the Windows environment, execute commands, manage files, develop and test websites, organize documents, operate browsers and desktop applications, and recover automatically from ordinary service failures and reboots. Windows runs only lightweight control components; it does not run a model.

## 2. First-release scope

The first release implements:

- Controller: macOS.
- Target: Windows 10/11, with explicit Pro/Home desktop-control differences.
- Network transport: Tailscale only.
- Command and file control: Windows OpenSSH, PowerShell, SFTP/SCP.
- Structured desktop control: Windows-MCP over an SSH tunnel.
- Visual and emergency desktop access: RustDesk in unattended service mode.
- Recovery: a restricted Windows watchdog and configuration rollback.
- Enrollment: one elevated PowerShell command generated on the Mac.

The core device and transport interfaces remain platform-neutral. Windows-to-Windows, Mac targets, alternative VPNs, VPS relays, WinRE, BIOS, BitLocker pre-boot, and hardware recovery are not implemented in the first release.

### 2.1 First-release prerequisites

The one-command guarantee applies when:

- Windows boots normally and can reach the release source and Tailscale over HTTPS;
- the user can open one elevated PowerShell session locally;
- the Mac is online, already joined to the intended Tailnet, and authorized to provision a single-use device credential;
- neither device is subject to an organization policy that forbids the required service installation or network connection.

If the Mac lacks Tailnet provisioning authorization, enrollment stops with `TAILSCALE_AUTH_REQUIRED`; it does not embed or request a long-lived administrator key. Offline bootstrap, organization-managed devices, and pre-boot recovery are deferred.

## 3. Design principles

1. The model and planning Agent stay on the controller.
2. No target is controllable before an intentional local enrollment action or an existing authorized remote entry point.
3. Shell and file operations are preferred over GUI automation.
4. Desktop automation is a separate capability, not an implied property of SSH.
5. No single service is the only recovery path.
6. Connection changes are transactional and automatically rolled back until a second connection succeeds.
7. Existing user files and pre-existing Tailscale or SSH configuration are preserved.
8. Long-lived secrets never appear in enrollment commands or logs.
9. Destructive, external, identity-sensitive, and security-boundary operations require user confirmation.
10. A device is not ready until end-to-end task checks pass after a reboot.

## 4. System architecture

### 4.1 Mac controller

The Mac controller contains:

- `agent-road` CLI for enrollment, status, diagnosis, shell, files, desktop access, reboot, and uninstall.
- Device registry containing device IDs, capabilities, pinned SSH host keys, and non-secret status.
- Per-device SSH keys stored with restrictive filesystem permissions and protected by macOS Keychain where appropriate.
- Credential storage in macOS Keychain for the dedicated Windows login and unattended desktop credential.
- SSH/SFTP transport adapter.
- MCP client connected only through an SSH tunnel.
- Agent tool adapter exposing platform-neutral device operations.

The Agent-facing interface is:

- `device.exec`
- `device.read`
- `device.write`
- `device.upload`
- `device.download`
- `device.screenshot`
- `device.ui`
- `device.browser`
- `device.reboot`
- `device.health`

Every operation names a target device explicitly.

### 4.2 Windows target

The Windows target contains:

- Tailscale in unattended mode.
- Windows OpenSSH Server configured for automatic startup.
- A dedicated local administrator account named `agent-road-admin`.
- Device-specific SSH public-key authentication; SSH password login is disabled for the automation account.
- Windows-MCP bound to `127.0.0.1` only.
- RustDesk running as a service for login-screen and emergency visual access.
- Agent Road Watchdog, restricted to health checks, restart of known services, and rollback of Agent Road connection configuration.
- Versioned configuration backups, install state, and redacted logs under `%ProgramData%\AgentRoad`.

The watchdog does not expose general-purpose remote command execution.

## 5. Enrollment and bootstrap

### 5.1 User experience

On the Mac, the user runs:

```text
agent-road enroll
```

The CLI generates a short-lived, single-use PowerShell enrollment command. The user pastes it once into an elevated PowerShell window on Windows. No Git, Node.js, Python, package manager, model, or Agent may be assumed to exist on the target beforehand.

Agent Road therefore installs pinned runtimes required by its own components or ships those components as self-contained packages. Their absence on a fresh target is not an enrollment failure.

### 5.2 Enrollment token

The enrollment token:

- expires with the selected bounded 5–30 minute enrollment-session lifetime (10 minutes by default);
- is valid for one device and one use;
- is bound to the controller's enrollment public key;
- cannot be exchanged for an unrestricted or reusable Tailscale credential;
- is redacted from process output and installation logs;
- is destroyed after successful enrollment or expiry.

The first implementation may use the Mac controller to mint a short-lived, non-reusable Tailscale authorization key. No long-lived Tailnet administrator secret is embedded in the generated command.

### 5.3 Bootstrap state machine

The installer is idempotent and records these checkpoints:

1. `preflight`
2. `tailscale`
3. `ssh`
4. `account`
5. `mcp`
6. `remote-desktop`
7. `watchdog`
8. `verification`
9. `complete`

The bootstrap downloads a pinned release manifest over HTTPS, verifies signatures and cryptographic hashes before execution, detects pre-existing installations, and backs up configuration before changing it. Re-running a newly generated enrollment command resumes from valid checkpoints.

## 6. Runtime data flow

### 6.1 Commands and files

The Mac connects to the Windows Tailscale address using pinned-key SSH. PowerShell handles system operations; SFTP/SCP handles file transfer. Commands return structured exit status, stdout, stderr, timestamps, and a redacted audit record.

### 6.2 Desktop and applications

Windows-MCP listens only on localhost. The Mac opens an authenticated SSH tunnel and connects the MCP client through that tunnel. No MCP control port is exposed to the LAN, Tailnet, or public internet.

Windows-MCP operates within a logged-in interactive session. Background command and file control remain available before desktop login.

### 6.3 Browser control

Browser tasks prefer structured browser or DOM control. System dialogs and non-web application UI fall back to Windows-MCP or RustDesk visual control. CAPTCHA, MFA, hardware-key requests, and ambiguous identity or consent decisions return control to the user.

### 6.4 Desktop session establishment

- Windows Pro, Enterprise, and Education: establish a dedicated RDP session when appropriate.
- Windows Home: use RustDesk service access to reach the login screen and create the interactive session.

Automatic Windows login is not enabled. The dedicated account's random password is stored only in Mac Keychain after secure retrieval and is not written to logs.

The bootstrap generates the dedicated account and unattended-desktop credentials on the target, encrypts the controller copy to the enrollment public key, and makes that encrypted envelope retrievable only during the authenticated enrollment. Plaintext temporary values are removed after handoff. Windows retains only the local credential material required by Windows and RustDesk to authenticate future sessions.

## 7. Permissions and safety

Normal autonomous operations include project creation, dependency installation, builds and tests, work inside user-approved directories, service restarts, non-destructive document indexing, and maintenance of Agent Road components.

Explicit confirmation is required for:

- bulk deletion or irreversible overwrites;
- disk formatting, partitioning, BitLocker changes, or recovery-partition changes;
- deleting users or changing authentication boundaries;
- disabling security software;
- changing core network, Tailscale, SSH, or firewall configuration outside a guarded transaction;
- uploading private material to external services;
- external publishing, messaging, or deployment;
- operations involving payment, MFA, legal consent, or physical identity.

## 8. Recovery model

### 8.1 Recoverable in the first release

- Application or development server crash: restart, verify, collect logs, then reinstall the affected component if required.
- Windows-MCP failure: repair or reinstall through SSH.
- SSH service failure or invalid SSH configuration: watchdog restart or rollback; RustDesk is the secondary repair route.
- Tailscale service failure: watchdog restart and restoration of the last known Agent Road configuration.
- Logout or reboot: background services return before login; the Mac establishes a desktop session only when GUI work is required.
- Interrupted installation: resume from the last verified checkpoint.

### 8.2 Connection-safe changes

Before modifying SSH, Tailscale, firewall, routing, or network configuration, Agent Road must:

1. create a timed rollback action;
2. preserve the current connection;
3. apply the new configuration;
4. establish a new independent connection from the Mac;
5. verify command, file, and restart recovery;
6. cancel rollback only after success.

### 8.3 Not recoverable in the first release

- Windows cannot boot normally;
- WinRE or installation-console control;
- blue-screen loops;
- BIOS/UEFI;
- BitLocker pre-boot entry;
- physical disk, memory, power, or network hardware failure;
- loss of every software communication path.

These require a person, prebuilt recovery media, MDM/enterprise provisioning, or hardware control such as PiKVM/AMT.

## 9. Network and VPN boundary

The first release implements a transport interface but ships only a Tailscale adapter. It does not add a custom VPS relay or special-case V2Box.

The design separates:

- Mac Agent/model internet egress;
- Mac-to-Windows control traffic;
- Windows internet egress for downloads and browsing.

Windows does not inherit the Mac's VPN or egress location. A future transport or egress adapter may add other VPNs, self-hosted relays, proxies, or VPS routes after first-release measurements.

First-release network tests record behavior with the Mac's existing VPN off, on, and reconnecting. A VPN conflict must be reported as a routing/transport problem and must not trigger unguarded Windows network changes.

## 10. Status model

Agent Road reports capability state rather than a single online flag:

- `ENROLLING`
- `CONNECTED_SSH_ONLY`
- `GUI_LOGIN_REQUIRED`
- `MCP_UNAVAILABLE`
- `TAILSCALE_AUTH_REQUIRED`
- `DEGRADED_RECOVERY_AVAILABLE`
- `REBOOT_RECOVERY_FAILED`
- `READY`

`READY` requires verified command execution, bidirectional file transfer, administrative capability, MCP tunneling, desktop availability, backup access, and successful post-reboot reconnection.

## 11. Verification

### 11.1 Installation matrix

Test at minimum:

- fresh supported Windows Pro VM;
- fresh supported Windows Home VM;
- existing Tailscale installation;
- existing OpenSSH configuration;
- interrupted download and interrupted component installation;
- repeated bootstrap execution;
- user logout and Windows reboot;
- Mac sleep and reconnect;
- Mac VPN off, on, and reconnecting.

### 11.2 Fault injection

Test manual termination or corruption of:

- OpenSSH service;
- Windows-MCP process;
- Tailscale service;
- Agent Road Watchdog child checks;
- staged SSH configuration;
- network availability during bootstrap and verification.

### 11.3 End-to-end tasks

Website task:

- install required development tools;
- create and run a test website;
- open it in a Windows browser;
- inspect and interact from the Mac;
- modify code and verify the rendered change.

Document task:

- inventory mixed PDF, Office, image, and duplicate test files;
- propose a classification without mutation;
- copy a sample into a new organized structure;
- build an index;
- verify that originals are unchanged.

System task:

- install software;
- update an environment variable;
- create and restart a managed process or service;
- reboot Windows;
- recover command, file, and desktop control without touching Windows.

## 12. Completion criteria

The first release is complete only when:

1. A fresh Windows target needs one elevated PowerShell command and no preinstalled development runtime.
2. The Mac automatically identifies and pins the enrolled device.
3. The Agent can execute administrative PowerShell and transfer files safely.
4. The Agent can operate the Windows desktop and browser.
5. All three end-to-end tasks pass.
6. The device recovers without local interaction after a normal reboot.
7. A single SSH or MCP failure has a verified repair path.
8. Long-lived credentials do not appear in commands, output, or logs.
9. Existing user data and unrelated configuration remain intact.
10. Uninstall removes Agent Road components without deleting user material.
11. Core device tools and transport interfaces contain no Mac-to-Windows assumptions that would prevent later platform adapters.

## 13. Deferred work

- Windows controller adapter;
- macOS target bootstrap and TCC permission workflow;
- alternate VPN and transport adapters;
- self-hosted VPS or HTTPS/WebSocket relay;
- optional remote egress proxy;
- multi-device orchestration;
- recovery media, WinRE, and hardware KVM integration.
