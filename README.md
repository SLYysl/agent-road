<img src="docs/assets/mac-lifebuoy.png" alt="A classic Mac on a red and white lifebuoy" width="180" align="right" />

# Agent Road

**Let the AI agent on your Mac work on your Windows PC.**

Run a Windows command, move a file, or start a background task without moving your agent to another computer. Agent Road supplies the connection and tools; you keep using your existing terminal-capable agent.

[中文说明](README.zh-CN.md) · [Website & demo](https://agent-road.brahma-technologies.com/) · [Setup guide](docs/agent-setup.md) · [Command reference](docs/agent-interface.md)

> **Free Alpha · Mac → Windows.** This is a private open-source preparation snapshot. Public source licensing is pending, and the native Windows installer is not publicly released. Existing enrolled devices can be used; fresh testers need the maintainer-provided bundle and its instructions.

## What can I do with it?

- **Check a Windows project from your Mac.** Ask your agent to inspect the environment, run an authorized test command and return the output.
- **Move work between machines.** Transfer a script or retrieve a generated report, with file-integrity checks.
- **Leave a longer task running.** Submit a background job, retain its job ID, and retrieve that same job's status and logs later. Jobs do not survive a Windows reboot.

For example: “Check which Python is already installed on my Windows PC, run this script with my approval, and bring back the report.” Existing tools are inspected before any installation is proposed.

```text
Your Mac                         Your Windows PC
Existing AI agent                Commands, files and background jobs
       │                                      ▲
       └── Agent Road CLI ── Tailscale + SSH ──┘
           You authorize the connection and the task.
```

The target PC does not need another AI subscription or a local model. This is a command-and-file workflow; general mouse, desktop and browser control are not guaranteed capabilities.

## Start here

| Your situation | First step |
| --- | --- |
| New to Agent Road | Read the prerequisites below, then give the setup prompt to your agent. |
| You received a test bundle | Follow that bundle's version, manifest and instructions. Do not mix it with website downloads. |
| Your Windows PC is already enrolled | Keep the original controller state; use `list` and `status`, then run a small task. Do not re-pair. |
| You want to contribute | Read [CONTRIBUTING](CONTRIBUTING.md) and the [release preparation checklist](OPEN_SOURCE_PREPARATION.md). |

**You need:** a Mac with an agent that can run terminal commands; a Windows PC whose owner can approve administrator changes; internet access on both machines; and Tailscale networking. Account authorization and network setup are separate steps. The current test focus is Apple Silicon Mac → Windows 11 x64; other targets are not claimed as supported.

<details>
<summary><strong>Copy a setup prompt for your agent</strong></summary>

```text
Help me use Agent Road from this Mac with a Windows PC I own or am authorized to manage.
First read this repository's docs/agent-setup.md, docs/onboarding-status.json,
and docs/agent-interface.md in full. Inspect the existing environment before changing it.
If I supplied a test bundle, use its pinned instructions and manifest.
If the public Windows installer is unavailable, explain the blocker; do not invent an
installer or automatically fall back to the legacy flow. Preserve existing tools and
controller state. Obtain my approval for installation, admin changes and reboots.
After connection, verify one read-only command and report the result. Verify file
transfer and background jobs separately. Never replay a write whose result is unknown.
Keep credentials and pairing commands out of chat and logs I might share.
```

For a Chinese prompt and detailed usage, see [给 Agent 的中文指南](docs/agent-guide-zh.md).

</details>

<details>
<summary><strong>Already connected? Try a small task</strong></summary>

From this checkout on your Mac, with Node.js 22 or newer and the **original controller state**:

```sh
node src/cli.mjs list
node src/cli.mjs status <device-id>
```

Ask your agent to create a local PowerShell script containing `Write-Output 'Hello from Windows'`, then run:

```sh
node src/cli.mjs exec <device-id> --script /absolute/path/hello.ps1
```

Success means the remote output contains `Hello from Windows` and the script exits with code 0. This proves that command worked; file transfer, runtime readiness and reboot recovery require their own checks. Device IDs and command results are private—redact them in feedback.

</details>

## What has been tested?

Internal physical-PC and VM trials cover commands, Unicode file round trips and durable jobs. Claude and DeepSeek independently used the existing controller to complete task checks. One 24-hour observation recorded 95 successful scheduled samples plus a successful closing probe; this is sampled evidence, not an uptime guarantee.

An earlier SSH service stop still has no confirmed root cause. Fresh unfamiliar machines, signed installer delivery and general reboot recovery are not fully accepted. See [evidence and publication limits](OPEN_SOURCE_PREPARATION.md).

<details>
<summary><strong>Questions people ask</strong></summary>

**Does this replace Claude Code, Codex or another agent?** No. It provides tools for an existing agent with terminal access. Compatibility must be checked for the agent you use.

**Is it remote desktop?** No. The validated core is remote commands, single-file transfers and background jobs. GUI workflows need separate components and checks.

**Do both people need an Agent Road account?** The Mac controller uses browser account authorization. The Windows owner confirms the invitation and administrator changes; a separate Windows-side Agent Road account is not required.

**Can it fix an offline or unbootable PC?** No. Remote work requires a functioning authorized network channel. BIOS, BitLocker pre-boot prompts, hardware failures and fully unreachable machines need local intervention.

**Is it open source yet?** Not yet. This candidate is being prepared for release. The license and third-party notices must be finalized before an open-source release is declared.

</details>

## Developers and feedback

```sh
npm test
npm run check
python3 -m unittest discover -s test -p '*_test.py'
```

No npm dependencies are declared by the controller package. Native installer builds and real-device acceptance are separate from these local checks.

Use the Alpha feedback issue template for your OS versions, agent, candidate revision, failure stage and redacted error. Read [SECURITY.md](SECURITY.md) before reporting a security issue; never attach tokens, keys, pairing commands or raw controller state.

[Engineering reference](docs/controller-reference.md) · [Third-party review](THIRD_PARTY_REVIEW.md) · [Release preparation](OPEN_SOURCE_PREPARATION.md)
