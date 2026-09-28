# Windows development workflow demonstration

2026-09-19: user requested an arbitrary real Windows task to test practical parity
with work normally done from the Mac. No claim of general OS/application parity.

A new `D:\AgentRoad-Demos\earth-received-d51cc175` workspace used existing bound
Git, Node.js and Python through `tools/run-existing-task.mjs`:

- Python read 12 synthetic CSV rows and wrote JSON aggregates (112 sample minutes;
  Code 42, Research 30, Design 40).
- Three Python tests passed: empty input, category aggregation, negative-duration rejection.
- Node checked the expected aggregates, generated a self-contained HTML dashboard,
  served it on an ephemeral loopback port, fetched it and compared the response bytes.
  The HTTP server was closed after the check.
- Git initialized a new local repository and committed seven generated/source/result
  files as `a5a2f51`; the worktree was clean. Identity/hook/signing settings were scoped
  to those Git invocations; no remote or deployment was configured.
- PowerShell created a ZIP; pinned SSH downloaded both HTML and ZIP to the Mac.
  The downloaded ZIP matched the Windows SHA-256, passed CRC checks, and contained
  the expected data and test output.
- Edge opened the actual Windows HTML page in a separate temporary browser profile.
  Interactive execution used a short-lived scheduled task; the task registration
  was removed after capture. The demo browser window was left available to inspect.

An initial isolated attempt stopped because Python unittest writes progress to
stderr, which PowerShell 5.1 with Stop error handling treated as NativeCommandError.
The demo runner was changed to emit its unittest report to stdout and explicitly
check the Python exit code. The successful run used a fresh workspace; the earlier
failed workspace was retained. No existing projects were changed or tools installed.

Browser first-run prompts also required handling before an unobstructed screenshot.
This is manual acceptance, not a general GUI automation implementation. No GPU,
Docker, WSL, external package installation, long-running workload, arbitrary desktop
application, or macOS-specific application capability was tested.

Private receipts: OS-temp `agent-road-existing-task-rVxC0Z` and controller
`inspection-captures/mission-*`. Screenshots remain local; they are not committed.
The complete portable source bundle is the returned `windows-demo.zip`; its seven
source/output files are also preserved in [examples/earth-received](../examples/earth-received/README.md).
