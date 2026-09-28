# Windows browser control: skills withheld, then enabled

On 2026-09-19, the controller first completed a Windows browser task without
loading browser skills, then loaded the Playwright skill for a second run using
the same HTML fixture. This is a sequential functional smoke comparison, not a
randomized or repeated measurement of the causal benefit of skills.

## Shared task and acceptance

The [local fixture](../examples/windows-browser-ablation/index.html) has an
initially enabled **Arm mission** button and disabled **Launch mission** button.
Arm must enable Launch; Launch must produce **Mission complete — Astra ✅**.
The page counts click events only when `isTrusted` is true and `pointerType` is
`mouse`. Acceptance requires two such events, the final status and disabled
buttons. The event counter is corroborating evidence, not a general proof that
input came from a physical mouse: browser automation can produce trusted events.

The existing Agent Road pinned SSH transport staged temporary, Interactive/Limited
scheduled tasks under the logged-in desktop user. Each used the existing bounded
native Job Object worker. SSH alone does not grant an interactive desktop, and
this bridge is not yet a general browser adapter in the main CLI.

## A: no-skills baseline

No browser or screenshot skill was loaded before this phase completed.
The built-in Computer Use entry point was attempted, but reported a native pipe
startup failure and no available apps/browsers; it did not control this Windows PC.

1. Native Edge `--headless --dump-dom` loaded the fixture through `file://` using
   a separate profile. Exit 0 and `data-cli-ready="true"` in the dumped DOM
   confirmed JavaScript execution.
2. A headed Edge instance used a distinct trial profile. Windows UI Automation
   located its own window and buttons. Foreground ownership was checked before
   keyboard navigation; Win32 cursor positioning and mouse down/up performed
   actual desktop clicks on the current button bounds.
3. UI Automation and the final window screenshot confirmed the mission completed
   with **Trusted mouse clicks: 2**.

A fresh Edge profile did not mean an unauthenticated browser: account integration
and an extension opened additional UI. The controller navigated to the fixture,
dismissed the informational **明白** dialog and translation popup through the GUI,
then performed the task. No sync settings or credentials were changed/copied.
The initial screenshot contains account information and remains private.

## B: Playwright skill comparison

Only after A passed, the controller loaded the installed `playwright/SKILL.md`.
Windows `npx.cmd` was available. The workflow used the Windows equivalent of its
shell wrapper: `npx --yes --package @playwright/cli playwright-cli` (resolved
package version 0.1.21), with a named session and headed installed Edge.
No global package or browser installation was requested; npx used its package cache.

The initial cold help command printed help but exited with a Node/libuv assertion
(`UV_HANDLE_CLOSING`). A subsequent help command exited 0. The cause of that first
exit failure is not established or claimed fixed. Opening a `file://` URL was
explicitly rejected by Playwright. The same fixture bytes were therefore served
by a temporary HTTP server bound only to Windows loopback, rather than relaxing
that restriction. This changes the delivery protocol between phases.

The initial page snapshot exposed Arm as `e5` and disabled Launch as `e6`.
`click e5` returned exit 0 and a new snapshot with **Armed. Ready to launch.**,
Launch enabled and one trusted mouse event. Using `e6` from that fresh snapshot,
`click e6` returned exit 0, both buttons disabled, **Mission complete — Astra ✅**
and **Trusted mouse clicks: 2**. These were Playwright browser input events,
not Win32 desktop mouse input. Neither run used JavaScript to click the buttons
or set the completion state. A final Playwright screenshot was retrieved.

## Result and limits

| Check | Skills withheld | Playwright skill loaded |
| --- | --- | --- |
| Windows browser | Installed Edge, native launch | Installed Edge, named headed session |
| HTML/JavaScript loaded | Headless DOM marker and exit 0 | Navigation and live page snapshots |
| Arm then Launch | UI Automation bounds + Win32 mouse | Fresh snapshot element references |
| Final completion / trusted events | Complete / 2 | Complete / 2 |
| Artifact | Desktop window screenshot | Browser page screenshot |

Both paths worked for this local two-button task. Differences in control mechanism,
profile handling and file-vs-loopback delivery prevent attributing any performance
or reliability difference specifically to the skill text.

Recorded wall-clock windows were approximately five minutes each: baseline remote
worker start at 18:54:51 UTC to controller confirmation at 19:00:11 (5m20s), and
skill worker staging at 19:04:00 to the successful final browser snapshot at
19:09:17 (5m17s). These endpoints differ slightly and include setup, diagnosis,
controller reasoning and transfers; they exclude prior script writing/skill
reading. They are coarse execution windows, not click latency or a speed benchmark.
No universal macOS/Windows parity claim is made.

Raw captures, profile data, account identifiers, device IDs and remote paths stay
outside Git. This trial does not establish arbitrary-site coverage, authentication
flows, locked-desktop operation, elevated UI interaction, reliability rates or
that all tasks available on macOS are available through Agent Road.

## Cleanup

The named Playwright session was closed, trial workers/server stopped and all six
temporary scheduled-task definitions removed only after successful terminal states.
A final check found no processes referencing these trial directories and no listener
on the trial loopback port. Evidence files were retained; unrelated apps were not stopped.
