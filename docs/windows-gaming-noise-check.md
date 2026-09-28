# Windows capability recheck during user-reported gaming

Date: 2026-09-19. The user reported playing a game and requested another capability
audit under that activity. This was a light background coexistence check, not a
stress test. No reboot, game control, foreground activation, desktop mouse/keyboard
input, installation, game configuration or existing-project modification occurred.

## Observed load and successful work

A bounded S4U/Limited background job ran in session 0, lowered its own process
priority to BelowNormal, launched only headless Edge with GPU disabled, and emitted
24 numbered Chinese/emoji heartbeats. Independent SSH control calls observed
RUNNING, later SUCCEEDED/0 with an inactive scheduler, and recovered all 24 exact
UTF-8 lines with empty task stderr. Its script ran for 132.33 seconds.

Six coarse CPU samples were 57, 52, 62, 63, 62 and 65 percent. Available memory
ranged from 3459 to 3594 MiB. The user activity supplies the gaming context; this
measurement does not attribute load to a specific application. A narrow `r5apex`
process-name lookup did not match; no foreground inspection was used to identify
the actual game. FPS, frame time and GPU load were not measured. In response to a
question about stutter, frame drops or focus stealing, the user reported no
noticeable impact during this test.

| Probe | Result | Recorded time |
| --- | --- | --- |
| Headless installed Edge, fresh job-local profile, local HTML/JS | Exit 0; executed marker and DOM text verified | 4.777 s inside Windows |
| Background worker, 24 UTF-8 heartbeats across connections | Exact numbered output, stderr empty, SUCCEEDED/0 | 132.33 s script duration |
| 2 MiB random file, Chinese/spaces/emoji in Windows filename | put/get success; SHA-256 equal | 10.095 s upload, 6.356 s download |
| Zero-byte file round trip | Both directions succeeded; length 0 | 8.884 s upload, 5.605 s download |
| Ordinary exec with explicit UTF-8 | Chinese/emoji exact; exit 0 | 10.275 s first, 9.851 s second |

Transfer/exec times include controller work, SSH setup, verification and cleanup;
they are not wire-throughput or script-runtime measurements. Background start,
status and logs calls took roughly 12–14 seconds. No connection failure occurred
among these valid operations. One controller invocation initially omitted the
required `--script` flag and was rejected locally with `REMOTE_INPUT_INVALID`;
the corrected invocation then ran. That is a harness input error, not a remote
failure, and no uncertain user task was replayed.

There was no matched idle run, induced packet loss, game frame-time monitoring or
long-duration soak. These observations establish successful background work during
the reported activity with no user-noticed impact; they do not establish zero
measurable gameplay impact or a reliability rate. The earlier
[browser trial](windows-browser-ablation.md) demonstrated actual desktop clicks
before this gaming check, not simultaneous foreground ownership.

## Current gaps, separated from untested capabilities

| Capability | Current boundary / evidence |
| --- | --- |
| Interactive terminal / REPL / password prompts | Still missing through normal exec: live Read-Host rejected under NonInteractive; no supported stdin/PTY API. |
| Persistent shell state | Still missing: a second exec did not retain the first call's environment variable or working directory. |
| Independent GUI control while the user plays | Not established: ordinary exec runs in session 0; the temporary desktop bridge needs a logged-in session and shares its focus/input. It is not a supported general CLI desktop adapter. |
| Parallel controller operations | Local identity-lock timeout is now correctly DEVICE_BUSY; transport remains serialized. Background Windows jobs can outlive SSH, but that does not make concurrent controller transport supported. |
| Remote agent invocation | Prior Claude generation/repair succeeded through the desktop-user bridge; no general agent adapter/account selection or Codex model execution has been established. |
| Job continuity | start/status/logs/cancel/remove exist; there is no reboot resume or automatic replay. Logs are bounded pull requests, not a live interactive stream. |
| File workflow | Single-file transfer, Unicode paths and empty files work. Recursive synchronization/resume and files over 256 MiB remain unsupported by the current API; ZIP packaging is an existing workaround for directories. |
| Control latency | Valid calls in this sample took about 6–14 seconds including connection/verification; no persistent low-latency transport is exposed. No claim that gaming caused these delays. |
| GPU computation, Docker/WSL execution, audio/video, elevated desktop and locked-desktop operation | Not tested by this check; do not label them absent or working. |

A future background-work improvement should prioritize reusable low-latency
connections and explicit session/account selection. A desktop adapter additionally
needs a clear foreground-ownership policy before promising coexistence with games.
This audit makes no implementation changes to those capabilities.

## Evidence and cleanup

Raw receipts, job IDs, remote paths, payloads, browser stderr and retained logs are
private under the controller's OS-temp gaming capture and the Windows job folder.
The completed job's scheduler definition was removed, retaining results and files.
No game or unrelated browser process was stopped.
