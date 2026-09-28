# Independent agent skill acceptance

On 2026-09-19 the user authorized an independent agent to use the newly installed
`agent-road` skill for a real Windows resource-report task. The agent received the
skill path and task, without the earlier conversation's device IDs, receipt paths
or implementation history. It discovered the current checkout and enrolled device
through the skill and unified CLI. The supervising agent stayed local and did not
issue concurrent remote operations.

## Observed workflow

- `capabilities` and `list` provided interface/device discovery.
- `base-inspect` found a usable existing Python 3.14.5 installation; the PATH entry
  was a Store alias, so the usable inspected candidate was selected explicitly.
- `job start` submitted a bounded PowerShell CIM collector. A later status query
  observed RUNNING with the scheduler active after the initiating command ended.
- A subsequent receipt confirmed SUCCEEDED with exit code 0. Fourteen samples
  spanned 62.073 seconds on the monotonic timer (62.077 seconds between UTC sample
  timestamps). Extra sampling ensured a full minute between actual observations.
- `base-exec` revalidated and bound the existing Python to generate Markdown,
  summary JSON and a manifest from the raw JSON. No package installation occurred.
- Logs were retrieved, four report artifacts transferred to the Mac, and their
  hashes checked against independent Windows Get-FileHash output and get receipts.

The collector observed total CPU percentage, OS-visible physical memory,
physical-disk read/write rates and queue length, and fixed logical-drive capacity.
CIM queries within a sample are sequential; the timestamp marks sample completion.
Means are arithmetic sample means, not duration-weighted utilization or cumulative
I/O. This was a short background observation, not a performance benchmark or proof
of negligible interference with other workloads.

## Independent checks

The supervisor checked sample count/index order, monotonic and UTC time coverage,
finite numeric values, CPU/memory ranges, memory accounting identities, nonnegative
disk rates/queue length and valid free/total volume capacities. All five summary
metrics and Markdown table values were independently recomputed from raw samples.
The raw data, Markdown, summary and manifest all matched their remote hashes and
transfer byte counts. The manifest's three content hashes also matched locally.
Private receipts, actual resource values, device/job IDs and artifact paths remain
outside Git; the user received a direct local report link.

## Friction found and corrected

The collector initially wrote its own reports under Agent Road's internal reserved
root. A get attempt was rejected locally with REMOTE_INPUT_INVALID before remote
execution: `validateWindowsFilePath` excludes `C:\ProgramData\AgentRoad\` and all
its descendants. The skill and interface guide had not documented this boundary.

The independent agent diagnosed the validator, then used an authorized exec to
copy only its four generated report artifacts into a fresh directory outside that
root. Ordinary get succeeded there. Original outputs and the rejected invocation
were retained; the collector was not resubmitted, no uncertain work was replayed,
and no validator or pinned transport rule was weakened.

The shared Codex/Claude Code skill and interface guide now explain reserved paths,
absolute drive-letter/backslash syntax, output-directory selection and this narrow
recovery path. Both skill installations passed format validation. This task also
successfully used the previously documented nested job state and Base64 log format.

## Scope

This establishes one independently executed skill-driven task, including discovery,
durable execution, tool binding, artifact retrieval and local acceptance. It is not
a general reliability estimate or evidence of a supported remote model/desktop
adapter. The second agent ran on the Mac controller; it did not invoke a Windows
model. No foreground input, reboot or credential access was needed. Execution code
was unchanged; only the skill/documentation boundary was corrected.

After retrieval, `job remove` succeeded. A separate `job status` readback retained
SUCCEEDED/0 and confirmed `definitionPresent=false`, `schedulerActive=false` and
`schedulerResult=null`. Job files and reports remain available; the temporary
scheduler definition is gone.
