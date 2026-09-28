# VM host storage and recovery checks

Before starting, cloning, snapshotting or resuming a development Windows VM, inspect
both the virtualization host and the guest. An SSH failure alone cannot distinguish
a paused VM, guest shutdown, host storage exhaustion or network failure.

Run `tools/vm-host-preflight.ps1 -VmName <registered-name>` on the VirtualBox Windows
host through the existing trusted controller. It reads machine-readable VM state
and free bytes on local drive-letter volumes used by the config, snapshots, logs
and attached media. It never installs, deletes, resumes, resets or reboots anything.
Output is JSON; `findings` retains concurrent conditions such as a paused VM
and low storage instead of hiding one behind the other. `guestConnectivity` is
explicitly NOT_CHECKED: this host observation cannot assert SSH failure or success.
Exit 2 means storage is low, the VM is paused, or inspection is unknown. Never translate unknown into "missing" or permission to install.

The default 20 GiB is a conservative development-test headroom policy, **not** an
Oracle minimum or a guarantee that the next snapshot will fit. Full clones may need
far more than that; estimate the actual disks, snapshots and memory state before
allocating. The script is scoped to local drive-letter storage, not network or
folder-mounted volume accounting; those configurations need separate inspection.
Unknown volume data, invalid sizes and unsupported attached UNC paths fail closed;
known drive observations are retained alongside unknown findings. An exit 0 only reports observed storage headroom, never guest/application readiness.

For a paused VM:
1. Read `showvminfo --machinereadable` and the current VBox log without modifying it.
2. If `VERR_DISK_FULL`, `BLKCACHE_IOERR` or `DrvVD_DISKFULL` is present, correlate it
   with the pause transition. Historical log errors alone do not identify a new pause.
3. Review actual host volume free space. Do not reset the guest, grow its virtual
   partition, reinstall Tailscale or replay pairing to solve host disk exhaustion.
4. Have the owner approve a concrete cleanup or relocation. Preserve snapshots,
   differential disk parent chains, journals and original identities. Do not delete
   apparently old VDI/SAV files independently; other VM disks may depend on them.
5. Remeasure free space and estimate the recovery workload. Only then consider one
   authorized resume of the same VM. If storage errors recur, preserve the new event
   and stop; do not loop resume/reset.
6. Recheck the original pinned SSH identity, a harmless command, runtime-status and
   known file hash. Restored connectivity is not reboot-recovery acceptance.
7. For a later reboot test, record host UTC and monotonic observation times, guest
   boot time and service state, request once, observe offline/online transitions,
   then compare the original identity and runtime. Guest clock changes can make
   Windows event timestamps misleading; correlate with the hypervisor timeline.

The public controller cannot infer VirtualBox host storage from an arbitrary remote
Windows device. This is a development-host diagnostic, not an automatic production
recovery command. No public installer or existing tester kit changes are implied.

## Diagnostics-only hold (2026-09-23)

The owner explicitly chose to retain the VM paused and improve diagnostics only.
Do not resume, reset, reboot, clean or migrate it under the older recovery permission.
Host directory-size inspection is separately authorized and does not authorize deletion.

The Windows fixture extracts only the pure assessment function using the PowerShell
AST; it never executes VBoxManage or changes a VM. Eight cases passed on Windows:
headroom-only, paused plus low storage, paused with headroom, missing VM state,
access-denied volume, impossible size, attached UNC path, and an attached disk on
a different low-space volume. Temporary fixture source files are the only test
artifacts; there are no scheduled jobs, services or VM settings changed by the fixture.

## Later authorized host restart (2026-09-23)

The owner subsequently authorized restoring default host pagefile management and
restarting the physical Windows computer. The paused test VM was saved to disk
without resuming its guest, then the host restarted once. New host boot and trusted
SSH were verified; sshd and Tailscale were running with automatic startup. The
190 GiB D: pagefile was absent after restart; C: retained a 10.5 GiB automatically
managed pagefile. The VM remains SAVED and is not running. This host result does
not accept the earlier guest graceful-reboot recovery or authorize resuming tests.

## Resumed mainline and SSH startup diagnosis (2026-09-23)

The owner subsequently resumed VM testing. The same saved VM was restored and
one guest reboot recovered without external reset, preserving the original pinned
identity, file hash and live core generation. See
`experiments/vm-recovery-20260923/guest-graceful-reboot-retest.json`.
The earlier diagnostics-only hold and SAVED state above are historical.

For SSH startup failures, inspect **both** OpenSSH/Admin and OpenSSH/Operational
in a bounded window around the actual new guest boot. Operational alone omitted
the fatal bind error in this trial. Correlate SCM 7031 recovery events with the
first successful listener; do not infer an application crash from SCM alone.
The observed boot had a failed tailnet-address bind, then a working listener six
seconds later despite an existing Tailscale dependency. Service dependency is not
evidence that the tailnet address was bindable at sshd startup.

A delayed automatic sshd startup candidate was tested with the existing
dependency and failure recovery retained. Both observed boots avoided bind errors,
but recovery was slower and shutdown delay remained. The candidate was rejected
as the default; automatic startup and SCM recovery remain. Delayed auto-start is
not an address-ready gate. Never widen ListenAddress or firewall scope to hide the error.
Count only a changed guest boot time as reboot acceptance; a successful SSH probe
during pending shutdown can still be running the previous boot. Measure elapsed
recovery using the controller's monotonic clock, not mixed guest/controller UTC.

## Observing the pre-shutdown phase

`tools/windows-preshutdown-observe.ps1` is a read-only, targeted service observer.
The default `-DurationSeconds 0` emits one JSON-lines snapshot and exits. An explicit
bounded duration (up to 1800 seconds) emits status changes plus 30-second heartbeats.
It queries SCM status and `SERVICE_CONFIG_PRESHUTDOWN_INFO`; it neither shuts down
Windows nor starts/stops/configures services. Unknown/inaccessible queries are
reported as UNKNOWN, not as stopped. Null timeout means unavailable configuration.

Run the default through checked `exec`. To observe an independently authorized
reboot, invoke it with an explicit duration from a durable job, confirm RUNNING and
initial output, then request the reboot once. Retrieve that same job's retained
logs after recovery; do not resubmit the observer because the restart interrupted
its task. In the measured trial, observer output ended before the pre-shutdown service
transitions: it captured the lead-up, not the entire shutdown.
A trace that survives that phase is needed for attribution. This is a development
diagnostic, not an automatic repair command.

The candidate list covers the services observed in this VM, update services and
Agent Road transport; it is not exhaustive. SCM state 3 is STOP_PENDING, 1 STOPPED,
4 RUNNING; accepted-controls bit 0x100 means pre-shutdown notifications. Checkpoint
and wait-hint progress can identify a waiting service, but a stopped recorder or
missing final sample cannot prove which service blocked shutdown. Correlate System
RecordId ordering, event 7043, boot identity and performance event 200; timestamps
alone can mislead after VM clock adjustments.

Reference: [Microsoft pre-shutdown settings](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/ns-winsvc-service_preshutdown_info).

## Shutdown-persistent service trace

`tools/windows-shutdown-trace.wprp` is an opt-in diagnostic profile, not an
installer setting. Unlike a scheduled PowerShell observer, the WPR shutdown
recording retained service transitions after Task Scheduler stopped in the
2026-09-23 trial. It requires an elevated session and built-in WPR support for
`-shutdown`. Read `wpr -help start`, existing WPR/ETW session state and available
space first; never cancel another recorder's session.

Copy the profile to a new task directory outside the reserved Agent Road root.
Use a unique instance name, retained in the operation receipt, for **every** WPR
command. Example after preparing `C:\AgentRoad-Work\shutdown-trace-unique`:

```powershell
$dir = 'C:\AgentRoad-Work\shutdown-trace-unique'
$instance = 'AgentRoadShutdownUnique'
wpr -start "$dir\windows-shutdown-trace.wprp!RoadShutdown" -filemode -shutdown -recordtempto $dir -instancename $instance
wpr -status collectors -instancename $instance
logman query "WPR_initiated_${instance}_AgentRoadShutdownEvents" -ets
logman query "WPR_initiated_${instance}_WPR System Collector" -ets
```

Check each native exit code separately. Confirm the collector is running and
`logman` reports **Circular: On, Segment Max Size: 256 MB** for the event collector
and **128 MB** for the system collector before requesting one
separately authorized guest reboot. Each collector has 64 buffers of 128 KiB.
The combined 384 MB limit applies to the two raw ETLs, not all merged files, metadata or exported XML;
retain disk headroom and stop after the scoped test. Circular mode can overwrite
old events. Enabled providers do not prove emitted events or complete coverage.

After confirming a new guest boot, save only this instance (do not overwrite an
existing evidence file):

```powershell
wpr -stop "$dir\shutdown.etl" 'VM shutdown diagnosis' -skipPdbGen -instancename $instance
wpr -status -instancename $instance
Get-FileHash "$dir\shutdown.etl" -Algorithm SHA256
```

Verify stop success, that the named instance is no longer recording, and the
transferred ETL hash. `Get-WinEvent -Path ... -Oldest` can decode service event XML
although the rendered Message may be null. Retain provider GUIDs and raw XML for
unresolved events; do not treat missing rendered messages as empty events.
Do not replay a start/stop/reboot whose result is uncertain. Inspect its existing
instance and files first. If the guest stalls, preserve the fault state and files
before any authorized external recovery; a hard power loss may truncate a trace.

The first, event-only profile trial decoded 252 service events and 39 unnamed metadata/events. Other
configured providers supplied no named decoded events, so storage/root-cause
coverage is **not accepted**. It demonstrated successful shutdown persistence,
not reproduction of the intermittent stall. See `shutdown-trace-trial.json` in
`experiments/vm-recovery-20260923/` for timing and limitations. The later positive control below validates normal disk emission. Fault diagnosis
still needs host-side correlation, not another blind cache/service-timeout change.

References: [WPR command options](https://learn.microsoft.com/en-us/windows-hardware/test/wpt/wpr-command-line-options),
[MaximumFileSize](https://learn.microsoft.com/en-us/windows-hardware/test/wpt/maximumfilesize).

### Validated kernel disk collector

The profile now also includes a SystemCollector with `DiskIO`, `DiskIOInit`,
`FileIO`, `FileIOInit` and `ProcessThread`. Windows WPR 10.0.26100 rejected the
`DiskIOInitialization` spelling in the Microsoft keyword reference; use the
locally validated `DiskIOInit`. The XML schema also requires collector definitions
before provider definitions. Two rejected parses performed no probe I/O and
started no recording; their receipts were retained.

A 16 MiB write-through probe produced 151 DiskIo events. File-name/FileObject
correlation linked 18 completed disk writes totaling exactly 16,777,216 bytes to
the probe file. This validates normal disk-event emission, not stall diagnosis,
physical SSD performance, uncached reads or shutdown persistence of this newly
added collector. No reboot occurred during this validation.

`Get-WinEvent` returned blank provider names and ProcessingErrorData 15003 for
classic kernel events. Preserve GUID, opcode and payload rather than counting
only ProviderName. Built-in `tracerpt` decoded the relevant disk/file records:

```powershell
tracerpt "$dir\shutdown.etl" -o "$dir\decoded.xml" -of XML -summary "$dir\summary.txt"
```

Use new output paths and inspect native exit code **and warnings**. The trial
reported some schema mismatches, but its relevant disk/file records decoded and
its summary reported zero lost events. This is not proof every record decoded.
XML can be much larger than ETL and includes unrelated process/file paths; keep
raw captures private. In tracerpt XML the outer provider GUID is MSNT_SystemTrace;
classify DiskIo using `ExtendedTracingInfo/EventGuid` equal to
`{3d6fa8d4-fe05-11d0-9dda-00c04fd7ba7c}` and opcode, not the outer provider alone.
Do not convert HighResResponseTime to milliseconds without the trace clock rate.

See `storage-trace-validation.json` for the result and remaining acceptance gates.
References: [SystemProvider](https://learn.microsoft.com/en-us/windows-hardware/test/wpt/systemprovider),
[DiskIo event types](https://learn.microsoft.com/en-us/windows/win32/etw/diskio).

The combined profile subsequently survived a stalled reboot and external recovery;
see `combined-shutdown-trace.json`. Windows recorded a 6.424-second shutdown,
while the VM did not complete the restart. ETW ends near the recorded shutdown
end, not at external poweroff eight minutes later. Treat this as a coverage boundary:
a last unmatched I/O initiation and zero reported lost events do not prove that
request caused the stall or that the later interval was observed. Separate cold-
recovery disk errors from the earlier incident. Next investigate the late guest
reset/VirtualBox transition with retained fault-state evidence, preserving host
security and avoiding another speculative service-timeout or cache change.

September 25 follow-up found the same relative four-vCPU RIP signature after a
cold start reached a `Restarting` screen without a requested guest reboot. This
supports recurrence, not symbol-level attribution. The fault was snapshotted and
the VM saved; see `experiments/vm-recovery-20260923/reset-handoff-followup.json`.
Connection readiness remains false; do not re-pair or call this SSH-only failure.

Offline symbols subsequently mapped the prior fault to `HalpNmiReboot` waiting
for a processor counter, two CPUs in a reset HLT loop, and one CPU idle. See
`offline-kernel-symbols.json` for base-inference and version limits. This supports
a multiprocessor reboot-wait diagnosis, not proven NMI/virtualization causality.
Use an isolated CPU-count comparison next; keep the original VM saved.
