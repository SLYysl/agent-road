# Agent Road Diagnostics Preview

This is a local diagnostics application with per-user installation/removal. It is
not the replacement Agent Road onboarding installer, and does not contain or run
the blocked bootstrap. No network requests, pairing, service changes, credential
collection, autostart or security policy changes are implemented.

Development build is unsigned. Package SHA-256 detects corruption, not publisher
trust. If Windows blocks it, stop and retain the diagnostic; do not disable protection,
add exclusions, unblock policy or import a certificate to run it.

On a Windows development machine with the .NET Framework compiler:

```powershell
.\Build.ps1 -OutputDirectory C:\YourBuildFolder\DiagnosticsPreview
```

Extract the ZIP, open `AgentRoadDiagnostics.exe`, and choose **Install for me**.
The confirmation shows the current user's installation folder and states that no
remote access will be installed. The application can also run without installation.
Choose **Run local checks**, then **Save report** to create a new report file.

To uninstall, close the installed copy, launch the program from the original
extracted package and choose **Uninstall**. The native workflow does not invoke
PowerShell or alter its execution policy. `Install.ps1` remains a developer helper;
it is not the default user entry and does not work under Restricted script policy.

Reports include OS version, UTC, service status and at most ten Defender events
with time, event ID, threat/action names. Unavailable evidence is labelled; no event
messages, command lines, credentials or Windows activation keys are exported.

Only the owned application and receipt are removed. Exported reports stay where
you saved them. Changed executable bytes, unexpected files, or reparse points stop
uninstallation for inspection. A partial installation is not retried automatically.
No Start menu shortcut or Windows Installed Apps registration is created yet.

For unattended local diagnostics: `AgentRoadDiagnostics.exe --report C:\new-report.json`.
Existing reports are never overwritten. This mode does not install the app.

For explicit unattended lifecycle tests, the original package executable accepts
`--install-local` and `--uninstall-local` (0 success, 2 stopped). These affect only
its own per-user diagnostic copy. A pre-existing folder is never overwritten.
