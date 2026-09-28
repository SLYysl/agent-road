# Requesting an Agent Road Alpha bundle

The current free trial focuses on Apple Silicon Mac → Windows 11 x64. A fresh device needs a maintainer-provided bundle; the native Windows installer is not publicly released.

Email **syin31437@gmail.com** with your Mac version/chip, Windows version/architecture, existing AI agent, and one task you want to try. Confirm that you are authorized to manage both machines and can arrange local Windows access. Do not include passwords, tokens, pairing codes or raw logs.

The maintainer reviews fit before sending a bundle. Sending an email does not automatically enroll a device or guarantee a place or response time. The [website request button](https://agent-road.brahma-technologies.com/#request-access) opens a draft that you send yourself.

## Before running anything

Ask for a pinned version, file manifest and SHA-256 checksums through the maintainer's confirmed delivery channel. A handed-out bundle should identify its installer/setup material, assets, agent prompts, prerequisites, known limitations and feedback instructions. This is a delivery checklist, not a claim that every earlier archive contains these documents.

On Mac, compute the archive checksum with `shasum -a 256 /path/to/bundle.zip`. On Windows, use `Get-FileHash -Algorithm SHA256 -LiteralPath 'C:\path\to\bundle.zip'`. Compare against the separately supplied checksum. A checksum inside the same archive alone does not authenticate its publisher; checksums are not a trusted code signature.

Keep the bundle's versioned instructions together. Do not mix them with older website downloads or reuse old pairing codes. Have your agent inspect the environment first, then explain required changes and obtain authorization. Read [Windows changes and withdrawal](windows-access-and-removal.md) before setup. Existing enrolled users should retain their original controller state and check status rather than re-pair.

## Acceptance and feedback

Verify a read-only command, file round trip and background job separately. Record the bundle version, both OS versions, agent, failing stage, expected/actual result, and a redacted error. Keep job IDs privately to reconcile uncertain operations; never automatically repeat a write with an unknown result.

Send ordinary trial feedback to the same email. Review shared material for credentials, device identifiers, private paths and personal files before sending. Follow the withdrawal checklist when ending the trial; there is no universal one-command uninstall today.
