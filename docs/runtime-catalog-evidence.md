# Runtime catalog evidence

## Reviewed primary sources

- PowerShell v7.6.4 release: <https://github.com/PowerShell/PowerShell/releases/tag/v7.6.4>
- PowerShell v7.6.4 published hashes: <https://github.com/PowerShell/PowerShell/releases/download/v7.6.4/hashes.sha256>
- Microsoft installation guidance for PowerShell on Windows: <https://learn.microsoft.com/en-us/powershell/scripting/install/install-powershell-on-windows?view=powershell-7.6>
- Microsoft PowerShell support lifecycle: <https://learn.microsoft.com/en-us/powershell/scripting/install/powershell-support-lifecycle?view=powershell-7.6>

## Catalog revision 1

- Platform: `windows` / `x64`; minimum build `17763` (Windows 10 version 1809 boundary).
- Artifact: `powershell-7` version `7.6.4`.
- Stable source URL: `https://github.com/PowerShell/PowerShell/releases/download/v7.6.4/PowerShell-7.6.4-win-x64.zip`.
- Observed download bytes: `116979293`.
- Published SHA-256: `80832551C52809301E6071C8BAC977BEB5A2F1EC953EB4DB9F94DEB953333793`.
- ZIP expanded-byte sum: `296034085`; this is the pinned extraction ceiling.
- Packaging: `zip`.
- Expected extracted-binary signer: `Microsoft Corporation`, represented by `microsoft-corporation`.
- Runtime verifier: `powershell-json-roundtrip`.

The independently observed Chrome download chain had exactly two origins: `github.com` then `release-assets.githubusercontent.com`. The catalog records only the stable GitHub URL and the reviewed redirect origin. It does not record an expiring CDN path, query, token, or key.

`core` and `base` both currently resolve only `powershell-7`; `base` is reserved and is not claimed available. Core physical acceptance and the subsequent CLI reliability checks are recorded in `CURRENT_STATE.md` and `docs/doctor-intermittent-diagnosis.md`. Base still requires its own artifact, verifier, and multi-component transaction acceptance; see [the Python provider candidate](base-python-candidate.md).
