# Third-party review inventory (incomplete)

This is a review checklist, not a license grant or a completed NOTICE file. No third-party license determination is asserted here.

| Component | Source reference in this snapshot | Review before release |
| --- | --- | --- |
| Node.js | package.json, engine >=22 | Controller prerequisite; installation/distribution terms if bundled |
| Python 3 | tools/acceptance/*.py | Optional acceptance helper prerequisite; terms if bundled |
| Tailscale Windows | config/releases.json (1.98.9) | Installer download/distribution, notices, hosted account/network requirements |
| PowerShell | config/runtime-catalog.json (7.6.4) | Portable runtime distribution and required license/notices |
| Windows OpenSSH | windows/ and tools/native-setup/ | OS capability vs any independently distributed payload; applicable notices |
| .NET Framework | tools/native-setup/Build.ps1 | Build/runtime requirements and redistributable terms if bundled |
| Cloudflare Workers | services/pairing/ | Deployment/tooling dependencies, user-owned configuration and service scope |

The root package declares no npm dependencies. That does not establish absence of third-party components in generated installers, downloads, examples, separate services or tooling. Review the exact release asset contents and their provenance before publishing binaries. Gitleaks is an external verification tool and is not included in this repository.
