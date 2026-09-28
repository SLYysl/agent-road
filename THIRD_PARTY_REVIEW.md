# Third-party licensing and distribution review

Reviewed 2026-09-28 against candidate source `880767a` and the website lockfile recorded in [review evidence](docs/license-review-20260928/README.md). This inventory distinguishes upstream source licensing, downloaded products, and hosted-service terms. It is not clearance of every historical or future binary archive.

## Controller and Windows setup

| Component | Verified terms / source | Actual use and release treatment |
| --- | --- | --- |
| Tailscale core 1.98.9 | [BSD-3-Clause, pinned tag](https://github.com/tailscale/tailscale/blob/v1.98.9/LICENSE) | Invoked as an external executable; not linked into Agent Road. Retain its notices if its open-source code/binaries are redistributed. |
| Tailscale full Windows installer 1.98.9 | [Official open-source boundary](https://tailscale.com/opensource), [service terms](https://tailscale.com/terms) | `NativeTailscale.cs` downloads the official installer from pkgs.tailscale.com. Windows GUI and hosted coordination are not covered merely by the core BSD license. Do not mirror/repackage the full installer based on BSD alone. |
| Node.js 22.23.2 | [MIT and bundled third-party notices](https://github.com/nodejs/node/blob/v22.23.2/LICENSE) | `install.sh.in` downloads and extracts the full official Mac archive; the controller tarball does not embed Node. Retain the archive's LICENSE and embedded third-party notices; a binary mirror requires exact-artifact review. |
| PowerShell 7.6.4 | [MIT](https://github.com/PowerShell/PowerShell/blob/v7.6.4/LICENSE.txt), [third-party notices](https://github.com/PowerShell/PowerShell/blob/v7.6.4/ThirdPartyNotices.txt) | Core runtime catalog downloads official portable ZIP. Preserve the complete runtime licenses/notices when caching, installing or redistributing; MIT for PowerShell does not cover every bundled component by itself. |
| Windows OpenSSH | [Upstream license collection](https://github.com/PowerShell/openssh-portable/blob/latestw_all/LICENCE) | Installed as a Windows optional capability, not bundled by the native build script. BSD-style upstream terms are not a blanket license for Windows payloads. |
| Windows PowerShell / .NET Framework | OS-provided prerequisite; `tools/native-setup/Build.ps1` | Native preview uses the installed Windows compiler and framework references. No framework DLL/installer is copied into its output by this script. Reassess if a redistributable is added. |
| Python 3 | [PSF license and incorporated software notices](https://docs.python.org/3/license.html) | Local acceptance/test helper prerequisite, not bundled. Review exact version if later distributed. |
| Git | [GPL version 2](https://github.com/git/git/blob/master/COPYING) | Existing external tool inspected/invoked; no Git implementation or binary in the candidate. This does not require applying GPL to independently written Agent Road code. Bundling Git would require its own GPL distribution obligations. |
| ripgrep | [MIT or Unlicense](https://github.com/BurntSushi/ripgrep/blob/master/COPYING) | Existing optional tool detection only; no binary bundled. |
| Cloudflare Workers | Platform API import `cloudflare:workers` | Pairing source imports local project modules and platform APIs; no npm library is vendored. Hosted deployment and tooling have separate terms. |

The root package has no npm dependencies. The current `base` runtime profile contains PowerShell only; it does not distribute Git, Node or Python for Windows. Native compilation packages Agent Road code, not a Tailscale/OpenSSH/.NET payload.

## Tailscale hosted-service boundary

Tailscale's terms reviewed on this date were updated August 25, 2026. Sections 2.1–2.3 distinguish permitted use and restrict exploitation/mirroring/resale of its service. BSD source permission is not permission to offer a shared hosted Tailscale service. For external trials, follow the existing user-owned-account/tailnet instructions; operating a pooled service for unrelated users needs a separate terms/authorization review. No such clearance is claimed here, and no existing network has been changed.

## Website, audited separately

The complete website checkout and its node_modules are not part of this controller repository or controller tarball. Direct package versions and lock metadata are recorded under `docs/license-review-20260928/`.

| Component | Finding | Treatment |
| --- | --- | --- |
| Next.js, React, next-intl, Supabase JS, Clerk JS, Motion, Three.js, Phosphor, Tailwind | Installed package metadata identifies MIT; exact versions in inventory | Retain upstream notices in any distributed copies. SDK licensing does not license the corresponding hosted service. |
| OGL / TypeScript | Unlicense / Apache-2.0 in installed metadata | Preserve applicable upstream terms. |
| GSAP 3.15.0 | [Custom Standard No Charge license](https://gsap.com/standard-license/) | Permits website use subject to restrictions, including visual-animation-builder competition. Do not label it MIT or relicense it under Apache. It is outside the controller release. |
| Sharp / libvips | [Sharp installation](https://sharp.pixelplumbing.com/install/), lock metadata includes Apache-2.0 and LGPL-3.0-or-later | Platform-specific optional binaries are not all installed or shipped. Before publishing a website/container binary bundle, determine the actual artifacts and retain notices/source and replacement rights required by their licenses. No such bundle was cleared. |
| Lightning CSS / axe-core | MPL-2.0 in lock metadata | Check which files actually ship and preserve notices/source obligations for covered files if redistributed. |
| caniuse-lite | CC-BY-4.0 in lock metadata | Preserve applicable attribution for redistributed data; not a project-wide code license. |
| Cabinet Grotesk | [Official family page](https://www.fontshare.com/fonts/cabinet-grotesk), read in browser: Closed Source / ITF Free Font License | Own-site self-hosting is permitted under that license; distributing font files through a repository is restricted. Keep existing appearance, but exclude the font files from a public source/asset release unless separately cleared. |
| Inter Tight / Geist Mono | [Inter Tight OFL](https://github.com/google/fonts/blob/main/ofl/intertight/OFL.txt), [Geist Mono OFL](https://github.com/google/fonts/blob/main/ofl/geistmono/OFL.txt) | Keep SIL OFL notices with distributed font files and check actual versions. |
| Mac lifebuoy image, other illustrations, video, voice/audio | Exact provenance and reuse permissions not established in this audit | Excluded from project code license. Preserve current private/website files; publication of asset copies remains a gate. |

Metadata alone is not a complete license audit: it can omit per-file exceptions, vendored code and generated output. Do not publish node_modules, compiled website bundles, third-party installers or media under one blanket Apache label.

## Distribution checks and remaining work

- New controller builds must include LICENSE, NOTICE, LICENSE_SCOPE.md and this inventory; missing or dirty legal inputs fail the build.
- Native build output copies these files beside the executable. Execution on Windows still needs its own build verification.
- The historical tester-kit builder pins old `59e025e` / build11 artifacts. This review does not rewrite those archives or retroactively establish their notices. Regenerate and inspect a new kit before public binary distribution.
- Preserve exact upstream notices in downloaded runtime archives. A source-license lookup alone does not complete an exact-binary SBOM or redistribution review.
- Confirm original-source ownership and media provenance before making the entire repository public. No external contributor was shown in this snapshot's Git authors, but an exported snapshot cannot prove complete provenance.
