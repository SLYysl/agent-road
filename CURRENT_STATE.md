# CURRENT_STATE — License selection and dependency review
Updated: 2026-09-28
- Repository: SLYysl/agent-road, main, private; licensing does not publish it.
- Selected/applied Apache-2.0 to original code/docs under user authorization; LICENSE, NOTICE, LICENSE_SCOPE.md and package metadata added.
- Reviewed Tailscale core vs full Windows installer vs hosted service; no blanket BSD redistribution claim.
- Reviewed Node 22.23.2, PowerShell 7.6.4, OpenSSH, Python, Git, ripgrep and website direct/transitive package metadata.
- Website exceptions: GSAP custom license, Cabinet Grotesk restricted font redistribution, LGPL/MPL/CC-BY dependencies require exact artifact review.
- Lifebuoy Mac retained; image/font/video reuse rights excluded from the code license pending provenance review.
- Controller packager now requires legal files and includes new user guides; native builder copies notices beside its executable.
- Distribution contract test passed after reproducing missing-license packaging; npm run check passed.
- Native Windows build not executed; no runtime/network/Windows changes, no website deploy or public installer release.
- Evidence: docs/license-review-20260928/; private downloads under agent-road-private/license-review-20260928/.
- Existing site production remains dpl_91yVvDZ5Wizfd975xze59gaqsWoj; email entry syin31437@gmail.com.
- Historical pinned tester-kit archives were not regenerated or retroactively cleared.
- Next: verify actual licensed controller archive, resolve source/media provenance and exact installer notices before public release.
