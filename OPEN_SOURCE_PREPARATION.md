# Open-source preparation / 开源准备

This repository publishes **experimental Alpha source under Apache-2.0**. Public source, prebuilt installers and hosted-service access are separate release scopes.

## Included and excluded

Exported tracked source from development revision `335cfeee6614a6e7c2599cb1c1fe00cf2ce61787` without its git history. Controller, Windows bootstrap/native installer source, pairing service source, tests and technical documentation are retained. The entire `experiments/` directory is excluded: it contains operational receipts, screenshots and historical bundles. Links to that directory are therefore historical references, not available public evidence. Original evidence remains in the private development repository.

## Evidence and limits

- Mac-to-Windows command execution, file round trips and durable jobs have internal physical/VM acceptance evidence.
- Claude and DeepSeek independently orchestrated the existing controller; this does not prove arbitrary agents or first-time users can onboard.
- The latest 24-hour observation had 95 successful scheduled samples plus a successful closing probe. A boot timestamp precision change was separately reconciled using the Windows boot event identity. This is sampled stability, not continuous uptime.
- An earlier sshd service stop has no confirmed root cause. A four-vCPU VM update/reboot stall remains unresolved; a one-vCPU workaround is not a general fix.
- Native installer builds remain unsigned. This repository does not publish prebuilt installers.
- Primary validated direction is Mac controller to Windows target. Do not advertise all operating systems or recovery from any failure.
- Remote access requires a booted, reachable system. No promise of recovery from firmware, disk encryption, hardware or offline failures.

Use the [license release decision checklist](docs/LICENSE_RELEASE_CHECKLIST.md) to resolve ownership, license and media scope before publication.

See [third-party review inventory](THIRD_PARTY_REVIEW.md) for the initial component checklist.

## Source publication and remaining delivery work

- [x] Independent source snapshot; no private development history.
- [x] Exclude raw experiment directory and historical packaged binaries.
- [x] Initial Gitleaks 8.30.1 scan: no detections (text/source scan, not a security audit).
- [x] Select Apache-2.0 for original code; add LICENSE, NOTICE and explicit scope.
- [x] Maintainer authorized source publication and confirmed the displayed media is self-generated without external assets; artwork remains separate from the code license.
- [x] Inventory identified source/runtime/website dependencies and separate upstream/service/asset terms.
- [ ] Validate notices and provenance of each exact redistributed binary; historical tester archives remain pending.
- [ ] Review remaining documentation, example identifiers, hosted URLs and broken historical evidence links; replace old README onboarding claims with one supported public path.
- [ ] Validate hosted pairing ownership isolation, revocation, expiry, rate limits and operating scope before inviting unrestricted public use.
- [ ] Complete fresh external two-machine trials with user-owned accounts, using the distributed prompt and package.
- [ ] Publish reproducible installer build instructions, hashes and signing status before distributing a release asset.
- [x] Publish the maintainer-approved private security contact in SECURITY.md; no response SLA or inbox-delivery test is claimed.
- [x] User explicitly authorized public Alpha source release; final source/history credential review performed.

## Tester feedback / 测试反馈

请记录控制端和目标端系统版本、使用的 Agent、候选版本、失败阶段、脱敏错误码、是否需要人工介入，以及是否发生意外重复任务。不要上传 token、配对命令、密钥、账号资料、原始控制器状态或未经审查的日志。先诊断现有环境；安装、重启和变更安全策略必须明确说明并获得设备所有者授权。结果不明的写操作不得盲目重试。

The public source is not a promise to run a hosted service for every user. Repository publication, installer distribution and hosted-service availability are separate decisions.

## Candidate validation (2026-09-28)

- At initial export, 277 implementation/test/tool/service/example/config files matched the source snapshot. Later commits add licensing, notices and packaging checks; see Git history.
- `npm run check`: passed.
- Python acceptance regression: 22 tests passed.
- Gitleaks 8.30.1 source scan: zero detections; private raw reports kept outside this repository. No claim that regex scanning proves absence of all secrets.
- `npm test`: 1,596 tests; 1,577 passed, 19 skipped, zero failures (797.3 seconds). Skipped checks do not establish Windows acceptance.
- Historical Markdown retains intentional double-space line breaks; staged whitespace validation excludes end-of-line spaces.
