#!/usr/bin/env node
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
const repo = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const output = resolve(process.argv[2] ?? '/tmp/agent-road-distribution');
const origin = process.argv[3] ?? 'https://agent-road.brahma-technologies.com';
if (!/^https:\/\/[a-z0-9.-]+$/.test(origin)) throw Error('HTTPS origin required');
// Tracked runtime plus the agent guide: no local state, tests, private captures or tools.
const files = execFileSync('git', ['ls-files', '-z', 'src', 'windows', 'config', 'package.json', 'docs/agent-setup.md', 'docs/agent-interface.md', 'docs/agent-guide-zh.md', 'docs/windows-installer-delivery.md', 'docs/onboarding-status.json'], { cwd: repo }).toString().split('\0').filter(Boolean).sort();
if (['src/cli.mjs', 'package.json', 'docs/agent-setup.md', 'docs/onboarding-status.json'].some(path => !files.includes(path))) throw Error('Tracked runtime or onboarding guide missing');
// Revision must identify the exact packaged source, including staged changes.
const buildInputs = ['tools/distribution/build.mjs', 'tools/distribution/install.sh.in'];
execFileSync('git', ['ls-files', '--error-unmatch', ...buildInputs], { cwd: repo, stdio: 'pipe' });
execFileSync('git', ['diff', '--exit-code', '--quiet', 'HEAD', '--', ...files, ...buildInputs], { cwd: repo });
await mkdir(output, { recursive: true, mode: 0o700 });
const archive = 'agent-road-controller.tar.gz';
// tar input paths are fixed git-tracked runtime paths, never user-provided entries.
execFileSync('tar', ['-czf', resolve(output, archive), ...files], { cwd: repo, env: { ...process.env, COPYFILE_DISABLE: '1' } });
const sha256 = createHash('sha256').update(await readFile(resolve(output, archive))).digest('hex');
const named = `agent-road-${sha256.slice(0, 16)}.tar.gz`;
await writeFile(resolve(output, named), await readFile(resolve(output, archive)), { mode: 0o600 });
const template = await readFile(new URL('./install.sh.in', import.meta.url), 'utf8');
const installer = template.replaceAll('@RELEASE@', sha256).replaceAll('@ORIGIN@', origin).replaceAll('@ARCHIVE@', named).replaceAll('@SHA256@', sha256);
await writeFile(resolve(output, 'install.sh'), installer, { mode: 0o700 });
const manifest = { schemaVersion: 1, revision: execFileSync('git', ['rev-parse', 'HEAD'], { cwd: repo }).toString().trim(), archive: named, sha256, installerSha256: createHash('sha256').update(installer).digest('hex'), files, nodeVersion: '22.23.2', onboarding: JSON.parse(await readFile(resolve(repo, 'docs/onboarding-status.json'), 'utf8')), published: false };
await writeFile(resolve(output, 'manifest.json'), JSON.stringify(manifest, null, 2) + '\n');
console.log(JSON.stringify({ output, archive: named, sha256, fileCount: files.length, published: false }));
