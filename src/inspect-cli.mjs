#!/usr/bin/env node

import { realpathSync } from 'node:fs';
import { isAbsolute, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseArgs } from 'node:util';

import { captureRecoveryInspect, readRecoveryInspectCapture } from './runtime/recovery-inspect-capture.mjs';

const HELP = `Agent Road inspect capture

Usage:
  node src/inspect-cli.mjs inspect <device-id> --run-directory <absolute-path>
  node src/inspect-cli.mjs readback --run-directory <absolute-path>

Inspect invokes the production recovery inspection once and requires separate
physical authorization. Readback reads local evidence only. Keep the exact run
path; never choose a new path to retry an uncertain invocation.
`;
const EXIT_CODES = Object.freeze({ FINITE_RESULT: 0, FINITE_STOP: 2, BLOCKED: 3, STOP_UNKNOWN: 4 });
const blocked = () => ({ phase: 'pre-inspection', outcome: 'BLOCKED', code: 'CAPTURE_START_FAILED' });
const unknown = () => ({
  phase: 'recovery-inspect', outcome: 'STOP_UNKNOWN', code: 'INSPECT_INVOKED_RESULT_UNCERTAIN',
});

function parseInput(argv) {
  const [mode, ...args] = argv;
  if (mode !== 'inspect' && mode !== 'readback') throw new Error();
  const { values, positionals, tokens } = parseArgs({
    args, options: { 'run-directory': { type: 'string' } },
    allowPositionals: true, strict: true, tokens: true,
  });
  const runDirectory = values['run-directory'];
  if (tokens.filter((token) => token.kind === 'option').length !== 1
    || tokens.some((token) => token.kind === 'option-terminator')
    || typeof runDirectory !== 'string' || !isAbsolute(runDirectory)
    || resolve(runDirectory) !== runDirectory || Buffer.byteLength(runDirectory) > 4_096
    || /[\x00-\x1f\x7f]/u.test(runDirectory)) throw new Error();
  if (mode === 'readback') {
    if (positionals.length !== 0) throw new Error();
  } else if (positionals.length !== 1 || positionals[0].length > 64
    || !/^dev_[a-z0-9]+$/u.test(positionals[0])) throw new Error();
  return { mode, runDirectory, deviceId: positionals[0] };
}

// The final argument is a trusted local test seam. Readback never touches it.
export async function main(
  argv = process.argv.slice(2),
  env = process.env,
  io = { stdout: process.stdout },
  loadMain = async () => (await import('./cli.mjs')).main,
) {
  let output;
  let enteredCapture = false;
  let result;
  try {
    const sink = io.stdout;
    const write = sink.write;
    if (typeof write !== 'function') throw new Error();
    output = (text) => Reflect.apply(write, sink, [text]);
    if (argv.length === 1 && argv[0] === '--help') {
      output(HELP);
      return 0;
    }
    const input = parseInput(argv);
    if (input.mode === 'readback') {
      result = await readRecoveryInspectCapture(input.runDirectory);
    } else {
      if (typeof loadMain !== 'function') throw new Error();
      enteredCapture = true;
      result = await captureRecoveryInspect({
        runDirectory: input.runDirectory,
        diagnostics: true,
        // This adapter emits the returned finite projection exactly once.
        stdout: { write() {} },
        invoke: async (captureIo) => {
          const cliMain = await loadMain();
          return await cliMain(['runtime-recover', input.deviceId, '--inspect'], env, captureIo);
        },
      });
    }
  } catch {
    result = enteredCapture ? unknown() : blocked();
  }
  try { output?.(`${JSON.stringify(result)}\n`); } catch {
    // Display failure does not delete or replace an already published receipt.
  }
  return EXIT_CODES[result.outcome];
}

if (process.argv[1]
  && realpathSync(process.argv[1]) === realpathSync(fileURLToPath(import.meta.url))) {
  main().then(
    (exitCode) => { process.exitCode = exitCode; },
    () => { process.exitCode = 4; },
  );
}
