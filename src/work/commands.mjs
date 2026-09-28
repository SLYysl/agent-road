const commands = Object.freeze({
  session: 'session.mjs',
  job: 'job.mjs',
  'base-inspect': 'base-inspect.mjs',
  'base-exec': 'base-exec.mjs',
  'measure-exec': 'measure-exec.mjs',
});

export function isWorkCommand(command) {
  return Object.hasOwn(commands, command);
}

export async function runWorkCommand(command, args, env, io) {
  if (!isWorkCommand(command)) throw new Error('WORK_COMMAND_INVALID');
  const { run } = await import(new URL(commands[command], import.meta.url));
  return run(args, env, io);
}

// Static interface discovery, not a live device health/capability assertion.
export function workCapabilities() {
  return {
    schemaVersion: 1,
    scope: 'controller-interfaces',
    deviceProbed: false,
    commands: [
      { name: 'list', usage: 'list', output: 'json', localOnly: true },
      { name: 'status', usage: 'status <device-id>', output: 'json', localOnly: true },
      { name: 'exec', usage: 'exec <device-id> --script <local.ps1> [--timeout-seconds <1-1800>]', output: 'json' },
      { name: 'put', usage: 'put <device-id> <local-file> <absolute-windows-path> [--overwrite]', output: 'json' },
      { name: 'get', usage: 'get <device-id> <absolute-windows-path> <local-file> [--overwrite]', output: 'json' },
      { name: 'session', usage: 'session <device-id> <absolute.ps1> [more absolute.ps1...]', output: 'jsonl', maxScripts: 20, timeoutSecondsPerScript: 300, sharedShell: false },
      { name: 'job', usage: 'job <start|status|logs|cancel|remove> <device-id> <script-or-job-id> [start-timeout-seconds | logs: --include-output]', output: 'jsonl', durable: true, rebootResume: false, statePath: 'state.status', logEncoding: 'base64', logResultFile: 'response.json', logOutputFlag: '--include-output' },
      { name: 'base-inspect', usage: 'base-inspect <device-id>', output: 'jsonl', installsTools: false },
      { name: 'base-exec', usage: 'base-exec <device-id> <absolute-inspection-directory> <absolute.ps1> <git,node,python,rg subset> [timeout-seconds]', output: 'jsonl' },
      { name: 'measure-exec', usage: 'measure-exec <device-id> [1-20 iterations]', output: 'jsonl' },
    ],
    automaticReplay: false,
    controllerTransport: 'serialized-per-device',
    experimentalEvidenceOnly: ['desktop-browser-control', 'desktop-user-agent-handoff'],
    unsupportedInterfaces: ['pty', 'shared-shell', 'recursive-file-sync', 'general-agent-backend'],
    guide: 'docs/agent-interface.md',
  };
}
