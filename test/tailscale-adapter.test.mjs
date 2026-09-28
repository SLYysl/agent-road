import assert from 'node:assert/strict';
import test from 'node:test';

import { TailscaleAdapter } from '../src/tailscale/tailscale-adapter.mjs';

const APP_EXECUTABLE = '/Applications/Tailscale.app/Contents/MacOS/Tailscale';
const CANDIDATES = [
  APP_EXECUTABLE,
  '/opt/homebrew/bin/tailscale',
  '/usr/local/bin/tailscale',
  '/usr/bin/tailscale',
];

function runningStatus({ dnsName = 'alex-mac.example.ts.net', tailscaleIPs = ['100.64.0.1'] } = {}) {
  return {
    exitCode: 0,
    stdout: JSON.stringify({
      BackendState: 'Running',
      Self: { DNSName: dnsName, TailscaleIPs: tailscaleIPs },
    }),
    stderr: '',
  };
}

function successfulProcess(calls, status = runningStatus()) {
  let ownedRoute = null;
  return async (command, args) => {
    calls.push({ command, args });
    if (args[0] === 'status') return status;
    if (isRouteStatus(args)) {
      return ownedRoute !== null
        ? ownedRouteStatus(ownedRoute)
        : emptyRouteStatus();
    }
    if (args.includes('--bg')) {
      ownedRoute = {
        dnsName: 'alex-mac.example.ts.net',
        localPort: Number(new URL(args.at(-1)).port),
        path: args.find((arg) => arg.startsWith('--set-path=')).slice('--set-path='.length),
      };
    }
    if (args.at(-1) === 'off') ownedRoute = null;
    return { exitCode: 0, stdout: '', stderr: '' };
  };
}

function isRouteStatus(args) {
  return (args[0] === 'serve' || args[0] === 'funnel') && args[1] === 'status' && args[2] === '--json';
}

function emptyRouteStatus() {
  return { exitCode: 0, stdout: '{}', stderr: '' };
}

function ownedRouteConfig({
  dnsName = 'alex-mac.example.ts.net',
  localPort = 43123,
  path = '/agent-road/v1/dev_abc123',
  handlers = {},
  topLevel = {},
} = {}) {
  return {
    TCP: { 443: { HTTPS: true } },
    Web: {
      [`${dnsName}:443`]: {
        Handlers: {
          [path]: { Proxy: `http://127.0.0.1:${localPort}` },
          ...handlers,
        },
      },
    },
    ...topLevel,
  };
}

function ownedRouteStatus(options) {
  return { exitCode: 0, stdout: JSON.stringify(ownedRouteConfig(options)), stderr: '' };
}

function postvalidationProcess({
  postServe = ownedRouteStatus(),
  postFunnel = ownedRouteStatus(),
  cleanupServe = emptyRouteStatus(),
  cleanupFunnel = emptyRouteStatus(),
  offResult = { exitCode: 0, stdout: '', stderr: '' },
} = {}) {
  const calls = [];
  let setupApplied = false;
  let cleanupAttempted = false;
  return {
    calls,
    runProcess: async (command, args) => {
      calls.push({ command, args });
      if (args[0] === 'status') return runningStatus();
      if (isRouteStatus(args)) {
        if (!setupApplied) return emptyRouteStatus();
        if (cleanupAttempted) return args[0] === 'serve' ? cleanupServe : cleanupFunnel;
        return args[0] === 'serve' ? postServe : postFunnel;
      }
      if (args.at(-1) === 'off') {
        cleanupAttempted = true;
        if (offResult instanceof Error) throw offResult;
        return offResult;
      }
      setupApplied = true;
      return { exitCode: 0, stdout: '', stderr: '' };
    },
  };
}

function errorHasCode(code) {
  return (error) => error.code === code;
}

test('returns canonical status and configures a unique loopback Serve route with exact argv', async () => {
  const calls = [];
  const adapter = new TailscaleAdapter({
    runProcess: successfulProcess(calls),
    executable: '/mock/tailscale',
  });

  assert.deepEqual(await adapter.status(), {
    backendState: 'Running',
    dnsName: 'alex-mac.example.ts.net',
    tailscaleIPs: ['100.64.0.1'],
  });

  const route = await adapter.serve({ deviceId: 'dev_abc123', localPort: 43123 });
  assert.deepEqual({
    baseUrl: route.baseUrl,
    path: route.path,
    localPort: route.localPort,
    close: typeof route.close,
  }, {
    baseUrl: 'https://alex-mac.example.ts.net/agent-road/v1/dev_abc123',
    path: '/agent-road/v1/dev_abc123',
    localPort: 43123,
    close: 'function',
  });

  await route.close();
  assert.deepEqual(calls, [
    { command: '/mock/tailscale', args: ['status', '--json'] },
    { command: '/mock/tailscale', args: ['status', '--json'] },
    { command: '/mock/tailscale', args: ['serve', 'status', '--json'] },
    { command: '/mock/tailscale', args: ['funnel', 'status', '--json'] },
    {
      command: '/mock/tailscale',
      args: ['serve', '--bg', '--https=443', '--set-path=/agent-road/v1/dev_abc123', 'http://127.0.0.1:43123'],
    },
    { command: '/mock/tailscale', args: ['serve', 'status', '--json'] },
    { command: '/mock/tailscale', args: ['funnel', 'status', '--json'] },
    {
      command: '/mock/tailscale',
      args: ['serve', '--https=443', '--set-path=/agent-road/v1/dev_abc123', 'off'],
    },
    { command: '/mock/tailscale', args: ['serve', 'status', '--json'] },
    { command: '/mock/tailscale', args: ['funnel', 'status', '--json'] },
  ]);
});

test('removes one terminal DNS dot and canonicalizes IPs into a bounded unique list', async () => {
  const calls = [];
  const adapter = new TailscaleAdapter({
    runProcess: successfulProcess(calls, runningStatus({
      dnsName: 'Alex-Mac.Example.TS.NET.',
      tailscaleIPs: ['100.64.0.1', '2001:0db8::1'],
    })),
    executable: '/mock/tailscale',
  });

  assert.deepEqual(await adapter.status(), {
    backendState: 'Running',
    dnsName: 'alex-mac.example.ts.net',
    tailscaleIPs: ['100.64.0.1', '2001:db8::1'],
  });
});

test('executes the attested resolved target of the first fixed candidate', async () => {
  const calls = [];
  const probes = [];
  const adapter = new TailscaleAdapter({
    runProcess: successfulProcess(calls),
    fsProbe: async (path) => {
      probes.push(path);
      if (path === CANDIDATES[0]) {
        return {
          isFile: true,
          isSymbolicLink: false,
          isExecutable: true,
          resolvedPath: '/opt/homebrew/Cellar/tailscale/1.0.0/bin/tailscale',
        };
      }
      throw new Error('later candidate should not be probed');
    },
  });

  await adapter.status();
  assert.deepEqual(probes, [CANDIDATES[0]]);
  assert.equal(calls[0].command, '/opt/homebrew/Cellar/tailscale/1.0.0/bin/tailscale');
});

test('rejects missing, nonregular, nonexecutable, and unattested executable candidates without invoking a process', async () => {
  for (const fsProbe of [
    async () => false,
    async () => ({ isFile: false, isSymbolicLink: false, isExecutable: true, resolvedPath: '/safe/tailscale' }),
    async () => ({ isFile: true, isSymbolicLink: false, isExecutable: false, resolvedPath: '/safe/tailscale' }),
    async () => ({ isFile: true, isSymbolicLink: false, isExecutable: true }),
    async () => ({ isFile: true, isSymbolicLink: false, isExecutable: true, resolvedPath: 'tailscale' }),
  ]) {
    let calls = 0;
    const adapter = new TailscaleAdapter({
      runProcess: async () => { calls += 1; return runningStatus(); },
      fsProbe,
    });
    await assert.rejects(adapter.status(), errorHasCode('TAILSCALE_NOT_AVAILABLE_ON_MAC'));
    assert.equal(calls, 0);
  }
});

test('redacts stopped, malformed, non-Tailnet, and malicious status failures', async () => {
  const statuses = [
    { exitCode: 0, stdout: JSON.stringify({ BackendState: 'Stopped', Self: {} }), stderr: 'secret-stderr' },
    { exitCode: 0, stdout: '{"BackendState":"Running"} trailing', stderr: 'secret-stderr' },
    runningStatus({ dnsName: 'ts.net' }),
    runningStatus({ dnsName: 'https://alex-mac.example.ts.net/path' }),
    runningStatus({ dnsName: 'alex-mac.example.ts.net@evil.test' }),
    runningStatus({ dnsName: ' alex-mac.example.ts.net' }),
    { exitCode: 1, stdout: 'secret-stdout', stderr: 'secret-stderr' },
  ];

  for (const status of statuses) {
    const adapter = new TailscaleAdapter({
      runProcess: async () => status,
      executable: '/mock/tailscale',
    });
    await assert.rejects(adapter.status(), (error) => (
      error.code === 'TAILSCALE_NOT_RUNNING_ON_MAC'
      && !error.message.includes('secret')
      && error.details === undefined
    ));
  }
});

test('rejects invalid and duplicate Tailnet IP lists without exposing status output', async () => {
  for (const tailscaleIPs of [
    [],
    ['100.64.0.1', '999.1.1.1'],
    ['2001:db8::g'],
    ['100.64.0.1', '100.64.0.1'],
    Array.from({ length: 9 }, (_, index) => `100.64.0.${index + 1}`),
  ]) {
    const adapter = new TailscaleAdapter({
      runProcess: async () => runningStatus({ tailscaleIPs }),
      executable: '/mock/tailscale',
    });
    await assert.rejects(adapter.status(), errorHasCode('TAILSCALE_NOT_RUNNING_ON_MAC'));
  }
});

test('rejects invalid serve input before status or Serve process calls', async () => {
  for (const input of [
    { deviceId: 'bad', localPort: 43123 },
    { deviceId: `dev_${'a'.repeat(61)}`, localPort: 43123 },
    { deviceId: 'dev_abc123', localPort: 0 },
    { deviceId: 'dev_abc123', localPort: 65536 },
    { deviceId: 'dev_abc123', localPort: 1.5 },
  ]) {
    let calls = 0;
    const adapter = new TailscaleAdapter({
      runProcess: async () => { calls += 1; return runningStatus(); },
      executable: '/mock/tailscale',
    });
    await assert.rejects(adapter.serve(input));
    assert.equal(calls, 0);
  }
});

test('refuses any pre-existing Serve or Funnel configuration before setup without leaking output', async () => {
  for (const conflictingCommand of ['serve', 'funnel']) {
    const calls = [];
    const adapter = new TailscaleAdapter({
      executable: '/mock/tailscale',
      runProcess: async (command, args) => {
        calls.push({ command, args });
        if (args[0] === 'status') return runningStatus();
        if (isRouteStatus(args)) {
          return args[0] === conflictingCommand
            ? { exitCode: 0, stdout: '{"Web":{"secret":"must-not-leak"}}', stderr: 'secret-stderr' }
            : emptyRouteStatus();
        }
        throw new Error('setup must not run');
      },
    });
    await assert.rejects(adapter.serve({ deviceId: 'dev_abc123', localPort: 43123 }), (error) => (
      error.code === 'TAILSCALE_SERVE_CONFLICT'
      && !error.message.includes('secret')
      && error.details === undefined
    ));
    assert.ok(calls.every(({ args }) => !args.includes('--bg') && args.at(-1) !== 'off'));
  }
});

test('fails closed on unavailable or malformed Serve/Funnel status before setup', async () => {
  for (const status of [
    { exitCode: 1, stdout: 'secret-stdout', stderr: 'secret-stderr' },
    { exitCode: 0, stdout: '[]', stderr: 'secret-stderr' },
    { exitCode: 0, stdout: '{} trailing', stderr: 'secret-stderr' },
  ]) {
    const calls = [];
    const adapter = new TailscaleAdapter({
      executable: '/mock/tailscale',
      runProcess: async (command, args) => {
        calls.push({ command, args });
        if (args[0] === 'status') return runningStatus();
        if (isRouteStatus(args)) return status;
        throw new Error('setup must not run');
      },
    });
    await assert.rejects(adapter.serve({ deviceId: 'dev_abc123', localPort: 43123 }), (error) => (
      error.code === 'TAILSCALE_SERVE_STATUS_FAILED'
      && !error.message.includes('secret')
      && error.details === undefined
    ));
    assert.ok(calls.every(({ args }) => !args.includes('--bg') && args.at(-1) !== 'off'));
  }
});

test('removes only the owned path when a concurrent Serve route appears after setup', async () => {
  const concurrentState = ownedRouteStatus({
    handlers: { '/concurrent': { Proxy: 'http://127.0.0.1:49999' } },
  });
  const remainingConcurrentState = ownedRouteStatus({
    path: '/concurrent',
    localPort: 49999,
  });
  const process = postvalidationProcess({
    postServe: concurrentState,
    postFunnel: concurrentState,
    cleanupServe: remainingConcurrentState,
    cleanupFunnel: remainingConcurrentState,
  });
  const adapter = new TailscaleAdapter({ executable: '/mock/tailscale', runProcess: process.runProcess, sleep: async () => {} });

  await assert.rejects(adapter.serve({ deviceId: 'dev_abc123', localPort: 43123 }), (error) => (
    error.code === 'TAILSCALE_SERVE_RECONCILIATION_FAILED'
    && error.details === undefined
  ));
  assert.deepEqual(process.calls.filter(({ args }) => args.at(-1) === 'off').map(({ args }) => args), [
    ['serve', '--https=443', '--set-path=/agent-road/v1/dev_abc123', 'off'],
  ]);
  assert.deepEqual(process.calls.slice(-2).map(({ args }) => args), [
    ['serve', 'status', '--json'],
    ['funnel', 'status', '--json'],
  ]);
});

test('removes the owned path and fails closed when Funnel appears after setup', async () => {
  const funnelState = ownedRouteStatus({
    topLevel: { AllowFunnel: { 'alex-mac.example.ts.net:443': true } },
  });
  funnelState.stderr = 'secret-funnel-output';
  const process = postvalidationProcess({ postServe: funnelState, postFunnel: funnelState });
  const adapter = new TailscaleAdapter({ executable: '/mock/tailscale', runProcess: process.runProcess, sleep: async () => {} });

  await assert.rejects(adapter.serve({ deviceId: 'dev_abc123', localPort: 43123 }), (error) => (
    error.code === 'TAILSCALE_SERVE_POSTVALIDATION_FAILED'
    && !error.message.includes('secret')
    && error.details === undefined
  ));
  assert.equal(process.calls.filter(({ args }) => args.at(-1) === 'off').length, 1);
});

test('rejects the obsolete serve-owned and empty-funnel postsetup model', async () => {
  const process = postvalidationProcess({ postFunnel: emptyRouteStatus() });
  const adapter = new TailscaleAdapter({ executable: '/mock/tailscale', runProcess: process.runProcess, sleep: async () => {} });

  await assert.rejects(adapter.serve({ deviceId: 'dev_abc123', localPort: 43123 }), errorHasCode('TAILSCALE_SERVE_POSTVALIDATION_FAILED'));
  assert.equal(process.calls.filter(({ args }) => args.at(-1) === 'off').length, 1);
});

test('treats a missing post-setup route as failed setup after proving the path is absent', async () => {
  const process = postvalidationProcess({
    postServe: emptyRouteStatus(),
    postFunnel: emptyRouteStatus(),
    offResult: { exitCode: 1, stdout: 'handler missing secret', stderr: 'secret-stderr' },
  });
  const adapter = new TailscaleAdapter({ executable: '/mock/tailscale', runProcess: process.runProcess, sleep: async () => {} });

  await assert.rejects(adapter.serve({ deviceId: 'dev_abc123', localPort: 43123 }), (error) => (
    error.code === 'TAILSCALE_SERVE_POSTVALIDATION_FAILED'
    && !error.message.includes('secret')
  ));
  assert.equal(process.calls.filter(({ args }) => args.at(-1) === 'off').length, 1);
});

test('redacts a post-setup status failure and verifies exact-path cleanup', async () => {
  const process = postvalidationProcess({
    postServe: { exitCode: 1, stdout: 'secret-stdout', stderr: 'secret-stderr' },
  });
  const adapter = new TailscaleAdapter({ executable: '/mock/tailscale', runProcess: process.runProcess, sleep: async () => {} });

  await assert.rejects(adapter.serve({ deviceId: 'dev_abc123', localPort: 43123 }), (error) => (
    error.code === 'TAILSCALE_SERVE_POSTVALIDATION_FAILED'
    && !error.message.includes('secret')
    && error.details === undefined
  ));
  assert.equal(process.calls.filter(({ args }) => args.at(-1) === 'off').length, 1);
});

test('reports reconciliation failure when postvalidation cleanup leaves the owned path', async () => {
  const process = postvalidationProcess({
    postServe: emptyRouteStatus(),
    postFunnel: emptyRouteStatus(),
    cleanupServe: ownedRouteStatus(),
    cleanupFunnel: ownedRouteStatus(),
    offResult: new Error('ambiguous cleanup secret'),
  });
  const adapter = new TailscaleAdapter({ executable: '/mock/tailscale', runProcess: process.runProcess, sleep: async () => {} });

  await assert.rejects(adapter.serve({ deviceId: 'dev_abc123', localPort: 43123 }), (error) => (
    error.code === 'TAILSCALE_SERVE_RECONCILIATION_FAILED'
    && !error.message.includes('secret')
    && error.details === undefined
  ));
  assert.equal(process.calls.filter(({ args }) => args.at(-1) === 'off').length, 1);
});

test('reconciles an ambiguous setup rejection after the injected delay without returning a route', async () => {
  const calls = [];
  const delays = [];
  const adapter = new TailscaleAdapter({
    executable: '/mock/tailscale',
    sleep: async (milliseconds) => { delays.push(milliseconds); },
    runProcess: async (command, args) => {
      calls.push({ command, args });
      if (args[0] === 'status') return runningStatus();
      if (isRouteStatus(args)) return emptyRouteStatus();
      if (args.at(-1) === 'off') return { exitCode: 0, stdout: '', stderr: '' };
      throw new Error('setup may have applied secret');
    },
  });
  await assert.rejects(adapter.serve({ deviceId: 'dev_abc123', localPort: 43123 }), (error) => (
    error.code === 'TAILSCALE_SERVE_FAILED' && !error.message.includes('secret')
  ));
  assert.deepEqual(delays, [1250]);
  assert.equal(calls.filter(({ args }) => args.at(-1) === 'off').length, 1);
  assert.deepEqual(calls.slice(-2).map(({ args }) => args), [
    ['serve', 'status', '--json'],
    ['funnel', 'status', '--json'],
  ]);
});

test('reports a fixed reconciliation failure when ambiguous setup cleanup fails', async () => {
  const calls = [];
  let cleanupAttempted = false;
  const adapter = new TailscaleAdapter({
    executable: '/mock/tailscale',
    sleep: async () => {},
    runProcess: async (command, args) => {
      calls.push({ command, args });
      if (args[0] === 'status') return runningStatus();
      if (isRouteStatus(args)) return cleanupAttempted ? ownedRouteStatus() : emptyRouteStatus();
      if (args.at(-1) === 'off') {
        cleanupAttempted = true;
        return { exitCode: 1, stdout: 'secret-stdout', stderr: 'secret-stderr' };
      }
      throw new Error('setup may have applied secret');
    },
  });
  await assert.rejects(adapter.serve({ deviceId: 'dev_abc123', localPort: 43123 }), (error) => (
    error.code === 'TAILSCALE_SERVE_RECONCILIATION_FAILED' && !error.message.includes('secret')
  ));
  assert.equal(calls.filter(({ args }) => args.at(-1) === 'off').length, 1);
});

test('maps only a bounded canonical Tailscale consent URL and redacts other Serve output', async () => {
  const consentUrl = 'https://login.tailscale.com/admin/enable-https?next=ok';
  const adapter = new TailscaleAdapter({
    executable: '/mock/tailscale',
    runProcess: async (_command, args) => {
      if (args[0] === 'status') return runningStatus();
      if (isRouteStatus(args)) return emptyRouteStatus();
      return { exitCode: 1, stdout: `secret ${consentUrl}`, stderr: '' };
    },
  });
  await assert.rejects(adapter.serve({ deviceId: 'dev_abc123', localPort: 43123 }), (error) => (
    error.code === 'TAILSCALE_SERVE_AUTH_REQUIRED'
    && error.details === consentUrl
    && !error.message.includes('secret')
  ));

  for (const output of [
    'https://login.tailscale.com.evil.test/admin',
    'https://login.tailscale.com@evil.test/admin',
    'http://login.tailscale.com/admin',
    `https://login.tailscale.com/${'a'.repeat(4097)}`,
  ]) {
    const rejected = new TailscaleAdapter({
      executable: '/mock/tailscale',
      runProcess: async (_command, args) => (
        args[0] === 'status'
          ? runningStatus()
          : isRouteStatus(args)
            ? emptyRouteStatus()
            : { exitCode: 1, stdout: output, stderr: 'secret-stderr' }
      ),
    });
    await assert.rejects(rejected.serve({ deviceId: 'dev_abc123', localPort: 43123 }), (error) => (
      error.code === 'TAILSCALE_SERVE_FAILED'
      && error.details === undefined
      && !error.message.includes('secret')
    ));
  }

  const crossingConsentUrl = `https://login.tailscale.com/admin/${'a'.repeat(128)}`;
  const crossingOutput = `${'x'.repeat((16 * 1024) - 40)}${crossingConsentUrl}`;
  const truncated = new TailscaleAdapter({
    executable: '/mock/tailscale',
    runProcess: async (_command, args) => (
      args[0] === 'status'
        ? runningStatus()
        : isRouteStatus(args)
          ? emptyRouteStatus()
          : { exitCode: 1, stdout: crossingOutput, stderr: '' }
    ),
  });
  await assert.rejects(truncated.serve({ deviceId: 'dev_abc123', localPort: 43123 }), errorHasCode('TAILSCALE_SERVE_FAILED'));

  for (const punctuation of ['.', ',', ';', ':', '!', '?', ')', ']', '}']) {
    const punctuated = new TailscaleAdapter({
      executable: '/mock/tailscale',
      runProcess: async (_command, args) => (
        args[0] === 'status'
          ? runningStatus()
          : isRouteStatus(args)
            ? emptyRouteStatus()
            : { exitCode: 1, stdout: `https://login.tailscale.com/admin/enable-https${punctuation}`, stderr: '' }
      ),
    });
    await assert.rejects(punctuated.serve({ deviceId: 'dev_abc123', localPort: 43123 }), errorHasCode('TAILSCALE_SERVE_FAILED'));
  }
});

test('captures a streamed first-use consent URL before Tailscale Serve times out', async () => {
  const calls = [];
  const consentUrl = 'https://login.tailscale.com/f/serve?node=abc123';
  const adapter = new TailscaleAdapter({
    executable: '/mock/tailscale',
    sleep: async () => {},
    runProcess: async (command, args, options) => {
      calls.push({ command, args });
      if (args[0] === 'status') return runningStatus();
      if (isRouteStatus(args)) return emptyRouteStatus();
      if (args.at(-1) === 'off') return { exitCode: 0, stdout: '', stderr: '' };
      options.onOutput('stdout', Buffer.from('Serve is not enabled\nhttps://login.tail'));
      options.onOutput('stdout', Buffer.from('scale.com/f/serve?node=abc123\n'));
      const error = new Error('process timed out');
      error.code = 'PROCESS_TIMEOUT';
      throw error;
    },
  });

  await assert.rejects(adapter.serve({ deviceId: 'dev_abc123', localPort: 43123 }), (error) => (
    error.code === 'TAILSCALE_SERVE_AUTH_REQUIRED'
    && error.details === consentUrl
  ));
  assert.equal(calls.some(({ args }) => args.includes('--yes')), false);
  assert.equal(calls.filter(({ args }) => args.at(-1) === 'off').length, 1);
});

test('does not reconcile a definite nonzero setup failure or return a route', async () => {
  const calls = [];
  const adapter = new TailscaleAdapter({
    executable: '/mock/tailscale',
    runProcess: async (command, args) => {
      calls.push({ command, args });
      if (args[0] === 'status') return runningStatus();
      if (isRouteStatus(args)) return emptyRouteStatus();
      return { exitCode: 1, stdout: 'secret-stdout', stderr: 'secret-stderr' };
    },
  });
  await assert.rejects(adapter.serve({ deviceId: 'dev_abc123', localPort: 43123 }), errorHasCode('TAILSCALE_SERVE_FAILED'));
  assert.equal(calls.filter(({ args }) => args.at(-1) === 'off').length, 0);
});

test('shares one specific cleanup process across concurrent idempotent close calls', async () => {
  const calls = [];
  let resolveClose;
  let setupApplied = false;
  const adapter = new TailscaleAdapter({
    executable: '/mock/tailscale',
    runProcess: async (command, args) => {
      calls.push({ command, args });
      if (args[0] === 'status') return runningStatus();
      if (isRouteStatus(args)) return setupApplied ? ownedRouteStatus() : emptyRouteStatus();
      if (args.at(-1) === 'off') {
        setupApplied = false;
        return new Promise((resolve) => { resolveClose = resolve; });
      }
      setupApplied = true;
      return { exitCode: 0, stdout: '', stderr: '' };
    },
  });
  const route = await adapter.serve({ deviceId: 'dev_abc123', localPort: 43123 });
  const first = route.close();
  const second = route.close();
  assert.strictEqual(first, second);
  assert.equal(calls.filter(({ args }) => args.at(-1) === 'off').length, 1);
  resolveClose({ exitCode: 0, stdout: '', stderr: '' });
  await Promise.all([first, second]);
  await route.close();
  assert.equal(calls.filter(({ args }) => args.at(-1) === 'off').length, 1);
  assert.ok(calls.every(({ args }) => (
    !args.includes('reset')
    && (args[0] !== 'funnel' || (args[1] === 'status' && args[2] === '--json'))
  )));
});

test('returns a fixed cleanup error for a nonzero specific-path close', async () => {
  const calls = [];
  let setupApplied = false;
  const adapter = new TailscaleAdapter({
    executable: '/mock/tailscale',
    runProcess: async (command, args) => {
      calls.push({ command, args });
      if (args[0] === 'status') return runningStatus();
      if (isRouteStatus(args)) return setupApplied ? ownedRouteStatus() : emptyRouteStatus();
      if (args.at(-1) === 'off') return { exitCode: 1, stdout: 'secret-stdout', stderr: 'secret-stderr' };
      setupApplied = true;
      return { exitCode: 0, stdout: '', stderr: '' };
    },
  });
  const route = await adapter.serve({ deviceId: 'dev_abc123', localPort: 43123 });
  await assert.rejects(route.close(), (error) => (
    error.code === 'TAILSCALE_SERVE_CLEANUP_FAILED'
    && !error.message.includes('secret')
  ));
  assert.deepEqual(calls.filter(({ args }) => args.at(-1) === 'off').map(({ args }) => args), [
    ['serve', '--https=443', '--set-path=/agent-road/v1/dev_abc123', 'off'],
  ]);
});

test('accepts and caches a nonzero close only after both shared statuses prove exact absence', async () => {
  const process = postvalidationProcess({
    offResult: { exitCode: 1, stdout: 'handler already absent secret', stderr: 'secret-stderr' },
  });
  const adapter = new TailscaleAdapter({ executable: '/mock/tailscale', runProcess: process.runProcess, sleep: async () => {} });
  const route = await adapter.serve({ deviceId: 'dev_abc123', localPort: 43123 });

  await route.close();
  await route.close();
  assert.equal(process.calls.filter(({ args }) => args.at(-1) === 'off').length, 1);
  assert.deepEqual(process.calls.slice(-2).map(({ args }) => args), [
    ['serve', 'status', '--json'],
    ['funnel', 'status', '--json'],
  ]);
});

test('rejects and retries close when shared status cannot prove exact empty state', async () => {
  const allowFunnel = {
    exitCode: 0,
    stdout: JSON.stringify({ AllowFunnel: { 'alex-mac.example.ts.net:443': true } }),
    stderr: 'secret-funnel-output',
  };
  const extraRoute = ownedRouteStatus({ path: '/concurrent', localPort: 49999 });
  for (const [cleanupServe, cleanupFunnel] of [
    [{ exitCode: 1, stdout: 'secret-stdout', stderr: 'secret-stderr' }, emptyRouteStatus()],
    [{ exitCode: 0, stdout: '[]', stderr: 'secret-stderr' }, emptyRouteStatus()],
    [emptyRouteStatus(), ownedRouteStatus()],
    [extraRoute, extraRoute],
    [allowFunnel, allowFunnel],
  ]) {
    const process = postvalidationProcess({ cleanupServe, cleanupFunnel });
    const adapter = new TailscaleAdapter({ executable: '/mock/tailscale', runProcess: process.runProcess, sleep: async () => {} });
    const route = await adapter.serve({ deviceId: 'dev_abc123', localPort: 43123 });

    for (let attempt = 0; attempt < 2; attempt += 1) {
      await assert.rejects(route.close(), (error) => (
        error.code === 'TAILSCALE_SERVE_CLEANUP_FAILED'
        && !error.message.includes('secret')
        && error.details === undefined
      ));
    }
    assert.equal(process.calls.filter(({ args }) => args.at(-1) === 'off').length, 2);
  }
});

test('retries an exit-zero close whose shared status still retains the route', async () => {
  const calls = [];
  let closeAttempts = 0;
  let setupApplied = false;
  const adapter = new TailscaleAdapter({
    executable: '/mock/tailscale',
    runProcess: async (command, args) => {
      calls.push({ command, args });
      if (args[0] === 'status') return runningStatus();
      if (isRouteStatus(args)) return setupApplied ? ownedRouteStatus() : emptyRouteStatus();
      if (args.at(-1) === 'off') {
        closeAttempts += 1;
        if (closeAttempts > 1) setupApplied = false;
        return { exitCode: 0, stdout: '', stderr: '' };
      }
      setupApplied = true;
      return { exitCode: 0, stdout: '', stderr: '' };
    },
  });
  const route = await adapter.serve({ deviceId: 'dev_abc123', localPort: 43123 });
  await assert.rejects(route.close(), errorHasCode('TAILSCALE_SERVE_CLEANUP_FAILED'));
  await route.close();
  await route.close();
  assert.equal(calls.filter(({ args }) => args.at(-1) === 'off').length, 2);
});
