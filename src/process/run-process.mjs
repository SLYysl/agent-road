import { spawn } from 'node:child_process';
import { isProxy } from 'node:util/types';

const TERMINATION_GRACE_MS = 1_000;
const MAX_STDIN_BYTES = 64 * 1024;
const OPTION_FIELDS = new Set([
  'spawnProcess',
  'timeoutMs',
  'maxOutputBytes',
  'env',
  'onOutput',
  'stdinText',
]);

function ignoreLateError() {}

function validationError(message) {
  return new TypeError(message);
}

function validateCommand(command) {
  if (typeof command !== 'string' || command.length === 0 || command.includes('\0')) {
    throw validationError('command must be a nonempty string without NUL bytes');
  }
}

function snapshotArgs(args) {
  if (!Array.isArray(args)) {
    throw validationError('args must be an array of strings');
  }
  const snapshot = [];
  for (let index = 0; index < args.length; index += 1) {
    const descriptor = Object.getOwnPropertyDescriptor(args, String(index));
    if (!descriptor || !Object.hasOwn(descriptor, 'value') || typeof descriptor.value !== 'string' || descriptor.value.includes('\0')) {
      throw validationError('args must be an array of strings without NUL bytes');
    }
    snapshot.push(descriptor.value);
  }
  return snapshot;
}

function validatePositiveSafeInteger(value, name) {
  if (!Number.isSafeInteger(value) || value <= 0) {
    throw validationError(`${name} must be a positive safe integer`);
  }
}

function snapshotEnv(env) {
  if (env === null || typeof env !== 'object') {
    throw validationError('env must be a plain object mapping strings to strings');
  }
  const prototype = Object.getPrototypeOf(env);
  if (env !== process.env && prototype !== Object.prototype && prototype !== null) {
    throw validationError('env must be a plain object mapping strings to strings');
  }
  if (Object.getOwnPropertySymbols(env).length > 0) {
    throw validationError('env must be a plain object mapping strings to strings');
  }

  const snapshot = {};
  for (const key of Object.getOwnPropertyNames(env)) {
    const descriptor = Object.getOwnPropertyDescriptor(env, key);
    if (!descriptor || !Object.hasOwn(descriptor, 'value') || key.includes('\0') || typeof descriptor.value !== 'string' || descriptor.value.includes('\0')) {
      throw validationError('env must be a plain object mapping strings to strings');
    }
    Object.defineProperty(snapshot, key, {
      configurable: true,
      enumerable: true,
      value: descriptor.value,
      writable: true,
    });
  }
  return snapshot;
}

function cloneEnv(env) {
  const clone = {};
  for (const key of Object.getOwnPropertyNames(env)) {
    Object.defineProperty(clone, key, {
      configurable: true,
      enumerable: true,
      value: env[key],
      writable: true,
    });
  }
  return clone;
}

function snapshotOptions(input) {
  const options = input === undefined ? {} : input;
  if (
    options === null
    || typeof options !== 'object'
    || Array.isArray(options)
    || isProxy(options)
    || Object.getPrototypeOf(options) !== Object.prototype
    || Object.getOwnPropertySymbols(options).length !== 0
  ) throw validationError('options must be a plain object');
  const snapshot = {};
  for (const key of Object.getOwnPropertyNames(options)) {
    const descriptor = Object.getOwnPropertyDescriptor(options, key);
    if (!OPTION_FIELDS.has(key) || !descriptor || !Object.hasOwn(descriptor, 'value')) {
      throw validationError('options must contain only supported data properties');
    }
    snapshot[key] = descriptor.value;
  }
  return snapshot;
}

function snapshotStdin(value) {
  if (typeof value !== 'string' || value.length === 0 || value.length > MAX_STDIN_BYTES) {
    throw validationError('stdinText must be a nonempty bounded ASCII string');
  }
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code === 0 || code > 0x7f) {
      throw validationError('stdinText must be a nonempty bounded ASCII string');
    }
  }
  return value;
}

function processError(code, message) {
  const error = new Error(message);
  error.code = code;
  return error;
}

function spawnFailure() {
  return processError('PROCESS_SPAWN_FAILED', 'process spawn failed');
}

/**
 * Runs a program without a shell. maxOutputBytes is a single total raw-byte cap
 * shared by stdout and stderr (1 MiB by default).
 */
export async function runProcess(command, args, inputOptions) {
  validateCommand(command);
  const argsSnapshot = snapshotArgs(args);
  const options = snapshotOptions(inputOptions);
  const spawnProcess = Object.hasOwn(options, 'spawnProcess') ? options.spawnProcess : spawn;
  const timeoutMs = Object.hasOwn(options, 'timeoutMs') ? options.timeoutMs : 30_000;
  const maxOutputBytes = Object.hasOwn(options, 'maxOutputBytes')
    ? options.maxOutputBytes
    : 1024 * 1024;
  const env = Object.hasOwn(options, 'env') ? options.env : process.env;
  const onOutput = Object.hasOwn(options, 'onOutput') ? options.onOutput : undefined;
  const stdinText = Object.hasOwn(options, 'stdinText')
    ? snapshotStdin(options.stdinText)
    : undefined;
  validatePositiveSafeInteger(timeoutMs, 'timeoutMs');
  validatePositiveSafeInteger(maxOutputBytes, 'maxOutputBytes');
  if (onOutput !== undefined && typeof onOutput !== 'function') {
    throw validationError('onOutput must be a function');
  }
  const envSnapshot = snapshotEnv(env);
  if (typeof spawnProcess !== 'function') {
    throw validationError('spawnProcess must be a function');
  }

  let child;
  try {
    child = spawnProcess(command, [...argsSnapshot], {
      shell: false,
      stdio: [stdinText === undefined ? 'ignore' : 'pipe', 'pipe', 'pipe'],
      env: cloneEnv(envSnapshot),
    });
  } catch {
    throw spawnFailure();
  }

  return new Promise((resolve, reject) => {
    const stdoutChunks = [];
    const stderrChunks = [];
    let outputBytes = 0;
    let primaryError = null;
    let settled = false;
    let closed = false;
    let sigtermAttempted = false;
    let sigkillAttempted = false;
    let lateGuardsInstalled = false;
    let timer;
    let escalationTimer;

    const removeListener = (emitter, event, listener) => {
      emitter?.removeListener?.(event, listener);
    };

    const stopMainWork = () => {
      clearTimeout(timer);
      removeListener(child.stdout, 'data', onStdout);
      removeListener(child.stderr, 'data', onStderr);
    };

    function removeLateGuards() {
      clearTimeout(escalationTimer);
      removeListener(child, 'close', onLateClose);
      removeListener(child, 'error', ignoreLateError);
      removeListener(child.stdin, 'error', ignoreLateError);
      removeListener(child.stdout, 'error', ignoreLateError);
      removeListener(child.stderr, 'error', ignoreLateError);
      lateGuardsInstalled = false;
    }

    function onLateClose() {
      closed = true;
      removeLateGuards();
    }

    const cleanup = () => {
      stopMainWork();
      clearTimeout(escalationTimer);
      removeListener(child, 'close', onClose);
      removeListener(child, 'error', onError);
      removeListener(child.stdin, 'error', onStdinError);
      removeListener(child.stdout, 'error', onStreamError);
      removeListener(child.stderr, 'error', onStreamError);
      removeLateGuards();
    };

    const finish = (result) => {
      if (settled) {
        return;
      }
      settled = true;
      cleanup();
      if (primaryError) {
        reject(primaryError);
        return;
      }
      resolve(result);
    };

    const rejectPromptly = () => {
      if (settled) {
        return;
      }
      settled = true;
      stopMainWork();
      reject(primaryError);
    };

    const releaseToLateGuards = () => {
      if (closed || lateGuardsInstalled) {
        return;
      }
      stopMainWork();
      removeListener(child, 'close', onClose);
      removeListener(child, 'error', onError);
      removeListener(child.stdin, 'error', onStdinError);
      removeListener(child.stdout, 'error', onStreamError);
      removeListener(child.stderr, 'error', onStreamError);
      child.on('close', onLateClose);
      child.on('error', ignoreLateError);
      child.stdin?.on?.('error', ignoreLateError);
      child.stdout.on('error', ignoreLateError);
      child.stderr.on('error', ignoreLateError);
      lateGuardsInstalled = true;
    };

    const terminate = () => {
      if (sigtermAttempted) {
        return;
      }
      sigtermAttempted = true;
      if (!closed) {
        escalationTimer = setTimeout(() => {
          if (closed || sigkillAttempted) {
            return;
          }
          sigkillAttempted = true;
          try {
            child.kill('SIGKILL');
          } catch {
            // The primary error remains the public failure.
          }
          if (!closed) {
            releaseToLateGuards();
          }
        }, TERMINATION_GRACE_MS);
      }
      try {
        child.kill('SIGTERM');
      } catch {
        // Timeout, output-limit, or spawn errors remain the public failure.
      }
    };

    const failAndTerminate = (error) => {
      if (!primaryError) {
        primaryError = error;
      }
      terminate();
      rejectPromptly();
    };

    const capture = (stream, target, chunk) => {
      if (primaryError || settled) {
        return;
      }
      const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      outputBytes += buffer.length;
      if (outputBytes > maxOutputBytes) {
        failAndTerminate(processError('PROCESS_OUTPUT_LIMIT', 'process output limit exceeded'));
        return;
      }
      if (onOutput !== undefined) {
        try {
          onOutput(stream, Buffer.from(buffer));
        } catch {
          failAndTerminate(processError('PROCESS_OUTPUT_OBSERVER_FAILED', 'process output observer failed'));
          return;
        }
      }
      target.push(buffer);
    };

    const onStdout = (chunk) => capture('stdout', stdoutChunks, chunk);
    const onStderr = (chunk) => capture('stderr', stderrChunks, chunk);
    const onStreamError = () => {
      if (settled) {
        return;
      }
      failAndTerminate(processError('PROCESS_STREAM_FAILED', 'process stream failed'));
    };
    const onStdinError = () => {
      if (settled) {
        return;
      }
      failAndTerminate(processError('PROCESS_STDIN_FAILED', 'process stdin failed'));
    };
    const onError = () => {
      if (settled) {
        return;
      }
      if (!primaryError) {
        primaryError = spawnFailure();
      }
      rejectPromptly();
    };
    const onClose = (exitCode, signal) => {
      closed = true;
      if (settled) {
        cleanup();
        return;
      }
      finish({
        command,
        args: [...argsSnapshot],
        exitCode,
        signal,
        stdout: Buffer.concat(stdoutChunks).toString('utf8'),
        stderr: Buffer.concat(stderrChunks).toString('utf8'),
      });
    };

    child.stdout.on('data', onStdout);
    child.stderr.on('data', onStderr);
    if (stdinText !== undefined && typeof child.stdin?.on === 'function') {
      child.stdin.on('error', onStdinError);
    }
    child.stdout.on('error', onStreamError);
    child.stderr.on('error', onStreamError);
    child.on('error', onError);
    child.on('close', onClose);
    timer = setTimeout(() => {
      failAndTerminate(processError('PROCESS_TIMEOUT', 'process timed out'));
    }, timeoutMs);
    if (stdinText !== undefined) {
      try {
        if (typeof child.stdin?.end !== 'function') throw new Error('stdin unavailable');
        child.stdin.end(stdinText);
      } catch {
        failAndTerminate(processError('PROCESS_STDIN_FAILED', 'process stdin failed'));
      }
    }
  });
}
