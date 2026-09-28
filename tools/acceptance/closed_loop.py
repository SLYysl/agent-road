#!/usr/bin/env python3
"""Mac controller acceptance, private receipts, no reboot or automatic mutation replay."""
import argparse
import base64
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import uuid

ROOT = Path(__file__).resolve().parents[2]
PAYLOAD = 'Agent Road 闭环 ✅🚀\n'.encode()
MARKER = 'Agent Road job 闭环 ✅'
STOP = False


class Stopped(RuntimeError):
    pass


def persist(path, value):
    """Exclusive, fsynced records; never overwrite a receipt."""
    with path.open('x', encoding='utf-8') as f:
        json.dump(value, f, ensure_ascii=False)
        f.flush()
        os.fsync(f.fileno())
    fd = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def rows(path):
    # Incomplete trailing output after a crash must not hide the saved first job ID.
    result = []
    for line in path.read_text().splitlines() if path.exists() else []:
        try:
            value = json.loads(line)
            if isinstance(value, dict):
                result.append(value)
        except json.JSONDecodeError:
            continue
    return result


def launch(argv, out, err, env):
    with out.open('xb') as stdout, err.open('xb') as stderr:
        child = subprocess.Popen(argv, stdout=stdout, stderr=stderr, env=env, start_new_session=True)
        code = child.wait()
        for stream in (stdout, stderr):
            stream.flush()
            os.fsync(stream.fileno())
    return code


class Trial:
    def __init__(self, directory, runner=launch):
        self.directory = directory
        self.config = json.loads((directory / 'trial.json').read_text())
        self.context = digest(json.dumps(self.config, sort_keys=True).encode())
        for record in directory.glob('*/started.json'):
            if json.loads(record.read_text()).get('context') != self.context:
                raise Stopped('TRIAL_CONTEXT_CHANGED')
        for name, expected in self.config['inputHashes'].items():
            if digest((directory / name).read_bytes()) != expected:
                raise Stopped('TRIAL_INPUT_CHANGED')
        if self.config['root'] != str(ROOT):
            raise Stopped('CONTROLLER_PATH_CHANGED')
        home = str(Path((os.environ.get('AGENT_ROAD_HOME') or '~/.agent-road')).expanduser().resolve())
        if home != self.config['home']:
            raise Stopped('CONTROLLER_HOME_CHANGED')
        self.env = dict(os.environ, AGENT_ROAD_HOME=home)
        self.runner = runner
        self.device = self.config['device']

    def call(self, name, args, verify, mutation=False, job=False):
        if STOP:
            raise Stopped('STOPPED_BETWEEN_CALLS')
        step = self.directory / name
        if mutation and step.exists():
            if (step / 'done.json').exists():
                return json.loads((step / 'done.json').read_text())
            if job:
                saved = rows(step / 'stdout.jsonl')
                if saved and re.fullmatch(r'job_[a-f0-9]{32}', saved[0].get('jobId', '')):
                    # Never start again, even if submission had a nonzero controller exit.
                    return {'jobId': saved[0]['jobId'], 'submission': 'UNKNOWN'}
            raise Stopped('STOP_UNKNOWN: ' + name + '; inspect original receipts, do not replay')
        if not mutation:
            step = self.directory / (name + '-' + uuid.uuid4().hex)
        step.mkdir(mode=0o700)
        argv = ['node', str(ROOT / 'src/cli.mjs')]
        argv += args(step) if callable(args) else args
        persist(step / 'started.json', {'argv': argv, 'mutation': mutation, 'context': self.context})
        code = self.runner(argv, step / 'stdout.jsonl', step / 'stderr.txt', self.env)
        persist(step / 'exit.json', {'code': code})
        if code:
            raise Stopped('CLI_FAILED: ' + name + '; inspect ' + str(step))
        value = verify(rows(step / 'stdout.jsonl'), step)
        persist(step / 'done.json', value)
        return value

    def resume(self):
        doctor = self.call('doctor', ['doctor', self.device], verify_doctor)
        remote = self.config['remote']
        self.call('mkdir', ['exec', self.device, '--script', str(self.directory / 'mkdir.ps1'),
                           '--timeout-seconds', '60'], verify_exec, mutation=True)
        self.call('put', ['put', self.device, str(self.directory / 'input.txt'), remote + '\\roundtrip.txt'],
                  verify_hash, mutation=True)
        self.call('get', lambda step: ['get', self.device, remote + '\\roundtrip.txt', str(step / 'download.txt')],
                  verify_download)
        job = self.call('job-start', ['job', 'start', self.device, str(self.directory / 'job.ps1'), '120'],
                        verify_start, mutation=True, job=True)
        result = self.call('job-logs', ['job', 'logs', self.device, job['jobId'], '--include-output'],
                           lambda data, step: verify_logs(data, step, job['jobId']))
        report = {'status': result['status'], 'jobId': job['jobId'], 'device': self.device,
                  'generationVerified': doctor['generationVerified'], 'pendingReboot': doctor['pendingReboot'],
                  'rebootTested': False,
                  'freshOnboardingTested': False, 'fileSha256': digest(PAYLOAD)}
        persist(self.directory / ('report-' + uuid.uuid4().hex + '.json'), report)
        return report


def digest(data):
    return hashlib.sha256(data).hexdigest()


def require(condition, message):
    if not condition:
        raise Stopped(message)


def verify_exec(data, step):
    require(len(data) == 1 and data[0].get('exitCode') == 0, 'REMOTE_COMMAND_FAILED')
    return data[0]


def verify_doctor(data, step):
    require(len(data) == 1, 'DOCTOR_RESPONSE_INVALID')
    runtime = data[0].get('runtime', {})
    require(runtime.get('generationVerified') is True and 'pendingOperationId' in runtime
            and runtime['pendingOperationId'] is None and runtime.get('restartRequired') is False,
            'CORE_NOT_READY; no install or reboot attempted')
    return {'generationVerified': True, 'pendingReboot': data[0].get('pendingReboot')}


def verify_hash(data, step):
    require(len(data) == 1 and data[0].get('sha256', '').lower() == digest(PAYLOAD), 'FILE_HASH_MISMATCH')
    return {'sha256': digest(PAYLOAD)}


def verify_download(data, step):
    value = verify_hash(data, step)
    require((step / 'download.txt').read_bytes() == PAYLOAD, 'FILE_BYTES_MISMATCH')
    return value


def verify_start(data, step):
    require(len(data) == 2 and re.fullmatch(r'job_[a-f0-9]{32}', data[0].get('jobId', ''))
            and data[1].get('jobId') == data[0]['jobId'] and data[1].get('status') == 'SUBMITTED',
            'JOB_START_UNCERTAIN')
    return {'jobId': data[0]['jobId']}


def verify_logs(data, step, job_id):
    require(len(data) == 2 and all(x.get('jobId') == job_id for x in data), 'JOB_RESPONSE_INVALID')
    result = data[-1]
    state = result.get('state', {})
    if state.get('status') in ('SUBMITTED', 'RUNNING'):
        return {'status': 'WAITING'}
    require(state.get('status') == 'SUCCEEDED' and state.get('exitCode') == 0, 'JOB_NOT_SUCCESSFUL')
    for name, expected in [('stdout', (MARKER + '\r\n').encode()), ('stderr', b'')]:
        value = result.get(name, {})
        try:
            raw = base64.b64decode(value['base64'], validate=True)
        except (KeyError, ValueError, TypeError):
            raise Stopped('JOB_LOG_INVALID') from None
        require(value.get('offset') == 0 and value.get('bytes') == len(raw) and raw == expected,
                'JOB_LOG_MISMATCH')
    return {'status': 'PASSED'}


def initialize(directory, device):
    require(re.fullmatch(r'dev_[a-z0-9]{1,60}', device), 'DEVICE_INPUT_INVALID')
    directory.mkdir(mode=0o700, parents=False, exist_ok=False)
    remote = 'C:\\AgentRoad-Work\\Acceptance-' + uuid.uuid4().hex
    # Fixed generated scripts only; no arbitrary task or remote path input.
    (directory / 'input.txt').write_bytes(PAYLOAD)
    (directory / 'mkdir.ps1').write_text("$ErrorActionPreference='Stop'; $p='" + remote + "'; "
        "if(Test-Path -LiteralPath $p){throw 'FRESH_DIRECTORY_REQUIRED'}; "
        "New-Item -ItemType Directory -Path $p | Out-Null; 'DIRECTORY_CREATED'\n")
    (directory / 'job.ps1').write_text("$ErrorActionPreference='Stop'; "
        "[Console]::OutputEncoding=New-Object Text.UTF8Encoding($false); "
        "Start-Sleep -Seconds 15; Write-Output '" + MARKER + "'\n", encoding='utf-8-sig')
    persist(directory / 'trial.json', {'schemaVersion': 1, 'device': device, 'remote': remote,
        'inputHashes': {name: digest((directory / name).read_bytes()) for name in ('input.txt', 'mkdir.ps1', 'job.ps1')},
        'root': str(ROOT), 'home': str(Path((os.environ.get('AGENT_ROAD_HOME') or '~/.agent-road')).expanduser().resolve())})


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['init', 'status', 'resume'])
    parser.add_argument('directory', type=Path)
    parser.add_argument('--device')
    args = parser.parse_args()
    directory = args.directory.expanduser().absolute()
    try:
        if args.action == 'init':
            require(args.device is not None, 'DEVICE_REQUIRED')
            initialize(directory, args.device)
            print(json.dumps({'status': 'INITIALIZED', 'remoteCalls': 0}))
            return 0
        require(args.device is None, 'DEVICE_ONLY_ON_INIT')
        if args.action == 'status':
            print(json.dumps({'trial': json.loads((directory / 'trial.json').read_text()),
                'reports': [json.loads(p.read_text()) for p in sorted(directory.glob('report-*.json'))],
                'steps': [{'name': p.name, 'done': (p / 'done.json').exists()}
                          for p in sorted(directory.iterdir()) if p.is_dir()]}, ensure_ascii=False))
            return 0
        with (directory / 'observer.lock').open('a') as lock:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise Stopped('OBSERVER_BUSY') from None
            print(json.dumps(Trial(directory).resume(), ensure_ascii=False))
        return 0
    except (Stopped, OSError, ValueError) as error:
        print(str(error), file=sys.stderr)
        return 2


def request_stop(signum, frame):
    global STOP
    STOP = True


if __name__ == '__main__':
    signal.signal(signal.SIGINT, request_stop)
    signal.signal(signal.SIGTERM, request_stop)
    sys.exit(main())
