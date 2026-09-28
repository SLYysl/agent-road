import base64
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

MODULE = Path(__file__).resolve().parents[1] / 'tools/acceptance/closed_loop.py'
spec = importlib.util.spec_from_file_location('closed_loop', MODULE)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
JOB = 'job_' + 'a' * 32


class FakeRemote:
    def __init__(self, pending=False, crash=None, fail=None):
        self.calls = []
        self.pending = pending
        self.crash = crash
        self.fail = fail

    def __call__(self, argv, out, err, env):
        a = argv[2:]
        action = '/'.join(a[:2]) if a[0] == 'job' else a[0]
        self.calls.append(action)
        if action == 'doctor':
            data = [{'runtime': {'generationVerified': True, 'pendingOperationId': None, 'restartRequired': False}}]
        elif action == 'exec':
            data = [{'exitCode': 0, 'stdout': 'DIRECTORY_CREATED\r\n'}]
        elif action in ('put', 'get'):
            data = [{'sha256': m.digest(m.PAYLOAD).upper()}]
            if action == 'get':
                Path(a[-1]).write_bytes(m.PAYLOAD)
        elif action == 'job/start':
            data = [{'jobId': JOB, 'capture': 'fixture-only'}, {'jobId': JOB, 'status': 'SUBMITTED'}]
        elif action == 'job/logs':
            self.assert_logs_option = a[-1] == '--include-output'
            data = [{'jobId': JOB}, {'jobId': JOB, 'state': {'status': 'RUNNING' if self.pending else 'SUCCEEDED', 'exitCode': 0}}]
            for name, raw in [('stdout', (m.MARKER + '\r\n').encode()), ('stderr', b'')]:
                data[-1][name] = {'offset': 0, 'bytes': len(raw), 'base64': base64.b64encode(raw).decode()}
        else:
            raise AssertionError(action)
        out.write_text('\n'.join(json.dumps(x) for x in data) + '\n')
        err.write_text('DEVICE_BUSY\n' if action == self.fail else '')
        if action == self.crash:
            if action == 'job/start':
                out.write_text(json.dumps(data[0]) + '\n{"partial":')
            raise RuntimeError('simulated controller crash')
        return 2 if action == self.fail else 0


class AcceptanceTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name) / 'trial'
        self.env = patch.dict(os.environ, {'AGENT_ROAD_HOME': str(Path(self.temp.name) / 'state')})
        self.env.start()
        self.addCleanup(self.env.stop)
        m.STOP = False
        m.initialize(self.directory, 'dev_test')

    def trial(self, remote):
        return m.Trial(self.directory, remote)

    def test_full_round_and_repeat_only_observes_original_results(self):
        remote = FakeRemote()
        self.assertEqual(self.trial(remote).resume()['status'], 'PASSED')
        first = remote.calls[:]
        self.assertEqual(first, ['doctor', 'exec', 'put', 'get', 'job/start', 'job/logs'])
        self.assertEqual(self.trial(remote).resume()['status'], 'PASSED')
        self.assertEqual(remote.calls[len(first):], ['doctor', 'get', 'job/logs'])
        self.assertTrue(remote.assert_logs_option)

    def test_pending_job_stops_without_polling_and_resume_uses_same_id(self):
        remote = FakeRemote(pending=True)
        self.assertEqual(self.trial(remote).resume()['status'], 'WAITING')
        self.assertEqual(remote.calls.count('job/logs'), 1)
        remote.pending = False
        self.assertEqual(self.trial(remote).resume()['status'], 'PASSED')
        self.assertEqual(remote.calls.count('job/start'), 1)

    def test_crash_after_job_id_reconciles_without_resubmission(self):
        remote = FakeRemote(crash='job/start')
        with self.assertRaises(RuntimeError):
            self.trial(remote).resume()
        remote.crash = None
        self.assertEqual(self.trial(remote).resume()['status'], 'PASSED')
        self.assertEqual(remote.calls.count('job/start'), 1)

    def test_unknown_mutation_never_replays(self):
        remote = FakeRemote(crash='put')
        with self.assertRaises(RuntimeError):
            self.trial(remote).resume()
        remote.crash = None
        with self.assertRaisesRegex(m.Stopped, 'STOP_UNKNOWN'):
            self.trial(remote).resume()
        self.assertEqual(remote.calls.count('put'), 1)
        self.assertNotIn('job/start', remote.calls)

    def test_missing_job_id_stops(self):
        remote = FakeRemote(crash='job/start')
        with self.assertRaises(RuntimeError):
            self.trial(remote).resume()
        (self.directory / 'job-start/stdout.jsonl').write_text('')
        with self.assertRaisesRegex(m.Stopped, 'STOP_UNKNOWN'):
            self.trial(remote).resume()
        self.assertEqual(remote.calls.count('job/start'), 1)

    def test_device_busy_does_not_poll_or_submit(self):
        remote = FakeRemote(fail='doctor')
        with self.assertRaisesRegex(m.Stopped, 'CLI_FAILED'):
            self.trial(remote).resume()
        self.assertEqual(remote.calls, ['doctor'])

    def test_context_change_and_cooperative_stop_do_not_dispatch(self):
        remote = FakeRemote()
        with patch.dict(os.environ, {'AGENT_ROAD_HOME': '/different'}):
            with self.assertRaisesRegex(m.Stopped, 'CONTROLLER_HOME_CHANGED'):
                self.trial(remote)
        m.STOP = True
        with self.assertRaisesRegex(m.Stopped, 'STOPPED_BETWEEN_CALLS'):
            self.trial(remote).resume()
        self.assertEqual(remote.calls, [])

    def test_false_success_wrong_job_truncated_and_corrupt_logs_rejected(self):
        good = [{'jobId': JOB}, {'jobId': JOB, 'state': {'status': 'SUCCEEDED', 'exitCode': 0},
            'stdout': {'offset': 0, 'bytes': len((m.MARKER+'\r\n').encode()), 'base64': base64.b64encode((m.MARKER+'\r\n').encode()).decode()},
            'stderr': {'offset': 0, 'bytes': 0, 'base64': ''}}]
        for kind in ['failed', 'wrong-id', 'tail', 'invalid', 'empty']:
            data = json.loads(json.dumps(good))
            if kind == 'failed': data[-1]['state']['status'] = 'FAILED'
            if kind == 'wrong-id': data[-1]['jobId'] = 'job_'+'b'*32
            if kind == 'tail': data[-1]['stdout']['offset'] = 10
            if kind == 'invalid': data[-1]['stdout']['base64'] = '!'
            if kind == 'empty': data[-1]['stdout']['base64'] = ''
            with self.subTest(kind=kind), self.assertRaises(m.Stopped):
                m.verify_logs(data, self.directory, JOB)

    def test_init_status_are_local_and_refuse_existing_directory(self):
        env = dict(os.environ, PATH='/nonexistent')
        result = subprocess.run([os.sys.executable, str(MODULE), 'status', str(self.directory)], env=env, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)['reports'], [])
        result = subprocess.run([os.sys.executable, str(MODULE), 'init', str(self.directory), '--device', 'dev_test'], env=env, capture_output=True)
        self.assertEqual(result.returncode, 2)

    def test_changed_script_and_changed_target_do_not_dispatch(self):
        remote = FakeRemote()
        self.trial(remote).resume()
        count = len(remote.calls)
        config_path = self.directory / 'trial.json'
        original = config_path.read_text()
        config = json.loads(original)
        config['device'] = 'dev_other'
        config_path.write_text(json.dumps(config))
        with self.assertRaisesRegex(m.Stopped, 'TRIAL_CONTEXT_CHANGED'):
            self.trial(remote)
        config_path.write_text(original)
        (self.directory / 'job.ps1').write_text('modified')
        with self.assertRaisesRegex(m.Stopped, 'TRIAL_INPUT_CHANGED'):
            self.trial(remote)
        self.assertEqual(len(remote.calls), count)

    def test_exclusive_observer_lock_blocks_second_runner(self):
        import fcntl
        with (self.directory / 'observer.lock').open('a') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            result = subprocess.run([os.sys.executable, str(MODULE), 'resume', str(self.directory)], capture_output=True)
            self.assertEqual(result.returncode, 2)
            self.assertIn(b'OBSERVER_BUSY', result.stderr)
        self.assertFalse((self.directory / 'mkdir').exists())

    def test_exclusive_receipts_preserve_previous_evidence(self):
        path = self.directory / 'example.json'
        m.persist(path, {'a': 1})
        with self.assertRaises(FileExistsError):
            m.persist(path, {'a': 2})
        self.assertEqual(json.loads(path.read_text()), {'a': 1})


if __name__ == '__main__':
    unittest.main()
