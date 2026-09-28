#!/usr/bin/env python3
"""One read-only sample per invocation; a fixed 24h manifest bounds remote work."""
import datetime
import fcntl
import json
import os
from pathlib import Path
import subprocess
import sys
import time


def summarize(samples, start, deadline, now):
    ordered = sorted(samples, key=lambda x: x['started'])
    times = [start] + [x['started'] for x in ordered] + [min(now, deadline)]
    gaps = [b-a for a,b in zip(times,times[1:])]
    boots = {x.get('observation', {}).get('boot') for x in ordered if x.get('observation', {}).get('boot')}
    observations = [x.get('observation', {}) for x in ordered]
    use_events = any('bootRecord' in x or 'bootEventUtc' in x for x in observations)
    invalid_boot_events = use_events and any(type(x.get('bootRecord')) is not int or x['bootRecord'] <= 0
        or not isinstance(x.get('bootEventUtc'), str) or not x['bootEventUtc'] for x in observations)
    boot_identities = {(x['bootRecord'], x['bootEventUtc']) for x in observations} if use_events and not invalid_boot_events else boots
    pids = {x.get('observation', {}).get('sshdPid') for x in ordered if x.get('observation', {}).get('sshdPid')}
    failures = sum(x.get('status') != 'OK' for x in ordered)
    ended = now >= deadline
    covered = bool(ordered) and max(gaps, default=0) <= 1200
    return {'windowEnded': ended, 'status': ('PASSED' if covered and not failures and len(boot_identities) <= 1 and not invalid_boot_events and len(pids) <= 1 else 'NOT_ACCEPTED') if ended else 'OBSERVING',
            'samples': len(ordered), 'distinctBoots': len(boots), 'distinctBootIdentities': len(boot_identities),
            'bootIdentitySource': 'event' if use_events else 'legacy-timestamp', 'invalidBootEvents': bool(invalid_boot_events), 'distinctSshdPids': len(pids), 'failedOrIncomplete': failures,
            'maxGapSeconds': round(max(gaps, default=0), 1), 'coverageWithin20Minutes': covered,
            'observedWindowSeconds': max(0, round(min(now, deadline)-start, 1)),
            'startUtc': datetime.datetime.fromtimestamp(start, datetime.timezone.utc).isoformat(),
            'deadlineUtc': datetime.datetime.fromtimestamp(deadline, datetime.timezone.utc).isoformat()}


def main(directory):
    os.umask(0o077)
    directory = Path(directory)
    config = json.loads((directory/'watch.json').read_text())
    with (directory/'observer.lock').open('a') as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return
        now = time.time()
        records = list(directory.glob('sample-*.json'))
        previous = [json.loads(p.read_text()) for p in records]
        if not (directory/'PAUSE').exists() and now < config['deadline'] and (not previous or now-max(s['started'] for s in previous) >= 840):
            record = directory / ('sample-'+str(time.time_ns())+'.json')
            result = {'started': now, 'status': 'INCOMPLETE'}
            record.write_text(json.dumps(result))
            env = dict(os.environ, AGENT_ROAD_HOME=config['home'])
            args = [config['node'], config['cli'], 'exec', config['device'], '--script', str(directory/'probe.ps1'), '--timeout-seconds', '30']
            # CLI owns its timeout/cleanup; do not kill it mid-operation and strand a lock.
            with record.with_suffix('.stdout').open('x') as out, record.with_suffix('.stderr').open('x') as err:
                code = subprocess.run(args, env=env, stdout=out, stderr=err).returncode
            result.update(exitCode=code, elapsedSeconds=round(time.time()-now, 3))
            try:
                response = json.loads(record.with_suffix('.stdout').read_text())
                value = json.loads(response['stdout'])
                valid = code == 0 and response['exitCode'] == 0 and value['host'] == config['expectedHost'] and value['sshd'] == 'Running' and value['tailscale'] == 'Running' and value['listener'] is True
                result.update(status='OK' if valid else 'FAILED', observation=value)
            except (KeyError, TypeError, ValueError):
                result['status'] = 'FAILED'
            if result['status'] == 'FAILED' and record.with_suffix('.stderr').read_text().strip() == 'REMOTE_CONNECTION_FAILED' and config.get('fallback'):
                fallback=config['fallback']
                with record.with_suffix('.diagnostic.stdout').open('x') as out, record.with_suffix('.diagnostic.stderr').open('x') as err:
                    result['fallbackExitCode']=subprocess.run([config['node'],config['cli'],'exec',fallback['device'],'--script',fallback['script'],'--timeout-seconds','60'],env=dict(os.environ,AGENT_ROAD_HOME=fallback['home']),stdout=out,stderr=err).returncode
            tmp=record.with_suffix('.tmp');tmp.write_text(json.dumps(result));tmp.replace(record)
            previous.append(result)
        summary=summarize(previous, config['start'], config['deadline'], time.time())
        summary['paused']=(directory/'PAUSE').exists()
        tmp=directory/'summary.tmp';tmp.write_text(json.dumps(summary,indent=2));tmp.replace(directory/'summary.json')
        print(json.dumps(summary))


if __name__ == '__main__':
    main(sys.argv[1])
