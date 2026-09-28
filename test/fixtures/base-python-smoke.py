"""Offline candidate probe; call with the candidate's absolute python.exe -I -B.

Creates only a fresh scratch directory. Does not install into the candidate or
activate it as an Agent Road runtime. The caller owns scratch retention/cleanup.
"""
import base64
import csv
import hashlib
import io
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import zipfile


def run_python(executable, *args):
    env = {key: value for key, value in os.environ.items()
           if not key.upper().startswith(('PYTHON', 'PIP_'))}
    env['PIP_CONFIG_FILE'] = os.devnull
    result = subprocess.run(
        [str(executable), '-I', '-B', *args], env=env, capture_output=True,
        text=True, timeout=90, check=True,
    )
    return result.stdout.strip()


def main():
    if len(sys.argv) != 2 or os.name != 'nt':
        raise ValueError('CANDIDATE_INPUT_INVALID')
    if sys.version_info[:3] != (3, 14, 7) or struct.calcsize('P') != 8:
        raise ValueError('CANDIDATE_VERSION_INVALID')
    scratch = Path(sys.argv[1])
    if not scratch.is_absolute():
        raise ValueError('CANDIDATE_INPUT_INVALID')
    scratch.mkdir()  # Never reuse or erase an earlier probe directory.
    environment = scratch / 'venv'
    run_python(sys.executable, '-m', 'venv', str(environment))
    python = environment / 'Scripts' / 'python.exe'
    observed = json.loads(run_python(python, '-c',
        'import json,sys; print(json.dumps([sys.prefix,sys.base_prefix]))'))
    if Path(observed[0]).resolve() != environment.resolve() or observed[0] == observed[1]:
        raise ValueError('CANDIDATE_VENV_INVALID')

    # Locally built pure-Python wheel; no index, network or third-party package.
    package = 'agent_road_probe-1.0.0.dist-info'
    members = {
        'agent_road_probe.py': b'VALUE = "agent-road-offline-ok"\n',
        f'{package}/METADATA': b'Metadata-Version: 2.1\nName: agent-road-probe\nVersion: 1.0.0\n',
        f'{package}/WHEEL': b'Wheel-Version: 1.0\nGenerator: agent-road-probe\nRoot-Is-Purelib: true\nTag: py3-none-any\n',
    }
    record = io.StringIO(newline='')
    writer = csv.writer(record, lineterminator='\n')
    for name, content in members.items():
        digest = base64.urlsafe_b64encode(hashlib.sha256(content).digest()).rstrip(b'=').decode()
        writer.writerow([name, 'sha256=' + digest, len(content)])
    writer.writerow([f'{package}/RECORD', '', ''])
    members[f'{package}/RECORD'] = record.getvalue().encode()
    wheel = scratch / 'agent_road_probe-1.0.0-py3-none-any.whl'
    with zipfile.ZipFile(wheel, 'x') as archive:
        for name, content in members.items():
            archive.writestr(name, content)
    run_python(python, '-m', 'pip', '--isolated', '--disable-pip-version-check',
               '--no-cache-dir', 'install', '--no-index', '--no-deps', '--no-compile', str(wheel))
    value = run_python(python, '-c', 'import agent_road_probe; print(agent_road_probe.VALUE)')
    if value != 'agent-road-offline-ok':
        raise ValueError('CANDIDATE_PACKAGE_INVALID')
    # Confirm the package did not leak into the unmodified base interpreter.
    absent = run_python(sys.executable, '-c',
        'import importlib.util; print(importlib.util.find_spec("agent_road_probe") is None)')
    if absent != 'True':
        raise ValueError('CANDIDATE_PACKAGE_LEAK')
    print(json.dumps({'schemaVersion': 1, 'python': '3.14.7', 'architecture': 'x64',
                      'venv': True, 'offlineWheelInstall': True, 'isolatedImport': True,
                      'basePackageAbsent': True}))


if __name__ == '__main__':
    main()
