# Base Python provider candidate

Reviewed 2026-09-19. This is a provider experiment, not production catalog approval
or `base` availability. The production catalog and `core` activation remain unchanged.

The subsequent user decision is to [reuse existing tools first](existing-base.md).
This candidate remains a fallback experiment, not a replacement for the discovered
Python 3.14.5 installation.

## Provider choice

Use the CPython team's **full Windows x64 ZIP** as the first candidate. Python's
[Windows documentation](https://docs.python.org/3/using/windows.html#offline-installs)
explicitly permits extracting the offline runtime ZIP without registering an
installation and launching its executable directly. This avoids an additional
runtime manager and fits Agent Road's existing ZIP extraction format.

Do not substitute the embeddable ZIP: its package-management contract differs.
Do not invoke the Python install manager, register aliases, or change global PATH.
NuGet and python-build-standalone remain alternatives, not additional dependencies.

## Fixed candidate and local evidence

- Upstream metadata: <https://www.python.org/ftp/python/index-windows.json>.
- Entry: `pythoncore-3.14-64`, exact `sort-version` **3.14.7** (not a prerelease or free-threaded build).
- Artifact: <https://www.python.org/ftp/python/3.14.7/python-3.14.7-amd64.zip>.
- Observed bytes: **36,747,122**.
- SHA-256: `AC1A727A71738E11DE80B76E975F9B8A258AEA6412BFC31696B929D59C6AAFD0`.
- ZIP expanded-byte sum: **130,297,406**; **2,730** entries.
- Download SHA-256 matches the upstream index entry; ZIP CRC validation passed.
- No absolute/traversal/backslash/colon entry names, symlinks, or case-folded duplicate names observed.
- Includes `python.exe`, `python314.dll`, `python3.dll`, `Lib/venv`,
  `Lib/ensurepip`, bundled `pip-26.2.1-py3-none-any.whl`, and `LICENSE.txt`.
- Retain upstream license notices in any installed generation. This experiment
  downloads the unmodified upstream archive; it does not publish a repackaged distribution.

The mutable index is discovery evidence, not a production trust root. A future
catalog must pin exact archive metadata and separately define signature checks;
a matching index hash alone does not establish an Authenticode publisher.

## Physical probe contract

The probe uses a unique Windows temporary directory, outside the active runtime.
The controller transfers the archive through the existing pinned SSH file-transfer
path. Before extraction, Windows checks its exact length and SHA-256.

Before executing Python, check valid Authenticode signatures with publisher
`Python Software Foundation` on `python.exe`, `python314.dll`, and `python3.dll`.
Run [the fixture](../test/fixtures/base-python-smoke.py) using that absolute
`python.exe -I -B`, with a fresh absolute scratch directory. It checks:

1. Exact Python 3.14.7 and 64-bit process architecture.
2. `venv` creation with bundled pip, and distinct environment/base prefixes.
3. Installation of a locally generated pure-Python wheel with `--no-index`,
   `--no-deps`, `--no-cache-dir`, and `--no-compile`.
4. Import of its known value from an isolated virtual-environment interpreter.
5. Absence of that test package from the base interpreter.

Child processes use absolute interpreter paths, bounded execution time, isolated
Python/pip options, and no inherited Python/pip configuration variables. Scratch
is retained for inspection; the fixture never deletes or reuses an earlier directory.
This checks an explicit offline package operation; it does not prove host network
isolation or compatibility with arbitrary compiled packages.

## Physical result (2026-09-19)

The exact fixture passed on the enrolled Windows host with the pinned archive.
All three Authenticode checks were valid with the expected PSF publisher; all five
fixture checks passed. Runtime baseline comparison returned `UNCHANGED`, and the
Mac-side READY record and enrollment registry were byte/logically unchanged as
appropriate. No runtime activation or reboot occurred. The temporary candidate,
virtual environment, and test wheel are retained outside the managed runtime.

Controller-private evidence: `~/.agent-road/inspection-captures/base-python-probe-*`.
The successful capture contains `accepted-candidate.json`, `accepted.json`, exact
probe sources, per-process results, and the private scratch path. An earlier local
harness attempt rejected an unsupported `cwd` option before launching the baseline
command; it performed no remote operation and is retained as a separate stopped capture.

## Remaining production gates
- Review all executable/native extension dependencies and their publisher rules,
  including bundled VC runtime DLLs; three checked signatures are not whole-tree acceptance.
- Verify supported Windows minimum build and exact redirect-origin policy.
- Define immutable runtime versus task-owned virtual-environment locations and
  process-local environment selection; never install task packages into a runtime generation.
- Independently pin and verify Git, Node.js LTS, and ripgrep.
- Extend manifest, receipt, inventory, extraction, verification, activation, and
  rollback together for multiple components, retaining existing `core` compatibility.
- Test upgrade failure, interruption, previous-generation retention, repeated no-op,
  and physical base acceptance before enabling `runtime-plan --profile base`.
