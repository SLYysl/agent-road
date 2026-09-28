# Earth, received

The source and returned outputs of Agent Road's first complete Windows development
demo, run from Mac Astra on 2026-09-19. All CSV data is synthetic. No dependencies
need downloading: the scripts use Python and Node.js standard libraries.

From this directory, with Python 3 and Node.js 22 or newer:

```sh
python analyze.py test
python analyze.py
node build.mjs
```

On Windows, use the verified absolute `python.exe`/`node.exe` paths instead of
assuming the `python` Store alias or global PATH is suitable. The actual acceptance
used Python 3.14.5 and Node.js 24.15.0. Commands regenerate `summary.json` and
`index.html`; open the latter in a browser. The Node build also starts an ephemeral
loopback HTTP server, verifies its response, and closes it before exiting.

Expected result: 12 rows, 112 sample minutes, totals Code 42 / Research 30 / Design
40, three passing Python tests, and passing Node data/HTTP checks. The committed
`python-tests.txt` and `node-tests.json` preserve the original Windows result text (UTF-8/LF normalized for Git);
rerunning commands does not rewrite those two historical receipts automatically.

The Windows demo was also committed to its own local Git repository and packaged
into a ZIP, which was transferred to the Mac and verified by hash. This directory
preserves the portable source/output files, not that separate repository's `.git`
directory. See [the acceptance record](../../docs/windows-task-demo.md).

Screenshots, device identifiers, connection credentials, browser profiles, and raw
transport receipts are deliberately not part of this example.
