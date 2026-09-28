# Windows inspect rejection stages

The Windows recovery inspect wrapper now adds a finite stage to rejected results.
It retains the original checks and error allowlist. Unknown exceptions still map
to `RUNTIME_STATE_UNSUPPORTED`; no exceptions, paths, addresses, or identities are
copied into the diagnostic field. Apply generation and its rejection protocol
remain unchanged.

## Protocol and receipt behavior

Inspect rejection envelopes use canonical schema 2 fields, in order:
`schemaVersion`, `error`, `stage`. Exit 73, null signal, empty stderr, the existing
error allowlist, and an exact finite stage string are required. Missing/extra
fields, unknown versions/stages, arrays, wrong exit, and nonempty stderr fail
with the existing inventory error. Legacy schema 1 inspect rejections remain
accepted without an invented stage. Successful inspect results remain schema 1;
apply accepts only its existing schema 1 rejection envelope.

The parser stores the validated stage privately against the acknowledged error.
It does not publish a stage directly. Only the remote adapter, after the trusted
SSH operation and its post-operation trust checks finish, transfers that stage
to the active async-local recorder. Ordinary exceptions with a forged code/stage
cannot supply diagnostic provenance. Failed post-response trust validation also
prevents publication of the remote stage.

The local capture receipt remains schema 2; its `lastStage` allowlist now includes
`WINDOWS_*` labels. These denote the remote wrapper's reported last stage, as
opposed to the controller's locally entered stages. Legacy receipts retain their
original values. An old reader that lacks the new allowlist will fail closed on
these receipts; it must not invoke inspection again. Publication/crash uncertainty
and retained-directory duplicate prevention remain unchanged.

## Stage meanings

| Label | Boundary last entered |
| --- | --- |
| WINDOWS_INPUT | Payload decoding and initial shape validation |
| WINDOWS_NATIVE | Native interop type compilation and helper definition setup |
| WINDOWS_VALIDATION | Detailed Windows payload validation |
| WINDOWS_ADMIN | Administrator assertion |
| WINDOWS_STATE | Recovery state discovery before more specific helpers |
| WINDOWS_DIRECTORY_OPEN | Canonical path, directory handle, and attributes |
| WINDOWS_IDENTITY | File identity query and formatting |
| WINDOWS_ACL | Directory ACL checks |
| WINDOWS_CHILDREN | Child enumeration and subsequent topology decisions |
| WINDOWS_BOOT | Boot-marker discovery/validation |
| WINDOWS_STABILITY | Final state recheck before more specific helpers |
| WINDOWS_OUTPUT | Successful-result construction and serialization |

Helpers overwrite broader stages. A later comparison or cleanup exception can
retain the most recent helper label, so a stage is not an exact failure location.
No directory name, failing ACL entry, native error number, or exception text is
included. If parsing/compilation fails before valid rejection serialization, the
existing uncertain or inventory failure behavior remains; no stage is fabricated.

## Local evidence and limitations

Tests cover every stage, old/new rejection schemas, invalid diagnostic envelopes,
apply rejection compatibility, forged exceptions, post-response trust changes,
and a validated remote rejection carried through durable capture and readback.
Generated source tests check both inspect catch paths, unchanged success schema,
finite markers, and absence of inspect diagnostics in apply. A one-off comparison
of a representative apply invocation against the pre-change generator confirmed
identical argv/stdin bytes.

The nine related test files reported 238 tests: 236 passed, 2 skipped, zero
failures. `npm run check` passed. The full storage suite was not rerun.

This machine has no available PowerShell runtime. Generated-source assertions
and synthetic Node transport tests do not establish Windows PowerShell 5.1
execution or native API behavior. No physical Windows/SSH invocation was made.
The historical receipt cannot gain stages retroactively. The executable source
changed, so any further physical check needs a fresh concrete source-bound review;
previous one-shot authorizations and retained run directories are already used.
