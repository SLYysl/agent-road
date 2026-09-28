# Bounded Full-Gate Preflight Design

## Goal

Replace the failed monolithic diagnostic entry with a finite, read-only sequence that proves the current physical gate tree matches the known production residue closely enough to consider a separately authorized recovery. The sequence is evidence only: it never grants cleanup authority and never mutates Windows.

## Scope

This slice extends the local-only diagnostic files under `/private/tmp/agent-road-task8.ctv4Oa/production-gate`. It does not change product commands, enrollment, SSH trust, firewall scope, recovery mutation, GUI control, or the Windows installation. No Windows command may run while this design is implemented or reviewed.

The existing `transport`, `control`, and `watchdog` probes remain frozen after their physical pass. New work may add read-only probes and one Mac-side serial coordinator only.

## Rejected Alternatives

1. **Run the original monolithic inspector again.** It has the strongest single-snapshot shape, but the prior large transport path stalled and created recovery work. It is not a safe diagnostic entry.
2. **Install a target-side helper or service.** This could hold a Windows-side transaction, but it exceeds the v1 boundary of Tailscale plus OpenSSH with no additional target daemon.
3. **Allowlist PowerShell noise or relax command limits.** This would hide real failures. Nonempty stderr remains fatal, remote command length remains at most 7,200 characters, and the modeled `cmd.exe /d /s /c` command remains below 7,500 characters.

## Architecture

The selected design has three layers:

1. `bounded-direct-probe.mjs` builds short, identity-distinct PowerShell 5.1 children. Every child is read-only, emits one canonical JSON object, and is executed by the already proven bounded outer watchdog.
2. `bounded-full-gate.mjs` runs an exact allowlisted sequence on the Mac. It stops at the first failure, never retries, and emits only a finite success or failure envelope.
3. `gate-recovery.mjs` remains the only future mutation authority. A passing bounded preflight is not sufficient to delete or move anything; recovery must revalidate references, shape, hashes, age, and ACLs at every destructive boundary under a separate user authorization.

## Manifest and Shape

One frozen bounded manifest contains:

- the active root and quarantine root;
- the 16 exact relative directories from the original recovery inspector;
- the nine exact published files with byte lengths and SHA-256 digests;
- the 48-byte owner proof with its SHA-256 digest.

Tests bind this manifest back to the original recovery and ACL diagnostic sources so a copied count cannot drift silently.

The existing `path` probe keeps its public schema, but success additionally requires:

- the path root is exactly `C:\` and is a canonical non-reparse container;
- the active root is a canonical non-reparse container;
- the quarantine path does not exist as any filesystem type.

The existing `tree` result remains:

```json
{"status":"ok","nodes":27,"directories":16,"files":10}
```

It remains a bounded traversal and rejects reparse points and escapes. A new `dirs` probe proves every allowlisted directory exists at its exact canonical path and emits:

```json
{"status":"ok","directories":16}
```

Together, `tree`, `dirs`, and the ten hash probes prove the exact 27-node active shape. Each hash probe must additionally require `item.FullName` to equal the expected canonical path.

## Age

The `age` probe traverses exactly the same 27 non-reparse nodes, reads `LastWriteTimeUtc`, and emits:

```json
{"status":"ok","minimumSeconds":60,"maximumSeconds":31536000,"capped":false}
```

The numbers above illustrate the bounds, not fixed observed values. The parser accepts only integers satisfying `60 <= minimumSeconds <= maximumSeconds <= 31536000`, and only `capped:false`. Future timestamps, over-one-year timestamps, missing nodes, extra nodes, and noncanonical JSON fail.

## ACL Policies

The read-only preflight checks the known production profile before normalization:

- `aclinherited` checks the active root, all 16 directories, and the owner proof: 18 nodes total. Each descriptor must contain a DACL, be canonical, inherit rather than protect access rules, have no explicit access rules, have an owner equal to the current account or Administrators, and grant no mutating inherited rights to an untrusted trustee. Creator Owner is accepted only for an inherit-only rule.
- `aclpublished` checks all nine published files. Each must have a present DACL, Administrators owner, protected canonical rules, and exactly two non-inherited Allow FullControl rules for SYSTEM and Administrators with no inheritance or propagation.

Their only accepted results are:

```json
{"status":"ok","checked":18}
{"status":"ok","checked":9}
```

This pre-normalization profile is distinct from recovery's post-move policy. If recovery is later authorized, it must still normalize every quarantined node to the exact restricted policy and re-read the resulting ACL before deletion.

## CIM Reference Scans

`cimfirst` and `cimsecond` are identity-distinct children with exact schemas:

```json
{"status":"ok","scan":"first","total":2,"taskPs":0,"sftp":0,"gateRef":0,"otherRemotePs":0,"unknown":0}
{"status":"ok","scan":"second","total":2,"taskPs":0,"sftp":0,"gateRef":0,"otherRemotePs":0,"unknown":0}
```

`total` is an observed integer from 2 through 1,024. A scan must find exactly one self row and exactly one parent row, exclude those two PIDs, and classify all remaining relevant rows in this priority order:

1. a PowerShell task script below the fixed Agent Road task root;
2. `sftp-server.exe`, even if its command line is empty;
3. a command line referring to the active or quarantine gate root;
4. another PowerShell using a bounded encoded command or stdin command form;
5. `unknown` when a potentially relevant row cannot be classified safely.

Every category must be zero. No PID, process name, command line, path, address, or identity crosses the JSON boundary.

## Serial Coordinator

The only full read-only sequence is:

1. `cimfirst`
2. `path`
3. `tree`
4. `dirs`
5. `hash01` through `hash10` in order
6. `age`
7. `aclinherited`
8. `aclpublished`
9. `cimsecond`

The coordinator admits one in-process run, calls each probe exactly once, and stops at the first failure. It never invokes `transport`, `control`, `watchdog`, recovery, cleanup, or a mutating command. Its public outputs are exactly:

```json
{"status":"ok","probes":18}
{"status":"failed","probe":"age","completed":14}
```

The failure `probe` is restricted to the sequence allowlist and `completed` is a bounded integer. Raw errors and probe output never cross the coordinator boundary.

## Recovery and Physical Acceptance Boundary

A bounded preflight pass means only that a separately authorized recovery may be reviewed. Recovery must still:

- recheck the exact active state immediately before moving it;
- move only active to the exact quarantine path;
- normalize and re-read every quarantined ACL;
- recheck reference counts and exact leaf hashes before each destructive phase;
- delete only allowlisted leaves and then empty allowlisted directories;
- prove active and quarantine are absent at completion.

After recovery, a separate read-only absence/reference check is required. Only then may a fresh five-cycle physical gate and the final cold-start `reboot -> transport -> control -> watchdog` acceptance be authorized.

## Testing and Acceptance

Local tests must prove:

- the manifest matches the original recovery/ACL sources;
- every probe has an identity distinct from every other probe and the production wrapper;
- outer progress suppression remains first, stderr remains strict, children contain no mutators, and output is bounded;
- every remote command is at most 7,200 characters and every modeled `cmd.exe` command is below 7,500;
- exact JSON schemas reject missing, extra, reordered/noncanonical, nonzero, unbounded, proxy, getter, and sensitive values;
- shape fixtures reject a replaced directory, quarantine leaf, path alias, extra node, reparse point, future timestamp, and stale timestamp;
- ACL fixtures cover both policies and reject every trustee, owner, rule-shape, inheritance, propagation, DACL, and descriptor mismatch;
- CIM fixtures cover the four categories, overlap priority, empty SFTP command lines, missing self/parent, bad PIDs, unknown rows, and nonzero counts;
- the coordinator runs exactly 18 probes in order, stops on the first failure, never retries, and leaks no raw evidence.

Implementation is locally complete only after targeted tests, Node syntax checks, the existing remote-layer suite, command-length enumeration, a sensitive-value scan, spec review, and code-quality review all pass. Physical execution always requires a new explicit authorization.
