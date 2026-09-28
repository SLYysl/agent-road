# Short internet pairing — fresh Windows accepted, first-run controller incomplete

User authorization: two previously unconnected machines need only internet access;
a public pairing service is allowed. The existing enrolled Windows machine must
not be re-enrolled for this change. The public front door is the existing Vercel
site at `agent-road.brahma-technologies.com`. On 2026-09-19, Vercel confirmed the
existing project binding and matching CNAME; HTTPS returned 200. Cloudflare and
Vercel CLI login succeeded. The pairing Worker and two Vercel project routing
rules are now live; the existing showcase deployment was not replaced.
Cloudflare OAuth can list the zone but DNS-record access returned 403; no DNS
change was needed for the already configured site. Do not deploy unrelated local
changes in the separate agent-road-site checkout.

## Intended interaction

Mac: `agent-road pair` after one-time controller configuration. Windows administrator
PowerShell: one fixed `irm https://<join-host>/join.ps1 | iex` command, then enter the
short pairing code shown by the Mac. Both ends display a verification code; the Mac
operator verifies it before releasing bootstrap. The loader endpoint is live; actual enrollment requires the controller
configuration below. Two clean Windows environments passed enrollment/core/file acceptance via the inspected-file route on 2026-09-20; a controller with no prior configuration still stops at `PAIR_CONFIG_REQUIRED`. See [Windows acceptance](fresh-windows-acceptance-2026-09-20.md) and [fresh-controller check](fresh-controller-acceptance-2026-09-20.md). UAC/administrator consent remains necessary.

The existing stage-zero fixture generates about 23,122 characters. Moving its
per-device command behind a bounded public rendezvous removes that payload from
the pasted line; existing installer signature/hash checks and host-key-pinned SSH
verification remain in the enrollment path.

## Trust and transport

The public HTTPS service is a trusted bootstrap distributor, not a general command
relay and not an end-to-end-untrusted relay. It accepts bounded, temporary sessions
from an authenticated controller; a short code alone never approves a device.
A separate high-entropy claimant token binds delivery to the approved claimant.
Payloads are encrypted at rest, have a ten-minute logical expiry and are removed from
live storage after single delivery. Logical deletion does not promise erasure from
provider backups. HTTP logs must not contain request bodies or authorization data.

Two internet-connected machines still need a data-plane route. Reuse Tailscale;
issue a fresh non-reusable, non-ephemeral auth key on the controller for each new
join. In automatic mode, the Tailscale API credential stays on the Mac; each generated
key expires after 15 minutes and the controller attempts revocation on exit. API
access tokens themselves expire and must be renewed. In manual mode, the operator
must supply a fresh non-reusable, non-ephemeral auth key for each attempt; the
controller cannot infer those policy properties from the key string. Send only the one-off key in
the approved bootstrap, use an ACL-protected temporary key file on Windows, and
never pass the raw key to the Tailscale executable argument list. The encoded
PowerShell bootstrap contains the key and must also be treated as sensitive. Existing interactive enroll remains
available without changing its behavior. This feature must not publish public SSH,
RDP, Funnel, or the existing Mac enrollment receiver.

Cloudflare Worker plus a SQLite-backed Durable Object coordinate expiration,
claim/approval and atomic single delivery. Retransmitting an uncertain bootstrap is
not automatic. Once enrollment has started, retain the existing operation/receipt
recovery boundaries. Successful pairing is not CONNECTED_SSH_ONLY: only the original
pinned verifier and transfer probe may publish that device state.

## Acceptance gates

- Anonymous session creation, wrong owner/claimant tokens and approval of a different
  claimant are rejected; only one claimant and one payload delivery can win.
- Expired/cancelled sessions cannot release credentials; invalid/oversized inputs
  cause no provisioning; responses never echo tokens or encrypted payloads in errors.
- Short loader compatible with Windows PowerShell 5.1, HTTPS-only and bounded polling.
- Default legacy enrollment behavior/regression remains intact.
- Local service plus independent fake clients, then an explicit fresh-device trial.
- Deploy only to the confirmed Agent Road hostname/account; do not replace another
  site's DNS/service. Public service smoke and clean Windows acceptance passed; two unconfigured endpoints have not passed end-to-end acceptance.

References: [Tailscale auth keys](https://tailscale.com/docs/features/access-control/auth-keys),
[Tailscale file-based auth key](https://tailscale.com/docs/reference/tailscale-cli/up),
[Cloudflare durable storage](https://developers.cloudflare.com/durable-objects/api/sqlite-storage-api/).

## Controller configuration

The default config is `$AGENT_ROAD_HOME/pairing.json` (normally
`~/.agent-road/pairing.json`). Config and credential files must be owned by the
current Mac user, mode 0600, and not symlinks. All paths are absolute.

```json
{
  "origin": "https://agent-road.brahma-technologies.com",
  "adminTokenFile": "/Users/example/.agent-road/pairing-service/admin-token",
  "tailscaleApiTokenFile": "/Users/example/.agent-road/pairing-service/tailscale-api-token"
}
```

Alternatively replace `tailscaleApiTokenFile` with `tailscaleAuthKeyFile` pointing
to the fresh manual key. Exactly one of these options is required. Never commit
real config/credential files. Automatic API credentials and controller config were configured privately on
2026-09-19. Real key creation/readback confirmed reusable=false, ephemeral=false,
preauthorized=true and 900-second expiry. The test key was revoked immediately;
Tailscale retains its record with invalid=true and a revoked timestamp (GET 200,
not necessarily 404). No device was enrolled. Private verification evidence is in
`~/.agent-road/pairing-service/api-verification-X7aeyn/`.

Run `agent-road pair --name "New Windows PC"` in an interactive Mac terminal.
The Windows administrator pastes:

```powershell
irm https://agent-road.brahma-technologies.com/join.ps1 | iex
```

Enter the pairing code from the Mac on Windows, then enter the eight-digit code
shown by Windows at the Mac prompt. Approval releases the bootstrap exactly once.
The existing enrollment verifier, SSH pinning and core handoff determine success.
Do not repeat an uncertain join; retain the private capture and reconcile first.
API create failures are not retried: an unknown created key can remain valid until
its 15-minute expiry. Cleanup uncertainty returns a nonzero exit status.

## Deployment and verification, 2026-09-19

- Backend: `https://agent-road-pairing.brahma-agent-road.workers.dev`.
- Vercel `agent-road-site` project routes: `/join.ps1` and the six exact `/v1/`
  endpoints (create, claim, status, approve, receive, cancel), both external rewrites.
- Route version: `8368cf2d-0bcf-4baa-930b-e8cc33c62c5d`; only these two routes were
  staged/published. No unrelated site source changes were deployed.
- Public loader returned 200 and matched the configured local source byte for byte.
- Public authenticated fixture completed create/claim/approve/receive; anonymous
  create and duplicate delivery rejected. Fixture contained no device credentials
  and was never executed. Showcase still returned HTTPS 200.
- Real local workerd rejected simultaneous duplicate claims and deliveries.
- Existing Windows PowerShell 5.1.26100.9444 parsed the loader and paired stage-zero fixture with zero errors.
- 97 focused regression tests passed; one opt-in local Worker test was separately
  enabled and passed. `npm run check` passed.
- Limits: one private controller, 32 live records, global 180 requests/minute;
  not a multi-tenant service or denial-of-service resilience claim.

Local Worker test uses ONLY fixture credentials:

```sh
wrangler dev --local --config services/pairing/wrangler.jsonc --port 18749 \
  --persist-to /tmp/agent-road-pair-local-state \
  --var PAIR_ADMIN_TOKEN:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
  --var PAIR_STORAGE_KEY:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb \
  --var PUBLIC_ORIGIN:https://agent-road.brahma-technologies.com
# Separate terminal:
AGENT_ROAD_PAIR_LOCAL_TEST=1 node --test test/pairing-worker-local.test.mjs
```

Provider secrets are managed outside Git. `wrangler deploy` publishes the Worker;
Vercel project routing is managed with `vercel routes`, independently from site
source. Inspect existing staged routes before publishing; never include another
agent's staging changes. Disable the two named pairing routes to withdraw the
public entry points without replacing the showcase.

## Fresh Windows installation budget and inspected-file route

`pair --timeout-minutes <5-30>` now defaults to 30 minutes for enrollment completion:
a clean Windows installation downloads Tailscale and the Windows Update OpenSSH
capability before SSH verification. The public code still expires after ten minutes;
automatic Tailscale auth keys remain single-use with 900-second expiry. Changing the
completion budget does not extend either credential lifetime or replay a bootstrap.
Stage zero suppresses PowerShell download progress rendering, retaining stage/error
messages. A running process keeps its original timeout; changes apply to new trials.

In the VirtualBox acceptance harness, host Defender detects the `VBoxManage
keyboardputstring` command line containing the download-and-execute pipeline. The
reviewed alternative trial downloads `join.ps1` as a file in the guest, compares its
SHA256 with the independently fetched source-matching loader, updates Defender
signatures, performs a custom scan and checks detection records before running:

```powershell
powershell -NoProfile -ExecutionPolicy RemoteSigned -File C:\AgentRoad-Setup\join.ps1
```

This sets policy only for that process, honors higher-precedence policy, and does
not disable antivirus or add exclusions. It is a separate file-based acceptance
route, not proof that the original pipeline passes host keyboard automation. Public
loader SHA256 must be refreshed against source whenever that loader changes.


## Clean Windows path-length compatibility

Windows 11 with `LongPathsEnabled=0` exposed an excessive staging path during
core materialization. New operations use `staging/<operationId>/work` instead of
repeating the 64-character manifest digest in the working-directory name. The
signed capsule remains under `staging/<operationId>/<manifestDigest>` and retains
its existing operation, manifest, generation and controller bindings.

Existing `work-<manifestDigest>` directories remain readable for recovery. Both
formats in one operation, a mismatched legacy digest, or work without its matching
transaction are rejected. No registry long-path switch or system ACL was changed.
The explicit Windows fixture `test/fixtures/runtime-work-layout.mjs` checks new
selection, legacy selection and coexistence rejection; the isolated full-core
fixture also completed all phases on Windows PowerShell 5.1.

## Short invitation command increment (2026-09-20, not deployed)

The controller now uses a `codeInJoinUrl: true` capability in session creation
responses. With a matching service, it prints an 81-character invitation:

```powershell
irm 'https://agent-road.brahma-technologies.com/join.ps1?code=ABCDEFGHJKLM' | iex
```

The code above is an example, not a live invitation. Real codes remain 12 random
base32 characters (60 bits); the existing ten-minute expiry, claimant binding,
Mac verification and single bootstrap delivery remain unchanged. The Windows
loader asks for explicit YES consent before claiming. Windows needs no website
account. The command contains no long-lived account or Tailscale credentials.
GET only renders the loader: it does not claim or consume an invitation, so link
previews cannot consume it. Query-bearing responses are no-store. Codes may still
appear in URL logs/history, and must never be treated as authorization by themselves.

Against older services without the capability, the new CLI retains the generic
join.ps1 command plus manual code. New service also retains that generic loader.
This supports service/CLI rollout in either order. Existing Vercel join.ps1 rewrite
must be checked for query forwarding after an authorized deployment.

This increment is local only: no Worker/site deployment, no Windows execution,
and no fresh-device acceptance of the changed consent prompt. Existing configured
controller still requires its private pairing config and Tailscale credentials.
Account-backed first-run login and per-account service authorization remain next;
this does not claim they are implemented.

Validation: full suite 1,510 passed / 18 skipped / 0 failed; latest focused controller/loader/service suite 17 passed; local workerd lifecycle/short-loader test passed; npm run check and site production build passed. Full suite started before the compatibility follow-up; the final changed paths were rechecked by focused and workerd tests.
