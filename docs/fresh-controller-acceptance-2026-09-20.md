# Fresh controller acceptance and transport dependency — 2026-09-20

## Executed result

Revision tested: `b89b47e8d96d57c589bdea921f8ae7fde52bf828`.
At 11:28:58 UTC, a new mode-0700 directory was supplied through `AGENT_ROAD_HOME`.
No pairing configuration, controller identity, registry, or credentials were copied.
The real CLI was run on the existing macOS host:

| Command | Exit | Observed result |
| --- | --- | --- |
| `agent-road list` | 0 | `[]` |
| `agent-road pair --name "Fresh Controller Acceptance"` | 2 | `PAIR_CONFIG_REQUIRED` |

No files were created in the fresh state directory. The existing controller's
registry hash was unchanged. Configuration is loaded before the interactive-TTY
check, so the observed error is the configuration gate, not a missing terminal.
Raw evidence is private under `~/agent-road-private/fresh-controller-20260920-5agoskwp/`.

This is a fresh **application-state** test on an existing Mac, not a fresh macOS
or network environment. Docker is available but runs Linux/ARM64; it cannot be
counted as macOS acceptance. UTM is installed. No new macOS or Windows VM was
created this turn: the deterministic controller gate is reached before pairing
can begin. The complete two-fresh-endpoint test remains unpassed.

## New-user gaps confirmed from source

- The package is private, requires Node >=22, and the private repository has no
  GitHub releases as observed in this check. No release download was tested.
- `src/pairing/client.mjs` requires a private configuration, service admin token,
  and a Tailscale API token or single-use auth key before pairing can start.
- `src/pairing/service.mjs` authorizes create through the service-wide admin token.
  `services/pairing/worker.mjs` routes to `private-controller-v1`. This is not a
  customer login or per-customer authorization/provisioning flow.
- Enrollment preflight requires a running Tailscale instance with a `.ts.net`
  name; bootstrap delivery/completion uses Tailscale Serve on that controller.
- Windows installs and joins Tailscale; discovered Tailscale addresses are used
  for pinned SSH. Replacing only the auth-key API does not replace this dependency.
- Reboot-to-core continuation is still a separate step, as documented in the
  two Windows trials. Do not report zero-configuration or single-command closure.

## Transport choices (assessment, not implemented)

| Option | What remains to build or validate |
| --- | --- |
| Keep Tailscale | Customer authorization, isolated credentials/network policy, first-run setup, and distribution/commercial terms. |
| Embed Tailscale using tsnet | A Go integration can hide the separate system client; identity/control-plane dependence remains and current CLI transport must change. |
| Self-host Headscale | Still uses Tailscale clients; replace key issuance and validate or replace Serve/certificate/DNS assumptions. Not a drop-in endpoint substitution. |
| Self-host another mesh, e.g. NetBird | Rework provisioning and transport discovery; operate its management, signal and relay components; review applicable licenses. |
| Dedicated outbound application relay | Both endpoints dial out; preserve independently authenticated encrypted sessions, task receipts, cancellation and replay boundaries; operate relay capacity and availability. |

Tailscale is a current implementation dependency, not a fundamental requirement
of remote task execution. A public pairing endpoint alone supplies no data route
between arbitrary private networks. Product direction should separate customer
onboarding from the selected transport provider. This check does not choose or
deploy a replacement, claim its reliability, or authorize network migration.

For the existing transport, the next acceptance prerequisite is a first-run flow
that grants one customer's own controller scoped service/network access without
shipping a shared administrator token. Then test a fresh macOS controller and a
fresh Windows environment through download, approval, reboot continuation and
command/file execution. Existing successful enrolled devices remain unchanged.

Official references checked 2026-09-20:
- [Tailscale control/data planes](https://tailscale.com/docs/concepts/control-data-planes)
- [Tailscale connection types](https://tailscale.com/docs/reference/connection-types)
- [tsnet](https://tailscale.com/docs/features/tsnet)
- [Headscale features](https://headscale.net/stable/about/features/)
- [Headscale clients](https://headscale.net/stable/about/clients/)
- [NetBird architecture](https://docs.netbird.io/about-netbird/how-netbird-works)
