# Transport reuse and certificates — 2026-09-20

Status: official-source assessment plus local custom relay acceptance; none of
these alternative projects has been installed into Agent Road or Windows.

## Recommendation

Keep Tailscale as the working path. Evaluate **frp STCP** first for a narrow
SSH-only fallback, before investing further in the custom WebSocket broker.
Use Headscale if the goal becomes owning a Tailscale-compatible control plane;
use NetBird/Nebula if we actually need a full overlay network. These are choices
of scope, not claims that one is intrinsically safe or production-ready for us.

| Candidate | Reusable part | Published license checked today | Integration implications |
| --- | --- | --- | --- |
| frp | Reverse TCP tunnels; STCP visitor access; optional XTCP | Apache-2.0 | Closest to one SSH route; retains end-to-end SSH. Still needs hosted frps, per-user authorization, secret rotation and tested TLS configuration. STCP avoids publishing a target SSH port; it is not a complete customer identity system. |
| rathole | Small Rust reverse proxy | Apache-2.0 | Simple relay candidate; evaluate secured listener/visitor design and platform builds before selection. |
| Headscale | Self-hosted Tailscale-compatible coordination | BSD-3-Clause | Still uses Tailscale clients; existing Serve/.ts.net bootstrap cannot be assumed compatible. |
| Nebula | Cross-platform certificate-based overlay | MIT | Own CA, enrollment, lighthouse/relay operation and policies; broader integration work than an SSH tunnel. |
| NetBird | WireGuard-based networking and management | Root BSD-3-Clause except management/, signal/, relay/, combined/ under AGPLv3 | Assess exact components and dependencies. Do not describe the entire server stack as permissively licensed. |
| Tailscale client / tsnet | Existing client/userspace networking | BSD-3-Clause in client repository | Source license does not grant hosted service resale rights; partner/service terms are a separate question. |

MIT/BSD/Apache generally permit commercial use and redistribution with their
conditions (notices, attribution and, for Apache, modification/NOTICE obligations
where applicable). AGPL does not forbid commercial use; its source obligations
need a component-specific review, especially modified software offered over a
network. No license here automatically grants trademark use or hosted services.
This is an initial inventory, not a completed distribution/legal clearance:
freeze release revisions and review bundled dependencies before packaging.

## Certificates are distinct from licenses

- HTTPS/WSS: use a trusted TLS certificate for the relay domain. Let's Encrypt
  provides automated domain-validation certificates through ACME; a certificate
  does not establish which user may control which device.
- SSH: retain device-generated keys and pinned host identities. A TLS certificate
  cannot replace the SSH host-key check. Short-lived SSH certificates are a later
  option, not necessary for this prototype.
- step-ca: Apache-2.0 certificate authority implementation for X.509 and SSH
  certificates. Useful if we need device certificate lifecycle automation; it
  introduces CA-key protection/issuance/revocation responsibilities.
- Code signing/notarization: installer publisher trust is a third separate task;
  a website TLS certificate or SSH certificate does not sign an installer.

## Website/Supabase boundary

Repo records currently identify Vercel as the website and Cloudflare as pairing
backend. User mentions Supabase; the corresponding project has not been verified.
Supabase Auth/database can support customer login, ownership and scoped session
issuance. Realtime can carry status/signaling. Hosted Edge Functions support
WebSockets but have finite worker duration; avoid assuming a permanent SSH pipe.
Cloudflare Durable Objects are another candidate for coordinating WebSockets,
not a prebuilt authenticated SSH relay. No production migration/deployment done.

First-run work still needs authenticated, scoped pairing-service access instead
of the shared PAIR_ADMIN_TOKEN, customer-owned/isolated network authorization,
and a fresh-controller acceptance. Do not share the personal tailnet or admin
credential with customers. Selecting an identity provider precedes that rollout.

## Official sources checked

- https://github.com/fatedier/frp (STCP, XTCP, TLS; dev branch is not a pinned release)
- https://github.com/fatedier/frp/blob/dev/LICENSE
- https://github.com/rathole-org/rathole and its LICENSE
- https://github.com/juanfont/headscale/blob/main/LICENSE
- https://headscale.net/stable/about/clients/
- https://github.com/slackhq/nebula and its LICENSE
- https://github.com/netbirdio/netbird/blob/main/LICENSE
- https://github.com/tailscale/tailscale/blob/main/LICENSE
- https://tailscale.com/terms
- https://smallstep.com/docs/step-ca/
- https://github.com/smallstep/certificates/blob/master/LICENSE
- https://letsencrypt.org/how-it-works/
- https://supabase.com/docs/guides/functions/websockets
- https://supabase.com/docs/guides/functions/limits
- https://developers.cloudflare.com/durable-objects/best-practices/websockets/
