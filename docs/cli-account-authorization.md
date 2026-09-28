# Controller account authorization — deployed, bounded live acceptance

## Interaction

- Mac: agent-road login opens the website; --no-browser prints the same verification URL/code.
- Website: sign in with Supabase, review the requester-provided controller name and compare the 12-character code, then explicitly approve or deny.
- CLI: agent-road whoami checks the live grant; agent-road logout revokes it before deleting the local credential. Uncertain logout retains the credential for recovery.
- Website: Account → Manage CLI controller authorizations lists/revokes only the logged-in account's grants.
- Windows remains accountless: a separate short pairing command and local consent are required.

## Credential and enforcement

Private Agent Road authorization protocol, not a claim of RFC 8628/OAuth certification.
CLI creates a 256-bit secret plus random id; the broker retains SHA-256 only. Pending approval lasts 10 minutes; approved grant lasts 30 days. No automatic refresh: authorize again after expiry. Supabase access/refresh tokens never move into CLI storage.
The fixed Supabase project /auth/v1/user verifies every browser approval/list/revoke. Unconfirmed/anonymous users and wrong origins are refused; user metadata never supplies ownership. Up to 16 active controllers per account, 256 total records, bounded global request rate. These limits are an initial bounded deployment design, not public abuse/load acceptance.

Default CLI state: ~/.agent-road/cli-auth/credential.json, directory 0700/file 0600, plaintext local credential (not Keychain encryption). Exclusive command lock prevents concurrent edits; SIGINT/SIGTERM release it. After a hard crash, AUTH_COMMAND_BUSY needs manual inspection of the stale lock, not blind deletion. Network failures expose finite errors only.

Default pair prefers the saved account credential. A matching pairing.json still supplies controller-owned Tailscale API or single-use auth key configuration. adminTokenFile is optional for account mode; --config can explicitly select the legacy administrator path. Missing network configuration after login reports PAIR_NETWORK_CONFIG_REQUIRED; pending/revoked login is rejected before issuing a Tailscale key. No shared tailnet credential is distributed to new users.

Account-backed pair records bind the authorizing controller generation and account. Every controller operation rechecks the grant, and target claim/receive also require that grant to remain active. Revocation before delivery blocks installation; reauthorizing the same credential cannot revive old invites. Already-delivered bootstraps and established SSH sessions are not revoked by this grant mechanism. Device detach/key removal is separate work. Supabase browser logout/password reset does not itself revoke independent CLI grants; use the controller list or CLI logout.

## Rollout checklist (steps 1–3 now completed; see deployment update)

1. Review and authorize deploying the existing pairing Worker with this increment. Configure SUPABASE_PUBLISHABLE_KEY (public key only) and retain PUBLIC_ORIGIN and existing private pairing secrets; configured in the approved production deployment.
2. Review and authorize website deployment with AGENT_ROAD_AUTH_SERVICE_ORIGIN=https://agent-road-pairing.brahma-agent-road.workers.dev and existing Supabase public settings. The site contains an unrelated dirty design baseline and is archived as task-only patches, not pushed wholesale.
3. Verify real browser account → CLI → account-authorized pair with a configured controller, then revocation. No new Windows enrollment/reboot was attempted.
4. Complete first-run customer-owned network setup/distribution and device ownership inventory; fresh Mac + fresh Windows is still unaccepted. SMTP/confirmation delivery remains pending from the earlier site task.

## Initial local evidence

78 focused auth/CLI/pairing tests passed; npm run check passed. Real local workerd passed existing pairing serialization/one-shot delivery plus auth start/status/logout/revoked-status. Workerd did not call real Supabase. Browser mocks cover sign-in return, approval and revoke in two locales, mobile no overflow; site lint/type/build passed. Previous full suite 1510/18 belongs to the prior short-command increment and was not rerun for unrelated runtime stores.

## Deployment update, 2026-09-20

User approved Worker and site deployment. Real browser/CLI approval, account-authorized pair create/status/cancel and browser revocation passed with one temporary user, subsequently deleted and verified 404. See experiments/site-cli-auth/LIVE_ACCEPTANCE.md. The runtime verifier uses manual redirects because Cloudflare Workers rejects redirect:error. New Windows enrollment, fresh-controller networking and SMTP are not covered.

Future Worker deployments must retain SUPABASE_PUBLISHABLE_KEY using the reviewed deployment arguments or --keep-vars; the public key is not stored in this repository.
