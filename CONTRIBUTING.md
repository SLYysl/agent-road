# Contributing

This private snapshot is being prepared for open source. External contributions are not being solicited until licensing and publication gates in OPEN_SOURCE_PREPARATION.md are resolved.

Local development requires Node.js 22 or newer. Run `npm test` and `npm run check`. Acceptance helpers under tools/acceptance also use Python 3. Tests do not substitute for Windows hardware or fresh onboarding acceptance.

Keep changes small, preserve fail-closed behavior, do not replay uncertain mutations, and distinguish unit tests from real-device evidence. Never include credentials, personal device state or raw production logs in commits. Remote tests, installations and reboots require device-owner authorization.
