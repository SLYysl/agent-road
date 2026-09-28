# Contributing

Agent Road is an experimental open-source Alpha. Redacted bug reports, documentation corrections and small, scoped pull requests are welcome. Discuss substantial changes in an issue first. By submitting original contributions for inclusion, you offer them under the project Apache-2.0 license; disclose third-party sources and retain their notices. See OPEN_SOURCE_PREPARATION.md for current limitations.

Local development requires Node.js 22 or newer. Run `npm test` and `npm run check`. Acceptance helpers under tools/acceptance also use Python 3. Tests do not substitute for Windows hardware or fresh onboarding acceptance.

Keep changes small, preserve fail-closed behavior, do not replay uncertain mutations, and distinguish unit tests from real-device evidence. Never include credentials, personal device state or raw production logs in commits. Remote tests, installations and reboots require device-owner authorization.
