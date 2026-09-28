# License review evidence — 2026-09-28

Reviewed the clean private candidate at 880767a, controller and native distribution scripts, runtime catalogs, website package/lock metadata and official upstream license sources. `sources.json` records downloaded license URLs, byte counts and hashes. The exact official Apache text is copied to the repository LICENSE. Upstream dependency license text remains in privately retained evidence; dependency references in THIRD_PARTY_REVIEW.md are not substitutes for the notices of an actually redistributed binary.

The Tailscale 1.98.9 raw license endpoint succeeded with HTTP 200 through a direct HTTPS retrieval although the web research tool initially reported an internal error. Its bytes match the reviewed main-branch BSD text.

Fontshare's generic /licenses URL redirected to the homepage. Navigating its Cabinet Grotesk family page in Chrome exposed the actual ITF Free Font License: own-site self-hosting is permitted; repository redistribution and modifications are restricted. No agreement or download was submitted in the browser.

Website inventory includes optional packages for multiple platforms; counts must not be read as deployed components. No full media provenance, exact historical installer binary SBOM, hosted-service eligibility, or Windows-native build validation was completed in this review. See ../LICENSE_RELEASE_CHECKLIST.md for outstanding gates.
