# License release decision

Selected 2026-09-28 under the user's request: **Apache-2.0 for original Agent Road code and documentation**, scoped by LICENSE_SCOPE.md. LICENSE is the unmodified official Apache text; NOTICE identifies this project. This is now applied to the private candidate, not merely a proposed license.

Why: permissive reuse and a clear contributor patent grant fit a CLI intended for integration. Apache-2.0 includes notice/change obligations and does not grant trademark rights. See the [official license](https://www.apache.org/licenses/LICENSE-2.0.html). No integrated dependency found in the reviewed controller source requires selecting a copyleft project license. External tools keep their own licenses.

Remaining installer/asset delivery checks (source publication is separately authorized):

- Confirm provenance/authority for original source and any copied contributions; snapshot authors alone are insufficient.
- Retain the maintainer-approved Mac lifebuoy presentation; media remains outside Apache-2.0. Website fonts/video are not included in the source release.
- Regenerate an exact versioned installer/tester kit with notices and inspect all shipped payloads. Historical archives are not updated by this change.
- Keep Tailscale official downloads and user-owned network setup separate from a hosted-service offering; do not infer full Windows installer redistribution rights from BSD.
- Complete previously documented onboarding/security checks before unrestricted hosted-service or installer release.

The review covers source and identified dependencies, with unresolved artifact/media gates recorded in THIRD_PARTY_REVIEW.md. It does not certify a fully open-source end-to-end hosted stack.
