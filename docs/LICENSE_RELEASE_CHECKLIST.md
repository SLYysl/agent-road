# License release decision checklist

Status: preparation only, 2026-09-28. No license has been selected or granted by this document. The repository remains private.

Before adding LICENSE:

1. Confirm the copyright holder and authority to license the exported source, documentation and original artwork. Review any contributed or copied material separately.
2. Select the project license explicitly. MIT and Apache-2.0 are the existing candidates in OPEN_SOURCE_PREPARATION.md; use the chosen license's official text rather than a generated paraphrase.
3. Complete THIRD_PARTY_REVIEW.md against the exact intended release archive. Distinguish prerequisites, runtime downloads and files actually redistributed. Record version, source, bundled files and required notices per component.
4. Audit website/repository images, fonts and video separately from controller code. A project code license must not silently imply rights to all media.
5. Add the confirmed copyright notice, LICENSE and any required third-party notices; check package metadata and README wording for consistency.
6. Review the final archive and obtain explicit approval for public repository visibility and release assets. A licensed source release does not itself open the hosted pairing service or publish a signed Windows installer.

The existing component inventory is incomplete. This checklist records the remaining decisions; it is not a completed compliance assessment or permission to redistribute a dependency.
