# Release notice follow-up — 2026-09-28

## Confirmed

- The four C# files in the retained source-11.zip match the current Apache-2.0 source byte for byte. The retained development ZIP's executable matches build11 SHA-256 4ad217c8357cf37e9010b221c0ad77e39d6fdbcde9e95d7a7b283a31c2de7dfb.
- The old development archive had only the executable, README and manifest. A new private review ZIP adds LICENSE, NOTICE, scope/inventory, current source/build instructions and a Chinese review-only explanation. Original artifacts remain unchanged.
- Source match does not prove a reproducible build or complete binary composition. This task did not execute Windows code or build on Windows. No new installation acceptance is claimed.
- A separate source-only review export omits the unresolved illustration file and changes only the two exported README image URLs to the existing website image. The actual repository image and website remain intact. The export includes original source/docs, with no binary, font or video payload.
- Every ZIP member was read back and byte-compared; archive receipts include hashes and publication=false.

## Media evidence and remaining questions

The repository Mac lifebuoy image and website rescue-wheel.png have identical bytes. This establishes identity, not authorship or permission. Website HANDOFF.md attributes the waterbear background to a Kling-generated clip and documents a forward/reverse loop conversion. Local video materials include Kling-named stills; filenames do not establish generation terms or rights to input images, voices and music.

The user has been asked to identify which pictures/video/voice/music are original, generated or externally sourced. Until answered, the current code license exclusion remains. No asset was deleted or publicly relicensed.

## Artifacts

Privately retained under agent-road-private/release-notices-20260928:

- AgentRoad-build11-notices-REVIEW-ONLY.zip — historical executable with added notices and matching source; not an installation release.
- AgentRoad-source-review-Apache-2.0.zip — source review candidate at revision fb9976f; not a published repository.

Before distribution: resolve source/media provenance; verify the native build on Windows and binary contents; regenerate a consistently versioned full tester kit and complete its onboarding checks. No blanket public-release clearance is asserted.
