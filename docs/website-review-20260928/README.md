# Homepage, SEO and first-time-user review — 2026-09-28

Status: user authorized production deployment on 2026-09-28. The reviewed website is now deployed and 11 production routes passed; see `production-deployment.json`. README changes are in the private SLYysl repository. The source repository remains private and licensing remains pending.

## Findings and decisions

The live site already had descriptive bilingual metadata, canonical links, language alternatives, a sitemap and sign-in noindex. The old missing-metadata audit no longer described the live site. Current work is content clarity and consistency, not a claim of fixing every historical SEO issue again.

The existing light background, muted green accent, display typography and tardigrade film were retained. At the user’s request, the classic Mac-on-lifebuoy illustration is also retained beside the example request in the overview, responsive on mobile and desktop. The main issue was information order: a pairing command for a configured Mac dominated the first screen; future scenarios, recovery branding and internal state labels competed with first-use instructions. Some text claimed no valuable long-lived credentials and full desktop/browser readiness, despite SSH-only scope.

Changes:
- One function-oriented headline and a primary setup CTA, with the demo as a secondary action.
- A Mac / connection / Windows explanation, plus a plainly labeled example request.
- The copyable agent prompt in the getting-started section; configured-user pairing command in a disclosure.
- A concrete first success: expected output plus exit code 0, followed by separate file/job checks.
- Three present-day task examples instead of future-platform cards; removed their WebGL/animation/image requirements from this page.
- Six beginner FAQs; keep installer, open-source status and recovery limits visible.
- Corrected credential and administrative-operation wording; no universal approval-enforcement or GUI-readiness promise.
- Real internal evidence described as internal; no invented testimonials, stars, adoption numbers or uptime guarantees.
- Function-oriented localized search titles/descriptions and EN/ZH sitemap alternatives. Existing canonical/hreflang/noindex retained.
- Rendered footer with working localized docs link. No public GitHub CTA while the repository is private.
- Alpha availability page localized and speculative future pricing language removed.

## Jev review and human checks

Jev `jev-1.13.0` received public HTML-derived content from the same four routes, the same twelve questions, and no screenshots. Its Noul values are model judgments, not user-success rates or measured conversion. They are screening signals only.

| Check | Before | After |
| --- | ---: | ---: |
| Clear first action | 0.56 | 0.83 |
| Beginner objections answered by FAQ | 0.28 | 0.95 |
| Product function clear | 0.94 | 0.98 |
| Claims consistent | 0.81 | 0.82 |
| SEO basics present | 0.95 | 0.95 |
| Enough evidence to judge visual attractiveness | 0.02 | 0.02 |

Jev was too accepting of the old claims and generic first-task wording. Human review overrode that: the credential/READY claims were corrected and an observable first task added. The modest consistency change is not evidence the claims are fully audited. An exploratory unmatched call that also included README was excluded from this comparison.

Visual review was done separately in Chrome at the existing viewport, 390×844 and 1440×900. It led to shorter Chinese heading text and smaller narrow-screen typography. This is implementer review, not an independent designer or first-time-user study. No Lighthouse/Core Web Vitals benchmark was performed; fewer components alone do not prove a measured speed gain.

## Validation

- Final Next.js production build including TypeScript: passed.
- Targeted ESLint on changed TSX and sitemap: passed.
- 11 local routes: EN/ZH home, English alias, sitemap, robots, EN/ZH sign-in, EN/ZH Alpha page, both setup guides.
- Checked one H1, working static homepage anchors, canonical/language metadata, localized content, sitemap alternates and sign-in noindex.
- Chrome: primary CTA reaches setup; English and Chinese prompt copy report success; prompt disclosure and FAQ expand correctly.
- 390 px and 1440 px DOM checks: document width equals viewport width, no horizontal overflow observed.
- README local links and documented CLI signatures checked; no Windows or account mutation performed.
- Earlier source regression completed: 1,577 passed / 19 skipped / zero failed. This task changes documentation and site presentation, not controller runtime.

## Patch provenance and deployment boundary

`site.patch` is **only this task's delta**, relative to the pre-existing dirty website working tree. `patch-manifest.json` records exact before/after file hashes. Apply only to a matching website baseline; it is not a standalone site and does not apply to this controller repository. Original pre-existing website work was not staged or committed wholesale. The patch is archived here so the website changes have a reviewable durable commit without mixing unrelated work.

Public promotion still needs a usable tester path, license/publication review and a deployed candidate. Do not advertise a publicly available Windows installer or link a private source repository as if it were accessible to all. Next evidence: ask unfamiliar testers to explain the product and complete their first task using only the package and docs.

Reference used for the SEO approach: [Google Search Central SEO Starter Guide](https://developers.google.com/search/docs/fundamentals/seo-starter-guide). Content clarity and crawlable page metadata support discovery; no ranking improvement is claimed from local checks.
