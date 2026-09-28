# Tester entry and withdrawal documentation — 2026-09-28

The user approved publishing syin31437@gmail.com for Alpha requests. The website now offers localized email drafts and an explicit manual bundle handoff, plus Windows changes and owner-assisted withdrawal guidance. No email was sent, Windows device changed or repository made public.

The patch is incremental against the previously deployed site (dpl_EJetX1h47mteGnJAMQYyQinyyuTy), not against the website repository's older tracked baseline. Before/after hashes are recorded in manifest.json; the website has pre-existing uncommitted work.

Validation: targeted ESLint and Next.js production build passed; 15 local HTTP routes passed, including both homepages and four new documents. Parsed links confirm the request anchor and recipient/subject/body. Chrome confirmed the request layout, retained Mac lifebuoy illustration and prompt disclosure. No actual mail client send, inbox delivery or end-to-end Windows removal was tested. No controller code changed.

License preparation remains a decision checklist in ../LICENSE_RELEASE_CHECKLIST.md; ownership, license choice and third-party notices are still pending.

Production: canonical alias resolves to Ready deployment dpl_91yVvDZ5Wizfd975xze59gaqsWoj. All 15 HTTP checks passed on production; see deployment.json and production-checks.json. Gitleaks source scan found zero detections; this is not a security audit.
