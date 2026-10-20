# P1 Controls

Date: 20 October 2026. Public nusacred-lab repository, Apache-2.0 license.
The default branch `main` requires pull requests and the `security` and
`dependency-review` checks from GitHub Actions app 15368. Branches must be current;
force pushes and deletion are prohibited. Rules apply to administrators, and
review conversations must be resolved.

Actions are pinned to full commit SHAs, use ephemeral runners, and have read-only
default tokens. Workflows cannot approve pull requests. Only GitHub-owned actions
are allowed. Secret scanning, push protection, vulnerability alerts, and private
vulnerability reporting are enabled. Readback shows non-provider patterns are not
enabled; Gitleaks adds generic-pattern scanning across the full Git history.
Pull request dependency review does not replace resolved-dependency SCA or image
scanning.

There is one maintainer (`abeinoe`). Pull requests and CI are required, but the
required human approval count is zero. CODEOWNERS does not establish two-person
or independent review. The initial foundation commit was pushed before branch
protection to establish the workflows; later changes follow the pull request path.

Negative gate evidence: https://github.com/nusacred-lab/competency-proof/pull/1
A harmless marker file made the security check fail. An administrator merge
attempt was rejected with `Required status check "security" is failing.` The
trial pull request was then closed without merging. No CVE or secret was
intentionally published.

Historical P1 foundation status: project G1 had not passed at this point. Fork
builds, dependency locking/verification, and baseline/target-image scans are
tracked in waltid-identity. This repository foundation does not establish that
the application or deployment is available. Current gate status follows the
workspace implementation plan and its latest evidence.
