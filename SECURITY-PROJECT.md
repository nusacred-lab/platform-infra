# Project security controls

This repository belongs to the synthetic-data Competency Proof demo on nusacred-lab.
CI uses ephemeral GitHub-hosted runners, full-SHA actions and checksum-verified
scanners. PR and build jobs use read-only tokens. The P6 release workflow grants
registry/OIDC permissions only to downstream publication jobs on main or the
explicit codex/p6-release candidate branch after all build groups pass. Images
retain the synthetic-isolated-demo-only scope; publication is not production
promotion. APK signing stores and passwords remain offline. There are no
production credentials or automatic deployment jobs. Scanner errors and High/Critical findings block acceptance.

Secret scans cover complete Git history. Inherited findings remain findings until
individually reviewed; an upstream fixture is not automatically a safe exception.
Do not upload unredacted reports, keys, credentials, databases, reset links or QR grants.

Changes use pull requests and required checks. The current maintainer is abeinoe;
CODEOWNERS does not imply independent two-person review. Emergency bypasses must
be recorded. Dependency review checks PR changes; it does not replace scanning
resolved Gradle dependencies or final images. Build metadata generated during
bootstrap is a candidate requiring source/checksum review, not accepted lock state.

Report suspected vulnerabilities through GitHub private vulnerability reporting
when enabled. Do not post secret values in public issues.
