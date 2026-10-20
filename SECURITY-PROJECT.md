# Project security controls

This repository belongs to the synthetic-data Bukti Kompetensi demo on nusacred-lab.
CI uses ephemeral GitHub-hosted runners, read-only tokens, full-SHA actions and
checksum-verified scanners. There are no production credentials, registry publish
or deployment jobs. Scanner errors and High/Critical findings block acceptance.

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
