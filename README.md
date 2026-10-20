# Platform Infrastructure — Competency Proof

Infrastructure and release controls for the nusacred-lab synthetic-data demo.
Target operations: one Linux x86_64 VM with Docker Compose, HTTPS, private
networks, Keycloak/PostgreSQL, the application backend, issuer/wallet/verifier,
and private SMTP. Builds and CI run outside the VM. Encrypted off-VM backups,
restoration, and rollback must be demonstrated before opening the demo.
The provider, region, and backup destination have not been selected.

P1 status: repository and CI foundations. Production configuration is not yet
ready to deploy. Do not use the Python harness Compose setup as a public
deployment. Store only templates without secrets. Databases, keys, keystores,
tokens, runtime data, and backups belong in private storage. Pull request
workflows have no deployment or publishing privileges.

Local check: `python3 ci/check_policy.py`. CI scans the full Git history and
reviews dependency changes. See SECURITY-PROJECT.md for control and review limits.
Project code: Apache-2.0 (LICENSE).

All repository work must use English; see [AGENTS.md](AGENTS.md).
