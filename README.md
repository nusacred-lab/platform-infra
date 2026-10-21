# Platform Infrastructure — Competency Proof

Infrastructure and release controls for the nusacred-lab synthetic-data demo.
Target operations: one local Linux x86_64 host with Docker Compose and Pinggy Pro
TLS passthrough. Caddy terminates TLS locally. Public demo hostnames live under
`demo.inoerawan.id`; Rumahweb manages DNS. Builds primarily run on ephemeral
GitHub Actions runners, outside the active demo runtime. Encrypted off-host
backups, restoration, and rollback remain required.

The [local demo runbook](docs/local-demo.md) prepares a loopback-only TLS probe.
It does not deploy the application, Keycloak, or credential services. Public
routing and G1 containment must be reviewed before those services are exposed.

P1 status: repository and CI foundations. Production configuration is not yet
ready to deploy. Do not use the Python harness Compose setup as a public
deployment. Store only templates without secrets. Databases, keys, keystores,
tokens, runtime data, and backups belong in private storage. Pull request
workflows have no deployment or publishing privileges.

Local check: `python3 ci/check_policy.py`. CI scans the full Git history and
reviews dependency changes. See SECURITY-PROJECT.md for control and review limits.
Project code: Apache-2.0 (LICENSE).

All repository work must use English; see [AGENTS.md](AGENTS.md).

## Private P2 identity proof

The P2 branch adds production-mode Keycloak/PostgreSQL, private synthetic SMTP,
and loopback-only diagnostics on independent networks and persistent volumes.
See [P2 identity proof](docs/P2-identity-proof.md) for pinned image/source builds,
security checks, restart evidence, reproduction and remaining recovery work.
G2 and public application ingress remain open gates.

Current P2 work includes a persistent custodian recovery registry, guarded
Keycloak password changes, private role-separated portal BFFs and isolated
source-built protocol services. See [P2 recovery operations](docs/P2-recovery-proof.md).
Public login and the signed Android certificate association are active. The
credential/recovery public override is staged and requires separate approval;
physical acceptance and G2 remain open.
