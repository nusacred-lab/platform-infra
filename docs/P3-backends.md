# P3 backend deployment boundary

The optional `p3/backends.compose.yaml` overlay uses separate issuer/company
application distributions, databases and organization-assignment mounts. Merge
it after the existing P2 identity, application and portal configurations, using
`--project-directory p2` so relative P2 paths retain their meaning. Validate the
combined configuration before startup. The overlay does not change active P2
containers or public ingress; deploying it requires scanned immutable images.

Build the application repository's `custodian-backend:installDist`,
`issuer-backend:installDist`, `company-backend:installDist` and portal distribution.
The issuer/company Containerfiles reuse the reviewed native SQLite library from
the custodian distribution and the same pinned JRE base. The services retain the
private application network, non-root identity, read-only root filesystem,
resource limits, no Docker socket and per-client secret mounts inherited from P2.

Create private `issuer-organizations.json` and `company-organizations.json` in
`P2_RUNTIME`. Each is a JSON object mapping an existing Keycloak subject to an
organization identifier. Do not use emails as identifiers. Only the operator
may edit these files; they are secret mounts and never committed. Organization
IDs match `[A-Za-z0-9_-]{1,128}`. Subject membership is read at startup; restart the
corresponding backend when assignments change to invalidate existing sessions.
A missing assignment denies administrative data access even with a valid role.
The backend ignores client-supplied organization fields and user profile claims.

P2 roles map explicitly to the stable API role enum: `applicant` to `CANDIDATE`,
`issuer-admin` to `ISSUER_ADMIN`, `issuer-operator` to `ISSUER_OPERATOR`,
`custodian-admin` to `WALLET_ADMIN`, and `company-admin` to `COMPANY_ADMIN`.
`issuer-operator` must be assigned by a realm administrator; registration cannot
assign it. The role is declared by the application contract; add it through
controlled realm administration when testing that operator journey in P4/P5.

The public credential ingress allowlist remains the P2 allowlist. Stable P3
business routes are private until their P4 adapters and P5 portals are accepted.
No raw Wallet2, issuer management, verifier result-management, mailbox, health or
internal recovery route is opened by this overlay. API docs are in the application
repository at `docs/openapi.json`. A P3 reservation is not protocol completion.

Back up each application database and the custodian access registry before a
migration. Registry schema 3 adds persistent previews, consent idempotency and
audit without rotating wallet/key references. Roll back with a consistent backup
and the matching old binary; schema 2 binaries deliberately reject schema 3.
Do not start an old binary against a newly migrated volume. Full restore and
production-domain acceptance remain P7 work.
