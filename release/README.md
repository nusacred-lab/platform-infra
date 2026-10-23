# Install the synthetic Competency Proof release

This package contains the Compose definition, public templates and a private-state
preparation tool. It does not need the application/fork source, Gradle, a JDK or an
Android SDK. Images are built on ephemeral GitHub runners and pinned by registry
digest. Linux amd64 is the reviewed platform. This is an isolated synthetic demo,
with the inherited G1 exception still applicable; it is not a production release.

## Prerequisites and verification

Install Docker Engine with Compose v2, Python 3, OpenSSL, GitHub CLI and Cosign
3.1.3. Authenticate to GitHub/GHCR if packages are private. Read the trusted
workflow commit and branch from the reviewed PR/run independently, rather than
accepting an identity supplied only by an untrusted download.

Download `p6-distribution` from the successful P6 workflow run. Before extracting,
verify `competency-proof-compose.tar.gz` with:

```sh
gh attestation verify competency-proof-compose.tar.gz \
  --repo nusacred-lab/platform-infra \
  --signer-workflow nusacred-lab/platform-infra/.github/workflows/release.yml \
  --source-digest FULL_REVIEWED_INFRA_COMMIT \
  --signer-digest FULL_REVIEWED_INFRA_COMMIT \
  --source-ref refs/heads/main --deny-self-hosted-runners
tar -xzf competency-proof-compose.tar.gz
cd competency-proof
python3 install.py prepare --runtime /absolute/private/runtime/p6 \
  --trusted-commit FULL_REVIEWED_INFRA_COMMIT
```

For the initial P6 candidate only, explicitly use
`--trusted-ref refs/heads/codex/p6-release` in the preparation command and the same
`--source-ref` for archive verification. Main and that exact candidate branch are
the only accepted identities. No arbitrary repository, branch or mutable image
reference is accepted. Preparation verifies the manifest's GitHub attestation,
image signatures, provenance and signed SBOMs before generating private state.

The default preparation creates a fresh seven-day staging certificate, new issuer
and identity keys, distinct organization databases/secrets and private synthetic
accounts. It never copies the active demo database or keys. Account credentials
are in `installation.json` under the private runtime. They are preverified login
fixtures; this alone is not evidence of email verification. Keep the parent mode
0700. Container-readable secret files are 0644 inside that private directory.

For operator-supplied TLS, add `--certificate-directory /private/runtime/tls`
containing `fullchain.pem` and `privkey.pem`. Public DNS/TLS/tunnel setup and public
APK acceptance belong to P7. The generated staging certificate is not trusted by
Android and must not be used to claim verified public App Links.

## Initial startup and subsequent starts

```sh
python3 install.py pull --runtime /absolute/private/runtime/p6
python3 install.py up --runtime /absolute/private/runtime/p6
```

Initial startup waits for identity discovery, disables account-console credential
writers, restricts the recovery marker to administrators and requires a fresh
login after recovery. It then starts the full stack. On subsequent starts:

```sh
docker compose --env-file /absolute/private/runtime/p6/compose.env pull
docker compose --env-file /absolute/private/runtime/p6/compose.env up -d
```

There are no `build` sections or pre-existing external networks. All containers
use bounded memory/processes and rotating logs. State volumes are scoped by the
chosen project name. Keep the runtime path, project name and volumes together.
BFFs restart while their identity discovery is unavailable during a cold start.

Only loopback listeners are published: HTTPS 28443, private identity admin 28444,
and private mailbox 28025. Never forward admin/mailbox ports to a tunnel. Protocol
diagnostics require the explicit `acceptance` Compose profile and bind only to
loopback 37004/37005/37006. Public routes retain the reviewed P5 allowlist. For a
local browser, use a separate hosts/DNS mapping for the entity hostnames and trust
the staging certificate in a separate test profile; do not change active demo DNS.

## Updates, rollback and APK

Save the previous verified manifest/environment and take a consistent backup
while writers are stopped. Verify the new package, run preparation against the
same private runtime/project, then pull/start. Preparation preserves generated
accounts, client secrets, issuer key and capability key. Realm import files apply
only to empty databases; they do not overwrite existing identities.

The P6 schemas match the P5 baseline: registry version 5, business migration
version 3, policy `competency-v1`. Compatible rollback uses the previous verified
image manifest and environment with the same volumes. Do not downgrade a newer
schema. For an incompatible rollback, stop writers and restore the complete
consistent database/key/mapping snapshot before restarting the previous release.
Never run `down -v` against a retained installation. Restart alone is not an
upgrade/rollback proof; record actual before/after digest, schema and credential
verification evidence in G6 acceptance.

The CI unsigned APK is signed offline with the existing candidate key using the
application's `package_p6_release.py`. Include the signing record, signed checksum
and certificate fingerprint in the final release manifest/evidence. Install APK
version code 5 on Android separately. Preserve its signing identity when updating;
Android normally forbids a lower version-code downgrade, so a forward recovery
build or an explicitly tested uninstall/recovery procedure is required.

G6 requires release-candidate acceptance with per-case evidence. The package's
manifest starts with G6/G7 pending. Public participant access, external encrypted
backups, restore/RPO/RTO, operational monitoring/alerts and lifecycle remain P7.
