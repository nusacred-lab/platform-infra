# Competency Proof Infrastructure

Docker Compose deployment, release packaging and operational tools for
[Competency Proof](https://github.com/nusacred-lab/competency-proof), a digital
credential demo for an electrical installation technician.

The stack runs real walt.id issuer, wallet and verifier services alongside the
application portals, identity services and persistent storage. It supports the
complete journey: issue a synthetic competency credential, receive and store it
in a custodial wallet, then present it to an employer for verification.

## What's in the stack

| Component | Role |
| --- | --- |
| Issuer application | Assessment records and credential offers for LSP Nusantara |
| Custodian application | Wallet access, consent, invitations and account recovery for NusaCred Wallet |
| Employer application | Job requirements, issuer trust and verification results for Karya Instalasi |
| walt.id issuer, wallet and verifier | Credential issuance, server-side storage and cryptographic verification |
| Keycloak and PostgreSQL | Independent identity services and databases for the three organizations |
| Caddy | HTTPS termination and routing to public application endpoints |
| Mailpit | Private mailbox for isolated installation testing |

The Android wallet is installed separately. Application and wallet state persist
in Docker volumes; credentials and holder signing keys remain on the server.
Public deployment replaces the test mailbox with authenticated SMTP and adds
tunnel, monitoring, backup and lifecycle management.

## Install an isolated demo

Use Linux x86_64 with Docker Engine, Compose v2, Python 3, OpenSSL, GitHub CLI and
Cosign 3.1.3. Authenticate to GitHub and GHCR if the selected artifacts or images
are private. The host does not need application source, Gradle, a JDK or an Android
SDK.

The [installation guide](release/README.md) contains the full verification and
setup procedure. The essential steps are:

1. Select a successful [release workflow](.github/workflows/release.yml) run and
   independently review its full infrastructure commit and branch.
2. Download its `p6-distribution` artifact. Verify the Compose archive's GitHub
   attestation against that commit and branch before extracting it.
3. From the extracted `competency-proof` directory, prepare a private runtime and
   start the stack:

   ```sh
   python3 install.py prepare --runtime /absolute/private/runtime/demo \
     --trusted-commit FULL_REVIEWED_INFRA_COMMIT
   python3 install.py pull --runtime /absolute/private/runtime/demo
   python3 install.py up --runtime /absolute/private/runtime/demo
   ```

   This example selects a release from `main`. For the retained candidate branch,
   follow the exact branch verification instructions in the installation guide.

Preparation verifies the release manifest, image signatures, provenance and SBOMs,
then generates fresh keys, secrets and synthetic accounts. Account credentials
are written to `installation.json` inside the private runtime. Keep that directory
outside source control with a private parent directory (mode 0700).

The release uses digest-pinned images with no on-host builds. The Compose
definition is [release/compose.yaml](release/compose.yaml); run the installer from
the verified distribution, which also contains its attested release manifest.
A source checkout alone is not the assembled installation package.

## Access and credential walkthrough

The prepared stack binds HTTPS to `127.0.0.1:28443`, private identity administration
to `127.0.0.1:28444` and the test mailbox to `127.0.0.1:28025`. Local browser access
requires hostname mappings and certificate trust as described in the installation
guide. The default staging certificate is not trusted by Android.

Public routing uses these application hostnames:

| Interface | Hostname |
| --- | --- |
| Issuer portal | `lsp-nusantara.demo.inoerawan.id` |
| Wallet provider portal and Android App Links | `dompet-identitas.demo.inoerawan.id` |
| Employer portal and public job page | `karya-instalasi.demo.inoerawan.id` |

Those hostnames need operator-controlled DNS, trusted TLS and ingress configuration;
starting a fresh installation does not publish it at those addresses. The signed
APK must match the wallet origin and published signing-certificate association.
Never expose private administration, mailbox, database or diagnostic listeners.

With the services and matching APK running:

1. Sign in to the wallet and copy the participant's recipient code.
2. In the issuer portal, record a synthetic assessment for that recipient and
   create a credential offer.
3. Scan the offer in the Android wallet, review it and approve receipt. Confirm
   the issued credential appears in the wallet.
4. In the employer portal, configure the job requirement and approve the issuer
   through **Trusted issuers**.
5. Open the public job page, select **Check my competency**, then scan or open the
   request in the wallet. Select the credential and approve presentation.
6. Read the verification result on the job page and in the employer portal. The
   result combines proof verification with issuer trust and the job requirement.

See the application's
[wallet and portal guide](https://github.com/nusacred-lab/competency-proof/blob/main/docs/p5-experience.md)
for consent, recovery and verification behavior.

## Operate the deployment

The public demo runs on an operator workstation with Caddy and Pinggy Pro TLS
passthrough. The [operations runbook](operations/README.md) covers daily start and
shutdown, SMTP, participant invitations, monitoring, encrypted backups, restoration
and scheduled retirement. It also documents the dedicated-VM variant.

Updates must use a verified release and retain the existing keys, volumes and
account-to-wallet mappings. Take a consistent encrypted backup before updating.
Rollback across incompatible database schemas requires the matching snapshot;
do not remove retained volumes during an update or restart.

The workstation setup depends on the host and its internet connection. Its local
backups and monitors share that host, so independent off-host storage and outage
detection remain limitations. This is a synthetic demonstration deployment, not
a production service.

## Repository guide

| Path | Contents |
| --- | --- |
| `release/` | Compose definition, installer, public templates and release image manifest |
| `operations/` | Deployment lifecycle, invitations, monitoring, backup and restore tools |
| `ci/` and `.github/workflows/` | Build, scan, sign, publish and package automation |
| `docs/` | Detailed setup and validation records |
| `local-demo/`, `p2/`–`p5/` and `scripts/` | Earlier integration environments and supporting diagnostics |

Run `python3 ci/check_policy.py` from the repository root to check source-control
and workflow policy. See [SECURITY-PROJECT.md](SECURITY-PROJECT.md) for security and
review controls. Secrets, private runtime configuration, keys and backups belong
outside this repository.

Licensed under [Apache-2.0](LICENSE). Application source is maintained in
[competency-proof](https://github.com/nusacred-lab/competency-proof); credential
services are maintained in the
[walt.id fork](https://github.com/nusacred-lab/waltid-identity).
