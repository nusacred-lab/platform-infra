# P2 private recovery and signed Android candidate

The application implements the persistent account/wallet registry and the guarded
Keycloak `UPDATE_PASSWORD` provider. See the application repository's
`docs/P2-recovery-proof.md` for the invariants and transaction boundary.

## Composition and private files

Merge these files in order using `run_p2_stack.py --runtime <private-identity-runtime>`:

1. `p2/compose.yaml`
2. `p2/application.compose.yaml`
3. `p2/prerelease.compose.yaml`
4. `p2/recovery.compose.yaml`
5. `p2/portals.compose.yaml`
6. `p2/walt.compose.yaml`

The runtime environment contains immutable scanned IDs for the custodian,
Keycloak, issuer, wallet, verifier, PostgreSQL, Mailpit and Caddy images, plus
`P2_WALT_RUNTIME` pointing to separate synthetic protocol configuration/data.
`recovery-service-secret`, three distinct BFF client-secret files, PostgreSQL and
bootstrap credentials stay in the protected ignored runtime directory. The
custodian named volume contains its SQLite registry. Preserve it together with
Wallet2 data; never reset a registry to repair a failed request.

The provider is compiled against the exact reviewed base Keycloak image. Build
`Containerfile.keycloak-recovery` with the resulting provider JAR as its entire
context. A local image configuration ID is not a registry manifest reference:
assign a verified local build tag to that exact ID before using it as `FROM`.
Record the actual final image ID and rescan it before updating private runtime.

The source-built walt.id images use the pinned fork, reviewed dependency hashes
and its `ci/Dockerfile.api2`. Generate fresh configuration with the fork's
`ci/harness/prepare.py`; never copy upstream example signing/authentication keys.
The historical demo containers, networks and data are separate and preserved.

Protocol services have exclusively internal networks. A separate
`protocol-access` proxy publishes diagnostic ports 17004/17005/17006 on host
loopback. It has no application network. Issuer/company BFFs therefore cannot
reach raw wallet routes through the application diagnostic proxy. Wallet2 joins
only the protocol and custodian-wallet networks. Recovery uses its own internal
network and HMAC service identity.

The custodian image extracts the reviewed SQLite native library at build time,
so its `/tmp` remains `noexec`. Wallet2 retains the baseline-tested executable
SQLite extraction tmpfs. All services run without root, additional capabilities
or privilege escalation; protocol images and the custodian have read-only roots.

## Guard setup and evidence

After listener readiness, run `configure_p2_login.py` and
`configure_p2_recovery.py` against the private runtime. The latter disables account
clients, protects the commit-marker profile attribute, forces a fresh login and
enables private email reset. Unmanaged attributes are represented by a null policy
in Keycloak 26.8.1; there is no `DISABLED` enum value.

Run integration checks sequentially when they change or restart services:

- `test_p2_portals.py`: three confidential clients, correct admin roles, rejected
  applicant role and transplanted host-only cookies.
- `test_p2_recovery.py --protocol-harness <fork>/ci/harness`: normal email recovery,
  two sessions, old refresh/token rejection, same wallet/key/credential and real VP.
- Add `--required-action` for the authenticated required-action path, or
  `--restart-validated-flow` for an abandoned validated flow and stale browser retry.
- `test_p2_recovery_unavailable.py`: no pre-write acknowledgement means no password
  update; a forged completion cannot change access.
- `test_p2_recovery_concurrency.py`: two email-validated requests, observed
  PostgreSQL lock holder/waiter, one final password and revoked prior app session.
- `test_p2_password_paths.py`: restricted account/admin APIs, expired signed action
  token, protected marker and actual verification-email confirmation/consumption.
- `test_p2_wallet_restart.py`: actual Wallet2 container restart with unchanged key
  and credential and an authorized custodian read afterwards.

For the completion-loss proof, start `run_p2_stack.py --mode lost-completion`,
then run `test_p2_recovery.py --expect-lost-completion`. Its private fault proxy
forwards authenticated begin requests but returns 503 for completion. The proof
restarts the custodian and confirms the gate remains closed, then invokes the
offline reconciler. Always restore `--mode normal`; this removes the disposable
fault proxy. Do not run a wallet/session test concurrently with an IdP restart.

`reconcile_p2_recovery.py` accepts only the matching committed administrator-only
IdP marker and revokes IdP sessions before acknowledging. It never clears a gate
because a password request merely appears to have succeeded. A newer validated
flow can supersede an abandoned operation only through the guarded IdP lock.

Raw reports, browser pages, cookies, reset links, passwords and tokens remain in
ignored runtime. Public evidence contains only fixed-schema outcomes, artifact
hashes, immutable IDs and declared limitations.

## Signed candidate and public boundary

`assetlinks.json` associates only package `id.nusacred.wallet` and the controlled
P2 candidate signing certificate. The debug package has a different custom scheme.
The native HTTPS callback is exactly
`https://wallet-p2.demo.inoerawan.id/auth/android/callback`; debug callback remains
`id.nusacred.wallet.debug:/oauth2redirect`. There are no wildcard redirects.

The default login-only Caddy configuration permits login, portal
assets and the public certificate association. It denies reset/action-token/
required-action, credential/presentation APIs, admin, account console, mailbox,
raw protocol routes and health. Three portal BFFs are proved over private TLS;
only the custodian login portal is currently public.

On 21 October 2026, the owner explicitly approved and activated
`credential-testing.compose.yaml` and `credential-testing.caddy` for P2 testing.
They permit the guarded Keycloak
email/required-action paths and these five authenticated native wallet routes:

- `POST /api/v1/wallet/provision`
- `POST /api/v1/wallet/reconcile`
- `GET /api/v1/wallet/credentials`
- `POST /api/v1/wallet/preview`
- `POST /api/v1/wallet/present`

The override also serves an optional temporary `/p2-test` browser-link page from
private runtime. Public admin/account/mailbox/raw-Wallet2/health routes remain
denied. Recovery coordination stays internal and cannot be opened by that
allowlist. Activate this expansion with `run_p2_stack.py --public-credential-testing` only
after explicit approval beyond the prior login-only exposure; preserve that flag
for subsequent stack operations while the approved expansion is active.
`check_p2_ingress.py --credential-testing` passed 30 checks through both public
and loopback verified TLS. `test_p2_recovery.py --public-frontend` passed ten
real-service checks, including old-session revocation and retained-credential
presentation accepted by the actual verifier. These HTTP checks do not substitute
for physical APK acceptance.

A verified domain and an installed signed APK do not prove a physical QR scan or
completed credential/recovery journey. Keep G2 open until those results are recorded.


Physical phone evidence now also covers synthetic email recovery, rejection of the
old native session, actual candidate uninstall/reinstall, fresh HTTPS callback
login and presentation of the byte-identical retained credential (`SUCCESSFUL`).
An actual Chrome button opens the signed APK's verified HTTPS request without
sending automatically. Optical camera scanning remains a separate pending check.


Same-second fresh authentication uses registry schema 2: a server-issued,
nonce-bound flow must start strictly after the durable millisecond completion
boundary. OIDC still forces login and checks nonce, signature, role and live
introspection. Older, equal-boundary, unknown and future flows cannot use this
exception. Schema-one recovery timestamps migrate conservatively to the end of
the recorded second without changing wallet/key bindings. The camera preview
also clips its TextureView to Compose bounds; the phone no longer shows preview
overlap over the title or scanner controls.
