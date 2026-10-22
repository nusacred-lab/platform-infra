# P5 presentation preview

The Compose web bundle is embedded in each application image. The issuer, custodian
and company BFFs keep separate sessions and roles. The public company view lists job
requirements; applicant records require an owned browser session or company role.

Use `scripts/run_p5_stack.py --env-file /absolute/private/runtime/p5/compose.env` only
with scanned, immutable application image IDs. Prepare the private environment by
copying the existing P2 environment and adding `P3_ISSUER_IMAGE`, `P3_COMPANY_IMAGE`
and `P4_RUNTIME` (the directory holding the shared 32-byte offer capability key).
Keep the existing P2 issuer configuration, wallet data and Android signing key.
Do not run the isolated P4 preparation script against this environment.

Before activation, back up the access registry with SQLite's backup API, the private
protocol configuration and data, environment file and signing key. Keep backup
permissions private. Grant only container UID 10001 read access to the mounted
offer key and organization mapping files (for example, a user ACL); do not make
the private runtime directory public. Access-registry upgrades and session invalidation follow the
P4 implementation; the issuer and company databases use separate named volumes.
A rollback that predates a schema upgrade requires the matching consistent backup.

The edge imports `local-demo/p2-routes.caddy`, including issuer/company prerelease
hostnames. Ensure the existing Pinggy TLS tunnel forwards all four prerelease
hostnames; add the two portal forwards to its private SSH configuration without
changing its credentials. Restart the edge/tunnel after validating configuration.

The P5 ingress permits the verified wallet links and new application contracts. It
does not publish the Keycloak console, inbox, recovery coordinator, raw Wallet API,
private databases or key export. Credential approval remains in the APK. Do not
add public wildcard routes to resolve a missing endpoint.

Validate the loaded configuration before activation. After activation, check all
three portal identities, unauthenticated record-list denial, asset links, the
existing issuer public-key fingerprint and actual Android receive/present flows.
P5 preview validation does not replace P6 release acceptance or P7 operations.

## Branded identity and approved mobile renewal

Mount the reviewed `themes/nusacred` directory with the P5 overlay, then run
`scripts/configure_p5_auth.py --runtime /absolute/private/identity/runtime`.
The helper backs up current realm/client settings privately, selects the login
theme and applies the approved five-minute access / 24-hour idle / seven-day max
mobile policy. Refresh rotation remains enabled with zero reuse. Browser clients
retain their shorter client-session limits; no offline access or direct password
grant is enabled. The existing guarded recovery flow and disabled account console
remain intact. Theme inheritance preserves upstream authentication forms, actions,
validation and password visibility; custom CSS/messages/footer provide wallet branding.
The ingress adds only native renewal and the standard OIDC token revocation path.

## Independent organizations and named domains

Activate `independent-identity.compose.yaml` after `experience.compose.yaml` and
before any active walkthrough storage overlay. The issuer and employer each run
a separate provider-free Keycloak image and PostgreSQL service, with distinct
private database volumes, credentials, bootstrap administrators, internal database
networks, signing keys and client secrets. Their exact login origins are
`login-lsp-nusantara.demo.inoerawan.id/realms/lsp-nusantara` and
`login-karya-instalasi.demo.inoerawan.id/realms/karya-instalasi`. The wallet retains
its existing issuer, accounts, keys, coordinated recovery and mobile token policy.
No identity broker or cross-entity SSO is configured. Synthetic SMTP and the TLS
edge share host infrastructure for the demo; this is not physical host isolation.

Stop the source Keycloak and application writers, take a consistent database and
application backup, and export the realm offline with credentials. Run
`prepare_p5_independent_identity.py` against that private export into a new private
runtime directory. It retains staff subjects/password hashes while excluding
wallet users, wallet clients, source signing keys and identity federation. Import
only into empty independent databases. Prepare distinct database/bootstrap
credentials and the scanned `P5_STAFF_KEYCLOAK_IMAGE` before activation; the two
generated client secrets replace the old BFF secrets through the new overlay.
Verify staff logins before removing migrated users, staff roles and business
clients from the wallet realm. Invalidate old shared sessions during cutover.
Do not rerun old shared-realm fixture provisioning after this migration.

Run `check_p5_independent_identity.py --accounts <private-accounts.json> --output
<private-report.json>` for same-browser login, empty cross-entity login identity,
wrong-entity credential rejection, distinct signing keys, local recovery forms and
independent logout. Default transport verifies TLS through loopback. Check public
routes without credentials separately. Preserve offline rollback exports privately;
they contain password hashes and secrets. Do not publish them as evidence.

The issuer uses `lsp-nusantara.demo.inoerawan.id`, the custodial wallet uses
`dompet-identitas.demo.inoerawan.id`, the employer uses
`karya-instalasi.demo.inoerawan.id`, and the wallet-provider IdP uses
`login-dompet-identitas.demo.inoerawan.id`. Exact routes retain the existing
administrative boundary; old public entry points redirect to the matching entity.
All names are covered by the existing one-level wildcard certificate. Add the
four named TLS forwardings to the existing private tunnel; do not print its token.

Run exactly one tunnel supervisor, independently of the interactive terminal.
An interrupted connection can leave a remote session registered, causing the next
connection to be rejected as already active. For a token dedicated exclusively
to this demo, the private SSH `User` value may include Pinggy's `+force` option
to replace that stale session on reconnect. Never enable this for a shared token
or run competing supervisors. The helper redacts the underlying token with or
without this option and still stops on authentication or host-key failures.
Idle portal traffic does not deliberately stop the supervisor. Public access
still requires the local host to remain awake and connected to the internet.
The private deployment can pin a previously verified provider endpoint to avoid
server changes during reconnects and stale DNS destinations. Preserve the exact
existing host-key identity with `HostKeyAlias` (including its port); keep strict
host-key checks enabled. Revalidate public HTTPS after reconnecting, rather than
treating SSH authentication alone as readiness. This pin is an operational
workaround and must be reviewed if the provider retires that endpoint.

The P5 overlay fixes `KC_HOSTNAME` and the recovery issuer to the new IdP origin.
During a maintenance window, back up PostgreSQL, wallet and registry volumes and
private configuration, configure exact client callbacks with
`configure_p5_entities.py`, and log out old IdP sessions. Stop the custodian and
identity writers before copying the registry. Run `migrate_p5_registry_domain.py`
on the offline copy, inspect its invariant report, then install it with the
original ownership. Preserve the active walkthrough storage overlay when starting
the services. Check real login, recovery links, the same account/wallet bindings,
refresh, new App Links and private-route denial before handing back access.

This is a one-time issuer-URL migration, not a general issuer alias or bypass.
Never simply change `OIDC_ISSUER` on an existing registry: its `(issuer, subject)`
identity mapping would otherwise create different accounts. Realm/client IDs,
subjects, secrets, keys and recovery guards stay intact. Old mobile candidates
must be updated to signed versionCode 4. Use the new P5 transport/checks for these
domains; dated P2-P4 reports and compatibility harness defaults are historical.

Login themes are client-specific: purple `lsp-nusantara`, copper/navy
`karya-instalasi`, and teal `nusacred` for wallet clients. The footer distinguishes
the destination organization from authentication operated by the wallet provider.

The private `access` proxy gains a matching IdP hostname and application-network
alias. The backend still enforces equal issuer/backchannel hosts and full TLS
verification; the new private Caddy file is never imported by public ingress.
See [Keycloak hostname configuration](https://www.keycloak.org/server/hostname)
for why frontend URL changes affect discovery, tokens and action links.


## Public portal asset delivery

`ingress.caddy` compresses successful content-addressed JavaScript and WebAssembly
with negotiated zstd/gzip. Immutable public caching applies only to exact hashed
asset paths, GET/HEAD and status 200/206/304. HTML, authentication, application APIs,
errors and unversioned assets remain `no-store`. The wallet route allowlist permits
the two fingerprinted JavaScript names without widening credential or admin routes.
The application image packager versions JavaScript by content and rewrites HTML.

Run `check_p5_web_delivery.py --output <private-report.json>` for verified-loopback
byte/digest/compression/cache checks on all three portals. `--public` sends only
anonymous requests to verify the real public transport; it never sends account
credentials. Also run the authenticated BFF boundary and identity-isolation checks
through loopback. Browser inspection must verify the startup screen disappears
and normal refresh completes. Do not infer multi-hour cache retention or a fixed
load time from a short test; browsers may evict assets or bypass cache on hard reload.

## Public LSP profile and employer trust review

Set `P5_ISSUER_PUBLIC_IDENTITY_FILE` to the existing absolute path of the protocol's
`public-issuer.json` file. The issuer portal reads only that public file, generated
from the existing protocol identity. The bind mount refuses to create a missing
source path. Never mount `issuer2-profiles.conf` into the
portal: that file contains the private signing key. Before activation, compare the
public file's `identity` (or retained P2 `did`) with the actual `competencyDemo.issuerDid` without printing
private configuration or regenerating keys.

The anonymous LSP profile is `https://lsp-nusantara.demo.inoerawan.id/?view=issuer-profile`.
The company BFF retrieves its exact JSON publication through verified HTTPS on
port 8443. The ingress has a matching application-network DNS alias; no new host
port or public tunnel forwarding is needed. The fixed endpoint validates TLS,
rejects redirects and accepts no user-supplied URL. Independent organization
verification is still the employer's responsibility; this is not an accreditation
registry or automatic trust anchor.

In the company portal use **Trusted issuers → Review issuer → Approve trust**.
Select **Demo walkthrough only** for these synthetic organizations and record how
the identity was checked. Publication never enables trust automatically. Existing
trust entries retain their identity/revision and display a missing-review notice;
a new approval attaches provenance. Issuer/company database migration 3 requires a
consistent pre-migration checkpoint; old binaries need their matching old database
snapshots for rollback. Retain only the current verified recovery checkpoint.
