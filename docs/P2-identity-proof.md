# Private P2 identity proof — 21 October 2026

Owner: repository maintainer, assisted by Codex. P2.2 is partially proven; G2 is
open. This stack is private to the host. It is not the public demo deployment.

## Proven scope

Keycloak 26.8.1 runs `start --optimized` with PostgreSQL 18.6, TLS, an independent
`competency-proof-p2` realm, database volume and fresh realm signing keys. A
separate private Mailpit receives only `@example.test` recipients. An internal
Docker network has no credential-service containers or public-edge connection.
A separate diagnostic Caddy proxy publishes only `127.0.0.1:18443` (HTTPS) and
`127.0.0.1:18025` (private mailbox). PostgreSQL, Keycloak management/admin ports,
and SMTP have no direct host publication. The proxy's fixed upstreams cannot be
used as a general outbound proxy; the identity services have no egress network.
Admin access is available through this local diagnostic HTTPS endpoint only.

The real-service smoke checks prove discovery issuer/JWKS, public native client
without a secret, PKCE S256, exact redirects, disabled password/implicit grants,
three distinct confidential BFF clients and four business roles. Verification and
password-action emails reach private SMTP with the fixed prerelease hostname.
Restarting Keycloak and PostgreSQL preserves realm ID, signing key IDs and the
synthetic account. No tokens, inbox bodies or passwords belong in public reports.

## Image and source review

`p2/images.json` pins upstream image references. Final runtime references are
immutable local image IDs written only after `scripts/check_p2_images.py` scans
all four images with the pinned Trivy 0.76.0 and rejects High/Critical findings
or missing scanner coverage. On 21 October all four final images passed.

The first PostgreSQL candidate had one Critical and 25 High findings in its Go
`gosu` helper. The derived image removes that executable and starts directly as
`postgres`; the real database initialisation and persistence checks passed with
that non-root runtime. Mailpit 1.31.5 had one High finding in its Go 1.27.2 runtime.
It is rebuilt with pinned Go 1.27.3 from the exact upstream source commit
`4355c8cd7dbe745c6fc6ce8619d23a1a31b746c9`. Archive SHA-256:
`8d8b2a6d26eb4cd61746a2f00fa08d719a155faaea24aff6158db6dec8439541`.
The GitHub release tag is unsigned; this is checksum/source traceability, not a
signature claim. Upstream notices and bundled third-party licenses are retained.
The frontend uses its package lock; local Node 22.23.1/npm 10.9.8 built it with
`npm ci --ignore-scripts` (audit reported zero findings). Dependencies are checked
with Go module sums; no scanner suppressions are added. The existing reviewed
local Caddy build is reused; its build procedure remains in `docs/local-demo.md`.

## Reproduce from the infrastructure repository

Python 3.12+, Docker/Compose, Node/npm, the scanned local Caddy candidate from the
local-demo runbook, and a TLS certificate covering `auth-p2.demo.inoerawan.id` are
required. Keep the runtime beneath an ignored `runtime/` directory. Do not share
the environment file, generated realm import, certificate keys, inbox or volumes.

```sh
python3 scripts/build_p2_images.py --runtime runtime/p2-build
python3 scripts/prepare_p2.py --runtime runtime/p2 --tls runtime/local-demo/proxy/tls
python3 scripts/check_p2_images.py --runtime runtime/p2 --scanner /absolute/path/to/trivy --cache runtime/trivy-cache
python3 scripts/prepare_p2.py --runtime runtime/p2 --tls runtime/local-demo/proxy/tls
# Validate without dumping the interpolated configuration, which contains secrets.
docker compose --env-file runtime/p2/compose.env -f p2/compose.yaml config --quiet
docker compose --env-file runtime/p2/compose.env -f p2/compose.yaml up -d --no-build
python3 scripts/check_p2_identity.py --runtime runtime/p2
docker compose --env-file runtime/p2/compose.env -f p2/compose.yaml restart postgres keycloak
python3 scripts/check_p2_identity.py --runtime runtime/p2 --check-restart
```

`prepare_p2.py` preserves existing credentials. Its parent directory is mode 0700;
only explicitly mounted import/TLS/password files are readable by non-root
container UIDs. The TLS directory is shared read-only between Keycloak and its
local proxy. Realm import skips an existing realm; editing the template and
restarting does not update existing realm settings. Use an explicit, reviewed
migration for future changes. Do not delete database volumes to apply config.

The diagnostic proxy preserves the fixed upstream Host and TLS server name;
otherwise this Keycloak/proxy combination returns HTTP 421. The probes validate
certificate chain and hostname and do not disable TLS verification. Docker's
internal bridge did not publish service ports on this host, so publication is
limited to the diagnostic proxy on a separate bridge.

To stop without deleting identity or mail data:

```sh
docker compose --env-file runtime/p2/compose.env -f p2/compose.yaml down
```

## Password path inventory and remaining work

| Path on Keycloak 26.8.1 | Current proof / required follow-up |
| --- | --- |
| Anonymous forgot-password | Disabled by `resetPasswordAllowed=false` until the coordinated gate exists. Test enumeration/abuse and invalid-token behavior before enabling. |
| Email verification | A real verification email is delivered. Consuming valid/expired/replayed links is still pending. |
| Admin password-action email | A real `UPDATE_PASSWORD` action email is delivered. Link consumption and password replacement are not tested. This path currently lacks the recovery guard. |
| Account console / password required action | Stock Keycloak paths are not coordinated with a wallet registry; inventory and bypass tests remain open. |
| Admin REST credential reset, user update/delete, admin console | Local bootstrap administrator can bypass future application controls. Replace/restrict bootstrap authority and test every supported mutation before public ingress. |
| Federated identity, external user storage, service-account password mutation | Not configured. Freeze/deny such additions unless their password paths are covered. |

No wallet registry, recovery SPI, authenticated acknowledgement, token freshness
check or reopening protocol exists yet. Do not treat a post-change event or
successful email delivery as a recovery gate. P2.3–P2.9 and A19–A20/A25/A29 remain
open. G1 network containment is unchanged: no historical walt.id runtime was
attached to these networks. No new public route was enabled.

References: [Keycloak container guide](https://www.keycloak.org/server/containers),
[production configuration](https://www.keycloak.org/server/configuration-production),
[database compatibility](https://www.keycloak.org/server/db),
[Keycloak 26.8.1 fixes](https://www.keycloak.org/2026/10/keycloak-2681-released),
[Mailpit releases](https://github.com/axllent/mailpit/releases), and
[PostgreSQL security](https://www.postgresql.org/support/security/).
