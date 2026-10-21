# P2 login integration and staged prerelease ingress

The private P2 stack now provides real custodian BFF and native PKCE session
verification. `configure_p2_login.py` explicitly applies the fixed API audience
mapper and `basic` default scope to the two login clients. It creates two private
synthetic role fixtures; the fixture file, passwords, client secrets and tokens
must remain inside the ignored runtime. Fixtures are administratively verified
for authentication tests; email-link verification/recovery remains unproven.

The existing realm-import skip behavior still applies: run the migration against
an existing realm rather than deleting volumes or assuming import updates it.

```sh
python3 scripts/configure_p2_login.py --runtime runtime/p2
python3 scripts/prepare_p2.py --runtime runtime/p2 --tls runtime/local-demo/proxy/tls
# Build, scan and start the updated application using the existing P2 runbook.
python3 scripts/test_p2_login.py --runtime runtime/p2
```

The test driver uses the real Keycloak HTML login page and token endpoint over
verified local TLS. It binds state, nonce, cookies and S256, checks role and
negative cases, and revokes only the dedicated synthetic applicant's IdP sessions.
It writes a sanitized result and never prints token/password values. Its cookie
jar ignores unknown cookie extensions like a browser; it is not a physical-APK
or full-browser substitute. The 15 local real-service checks pass.

The application's backchannel uses the canonical auth hostname as an alias on
its internal network and the private TLS proxy's port 8443. Issuer claims remain
the public canonical HTTPS issuer; TLS validation is not disabled. Only the
custodian BFF secret is mounted into the application, not the bootstrap admin
credential or database/key directories. Client bootstrap authority is confined
to the host-side migration/test tool.

## Prerelease activation — confirmation required

These files are staged and validated without opening a public route:

- `p2/prerelease.compose.yaml` and `p2/prerelease.caddy`: a dedicated ingress
  container on the existing edge bridge, an internal auth bridge and the internal
  application bridge. It never joins the database/mail identity bridge or any
  historical walt.id network.
- `local-demo/p2.compose.yaml` and `local-demo/p2-routes.caddy`: mount the two
  explicit prerelease host routes in the existing tunnel-facing edge.

DNS for `auth-p2.demo.inoerawan.id` and `wallet-p2.demo.inoerawan.id` already
resolves to the chosen Pinggy tunnel. The wildcard certificate covers both.
The public auth allowlist contains only discovery, JWKS, authorization/token,
login authenticate/restart and static resources. Admin/master realm, mailbox,
account console, password actions, registration and credential routes are denied.
The wallet allowlist contains only compiled assets and application-login routes.
No listener is published directly by the new ingress container. The existing
four hostname probes remain intact. Public login is for synthetic P2 accounts.

After owner confirmation only, from the infrastructure repository:

```sh
docker compose --env-file runtime/p2/compose.env -f p2/compose.yaml -f p2/application.compose.yaml -f p2/prerelease.compose.yaml config --quiet
docker compose --env-file runtime/p2/compose.env -f p2/compose.yaml -f p2/application.compose.yaml -f p2/prerelease.compose.yaml up -d --no-build
docker compose --env-file runtime/local-demo/edge.env -f local-demo/compose.yaml -f local-demo/p2.compose.yaml config --quiet
docker compose --env-file runtime/local-demo/edge.env -f local-demo/compose.yaml -f local-demo/p2.compose.yaml up -d --no-build
```

Paths above are example repository-local runtime locations; use the actual
private environment paths on the operator host. Never dump an interpolated
Compose configuration into public logs. Verify the two HTTPS hosts, denial of
all private paths and the four original probe hosts before physical APK login.
Use the same complete Compose file set for subsequent updates. To withdraw the
public routes, recreate the local edge using only its original base Compose
file, then stop/remove only the `p2-ingress` service; preserve all state volumes.
