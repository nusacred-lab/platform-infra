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
