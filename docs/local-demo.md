# Local demo edge with Pinggy TLS passthrough

Status: local and public probe checks have passed; the owner confirmed phone access on 21 October 2026. The foundation is sufficient to start P2 implementation. This is a connectivity probe, not the P2
application stack or a G2/G7 acceptance result. The edge has no application
upstreams, no database mounts and no Docker socket. Do not
attach the historical harness or upstream example images to this public edge.

## Layout and boundaries

- Runtime stays in ignored `runtime/local-demo/` in this repository, mode 0700.
- Only `127.0.0.1:8443` is published; no LAN/public listener is needed.
- The edge uses a dedicated ingress bridge. This bridge permits egress and is
  not G1 containment for credential services; those must never join it directly.
- Four hostnames: `{issuer,wallet,auth,verifier}.demo.inoerawan.id`.
- GET/HEAD `/` and `/healthz` return a static probe. All other paths/mutations
  return 404. Access logging is not enabled; responses are never cached.
- Application P2 testing must use separate `*-p2.demo.inoerawan.id` hosts and
  realm/key/storage. Add those hosts explicitly during that implementation.
- No Keycloak, walt.id service, APK or recovery integration is included here.

Use Python 3.13 on Linux x86_64 for the locked Certbot wheels. Run commands from
this repository unless a path is absolute. An optional `LOCAL_DEMO_RUNTIME`
environment variable must point to a private ignored directory outside public
source. Docker daemon access is required for edge operations.

## Prepare the proxy

```sh
python3 scripts/local_demo.py prepare
python3 scripts/local_demo.py test-certificate
docker build -t competency-proof-local-edge:reviewed local-demo/caddy-build
docker image inspect competency-proof-local-edge:reviewed --format '{{.Id}}'
```

Scan the resulting image with a fresh vulnerability database. High/Critical or
scanner errors block use. Configure the exact image ID from inspection only after
the scan passes; local image IDs are not registry publication/provenance.

```sh
python3 scripts/local_demo.py configure-edge --image sha256:IMAGE_ID
python3 scripts/local_demo.py validate
python3 scripts/local_demo.py up
python3 scripts/local_demo.py check
```

The self-signed test certificate is for loopback validation only. The tunnel
helper refuses to publish it. Do not install it as a trusted device/OS CA.

The custom Caddy build retains Caddy v2.11.7 and uses Go 1.27.3 plus
`golang.org/x/net` v0.60.0. The official candidate image contained High findings in
its older Go runtime and x/net dependency. `go.mod` and `go.sum` record resolved
modules; the builder runs module checksum verification and a read-only build.
The final scratch image contains only the compiled binary. No compiler runs in
the final edge container. This is a locally tested candidate, not a released image.

## Request the public certificate

Create an isolated environment; do not install into system Python:

```sh
python3 -m venv runtime/local-demo/certbot-venv
runtime/local-demo/certbot-venv/bin/python -m pip install --require-hashes -r local-demo/certbot-requirements.lock
```

Use that environment's Python to run the request helper. Replace the example
email with the operator address. The `--agree-tos` flag accepts the
[Let's Encrypt subscriber agreement](https://letsencrypt.org/repository/).

```sh
runtime/local-demo/certbot-venv/bin/python scripts/local_demo.py request-certificate --email operator@example.com --agree-tos
```

The command waits in a DNS hook for up to 24 hours. Keep the process running.
In another terminal, `python3 scripts/local_demo.py certificate-status` shows the
current **public DNS validation value**. The pending JSON also records its expiry.
An ACME challenge is not a password or private key, but it must not be hardcoded
in public source or reused after a new certificate request.

In Rumahweb Clientzone, open the `inoerawan.id` DNS management screen:

| Field | Value |
| --- | --- |
| Type | TXT |
| Name | `_acme-challenge.demo` |
| Value | Exact value from `certificate-status` |
| TTL | 300 or the lowest supported value |

An explicit CNAME at that exact challenge name must be resolved before adding
TXT. A synthesized answer inherited from `*.demo` is not an explicit CNAME and
does not require deleting the application wildcard. The public wildcard CNAME
continues pointing to the target supplied by the Pinggy account.

Once saved, run `python3 scripts/local_demo.py confirm-dns`. It checks the exact
TXT using Google's public DNS resolver before releasing the waiting hook. A
failure leaves the request waiting. Do not keep creating new orders/reissuing.
After Certbot reports success:

```sh
python3 scripts/local_demo.py install-certificate
python3 scripts/local_demo.py down
python3 scripts/local_demo.py validate
python3 scripts/local_demo.py up
python3 scripts/local_demo.py check
```

Only the leaf certificate chain and private key are copied into the proxy mount;
the ACME account, logs and work directory are not exposed to Caddy. Never upload
runtime files, the private key or the ACME account to GitHub.

Manual DNS renewal is not automatic. Inspect certificate expiry and repeat the
request/DNS/install workflow before expiry. Automating renewal through a supported
DNS API or delegated challenge is future work. Keep reminders/monitoring as an
opening requirement for the final demo; no automation is installed by this guide.

## Configure the private Pinggy token

```sh
python3 scripts/local_demo.py configure-tunnel
```

Paste the token into the hidden terminal prompt, not into chat, command arguments
or a repository file. The helper writes a mode-0600 SSH config in ignored runtime.
It creates four named **TLS** forwardings to the same loopback proxy, based on
Pinggy's documented multiple-forwarding syntax. It never starts a tunnel by itself.
Review the SSH host fingerprint against a trusted Pinggy source on first use;
host-key checking is not disabled. Existing tunnels with the same token may need
to be stopped. The purchased account's named TLS routing must be tested; CNAME
validation alone does not establish that it works.

```sh
python3 scripts/local_demo.py tunnel
```

The foreground tunnel uses keepalive and reconnects after clean closure or
transport loss. Authentication, host-key and configuration errors stop for
diagnosis. Output redacts the token even if SSH includes it in an error message.
Ctrl-C stops it. No system service, automatic login or sleep policy is modified.

From a phone on mobile data, open all four `/healthz` URLs. Check the public CA
certificate, then test reconnect with the same names. Public paths such as
`/admin/` and credential/API routes must still return 404. Do not enable the full
stack until G1 network changes and application authorization have been reviewed.

## Operations still required

- Keep this machine powered and awake during published demo hours.
- Avoid source builds while the demo runs; use GitHub Actions for primary builds.
- Separate dev, prerelease and final demo state even on the same host.
- Choose off-host encrypted backup storage and retain decryption keys separately.
- Implement and test backup, restore, expiry/outage alerts, rotation and shutdown.
- Add service readiness, controlled Keycloak/SMTP, APK App Links and recovery in P2.

Sources: [Pinggy TLS](https://pinggy.io/docs/tls_tunnels/),
[named forwardings](https://pinggy.io/docs/http_tunnels/multi_port_forwarding/),
[Caddy supplied certificates](https://caddyserver.com/docs/caddyfile/directives/tls),
[Certbot manual hooks](https://eff-certbot.readthedocs.io/en/stable/using.html#manual).

## Recorded environment readiness — 21 October 2026

| Evidence | Result | Scope limit |
| --- | --- | --- |
| E01: local edge | Compose/Caddy validation and local TLS/blocked-route checks passed | Static probe only |
| E02: DNS and certificate | Local Let's Encrypt wildcard certificate installed, expires 19 January 2027 | Manual renewal; no scheduled reminder or automation yet |
| E03: public ingress | Four TLS forwardings authenticated; public certificates match the local leaf; probe GET 200 and admin/mutation 404, all no-store | Full application traffic is not enabled |
| E04: phone access | Confirmed by the owner in chat | Device/OS/network details not recorded; no APK or App Links acceptance claim |

The owner explicitly approved the offered SSH RSA fingerprint for first-use trust.
The active private SSH configuration pins the stored key with strict checking.
This is not independent verification of Pinggy's fingerprint. Credentials and keys
remain in ignored private runtime storage. The running tunnel is a managed
foreground process, not an installed OS startup service.

Continue with assignment validation (P2.0), toolchain builds (P2.1), then the real
IdP/application/recovery work. No VM purchase blocks this work. Before prerelease
application tests, add `*-p2.demo.inoerawan.id` routing, separate state and configure
OIDC/App Links; review G1 network changes before connecting credential services.
Backup/restore, resource/load tests, tunnel/host lifecycle, monitoring and renewal
operations remain requirements before opening the final demo. G2/G7 are not closed.
