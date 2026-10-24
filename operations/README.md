# P7 operations

## Selected deployment: operator workstation

### Daily start and shutdown

From the workspace root, use:

```sh
./repo/platform-infra/operations/p7-control.sh stop
./repo/platform-infra/operations/p7-control.sh start
./repo/platform-infra/operations/p7-control.sh status
```

Run `stop` and wait for its success message before shutting the laptop down.
It pauses monitoring/backup timers, waits for a running backup, closes the public
tunnel, creates an encrypted backup when needed, and stops P7 containers, relay
and log collector. A backup failure aborts shutdown and restores previously active
tunnel/timers. It retains all data, keys and volumes and never powers off the laptop.

Tomorrow, connect the laptop to the internet, log into the desktop and run `start`.
It starts the application, checks identity/portal readiness, then starts the tunnel
and timers. Enabled user services may already start at desktop login; `start` is
safe to repeat. Docker must be running. A missed persistent daily backup is ordered
after the application service. Startup remains blocked after the approved close
date, and the deletion timer remains separately controlled.

Append `--dry-run` to `start` or `stop` to inspect commands without changing services.
These scripts do not establish evidence that a real laptop power cycle has passed.


The operator moved P7 back from the VM to the workstation on 23 October 2026.
Only project `competency-proof-p7` should run. Superseded P2/P6/local-edge containers
are stopped with restart disabled; their data and a consistent checkpoint remain
available. Do not start another full acceptance/restore stack alongside P7.

The private runtime is `<workspace>/runtime/p7/active`, with SMTP input in
`<workspace>/runtime/p7/smtp.json`. Recover the P7 state from its authenticated
encrypted snapshot; do not regenerate issuer or wallet keys. Use the original
verified P6 distribution in `<workspace>/runtime/p6/final-distribution/competency-proof`.
After correcting the runtime path in compose.env, prepare with
`--host-mode workstation`. Existing operations.json supplies operator/dates; for a
new installation pass `--operator-config /private/operator.json` with owner,
alertRecipient, startsAt, closesAt and deleteAfter, including timezone offsets.

`install_workstation.py` installs user services. Start the log collector before
application startup; the application start helper creates the dedicated networks
and starts the SMTP relay. The relay binds only the internal bridge gateway
10.203.77.1:1587 and forwards to the one privately configured SMTP host/port.
IdP hostname mapping preserves end-to-end TLS hostname verification. All IdP
networks remain internal; no root firewall changes or privileged containers are
needed. Small explicit subnets in 10.203.70.0/24 avoid exhaustion of Docker's
legacy default pools. Check for host/VPN conflicts before selecting these subnets.

Containers use the syslog driver to a loopback TCP collector, with dual-log cache
disabled. The collector redacts known credentials, bearer/JWT tokens, action-link
parameters and email addresses, rotates at 5 MiB, keeps at most three files per
day and prunes files older than 14 days. It changes no other application's logs.
Service-manager lifecycle diagnostics remain subject to the host journal policy.
See [Docker syslog](https://docs.docker.com/engine/logging/drivers/syslog/) and
[dual logging](https://docs.docker.com/engine/logging/dual-logging/).

`backup_local.py` creates a consistent encrypted archive in the operator-selected
`<workspace>/runtime/backups/p7` directory. This is **same-host backup**, not
independent off-host storage. Its decryption key remains outside that directory.
Backups pause writers and resume identity dependencies before applications.
Monitoring suppresses a recorded planned backup window for at most ten minutes;
a stale maintenance marker cannot silence alerts indefinitely.

User timers check local readiness every two minutes and the public HTTPS path plus
synthetic login every three minutes. The latter still runs on the same laptop,
so it cannot report a laptop power failure or complete network loss. Off-host
monitoring and off-host storage remain separate acceptance gaps. Notifications
occur only on changes/recovery, with clearly labeled detector-injection tests.
A successful SMTP response is not operator-confirmed inbox delivery.

Backup runs at 02:00 Asia/Jakarta on 24–31 October 2026; close is scheduled for
1 November 00:00. The deletion unit is prepared for 1 November 12:00, but its timer
must remain disabled until the disposable lifecycle rehearsal passes. Never claim
scheduled future deletion has already happened. User services start at login;
headless boot/linger, sleep/resume and power-loss behavior require separate proof.

The operator approved switching the existing Pinggy names to public loopback
28443. Keep strict host-key checking, never print the private SSH username, and
remove the force takeover option after switching. Do not forward private admin
28444, mailbox, database or internal protocol APIs.

## Original dedicated-VM variant

Use the unchanged, attested P6 distribution and its exact eleven GHCR digests.
Verify the archive, manifest, signatures, provenance and SBOMs on the trusted
operator workstation before transferring the package and prepared private state.
Record the source manifest SHA-256 and the separately derived deployment hash.
The operational overlay is new source requiring review; it is not part of the P6
attestation. Do not build application images on the VM.

The private layout is `/home/ubuntu/competency-proof/{package,operations,runtime/p7}`.
SMTP input is `/home/ubuntu/.config/competency-proof/p7/smtp.json`, mode 0600.
Private parent directories must be 0700; container-readable children remain inside
the private parent. Never print Compose's expanded configuration or IdP secrets.

```sh
sudo python3 operations/p7.py --runtime runtime/p7 --package package \
  --smtp /home/ubuntu/.config/competency-proof/p7/smtp.json prepare
sudo python3 operations/p7.py --runtime runtime/p7 --package package \
  --smtp /home/ubuntu/.config/competency-proof/p7/smtp.json start
```

Preparation removes Mailpit and its host mailbox listener. Each IdP requires SMTP
authentication and verified TLS/STARTTLS. A dedicated IPv4 Docker egress subnet
is restricted in DOCKER-USER to the resolved SMTP destination and submission port.
Keep Docker's iptables backend and IPv6 disabled on this network. Install the
firewall service before Docker starts on reboot. Review provider DNS changes and
refresh rules; a failed refresh must retain existing restrictions. Do not flush
DOCKER-USER or open general egress as a workaround.

Wallet enrollment is invitation-only. Public registration stays disabled and
staff accounts remain operator-controlled. The operator approves each recipient;
the recipient completes email verification and chooses a password through a
15-minute Keycloak action link. No initial password is sent. Each invitation is
sent once, with at least 60 seconds between invitations. A partial failure leaves
the account for reconciliation instead of blind retries. This is controlled
self-enrollment, not an unrestricted public signup form.

```sh
sudo python3 operations/p7.py --runtime runtime/p7 --package package \
  --smtp /home/ubuntu/.config/competency-proof/p7/smtp.json invite \
  --email APPROVED_PARTICIPANT_ADDRESS
```

Monitor every two minutes. Readiness checks use each realm's discovery and the
application's portal-config endpoint; HTTP success alone does not prove credential
flows. Check OOM/restarts, memory headroom, disk, load, TLS (14 days), and the last
external backup acknowledgement (26 hours). Alert only on changes and recoveries;
SMTP acceptance is distinct from operator-confirmed inbox delivery. An independent
laptop monitor must check public HTTPS and important synthetic flows; a VM-only
monitor cannot notify while the VM or internet is down.

Backup stops every running writer, snapshots all project volumes and private
configuration/keys, encrypts with CMS AES-256-GCM and the operator public
certificate, then resumes exactly the previously running containers, including
on error. The laptop receives the encrypted stream and acknowledges only after a
durable atomic write. The private RSA decryption key stays outside the backup
directory and never goes to the VM. A laptop failure can still lose both VM and
backup if they share hardware. Keep a separate recoverable copy of the decryption
key; test decryption before relying on the backup. No historical keys are rotated.

```sh
python3 operations/backup_client.py --host ubuntu@VM_ADDRESS \
  --identity /private/operator-ssh-key --destination /private/runtime/backups/p7
```

Demo dates use Asia/Jakarta: active 24–31 October 2026, close 1 November at 00:00,
and delete P7 state/backups 1 November at 12:00. These are operator-approved dates;
scheduled deletion is not evidence of completed deletion. Stop invitations, revoke
sessions, stop the tunnel and application before deleting the exact P7 project
volumes and paths. Never apply cleanup to development or P6 installations. Rehearse
with a separate disposable project first. Keep sanitized audit evidence separately.
Do not use `down -v` during an active demo, update, rollback or restore.

Restore only into a separate project/runtime, isolated networks and alternate
loopback ports. Verify the encrypted archive, each volume checksum and all SQLite
integrity checks. Preserve issuer/wallet keys, mappings, schemas and signed release
pins. Verify a credential issued before the snapshot can still be presented after
restore, and measure RPO (24 hours) and RTO (4 hours). Do not declare G7 complete
until actual public APK, SMTP recovery, alert, load and restore evidence passes.

## Custodian invitation menu update

The P6 custodian UI used the same body for Service overview and Recovery & access.
The application update merged in competency-proof PR #10 separates these pages
and adds Participant invitations. It requires a **new verified application
release**, not an asset replacement inside a running container. Do not change the
existing attested package or claim that the menu is live before that release is
installed. The Android application and existing participant passwords stay valid.

After accepting that release, provision its dedicated client using
`configure_invitations.py --runtime <private-runtime> --package <verified-package>`
for a plan, then add `--apply` to prepare private configuration. This command does
not restart services or send invitations. Before restarting, take the standard
encrypted backup; then recreate only custodian and reload the validated ingress
configuration. Validate the public API denies anonymous and participant access,
and confirm the three menu bodies in a browser. SMTP end-to-end testing requires
an explicitly approved recipient; configuration alone does not send mail.

The client secret stays in `<private-runtime>/wallet-invitations-secret` (0444 within the private 0700 runtime parent),
mounted only into custodian. Compose retains host permissions; the file must be
readable by the unprivileged container user. It uses wallet-realm user administration roles
`manage-users`, `view-users`, `query-users`, `view-realm`, with Full Scope Allowed
off and only these client role scopes. These roles can manage wallet realm users;
they must be treated as privileged. The application fixes the target realm and
assigns only `applicant`. It receives no master/bootstrap admin secret and no
issuer/company administration access. See the
[Keycloak service account and administration guide](https://www.keycloak.org/docs/latest/server_admin/index.html).

The additive `/data/participant-invitations.sqlite` stores private recipient
emails and delivery requests in the existing custodian volume. Include that
volume and its WAL in consistent encrypted backups and the approved deletion
lifecycle. Restore must preserve this journal to avoid duplicate sends. The
server reserves each recipient and request key before upstream work; replay
returns the existing outcome. A crash or ambiguous SMTP result requires private
operator reconciliation and never triggers an automatic resend. Requests are
limited globally to one per minute. The recent list shows up to 50 requests;
legacy CLI invitations do not appear in it. `SENT` records SMTP acceptance,
not inbox receipt, email verification or completed password setup. Expired links
and `RECONCILE_REQUIRED` require operator review; this initial menu cannot resend
or reset an existing account.

Public self-registration remains disabled. An operator signs in to the custodian
workspace, opens Participant invitations, enters and explicitly confirms an
approved email, then sends one link. The participant verifies email and chooses
a password within 15 minutes, then signs in through the Android wallet.
