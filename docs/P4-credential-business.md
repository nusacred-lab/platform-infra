# P4 private credential business configuration

Owner: abeinoe, assisted by Codex. All runtime values, keys, databases, tokens and
raw credentials belong in an ignored workspace runtime outside public source.
The root workspace remains local. This configuration does not open public routes.

Run `scripts/prepare_p4.py --runtime /absolute/workspace/runtime/p4/bootstrap`.
The command generates fresh per-environment issuer/token keys, a stable did:jwk
identity, the `competencyDemo` / `competency_demo` profile and metadata, Wallet2
persistence configuration, verifier configuration and a 32-byte AES offer-reference
key. Repeated preparation retains existing keys. Never copy the P2 or upstream
example keys into another environment. Preserve the private key files and public
identity record together; changing them is not a supported rotation procedure.
The application supplies explicit server-owned NumericDates for actual offer time
and an exact 365-day lifetime; generated SD-JWT timestamp templates on the pinned
fork have privacy rounding and are not the application's source of dates.

For isolated acceptance, set `P4_RUNTIME` to that absolute directory and set
`P4_{ISSUER,WALLET,VERIFIER}_IMAGE` to the already accepted source-built fork image
references, with `P4_EDGE_IMAGE` for the scanned diagnostic Caddy image. Use
`p4/protocol.compose.yaml`; it starts a separate internal protocol network and
fresh wallet data with diagnostic listeners bound only to 127.0.0.1:27004–27006.
No protocol port is public. Stop the isolated composition after acceptance while
retaining its private data until the owner's retention policy permits deletion.

For a future application activation, merge `p4/backends.compose.yaml` after the
P2/P3 composition and use matching built/scanned P4 application images. Mount the
same `offer-reference-key` into issuer and custodian through Docker secrets.
Issuer/company/custodian need the private protocol network; the custodian retains
its separate recovery and wallet-backend networks. Back up application databases
and the registry consistently first: application schema 2 and custodian schema 5
require matching old backups for rollback. Do not activate the overlay with P3
binaries, or replace running public binaries during a physical demo.

## Reproducible private acceptance

1. Run the application's explicit `:custodian-backend:realBusinessProof` task with
   `P4_PORT_BASE=27000` and `P4_PROOF_RUNTIME` pointing at a fresh private directory.
   It uses real services, not simulated protocol outcomes.
2. For negative acceptance only, prepare with `--negative-fixtures`. This adds
   private empty-data and wrong-type profiles to the isolated issuer. Restart
   only that isolated issuer; do not enable fixture profiles on a public runtime.
3. Run `scripts/test_p4_negative_protocol.py --runtime <private-output>` and then
   the application's `:backend-common:realPolicyProof` with `P4_NEGATIVE_RUNTIME`
   pointing at that output. The matrix explicitly distinguishes issuer refusal,
   verifier rejection and application business validation. The controlled runner
   owns a disposable holder fixture key; application holder keys remain on server.
4. Run `scripts/test_p4_continuity.py --runtime <private-output> --registry
   <business-proof>/registry.sqlite --issuer-config
   <bootstrap>/walt/issuer/issuer2-profiles.conf`. It changes only the isolated
   profile's display name, restarts `competency-proof-p4-issuer-1`, checks the
   supported profile API, and verifies unchanged old credential bytes/key/identity
   through a new real verifier session.

Full output and raw verifier responses remain private. Publish only sanitized
assertions, test IDs, source commits, image digests and scan counts. G1 exceptions,
required CI and later public-domain, backup, recovery and operations gates remain
in force. Existing P3 real-OIDC tests now provide a private offer-reference key
for the P4 issuer startup requirement; they do not claim the P4 business journey.
