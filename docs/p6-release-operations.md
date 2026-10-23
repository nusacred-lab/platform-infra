# P6 release operations

The release workflow builds three pinned source groups with read-only tokens.
After all groups pass, downstream jobs may push/sign synthetic images to GHCR.
Only main and the explicitly reviewed `codex/p6-release` candidate branch are
trusted; PR runs cannot publish. Candidate tags include the full infrastructure
commit, workflow run and attempt. Installers use digests, never those tags.
Signatures/provenance pin the exact workflow identity and workflow commit.

The package verification tools reject another repository/workflow/ref, mutable
image references, missing image coverage and mixed source revisions. Verify the
archive before executing its installer. A digest checksum from an unauthenticated
manifest alone is insufficient.

## Daily digest scan and alerts

After acceptance, copy the attested `release-manifest.json` to
`release/current.json` through a reviewed PR, preserving the original attestation
bytes. The daily workflow scans those exact digests at 00:17 UTC / 07:17 WIB,
also on changes to the active manifest or manual dispatch. The schedule becomes
active only after the workflow is merged to the default branch. Until an active
manifest exists, it fails explicitly rather than claiming any digest was scanned.

Owner: **abeinoe**. Channel: GitHub Actions failed-workflow notifications. The
owner must enable Actions notifications/watch settings; record actual receipt of
a deliberately failing disposable scan before closing notification acceptance.
A workflow summary alone does not prove delivery. The P7 host/internet/backup
alerts remain a separate channel and acceptance requirement.

On a new High/Critical finding, scanner failure, stale database, signature failure
or missing coverage: block promotion/updates, inspect sanitized reports, determine
exposure, patch source/base dependencies and build a new candidate. Rerun the
acceptance cases affected by the change. Do not suppress new findings under the
inherited G1 history exception. Preserve the old manifest and evidence. If an
already deployed demo is affected, assess pausing access and use the P7 incident
runbook. Never rotate an issuer/holder key blindly: old credential verification
and recovery continuity must be preserved.

## Candidate acceptance and promotion

G6 requires actual installation from GHCR on disposable state, all due acceptance
subcases bound to the same source/image/APK candidate, negative supply-chain
checks, and tested upgrade/rollback. The unsigned CI APK must be attested and
signed offline without changing ZIP payload; retain the signed checksum and App
Links certificate match. Do not publish the draft APK release or open participant
access as a side effect of a successful image build.

The baseline compatibility contract is registry schema 5, business migrations 3
and policy competency-v1. A compatible image rollback must preserve final results,
account-to-wallet mappings and credential bytes. Downgrading an incompatible
schema is forbidden; restore a complete consistent stopped snapshot. APK version
rollback is constrained by Android version codes and signing identity. No cloud
service or public tunnel is required for package acceptance.

## Mail capture source update

P6 pins Mailpit 1.32.0 at `ce798cfd781ef07b321427fc5082b3eebdcae460`,
including DOMPurify 3.4.17. The previous 1.31.5 source scan failed closed on
[GHSA-cg2g-xh64-v4q7](https://github.com/advisories/GHSA-cg2g-xh64-v4q7)
and [GHSA-mrv2-3pqr-j5jr](https://github.com/advisories/GHSA-mrv2-3pqr-j5jr).
`release/mail-source.json` binds the source archive checksum and recipe; both
the complete source tree and final image must pass the fresh scanner gate.
The existing P2 source pin remains unchanged. The P6 recipe replaces the entire
Mailpit binary and embedded frontend while retaining the reviewed minimal OS/CA
layer, and compiles with the pinned Go 1.27.3 toolchain.

## Scanner completeness and Alpine security backport

Candidate infrastructure commit `9eff88c` is **quarantined**. A remote rescan
revealed Trivy could exit zero after warning that vulnerability details for
`CVE-2026-107891` were unavailable. Its severity filter omitted the unclassified
musl finding; a zero High/Critical count was insufficient evidence of health.
Do not promote that candidate or treat its functional staging results as G6.

The replacement PostgreSQL and Mailpit recipes pin Alpine's `musl` and
`musl-utils` security backport `1.2.6-r3`, following the
[Alpine security release](https://wwwtest.alpinelinux.org/posts/Alpine-3.21.9-3.22.7-3.23.7-3.24.3-released.html)
and [upstream advisory](https://seclists.org/oss-sec/2026/q4/289).
The P2 baseline recipe remains unchanged. P6 gates now include UNKNOWN severity,
reject missing vulnerability details even after exit zero, retain scanner stderr,
and remove an old report before rescanning. Regression tests cover this exact
false-success condition and stale-report reuse. The daily scanner applies the
same gate; no CVE ignore or exception was added.

Both Alpine runtime recipes also pin `ca-certificates-bundle=20261020-r0`,
following the vendor's eMudhra trust-store update. PostgreSQL aligns OpenSSL
(`libcrypto3`/`libssl3` 3.5.9-r0) and zlib (1.3.2-r1) with the security release;
Mailpit's pinned base already contains those versions. Candidate `7c771e8` was
cancelled before promotion while completing these vendor security updates.

The scanner also reports the module-level UNKNOWN advisory
[GO-2026-5932](https://pkg.go.dev/vuln/GO-2026-5932). Its affected packages are
specifically `golang.org/x/crypto/openpgp` and descendants, not the entire
`x/crypto` module. Keep this finding in the scan report. `go_scope.py` permits a
`not_affected / vulnerable_code_not_present` resolution only after checking the
actual Linux amd64, CGO-disabled import graph for the source or image. The pinned
Go compiler produces this graph immediately before building Caddy/Mailpit; the
final image includes it, so the image signature binds both graph and binary.
Source checks run `go list -mod=readonly -deps .` in the same pinned toolchain
against read-only source. Empty graphs, affected OpenPGP imports, other UNKNOWN
advisories and missing metadata still fail closed. Per-scan scope records and
complete import lists are retained beside the unmodified scanner findings.

## Monitored P6 candidate

`release/current.json` is the byte-exact attested manifest from
[run 39902945224](https://github.com/nusacred-lab/platform-infra/actions/runs/39902945224),
workflow commit `f33b988594560a5939e32bc9c6a546b6d7f442e5`. All three build groups,
three publication groups and assembly passed. It selects the immutable candidate
for security monitoring; it does not deploy any installation or close G6/G7.
The manifest deliberately retains its original pending acceptance fields.
The daily schedule becomes active only after this workflow reaches the default
branch; a candidate-branch push/dispatch proves the same scanner before merge.

Independent installation verified the archive/manifest attestations and all eleven
image signatures, provenance and SBOMs. Anonymous pulls matched the image config
digests scanned in CI. A separate fresh-database scan of those exact local Docker
digests passed the strict gate. A workstation remote-transport attempt failed on
DNS timeouts and was retained as failure evidence, rather than treated as clean.
The workflow uses remote registry transport on its ephemeral GitHub runner.

The APK attached to the draft application release is signed offline, has the same
ZIP payload as the CI APK, and is byte-identical to the version-code 5 APK updated
in place on the physical device. Biometric access and the existing credential
were confirmed by the operator. This physical check used the existing demo
backend; final registry-backend client walkthrough acceptance remains separate.
