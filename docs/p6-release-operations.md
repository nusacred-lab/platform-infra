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
