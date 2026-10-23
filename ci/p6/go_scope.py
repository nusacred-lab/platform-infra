"""Resolve one package-scoped Go advisory using the actual compiled import graph.

GO-2026-5932 affects only x/crypto/openpgp, not every package in x/crypto.
Keep the scanner finding visible. Reject it unless the affected package is absent
from the exact Linux amd64/CGO-disabled dependency graph used by these recipes.
"""
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile

GO_IMAGE='golang:1.27.3-alpine@sha256:f2c872bcee949b7be9c490efd02b48a8a2fbf947cdf533f1c58525ec9d8170fd'
ADVISORY='GO-2026-5932'
UNSAFE='golang.org/x/crypto/openpgp'


def safe_graph(packages):
    imports=packages.splitlines()
    return bool(imports) and not any(p==UNSAFE or p.startswith(UNSAFE+'/') for p in imports)


def prove_not_affected(command, row, finding, report):
    if finding.get('VulnerabilityID')!=ADVISORY or finding.get('PkgName')!='golang.org/x/crypto' or finding.get('Severity')!='UNKNOWN':
        return False
    mode=command[1]
    subject=command[-1]
    if mode=='fs':
        root=Path(subject).resolve()
        target=(root/row['Target']).resolve()
        if not target.is_relative_to(root) or target.name!='go.mod' or not target.is_file():return False
        project=target.parent
        packages=subprocess.check_output(['docker','run','--rm','--platform','linux/amd64','--read-only',
            '--cap-drop','ALL','--security-opt','no-new-privileges:true','--user','10001:10001',
            '--mount','type=bind,source='+str(project)+',target=/src,readonly',
            '--tmpfs','/tmp:rw,nosuid,nodev,mode=1777','--workdir','/src',
            '-e','CGO_ENABLED=0','-e','GOTOOLCHAIN=local','-e','GOCACHE=/tmp/go-cache',
            '-e','GOMODCACHE=/tmp/go-modules','-e','GOTELEMETRY=off',
            '--entrypoint','go',GO_IMAGE,'list','-mod=readonly','-deps','.'],text=True)
        source={'moduleSha256':hashlib.sha256(target.read_bytes()).hexdigest(),
                'sumSha256':hashlib.sha256((project/'go.sum').read_bytes()).hexdigest()}
    elif mode=='image':
        # Create but never start the signed/scanned image. Its reviewed recipe
        # produces this graph immediately before compiling the shipped binary.
        container=subprocess.check_output(['docker','create','--network','none','--read-only',
            '--cap-drop','ALL','--entrypoint','/bin/true',subject],text=True).strip()
        try:
            with tempfile.TemporaryDirectory() as directory:
                destination=Path(directory)/'go-packages.txt'
                subprocess.run(['docker','cp',container+':/usr/share/nusacred/go-packages.txt',str(destination)],check=True)
                packages=destination.read_text()
        finally:
            subprocess.run(['docker','rm','-v',container],check=True,stdout=subprocess.DEVNULL)
        source={'image':subject,'method':'import graph embedded by the reviewed build recipe; image digest binds graph and binary'}
    else:
        return False
    imports=packages.splitlines()
    if not safe_graph(packages):return False
    evidence={'advisory':ADVISORY,'upstream':'https://pkg.go.dev/vuln/'+ADVISORY,
        'status':'not_affected','justification':'vulnerable_code_not_present',
        'target':row['Target'],'subject':subject,'goToolchainImage':GO_IMAGE,
        'excludedPackage':UNSAFE,'packageCount':len(imports),
        'importsSha256':hashlib.sha256(packages.encode()).hexdigest(),**source}
    report.with_suffix(report.suffix+'.go-scope.json').write_text(json.dumps(evidence,indent=2)+'\n')
    report.with_suffix(report.suffix+'.go-packages.txt').write_text(packages)
    return True
