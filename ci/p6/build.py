"""Build one release group once; scan immutable local images before exporting them.

Run on an ephemeral Linux amd64 runner. No registry or signing permission is needed.
Source checkouts must match release/sources.json; private state never enters out/.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from scan_gate import scan

ROOT = Path(__file__).resolve().parents[2]
SCANNER = None

def run(*args, cwd=ROOT, **kwargs):
    if SCANNER is not None and str(args[0]) == str(SCANNER) and '--scanners' in args and 'vuln' in args:
        return scan(args, cwd=cwd, **kwargs)
    return subprocess.run(list(map(str, args)), cwd=cwd, check=True, **kwargs)

def sha(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024*1024), b''):
            h.update(chunk)
    return h.hexdigest()

def main():
    global SCANNER
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('kind', choices=['application', 'fork', 'infrastructure'])
    p.add_argument('--application', type=Path, required=True)
    p.add_argument('--fork', type=Path, required=True)
    p.add_argument('--scanner', type=Path, required=True)
    a = p.parse_args()
    sources = json.loads((ROOT/'release/sources.json').read_text())
    app, fork = a.application.resolve(), a.fork.resolve()
    for kind, path in [('application', app), ('fork', fork)]:
        revision = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=path, text=True).strip()
        if revision != sources[kind]['commit']:
            raise SystemExit('Source checkout does not match the reviewed full commit: '+kind)
    out = ROOT/'out'/a.kind
    out.mkdir(parents=True, exist_ok=False)
    scanner = a.scanner.resolve()
    SCANNER = scanner
    os.environ['TRIVY_CACHE_DIR'] = str(Path(os.environ.get('RUNNER_TEMP', '/tmp'))/'p6-trivy')
    run(scanner, 'image', '--download-db-only')
    metadata = Path(os.environ['TRIVY_CACHE_DIR'])/'db/metadata.json'
    updated = datetime.fromisoformat(json.loads(metadata.read_text())['UpdatedAt'].replace('Z', '+00:00'))
    age = (datetime.now(timezone.utc)-updated).total_seconds()
    if not 0 <= age < 86400:
        raise SystemExit('Scanner database is missing, stale or future-dated')
    shutil.copyfile(metadata, out/'scanner-db.json')
    # Source gates run before compilation, with no registry/OIDC permissions.
    target = app if a.kind == 'application' else fork if a.kind == 'fork' else ROOT
    run('python3', 'ci/install_tool.py', 'gitleaks', Path(os.environ.get('RUNNER_TEMP', '/tmp'))/'p6-tools', cwd=target)
    gitleaks = Path(os.environ.get('RUNNER_TEMP', '/tmp'))/'p6-tools/gitleaks'
    run('python3', 'ci/check_policy.py', cwd=target)
    if a.kind == 'fork':
        run('python3', 'ci/verify-checksum-findings.py', cwd=fork)
        run('python3', 'ci/demo_history.py', gitleaks, cwd=fork)
        run('python3', 'ci/test-supply-chain-controls.py', gitleaks, cwd=fork)
    else:
        run(gitleaks, 'git', '.', '--redact', '--no-banner', cwd=target)
    # Each source checkout has its own complete source scan in its own build group.
    exclusions = ['--skip-dirs', 'source-application', '--skip-dirs', 'source-fork'] if a.kind == 'infrastructure' else []
    run(scanner, 'fs', '--include-dev-deps', '--scanners', 'vuln', '--list-all-pkgs', '--severity', 'HIGH,CRITICAL',
        '--exit-code', '1', '--format', 'json', '--output', out/'source-scan.json', *exclusions, target)
    images = []
    infra_revision = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip()

    def image(name, context, file, revision, *args):
        tag = 'p6-build-'+name
        run('docker', 'build', '--platform', 'linux/amd64', '-f', file, '--build-arg', 'SOURCE_REVISION='+revision,
            '--label', 'org.nusacred.scope=synthetic-isolated-demo-only', '--label', 'org.opencontainers.image.revision='+revision,
            '-t', tag, *args, context)
        image_id = subprocess.check_output(['docker','image','inspect',tag,'--format','{{.Id}}'],text=True).strip()
        report = out/(name+'-scan.json')
        run(scanner,'image','--image-src','docker','--scanners','vuln','--list-all-pkgs','--severity','HIGH,CRITICAL',
            '--exit-code','1','--format','json','--output',report,image_id)
        data=json.loads(report.read_text())
        if data.get('Metadata',{}).get('ImageID') != image_id or not any(r.get('Packages') for r in data.get('Results',[])):
            raise SystemExit('Image scan identity/coverage missing: '+name)
        if any(v['Severity'] in ('HIGH','CRITICAL') for r in data['Results'] for v in r.get('Vulnerabilities',[])):
            raise SystemExit('Image scan contains High/Critical: '+name)
        run(scanner,'image','--image-src','docker','--format','cyclonedx','--output',out/(name+'-sbom.cdx.json'),image_id)
        run('docker','save','--output',out/(name+'.tar'),tag)
        images.append(dict(name=name,localTag=tag,localImageId=image_id,sourceRevision=revision,archiveSha256=sha(out/(name+'.tar'))))

    if a.kind == 'application':
        run('python3','ci/verify_dependency_review.py',cwd=app)
        run('python3','ci/check_api_contract.py',cwd=app)
        run('node','ci/test_portal_boot.mjs',cwd=app)
        run('./gradlew',':shared-contracts:jvmTest',':backend-common:test',':integration-tests:test',
            ':issuer-backend:installDist',':company-backend:installDist',':custodian-backend:test',':custodian-backend:installDist',
            ':android-wallet:assembleRelease',':android-wallet:lintRelease',':web-portals:wasmJsBrowserDistribution',
            '--dependency-verification','strict','--no-daemon',cwd=app)
        for service in ['custodian','issuer','company']:
            runtime=app/(service+'-backend/build/install')/(service+'-backend/lib')
            report=out/(service+'-runtime-scan.json')
            run(scanner,'rootfs','--scanners','vuln','--list-all-pkgs','--severity','HIGH,CRITICAL','--exit-code','1',
                '--format','json','--output',report,runtime)
            run('python3','ci/check_runtime_scan.py',report,cwd=app)
            image(service,app,app/('deploy/Containerfile.'+service),sources['application']['commit'])
        run('python3','ci/write_runtime_sbom.py','--module','android-wallet','--configuration','releaseRuntimeClasspath',
            '--output',out/'android-runtime.cdx.json',cwd=app)
        run(scanner,'sbom','--scanners','vuln','--list-all-pkgs','--severity','HIGH,CRITICAL','--exit-code','1','--format','json',
            '--output',out/'android-scan.json',out/'android-runtime.cdx.json')
        run('python3','ci/check_runtime_scan.py',out/'android-scan.json',out/'android-runtime.cdx.json',cwd=app)
        shutil.copyfile(app/'android-wallet/build/outputs/apk/release/android-wallet-release-unsigned.apk',out/'wallet-unsigned.apk')
        for module,task in [('shared-contracts','jvmTest'),('backend-common','test'),('integration-tests','test'),('custodian-backend','test')]:
            shutil.copytree(app/module/'build/test-results'/task,out/'tests'/module)
    elif a.kind == 'fork':
        run('bash','ci/test-cose.sh','verify',cwd=fork)
        run('bash','ci/build-baseline.sh','verify',cwd=fork)
        run('bash','ci/scan-baseline-runtime.sh',scanner,cwd=fork)
        run('bash','ci/test-baseline-images.sh',scanner,cwd=fork)
        shutil.copytree(fork/'build/baseline-evidence/reports',out/'baseline')
        for service in ['issuer','wallet','verifier']:
            image('walt-'+service,fork/'build/baseline-evidence/fat-jars',fork/'ci/Dockerfile.api2',sources['fork']['commit'],
                '--build-arg','SERVICE='+service)
    else:
        pins=json.loads((ROOT/'p2/images.json').read_text())
        image('postgres',ROOT/'p2',ROOT/'release/Containerfile.postgres',infra_revision,'--build-arg','POSTGRES_IMAGE='+pins['postgres'])
        runtime_pin=json.loads((ROOT/'release/runtime-base.json').read_text())['image']
        image('keycloak-staff',ROOT/'p2',ROOT/'release/Containerfile.keycloak-temurin',infra_revision,'--build-arg','KEYCLOAK_IMAGE='+pins['keycloak'],'--build-arg','JVM_RUNTIME_IMAGE='+runtime_pin)
        base_id=subprocess.check_output(['docker','image','inspect','p6-build-keycloak-staff','--format','{{.Id}}'],text=True).strip()
        provider=Path(os.environ.get('RUNNER_TEMP','/tmp'))/'p6-provider'
        run('python3',app/'ci/build_keycloak_provider.py','--image',base_id,'--jdk',os.environ['JAVA_HOME'],'--output',provider)
        shutil.copyfile(provider/'provider-build.json',out/'provider-build.json')
        image('keycloak-recovery',provider,ROOT/'p2/Containerfile.keycloak-recovery',infra_revision,'--build-arg','KEYCLOAK_IMAGE=p6-build-keycloak-staff')
        image('edge',ROOT/'local-demo/caddy-build',ROOT/'local-demo/caddy-build/Dockerfile',infra_revision)
        mail_pin=json.loads((ROOT/'release/mail-source.json').read_text())
        run('python3',ROOT/'scripts/build_p2_images.py','--runtime',ROOT/'runtime/p6-build','--mail-only',
            '--mail-pin',ROOT/'release/mail-source.json')
        mail_source=ROOT/'runtime/p6-build/source'/('mailpit-'+mail_pin['commit'])
        run(scanner,'fs','--include-dev-deps','--scanners','vuln','--list-all-pkgs','--severity','HIGH,CRITICAL','--exit-code','1',
            '--format','json','--output',out/'mail-source-scan.json',mail_source)
        tag='competency-proof-p2-mailpit:'+mail_pin['version']
        # Export the already built Mailpit using an exact image-only wrapper; no source recompilation.
        mail=Path(os.environ.get('RUNNER_TEMP','/tmp'))/'p6-mail'
        mail.mkdir(exist_ok=True)
        image_id=subprocess.check_output(['docker','image','inspect',tag,'--format','{{.Id}}'],text=True).strip()
        (mail/'Dockerfile').write_text('FROM '+tag+'\n')
        image('mail',mail,mail/'Dockerfile',infra_revision)
    (out/'build.json').write_text(json.dumps(dict(schemaVersion=1,kind=a.kind,infrastructureRevision=infra_revision,
        sources=sources,images=images,scope='synthetic-isolated-demo-only',productionEligible=False),indent=2)+'\n')
    print('PASS: built and scanned '+a.kind+' release group')

if __name__ == '__main__':
    main()
