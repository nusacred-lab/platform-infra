"""Publish only previously scanned image archives; sign exact registry digests."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

root=Path(__file__).resolve().parents[2]
folder=Path(sys.argv[1]).resolve()
build=json.loads((folder/'build.json').read_text())
revision=os.environ['GITHUB_SHA']
if build['infrastructureRevision']!=revision or build['scope']!='synthetic-isolated-demo-only':
    raise SystemExit('Candidate belongs to another workflow/source')
identity='https://github.com/nusacred-lab/platform-infra/.github/workflows/release.yml@'+os.environ['GITHUB_REF']
for row in build['images']:
    name=row['name']
    archive=folder/(name+'.tar')
    digest=hashlib.file_digest(archive.open('rb'),'sha256').hexdigest()
    if digest!=row['archiveSha256']:
        raise SystemExit('Image archive checksum mismatch')
    subprocess.run(['docker','load','--input',str(archive)],check=True,stdout=subprocess.DEVNULL)
    image_id=subprocess.check_output(['docker','image','inspect',row['localTag'],'--format','{{.Id}}'],text=True).strip()
    if image_id!=row['localImageId']:
        raise SystemExit('Loaded image differs from the scanned candidate')
    repository='ghcr.io/nusacred-lab/competency-proof-'+name
    tag=repository+':p6-'+revision+'-'+os.environ['GITHUB_RUN_ID']+'-'+os.environ['GITHUB_RUN_ATTEMPT']
    subprocess.run(['docker','tag',image_id,tag],check=True)
    subprocess.run(['docker','push',tag],check=True)
    refs=json.loads(subprocess.check_output(['docker','image','inspect',tag,'--format','{{json .RepoDigests}}'],text=True))
    immutable=next(ref for ref in refs if ref.startswith(repository+'@sha256:'))
    # A keyless signature records the exact GitHub workflow identity in the transparency log.
    subprocess.run(['cosign','sign','--yes',immutable],check=True)
    provenance={'buildDefinition':{'buildType':'https://nusacred-lab.github.io/p6/docker-archive/v1',
        'externalParameters':{'sources':build['sources'],'infrastructureRevision':revision},
        'internalParameters':{},'resolvedDependencies':[{'uri':'git+https://github.com/'+item['repository'],
        'digest':{'gitCommit':item['commit']}} for key,item in build['sources'].items() if key in ('application','fork')]},
        'runDetails':{'builder':{'id':identity},'metadata':{'invocationId':os.environ['GITHUB_SERVER_URL']+'/'+os.environ['GITHUB_REPOSITORY']+'/actions/runs/'+os.environ['GITHUB_RUN_ID']}}}
    predicate=folder/(name+'-provenance.json')
    predicate.write_text(json.dumps(provenance,indent=2)+'\n')
    subprocess.run(['cosign','attest','--yes','--type','slsaprovenance1','--predicate',str(predicate),immutable],check=True)
    subprocess.run(['cosign','attest','--yes','--type','cyclonedx','--predicate',str(folder/(name+'-sbom.cdx.json')),immutable],check=True)
    subprocess.run(['cosign','verify','--certificate-identity',identity,'--certificate-oidc-issuer','https://token.actions.githubusercontent.com',immutable],check=True,stdout=subprocess.DEVNULL)
    row['image']=immutable
    row['signerIdentity']=identity
    archive.unlink()
(folder/'published.json').write_text(json.dumps(build,indent=2)+'\n')
print('PASS: immutable image publication, signatures, provenance and SBOM attestations')
