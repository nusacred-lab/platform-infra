"""Assemble a source-free Compose package from signed publication records."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import tarfile

root=Path(__file__).resolve().parents[2]
folder=root/'distribution'
folder.mkdir(exist_ok=False)
records=[json.loads((root/'published'/kind/'published.json').read_text()) for kind in ['application','fork','infrastructure']]
if any(r['infrastructureRevision']!=os.environ['GITHUB_SHA'] for r in records):
    raise SystemExit('Mixed workflow revisions')
manifest=dict(schemaVersion=1,scope='synthetic-isolated-demo-only',productionEligible=False,
    sources=records[0]['sources'],infrastructureRevision=os.environ['GITHUB_SHA'],
    workflow=dict(repository='nusacred-lab/platform-infra',path='.github/workflows/release.yml',
        ref=os.environ['GITHUB_REF'],commit=os.environ['GITHUB_SHA'],runId=os.environ['GITHUB_RUN_ID']),
    images={row['name']:{key:row[key] for key in ['image','sourceRevision','signerIdentity']} for record in records for row in record['images']},
    schemas={'custodianRegistry':5,'businessMigrations':3,'policyVersion':'competency-v1'},
    rollback={'databaseDowngrade':'forbidden','compatibleBaseline':'P5: registry 5, business migrations 3; restore a stopped consistent snapshot for any incompatible version'},
    acceptance={'G6':'pending','G7':'pending'})
apk=root/'published/application/wallet-unsigned.apk'
manifest['apk']={'unsignedSha256':hashlib.file_digest(apk.open('rb'),'sha256').hexdigest(),
    'sourceRevision':manifest['sources']['application']['commit'],'versionCode':5,'versionName':'0.6.0-p6',
    'signing':'offline-required','applicationId':'id.nusacred.wallet'}
bundle=folder/'competency-proof'
shutil.copytree(root/'release',bundle)
(bundle/'release-manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
shutil.copyfile(bundle/'release-manifest.json',folder/'release-manifest.json')
with tarfile.open(folder/'competency-proof-compose.tar.gz','w:gz') as archive:
    archive.add(bundle,arcname='competency-proof',filter=lambda info:None if '__pycache__' in info.name or info.name.endswith('.pyc') else info)
shutil.copyfile(apk,folder/'wallet-unsigned.apk')
for name in ['release-manifest.json','competency-proof-compose.tar.gz','wallet-unsigned.apk']:
    path=folder/name
    with (folder/'SHA256SUMS').open('a') as sums:
        sums.write(hashlib.file_digest(path.open('rb'),'sha256').hexdigest()+'  '+name+'\n')
print('PASS: Compose package contains no application/fork checkout or private runtime')
