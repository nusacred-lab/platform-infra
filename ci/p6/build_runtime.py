"""Build and scan the common patched JVM runtime before downstream release builds."""
from datetime import datetime,timezone
import hashlib,json,os
from pathlib import Path
import subprocess
import sys
from scan_gate import scan
root=Path(__file__).resolve().parents[2]
out=root/'out/runtime';out.mkdir(parents=True,exist_ok=False)
scanner=Path(sys.argv[1]).resolve()
os.environ['TRIVY_CACHE_DIR']=str(Path(os.environ.get('RUNNER_TEMP','/tmp'))/'p6-runtime-trivy')
subprocess.run([str(scanner),'image','--download-db-only'],check=True)
metadata=Path(os.environ['TRIVY_CACHE_DIR'])/'db/metadata.json'
data=json.loads(metadata.read_text())
age=(datetime.now(timezone.utc)-datetime.fromisoformat(data['UpdatedAt'].replace('Z','+00:00'))).total_seconds()
if not 0<=age<86400:raise SystemExit('Scanner database unhealthy')
(out/'scanner-db.json').write_text(json.dumps(data,indent=2)+'\n')
revision=os.environ['GITHUB_SHA'];tag='p6-build-jvm-runtime'
subprocess.run(['docker','build','--platform','linux/amd64','--build-arg','SOURCE_REVISION='+revision,
 '-f',str(root/'release/Containerfile.jvm-runtime'),'-t',tag,str(root/'release')],check=True)
image_id=subprocess.check_output(['docker','image','inspect',tag,'--format','{{.Id}}'],text=True).strip()
scan([str(scanner),'image','--image-src','docker','--scanners','vuln','--list-all-pkgs','--severity','HIGH,CRITICAL',
 '--exit-code','1','--format','json','--output',str(out/'jvm-runtime-scan.json'),image_id])
report=json.loads((out/'jvm-runtime-scan.json').read_text())
if report['Metadata']['ImageID']!=image_id or not any(row.get('Packages') for row in report.get('Results',[])):
 raise SystemExit('Runtime scan coverage/identity missing')
subprocess.run([str(scanner),'image','--image-src','docker','--format','cyclonedx','--output',str(out/'jvm-runtime-sbom.cdx.json'),image_id],check=True)
subprocess.run(['docker','save','--output',str(out/'jvm-runtime.tar'),tag],check=True)
row=dict(name='jvm-runtime',localTag=tag,localImageId=image_id,sourceRevision=revision,
 archiveSha256=hashlib.file_digest((out/'jvm-runtime.tar').open('rb'),'sha256').hexdigest())
(out/'build.json').write_text(json.dumps(dict(schemaVersion=1,kind='runtime',infrastructureRevision=revision,
 sources=json.loads((root/'release/sources.json').read_text()),images=[row],scope='synthetic-isolated-demo-only',productionEligible=False),indent=2)+'\n')
print('PASS: patched common JVM image built and scanned')
