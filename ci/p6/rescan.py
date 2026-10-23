"""Re-verify and rescan the exact published release digests, failing closed."""
import argparse
from datetime import datetime,timezone
import importlib.util
import json
import os
from pathlib import Path
import subprocess
from scan_gate import scan

root=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('installer',root/'release/install.py')
installer=importlib.util.module_from_spec(spec);spec.loader.exec_module(installer)
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--manifest',type=Path,default=root/'release/current.json')
p.add_argument('--scanner',type=Path,required=True)
p.add_argument('--output',type=Path,required=True)
a=p.parse_args()
manifest=json.loads(a.manifest.read_text())
installer.verify(a.manifest,manifest['workflow']['commit'],manifest['workflow']['ref'])
a.output.mkdir(parents=True,exist_ok=True)
cache=Path(os.environ.get('RUNNER_TEMP','/tmp'))/'p6-rescan-cache'
env=dict(os.environ,TRIVY_CACHE_DIR=str(cache))
subprocess.run([str(a.scanner.resolve()),'image','--download-db-only'],env=env,check=True)
metadata=json.loads((cache/'db/metadata.json').read_text())
age=(datetime.now(timezone.utc)-datetime.fromisoformat(metadata['UpdatedAt'].replace('Z','+00:00'))).total_seconds()
if not 0<=age<86400:raise SystemExit('Scanner database unhealthy')
results=[]
for name,row in manifest['images'].items():
    report=a.output/(name+'.json')
    try:
        scan([str(a.scanner.resolve()),'image','--image-src','remote','--scanners','vuln','--list-all-pkgs',
            '--severity','HIGH,CRITICAL','--exit-code','1','--format','json','--output',str(report),row['image']],env=env)
        status=0
    except (subprocess.CalledProcessError, RuntimeError, ValueError, OSError):
        status=1
    try:
        data=json.loads(report.read_text()) if report.exists() else {}
    except ValueError:
        data={}
    covered=any(r.get('Packages') for r in data.get('Results',[]))
    results.append({'image':row['image'],'name':name,'passed':status==0 and covered})
(a.output/'result.json').write_text(json.dumps({'releaseWorkflowCommit':manifest['workflow']['commit'],
    'scannerDatabase':metadata,'images':results,'alertOwner':'abeinoe','channel':'GitHub Actions failure notifications'},indent=2)+'\n')
if not all(row['passed'] for row in results):raise SystemExit('Release digest scan failed; operator must investigate reports before use')
print('PASS: all exact release digests reverified and rescanned')
