"""Safely inject monitored values and exercise real SMTP alert and recovery.

Only the detector inputs and its separate test-state file change. No disk is
filled, certificate replaced, backup removed, or participant request interrupted.
"""
import argparse
import json
from pathlib import Path
import shutil
import subprocess
import time
from types import SimpleNamespace
from unittest.mock import patch
import p7

p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--runtime',type=Path,required=True)
p.add_argument('--package',type=Path,required=True)
p.add_argument('--smtp',type=Path,required=True)
a=p.parse_args()
a.monitor_state=a.runtime/'alert-test-state.json'
checks=[]
for label in ('disk','backup-stale','tls-expiry'):
    a.simulation_label=label
    a.monitor_state.unlink(missing_ok=True)
    if label=='disk':
        context=patch.object(p7.shutil,'disk_usage',return_value=SimpleNamespace(total=100,free=1,used=99))
        expected='disk-free-below-20-percent'
    elif label=='backup-stale':
        original=p7.load
        def read(path):
            value=original(path)
            if Path(path).name=='backup-ack.json':value=dict(value,completedEpoch=time.time()-27*3600)
            return value
        context=patch.object(p7,'load',side_effect=read)
        expected='backup-missing-or-stale'
    else:
        original_run=p7.subprocess.run
        def command(args,*positional,**kw):
            if args[:3]==['openssl','x509','-checkend']:
                return subprocess.CompletedProcess(args,1)
            return original_run(args,*positional,**kw)
        context=patch.object(p7.subprocess,'run',side_effect=command)
        expected='tls-expires-within-14-days'
    with context:
        assert p7.health(a)==1
        state=p7.load(a.monitor_state)
        assert expected in state['issues'] and state.get('alertAcceptedBySmtp') is True
    assert p7.health(a)==0
    state=p7.load(a.monitor_state)
    assert not state['issues'] and state.get('alertAcceptedBySmtp') is True
    checks.append({'simulation':label,'alertAcceptedBySmtp':True,'recoveryAcceptedBySmtp':True})
a.monitor_state.unlink(missing_ok=True)
report={'result':'PASS','checks':checks,'operatorInboxConfirmation':'pending',
        'scope':'safe detector-input fault injection with real SMTP; no real disk exhaustion or certificate replacement'}
p7.save(a.runtime/'alert-tests.json',report)
print(json.dumps(report))
