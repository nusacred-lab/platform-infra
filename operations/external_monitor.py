"""Check public P7 HTTPS and a synthetic login from outside the VM.

Run on the operator laptop; VM outage can then be reported through independently
stored private SMTP settings. A sleeping/disconnected laptop cannot monitor.
"""
import argparse
import datetime as dt
import json
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import time
from types import SimpleNamespace
import p7

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--runtime', type=Path, required=True, help='Private local monitoring state')
p.add_argument('--package', type=Path, required=True)
p.add_argument('--smtp', type=Path, required=True)
a = p.parse_args()
config = p7.load(a.runtime/'operations.json')
maintenance = a.runtime/'maintenance.json'
if maintenance.exists() and time.time()-p7.load(maintenance)['startedEpoch'] < 600:
    print(json.dumps({'status':'planned-backup-maintenance','maximumSeconds':600}))
    raise SystemExit(0)
if dt.datetime.now(dt.timezone.utc) >= dt.datetime.fromisoformat(config['closesAt']):
    raise SystemExit('Demo monitoring period has ended')
sys.path.insert(0,str(a.package))
from acceptance_transport import Browser,login
Browser.public_frontend = True
Browser.cafile = None
issues = []
checks = {}
for domain in ('dompet-identitas','lsp-nusantara','karya-instalasi'):
    origin = 'https://'+domain+'.demo.inoerawan.id'
    try:
        status, headers, raw = Browser().request(origin+'/api/v1/portal-config')
        ok = status == 200 and isinstance(json.loads(raw),dict) and headers.get('X-Competency-Environment') == 'p7-active'
    except Exception:
        ok = False
    checks[domain] = ok
    if not ok:
        issues.append('public-'+domain)
try:
    origin = 'https://dompet-identitas.demo.inoerawan.id'
    browser = Browser()
    status, headers, _ = browser.request(origin+'/auth/start')
    assert status == 302
    account = p7.load(a.runtime/'installation.json')['users']['custodian-admin']
    callback = login(browser,headers['Location'],account)
    assert browser.request(callback)[0] == 302
    status, _, raw = browser.request(origin+'/auth/me')
    assert status == 200 and json.loads(raw).get('csrf')
    # End the synthetic browser session instead of accumulating sessions.
    me = json.loads(raw)
    browser.request(origin+'/auth/logout','POST',{}, {'Origin':origin,'X-CSRF-Token':me['csrf']})
    checks['synthetic-login'] = True
except Exception:
    issues.append('public-synthetic-login');checks['synthetic-login'] = False
for domain,realm in [('dompet-identitas','competency-proof-p2'),('lsp-nusantara','lsp-nusantara'),('karya-instalasi','karya-instalasi')]:
    try:
        status, _, _ = Browser().request('https://login-'+domain+'.demo.inoerawan.id/admin/realms/'+realm)
        if status != 404:
            issues.append('public-admin-boundary-'+domain)
    except Exception:
        issues.append('public-identity-'+domain)
state = a.runtime/'external-monitor.json'
old = p7.load(state).get('issues',[]) if state.exists() else []
result = {'at':dt.datetime.now(dt.timezone.utc).isoformat(),'issues':sorted(set(issues)),'checks':checks,
          'scope':'public HTTPS, P7 environment identity, synthetic login, private admin boundary'}
if sorted(old) != result['issues']:
    p7.notify(a,'public outage' if result['issues'] else 'public recovered', json.dumps({'issues':result['issues'],'previous':old}))
    result['alertAcceptedBySmtp'] = True
p7.save(state,result)
print(json.dumps(result))
raise SystemExit(1 if result['issues'] else 0)
