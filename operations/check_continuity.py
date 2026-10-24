"""Present a credential issued before backup from the isolated restored wallet."""
import argparse
import base64
import hashlib
import json
from pathlib import Path
import secrets
import time
from types import SimpleNamespace
from urllib.parse import parse_qs, urlencode, urlsplit
import uuid
import p7

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--runtime', type=Path, required=True)
p.add_argument('--package', type=Path, required=True)
p.add_argument('--restored-active', action='store_true')
p.add_argument('--report', type=Path)
a = p.parse_args()
i = p7.installer(a.package)
import acceptance_transport
acceptance_transport.ssl = SimpleNamespace(create_default_context=p7.trusted_context)
from acceptance_transport import Browser, login
Browser.loopback_port = int(i.env_read(a.runtime/'compose.env')['P6_HTTPS_PORT'])
Browser.cafile = str(a.runtime/'tls/fullchain.pem')
project = i.env_read(a.runtime/'compose.env')['P6_PROJECT_NAME']
assert project == 'competency-proof-p7-rehearsal' or (a.restored_active and project == 'competency-proof-p7' and p7.load(a.runtime/'operations.json')['gateG7'] == 'pending' and not (a.runtime/'invitation-state.json').exists())
state = p7.load(a.runtime/'installation.json')
before = p7.load(a.runtime/'continuity-private.json')
W = 'https://dompet-identitas.demo.inoerawan.id'
C = 'https://karya-instalasi.demo.inoerawan.id'
AUTH = 'https://login-dompet-identitas.demo.inoerawan.id/realms/competency-proof-p2'
REDIRECT = W+'/auth/android/callback'


def req(b, origin, path, method='GET', body=None, headers=None):
    status, h, raw = b.request(origin+path, method, body, headers)
    assert status < 400, (status, path.split('?')[0])
    try:
        data = json.loads(raw)
    except ValueError:
        data = None
    return status, h, data


def mutate(b, origin, path, body, headers, method='POST'):
    return req(b, origin, path, method, body, dict(headers, **{'Idempotency-Key': str(uuid.uuid4())}))[2]


for attempt in range(90):
    try:
        if req(Browser(), W, '/api/v1/portal-config')[0] == 200:
            break
    except Exception:
        pass
    time.sleep(1)
client = Browser()
_, _, enrollment = req(client, W, '/auth/native/start', 'POST', {})
verifier = secrets.token_urlsafe(48)
nonce = secrets.token_urlsafe(32)
challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip('=')
callback = login(client, AUTH+'/protocol/openid-connect/auth?'+urlencode(dict(client_id='android-wallet-p2',redirect_uri=REDIRECT,
    response_type='code',scope='openid profile email',state=nonce,nonce=enrollment['nonce'],code_challenge=challenge,
    code_challenge_method='S256',prompt='login',max_age='0')), state['users']['applicant'])
query = parse_qs(urlsplit(callback).query);assert query['state'] == [nonce]
status, _, raw = client.request(AUTH+'/protocol/openid-connect/token','POST',dict(grant_type='authorization_code',
    client_id='android-wallet-p2',redirect_uri=REDIRECT,code=query['code'][0],code_verifier=verifier),form=True)
assert status == 200
tokens = json.loads(raw)
_, _, enrollment = req(client,W,'/auth/native/session','POST',dict(ticket=enrollment['ticket'],access_token=tokens['access_token'],id_token=tokens['id_token']))
nh = {'Authorization':'Bearer '+enrollment['session']}
_, _, provision = req(client,W,'/api/v1/wallet/provision','POST',{},nh)
assert provision['wallet_id'] == before['walletId']
_, _, credentials = req(client,W,'/api/v1/wallet/credentials',headers=nh)
assert hashlib.sha256(json.dumps(credentials,sort_keys=True).encode()).hexdigest() == before['credentialDigest']
company = Browser();_, h, _ = req(company,C,'/auth/start')
assert company.request(login(company,h['Location'],state['users']['company-admin']))[0] == 302
_, _, me = req(company,C,'/auth/me');ch = {'Origin':C,'X-CSRF-Token':me['csrf']}
job = 'p7-restored-'+uuid.uuid4().hex
mutate(company,C,'/api/v1/jobs/'+job,dict(title='Restored pre-backup credential',competencyCode='DEMO-ELEC-001',assessmentResult='competent'),ch,'PUT')
viewer=Browser();_,_,session=req(viewer,C,'/api/v1/browser-session');vh={'Origin':C,'X-CSRF-Token':session['csrf']}
verification=mutate(viewer,C,'/api/v1/jobs/'+job+'/verification-sessions',{},vh)
context=mutate(client,W,'/api/v1/exchange-contexts',dict(reference=verification['requestUrl'],credentialId=None),nh)
sent=mutate(client,W,'/api/v1/exchange-contexts/'+context['id']+'/present',dict(previewHash=context['previewHash'],consent=True,
    credentialId=context['credentialId'],disclosures=context['details']['disclosures']),nh)
assert sent['state']=='COMPLETED'
_,_,final=req(viewer,C,'/api/v1/verification-sessions/'+verification['id'])
assert final['final'] is True and final['decision']=='FULFILLED'
report_path = a.report or a.runtime.parent/'p7/restore-rehearsal.json'
report = p7.load(report_path) if report_path.exists() else {'result':'PASS','scope':'restored active P7 from encrypted VM snapshot; pre-opening synthetic test'}
report.update(credentialPresentation='FULFILLED',walletIdIdentical=True,credentialBytesIdentical=True,
              verifiedAt=__import__('datetime').datetime.now(__import__('datetime').timezone.utc).isoformat())
p7.save(report_path,report)
print(json.dumps(report))
