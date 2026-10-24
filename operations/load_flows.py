"""Exercise five distinct synthetic holders through issuance and presentation."""
import argparse
import base64
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
from pathlib import Path
import secrets
import threading
import time
from types import SimpleNamespace
from urllib.parse import parse_qs, urlencode, urlsplit
import uuid
import p7

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--runtime', type=Path, required=True)
p.add_argument('--package', type=Path, required=True)
p.add_argument('--smtp', type=Path, required=True)
a = p.parse_args()
i = p7.installer(a.package)
import acceptance_transport
acceptance_transport.ssl = SimpleNamespace(create_default_context=p7.trusted_context)
from acceptance_transport import Browser, login
Browser.loopback_port = int(i.env_read(a.runtime/'compose.env')['P6_HTTPS_PORT'])
Browser.cafile = str(a.runtime/'tls/fullchain.pem')
state = p7.load(a.runtime/'installation.json')
W = 'https://dompet-identitas.demo.inoerawan.id'
L = 'https://lsp-nusantara.demo.inoerawan.id'
C = 'https://karya-instalasi.demo.inoerawan.id'
AUTH = 'https://login-dompet-identitas.demo.inoerawan.id/realms/competency-proof-p2'
REDIRECT = W+'/auth/android/callback'
barrier = threading.Barrier(5)


def request(b, origin, path, method='GET', body=None, headers=None):
    code, h, raw = b.request(origin+path, method, body, headers)
    try:
        data = json.loads(raw)
    except ValueError:
        data = None
    if code >= 400:
        raise RuntimeError('Flow HTTP failure '+str(code)+' at '+path.split('?')[0])
    return code, h, data


def bff(origin, role):
    b = Browser()
    _, headers, _ = request(b, origin, '/auth/start')
    callback = login(b, headers['Location'], state['users'][role])
    if b.request(callback)[0] != 302:
        raise RuntimeError('BFF callback failed')
    _, _, me = request(b, origin, '/auth/me')
    return b, {'Origin': origin, 'X-CSRF-Token': me['csrf']}


def mutate(b, origin, path, body, headers, method='POST'):
    return request(b, origin, path, method, body, dict(headers, **{'Idempotency-Key': str(uuid.uuid4())}))[2]


users = []
api, token = p7.admin(a, 'wallet', 'dompet-identitas')
base = '/admin/realms/competency-proof-p2'
status, role = api.request(a.runtime, 'dompet-identitas', 'GET', base+'/roles/applicant', token=token)
assert status == 200
for n in range(5):
    email = 'p7-load-'+secrets.token_hex(6)+'@example.test'
    user = {'email': email, 'password': secrets.token_urlsafe(24)}
    body = dict(username=email, email=email, enabled=True, emailVerified=True, firstName='Synthetic', lastName='Load',
                credentials=[{'type': 'password', 'value': user['password'], 'temporary': False}])
    assert api.request(a.runtime, 'dompet-identitas', 'POST', base+'/users', body, token)[0] == 201
    status, rows = api.request(a.runtime, 'dompet-identitas', 'GET', base+'/users?'+urlencode({'username': email, 'exact': 'true'}), token=token)
    assert status == 200 and len(rows) == 1
    user['id'] = rows[0]['id']
    assert api.request(a.runtime, 'dompet-identitas', 'POST', base+'/users/'+user['id']+'/role-mappings/realm', [role], token)[0] == 204
    users.append(user)


def flow(user):
    barrier.wait(timeout=30)
    started = time.monotonic()
    issuer, ih = bff(L, 'issuer-admin')
    company, ch = bff(C, 'company-admin')
    client = Browser()
    _, _, enrollment = request(client, W, '/auth/native/start', 'POST', {})
    verifier = secrets.token_urlsafe(48)
    nonce = secrets.token_urlsafe(32)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip('=')
    callback = login(client, AUTH+'/protocol/openid-connect/auth?'+urlencode(dict(client_id='android-wallet-p2', redirect_uri=REDIRECT,
        response_type='code', scope='openid profile email', state=nonce, nonce=enrollment['nonce'], code_challenge=challenge,
        code_challenge_method='S256', prompt='login', max_age='0')), user)
    query = parse_qs(urlsplit(callback).query)
    assert query['state'] == [nonce]
    code, _, raw = client.request(AUTH+'/protocol/openid-connect/token', 'POST', dict(grant_type='authorization_code',
        client_id='android-wallet-p2', redirect_uri=REDIRECT, code=query['code'][0], code_verifier=verifier), form=True)
    assert code == 200
    tokens = json.loads(raw)
    _, _, enrollment = request(client, W, '/auth/native/session', 'POST', dict(ticket=enrollment['ticket'], access_token=tokens['access_token'], id_token=tokens['id_token']))
    nh = {'Authorization': 'Bearer '+enrollment['session']}
    _, _, me = request(client, W, '/api/v1/me', headers=nh)
    _, _, provision = request(client, W, '/api/v1/wallet/provision', 'POST', {}, nh)
    assert provision['state'] == 'READY'
    candidate = 'p7-load-'+uuid.uuid4().hex
    assessment = mutate(issuer, L, '/api/v1/assessments', dict(candidateAccountId=me['accountId'], candidateId=candidate,
        competencyCode='DEMO-ELEC-001', assessmentResult='competent'), ih)
    offer = mutate(issuer, L, '/api/v1/assessments/'+assessment['id']+'/offers', {}, ih)
    context = mutate(client, W, '/api/v1/exchange-contexts', dict(reference=offer['offerUrl'], credentialId=None), nh)
    received = mutate(client, W, '/api/v1/exchange-contexts/'+context['id']+'/accept', dict(previewHash=context['previewHash'], consent=True, credentialId=None, disclosures=[]), nh)
    assert received['state'] == 'COMPLETED'
    mutate(company, C, '/api/v1/jobs/'+candidate, dict(title='Synthetic P7 load validation', competencyCode='DEMO-ELEC-001', assessmentResult='competent'), ch, 'PUT')
    viewer = Browser()
    _, _, session = request(viewer, C, '/api/v1/browser-session')
    vh = {'Origin': C, 'X-CSRF-Token': session['csrf']}
    verification = mutate(viewer, C, '/api/v1/jobs/'+candidate+'/verification-sessions', {}, vh)
    context = mutate(client, W, '/api/v1/exchange-contexts', dict(reference=verification['requestUrl'], credentialId=None), nh)
    sent = mutate(client, W, '/api/v1/exchange-contexts/'+context['id']+'/present', dict(previewHash=context['previewHash'], consent=True,
        credentialId=context['credentialId'], disclosures=context['details']['disclosures']), nh)
    assert sent['state'] == 'COMPLETED'
    _, _, result = request(viewer, C, '/api/v1/verification-sessions/'+verification['id'])
    assert result['final'] is True and result['decision'] == 'FULFILLED'
    return {'result': 'PASS', 'seconds': round(time.monotonic()-started, 3)}


samples = []
stop = threading.Event()

def sample():
    while not stop.is_set():
        mem = dict(line.split(':', 1) for line in Path('/proc/meminfo').read_text().splitlines())
        samples.append({'availableFraction': int(mem['MemAvailable'].split()[0])/int(mem['MemTotal'].split()[0]),
                        'loadAverage': list(__import__('os').getloadavg())})
        stop.wait(.5)

thread = threading.Thread(target=sample); thread.start()
started = time.monotonic()
try:
    with ThreadPoolExecutor(max_workers=5) as pool:
        results = list(pool.map(flow, users))
finally:
    stop.set(); thread.join()
report = {'result': 'PASS', 'concurrentFlows': 5, 'distinctSyntheticHolders': 5, 'flows': results,
          'wallSeconds': round(time.monotonic()-started, 3), 'minimumAvailableMemoryFraction': round(min(x['availableFraction'] for x in samples), 3),
          'maximumLoadAverage1m': max(x['loadAverage'][0] for x in samples), 'samples': len(samples),
          'limitations': ['Synthetic HTTP consent/protocol flows; physical APK is separate', 'Host memory samples include concurrent desktop processes; desktop interaction latency is not measured']}
assert report['minimumAvailableMemoryFraction'] >= .25
p7.save(a.runtime/'load-test.json', report)
print(json.dumps(report))
