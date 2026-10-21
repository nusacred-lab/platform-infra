"""Prove missing pre-write acknowledgement prevents password change and forgery never opens access."""
import argparse
import http.client
import json
from pathlib import Path
import re
import secrets
import subprocess
import time
from urllib.parse import urlencode, urljoin
from check_p2_identity import request, REALM
from test_p2_login import Browser, AUTH, ISSUER, REDIRECT
from test_p2_recovery import Form, follow, tokens, wallet

p = argparse.ArgumentParser(__doc__)
p.add_argument('--runtime', type=Path, required=True)
a = p.parse_args(); r = a.runtime.resolve(); user = json.loads((r / 'recovery-fixture.json').read_text())
browser = Browser()
url = ISSUER + '/protocol/openid-connect/auth?' + urlencode({'client_id': 'android-wallet-p2', 'redirect_uri': REDIRECT,
    'response_type': 'code', 'scope': 'openid', 'code_challenge': secrets.token_urlsafe(32), 'code_challenge_method': 'S256'})
status, _, page = follow(browser, url); assert status == 200
forgotten = next(x for x in Form(page).links if '/login-actions/reset-credentials' in x)
status, _, page = follow(browser, urljoin(AUTH, forgotten)); assert status == 200
form = Form(page); assert form.action
_, _, inbox = request('GET', '/api/v1/messages', mail=True); old_ids = {m['ID'] for m in inbox['messages']}
status, _, _ = browser.request(form.action, 'POST', dict(form.hidden, username=user['email']), form=True); assert status == 200
for _ in range(15):
    _, _, inbox = request('GET', '/api/v1/messages', mail=True)
    found = [m for m in inbox['messages'] if m['ID'] not in old_ids and any(x['Address'] == user['email'] for x in m['To'])]
    if found: break
    time.sleep(1)
assert found
_, _, full = request('GET', '/api/v1/message/' + found[0]['ID'], mail=True)
link = next(x.rstrip(').') for x in re.findall(r'https://[^\s<>"\']+', full['Text']) if '/login-actions/action-token?' in x)
status, _, page = follow(browser, link); assert status == 200
form = Form(page); assert form.action
subprocess.run(['docker', 'stop', 'competency-proof-p2-custodian-1'], check=True, stdout=subprocess.DEVNULL)
try:
    candidate = secrets.token_urlsafe(32)
    status, _, _ = browser.request(form.action, 'POST', dict(form.hidden, **{'password-new': candidate, 'password-confirm': candidate}), form=True)
    assert status == 503, 'Password write must fail before an acknowledgement is available'
finally:
    subprocess.run(['docker', 'start', 'competency-proof-p2-custodian-1'], check=True, stdout=subprocess.DEVNULL)
for _ in range(30):
    try:
        c = http.client.HTTPConnection('127.0.0.1', 18080, timeout=3)
        c.request('GET', '/health/live'); response = c.getresponse(); ready = response.status == 200; response.read(); c.close()
        if ready: break
    except (OSError, http.client.HTTPException): pass
    time.sleep(1)
else: raise AssertionError('Custodian did not restart')
_, _, session = tokens(user)  # The original password must still work; gate was never acknowledged.
assert wallet(session, 'credentials')[0] == 200
print('PASS: unavailable coordinator prevents password write; original password and wallet remain usable')
c = http.client.HTTPConnection('127.0.0.1', 18080, timeout=10)
try:
    c.request('POST', '/internal/recoveries/complete', json.dumps({'issuer': ISSUER, 'subject': user['id'],
        'operation': secrets.token_urlsafe(32), 'revision': 999}), {'Content-Type': 'application/json',
        'X-Recovery-Time': str(int(time.time())), 'X-Recovery-Signature': 'invalid'})
    response = c.getresponse(); assert response.status == 503; response.read()
finally: c.close()
assert wallet(session, 'credentials')[0] == 200
print('PASS: forged completion callback is rejected without changing access')
(r / 'recovery-unavailable-result.json').write_text(json.dumps({'schemaVersion': 1,
    'checks': ['Missing pre-write acknowledgement prevents password change', 'Original password and wallet remain usable',
               'Forged completion callback cannot change account access']}, indent=2) + '\n')
