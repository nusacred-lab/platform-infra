from context import P6_PROJECT
"""Verify restricted password paths and real email verification/expiry using private Keycloak."""
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import secrets
import time
from urllib.parse import urlencode
from context import admin_request as request, REALM, AUTH
from context import Browser
from recovery import tokens, wallet, follow, Form

p = argparse.ArgumentParser(__doc__)
p.add_argument('--runtime', type=Path, required=True)
a = p.parse_args(); r = a.runtime.resolve(); c = json.loads((r / 'credentials.json').read_text()); results = []
def passed(s): results.append(s); print('PASS:', s, flush=True)
status, _, auth = request('POST', '/realms/master/protocol/openid-connect/token', {
    'grant_type': 'password', 'client_id': 'admin-cli', 'username': 'wallet-bootstrap', 'password': c['bootstrap']}, form=True)
assert status == 200
token = auth['access_token']; base = '/admin/realms/' + REALM
status, _, clients = request('GET', base + '/clients', token=token); assert status == 200
clients = {x['clientId']: x for x in clients}
assert all(not clients[name]['enabled'] for name in ('account', 'account-console'))
for name in ('android-wallet-p2', 'custodian-bff-p2'):
    assert not clients[name].get('serviceAccountsEnabled') and not clients[name].get('directAccessGrantsEnabled')
passed('Account console clients, direct password grants and runtime administrative service accounts are disabled')
status, _, profile = request('GET', base + '/users/profile', token=token); assert status == 200
assert profile.get('unmanagedAttributePolicy') is None
marker = next(x for x in profile['attributes'] if x['name'] == 'nusacred_recovery_commit')
assert marker['permissions'] == {'view': ['admin'], 'edit': ['admin']}
passed('Recovery reconciliation marker cannot be read or edited by applicant profile permissions')
user = json.loads((r / 'recovery-fixture.json').read_text())
browser, native, session = tokens(user)
status, _, _ = request('PUT', base + '/users/' + user['id'] + '/reset-password', {
    'type': 'password', 'value': secrets.token_urlsafe(32), 'temporary': False}, token=native['access_token'])
assert status == 403
for path in ('/realms/' + REALM + '/account/credentials', '/realms/' + REALM + '/account/credentials/password'):
    status, _, _ = browser.request(AUTH + path, headers={'Authorization': 'Bearer ' + native['access_token']})
    assert status in (401, 403, 404, 405)
assert wallet(session, 'credentials')[0] == 200
passed('Applicant access tokens cannot invoke administrative reset or account credential APIs')
# Exercise an actually expired, signed action token without changing realm-wide lifespans.
status, _, inbox = request('GET', '/api/v1/messages', mail=True); assert status == 200
old = {x['ID'] for x in inbox['messages']}
assert request('PUT', base + '/users/' + user['id'] + '/execute-actions-email?lifespan=1', ['UPDATE_PASSWORD'], token=token)[0] == 204
for _ in range(15):
    status, _, inbox = request('GET', '/api/v1/messages', mail=True)
    found = [m for m in inbox['messages'] if m['ID'] not in old and any(x['Address'] == user['email'] for x in m['To'])]
    if found: break
    time.sleep(1)
assert found
status, _, full = request('GET', '/api/v1/message/' + found[0]['ID'], mail=True); assert status == 200
link = next(x.rstrip(').') for x in re.findall(r'https://[^\s<>"\']+', full['Text']) if '/login-actions/action-token?' in x)
time.sleep(2)
status, _, page = follow(Browser(), link)
assert status == 400 and ('expired' in page.lower() or 'invalid' in page.lower())
assert wallet(session, 'credentials')[0] == 200
passed('Expired signed password-action token is rejected without closing wallet access')
# Verify a fresh synthetic email by consuming the actual SMTP-delivered link.
fixture = {'email': 'p2-email-' + secrets.token_hex(8) + '@example.test', 'password': secrets.token_urlsafe(32)}
status, headers, _ = request('POST', base + '/users', {'username': fixture['email'], 'email': fixture['email'],
    'firstName': 'Synthetic', 'lastName': 'Email', 'enabled': True, 'emailVerified': False,
    'credentials': [{'type': 'password', 'value': fixture['password'], 'temporary': False}]}, token=token)
assert status == 201
fixture['id'] = headers['Location'].rsplit('/', 1)[1]
(r / 'email-verification-fixture.json').write_text(json.dumps(fixture)); (r / 'email-verification-fixture.json').chmod(0o600)
assert request('PUT', base + '/users/' + fixture['id'] + '/send-verify-email', token=token)[0] == 204
for _ in range(15):
    status, _, inbox = request('GET', '/api/v1/messages', mail=True)
    found = [m for m in inbox['messages'] if any(x['Address'] == fixture['email'] for x in m['To'])]
    if found: break
    time.sleep(1)
assert found
status, _, full = request('GET', '/api/v1/message/' + found[0]['ID'], mail=True); assert status == 200
link = next(x.rstrip(').') for x in re.findall(r'https://[^\s<>"\']+', full['Text']) if '/login-actions/action-token?' in x)
verification_browser = Browser()
status, _, page = follow(verification_browser, link); assert status == 200
# A fresh browser must explicitly confirm the email action; a 200 page alone is insufficient.
confirmation = next(x for x in Form(page).links if '/login-actions/action-token?' in x)
status, _, _ = follow(verification_browser, confirmation); assert status == 200
status, _, detail = request('GET', base + '/users/' + fixture['id'], token=token)
assert status == 200 and detail['emailVerified'] is True
passed('Actual SMTP verification link is consumed and Keycloak persists verified email')
(r / 'password-paths-result.json').write_text(json.dumps({'schemaVersion': 1, 'time': datetime.now(timezone.utc).isoformat(),
    'checks': results, 'limits': ['Private bootstrap operator remains an explicitly trusted offline administrative boundary']}, indent=2) + '\n')
