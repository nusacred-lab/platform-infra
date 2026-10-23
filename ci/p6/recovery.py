"""P6 isolated email recovery and retained-credential proof, adapted from the accepted P2 tests."""
import argparse
import base64
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import hashlib
from html import unescape
from html.parser import HTMLParser
import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
import time
import subprocess
import sys
from urllib.parse import parse_qs, urlencode, urlsplit, urljoin
from context import admin_request, REALM, P6_PROJECT
from context import Browser, login, json_request, AUTH, WALLET, ISSUER, REDIRECT


class Form(HTMLParser):
    def __init__(self, page):
        super().__init__(); self.action = None; self.hidden = {}; self.inside = False; self.links = []
        self.feed(page)
    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == 'a' and a.get('href'): self.links.append(a['href'])
        if tag == 'form' and a.get('method', '').lower() == 'post' and self.action is None:
            self.action = a.get('action'); self.inside = True
        if self.inside and tag == 'input' and a.get('type') == 'hidden' and a.get('name'):
            self.hidden[a['name']] = a.get('value', '')
    def handle_endtag(self, tag):
        if tag == 'form': self.inside = False


def follow(browser, url):
    for _ in range(8):
        status, headers, page = browser.request(url)
        if status not in (302, 303, 307): return status, headers, page
        url = urljoin(url, headers['Location'])
    raise AssertionError('Too many private login redirects')


def tokens(user, expected_session=200):
    browser = Browser()
    status, _, flow = json_request(browser, '/auth/native/start', 'POST', {})
    assert status == 200
    verifier = secrets.token_urlsafe(48)
    state = secrets.token_urlsafe(32)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip('=')
    url = ISSUER + '/protocol/openid-connect/auth?' + urlencode({
        'client_id': 'android-wallet-p2', 'redirect_uri': REDIRECT, 'response_type': 'code',
        'scope': 'openid profile email', 'state': state, 'nonce': flow['nonce'],
        'code_challenge': challenge, 'code_challenge_method': 'S256', 'prompt': 'login', 'max_age': '0'})
    callback = login(browser, url, user)
    query = parse_qs(urlsplit(callback).query); assert query['state'] == [state]
    status, _, raw = browser.request(ISSUER + '/protocol/openid-connect/token', 'POST', {
        'grant_type': 'authorization_code', 'client_id': 'android-wallet-p2', 'redirect_uri': REDIRECT,
        'code': query['code'][0], 'code_verifier': verifier}, form=True)
    assert status == 200
    result = json.loads(raw)
    status, _, session = json_request(browser, '/auth/native/session', 'POST', dict(ticket=flow['ticket'],
        access_token=result['access_token'], id_token=result['id_token']))
    assert status == expected_session, 'Unexpected application-session registration status'
    if expected_session != 200: return None
    return browser, result, session['session']


def wallet(opaque, path, body=None):
    return json_request(Browser(), '/api/v1/wallet/' + path, 'POST' if body is not None else 'GET', body,
                        {'Authorization': 'Bearer ' + opaque})


def email_reset_form(user):
    browser = Browser()
    url = ISSUER + '/protocol/openid-connect/auth?' + urlencode({'client_id': 'android-wallet-p2',
        'redirect_uri': REDIRECT, 'response_type': 'code', 'scope': 'openid',
        'code_challenge': secrets.token_urlsafe(32), 'code_challenge_method': 'S256'})
    status, _, page = follow(browser, url); assert status == 200
    forgotten = next(x for x in Form(page).links if '/login-actions/reset-credentials' in x)
    status, _, page = follow(browser, urljoin(AUTH, forgotten)); assert status == 200
    form = Form(page); assert form.action
    _, _, inbox = admin_request('GET', '/api/v1/messages', mail=True)
    old_ids = {m['ID'] for m in inbox['messages']}
    status, _, _ = browser.request(form.action, 'POST', dict(form.hidden, username=user['email']), form=True)
    assert status == 200
    found = []
    for _ in range(15):
        _, _, inbox = admin_request('GET', '/api/v1/messages', mail=True)
        found = [m for m in inbox['messages'] if m['ID'] not in old_ids and any(x['Address'] == user['email'] for x in m['To'])]
        if found: break
        time.sleep(1)
    assert found
    _, _, mail = admin_request('GET', '/api/v1/message/' + found[0]['ID'], mail=True)
    links = re.findall(r'https://[^\s<>"\']+', mail['Text'])
    link = next(unescape(x).rstrip(').') for x in links if '/login-actions/action-token?' in x)
    status, _, page = follow(browser, link); assert status == 200
    form = Form(page); assert form.action
    return browser, form, page, link


def main():
    p = argparse.ArgumentParser(__doc__)
    p.add_argument('--runtime', type=Path, required=True)
    p.add_argument('--public-frontend', action='store_true', help='Use approved public auth/wallet HTTPS; admin and mailbox stay private')
    p.add_argument('--protocol-harness', type=Path, required=True)
    p.add_argument('--expect-lost-completion', action='store_true')
    p.add_argument('--required-action', action='store_true')
    p.add_argument('--restart-validated-flow', action='store_true')
    p.add_argument('--restart-keycloak-after-gate', action='store_true')
    a = p.parse_args(); runtime = a.runtime.resolve(); assert 'runtime' in runtime.parts
    if a.public_frontend or a.expect_lost_completion:
        raise ValueError('Use isolated P6 transport; lost-completion reconciliation requires a separate disposable fault overlay')
    Browser.public_frontend = False
    reports = []
    def passed(message): reports.append(message); print('PASS:', message, flush=True)
    credentials = json.loads((runtime / 'credentials.json').read_text())
    status, _, admin = admin_request('POST', '/realms/master/protocol/openid-connect/token', {
        'grant_type': 'password', 'client_id': 'admin-cli', 'username': 'wallet-bootstrap',
        'password': credentials['bootstrap']}, form=True)
    assert status == 200
    admin = admin['access_token']; base = '/admin/realms/' + REALM
    fixture = runtime / 'recovery-fixture.json'
    if fixture.exists(): user = json.loads(fixture.read_text())
    else:
        user = {'email': 'p2-recovery-' + secrets.token_hex(8) + '@example.test', 'password': secrets.token_urlsafe(32)}
        status, headers, _ = admin_request('POST', base + '/users', {
            'username': user['email'], 'email': user['email'], 'firstName': 'Synthetic', 'lastName': 'Recovery',
            'enabled': True, 'emailVerified': True,
            'credentials': [{'type': 'password', 'value': user['password'], 'temporary': False}]}, token=admin)
        assert status == 201
        user['id'] = headers['Location'].rsplit('/', 1)[1]
        fixture.write_text(json.dumps(user)); fixture.chmod(0o600)
    status, _, role = admin_request('GET', base + '/roles/applicant', token=admin); assert status == 200
    assert admin_request('POST', base + '/users/' + user['id'] + '/role-mappings/realm', [role], token=admin)[0] == 204
    one, old_tokens, session_one = tokens(user)
    two, _, session_two = tokens(user)
    with ThreadPoolExecutor(max_workers=2) as pool:
        created = list(pool.map(lambda s: wallet(s, 'provision', {}), (session_one, session_two)))
    assert all(r[0] == 200 for r in created), 'Wallet provisioning failed'
    wallet_id = created[0][2]['wallet_id']; assert created[1][2]['wallet_id'] == wallet_id
    passed('Two real PKCE logins concurrently resolve to one persistent wallet')

    for service, port in (('issuer', 37005), ('wallet', 37006), ('verifier', 37004)):
        os.environ[service.upper() + '_URL'] = 'http://127.0.0.1:' + str(port)
    spec = importlib.util.spec_from_file_location('p2_protocol', a.protocol_harness / 'walt.py')
    protocol = importlib.util.module_from_spec(spec); spec.loader.exec_module(protocol)
    key_rows = protocol.call('wallet', '/wallet/' + wallet_id + '/keys')
    assert len(key_rows) == 1; key = key_rows[0]['keyId']
    before = protocol.credentials(wallet_id)
    if not before:
        offer = protocol.offer(); resolved = protocol.resolve_offer(wallet_id, offer['credentialOffer'])
        protocol.accept(wallet_id, key, resolved)
        before = protocol.credentials(wallet_id)
    assert before and wallet(session_one, 'credentials')[0] == 200
    credential_fingerprint = hashlib.sha256(json.dumps(before, sort_keys=True).encode()).hexdigest()
    request = protocol.session()
    status, _, pending = wallet(session_one, 'preview', {'request_url': request['bootstrapAuthorizationRequestUrl']})
    assert status == 200 and pending['consent_required'] is True
    passed('Real credential stored with the original holder key; pending presentation requires consent')

    reset = Browser()
    url = ISSUER + '/protocol/openid-connect/auth?' + urlencode({'client_id': 'android-wallet-p2',
        'redirect_uri': REDIRECT, 'response_type': 'code', 'scope': 'openid', 'code_challenge': secrets.token_urlsafe(32),
        'code_challenge_method': 'S256'})
    if a.required_action:
        assert admin_request('PUT', base + '/users/' + user['id'], {'requiredActions': ['UPDATE_PASSWORD']}, token=admin)[0] == 204
        redirect = login(reset, url, user)
        status, _, page = follow(reset, redirect); assert status == 200
        link = None
        passed('Authenticated required-action password update enters the guarded provider')
    else:
        status, _, page = follow(reset, url); assert status == 200
        forgotten = next(x for x in Form(page).links if '/login-actions/reset-credentials' in x)
        status, _, page = follow(reset, urljoin(AUTH, forgotten)); assert status == 200
        form = Form(page); assert form.action
        status, _, page = reset.request(form.action, 'POST', dict(form.hidden, username=user['email']), form=True)
        assert status == 200
        assert wallet(session_one, 'credentials')[0] == 200 and wallet(session_two, 'credentials')[0] == 200
        passed('Anonymous forgotten-password request does not revoke sessions or close wallet access')
        messages = []
        for _ in range(15):
            status, _, inbox = admin_request('GET', '/api/v1/messages', mail=True); assert status == 200
            messages = [m for m in inbox['messages'] if any(r['Address'] == user['email'] for r in m['To'])]
            if messages: break
            time.sleep(1)
        assert messages
        status, _, mail = admin_request('GET', '/api/v1/message/' + messages[0]['ID'], mail=True); assert status == 200
        links = re.findall(r'https://[^\s<>"\']+', mail['Text'])
        link = next(unescape(x).rstrip(').') for x in links if '/login-actions/action-token?' in x)
        # A tampered proof must never enter the guarded required action.
        parsed = urlsplit(link); params = parse_qs(parsed.query); bad = {k: v[0] for k, v in params.items()}
        key_token = bad['key']; bits = key_token.split('.'); bits[2] = ('A' if bits[2][0] != 'A' else 'B') + bits[2][1:]
        bad['key'] = '.'.join(bits)
        follow(Browser(), parsed._replace(query=urlencode(bad)).geturl())
        assert wallet(session_one, 'credentials')[0] == 200
        passed('Invalid email recovery token cannot close the gate')
        status, _, page = follow(reset, link); assert status == 200
    form = Form(page); assert form.action, 'Expected real Keycloak update-password form'
    # Valid email proof, invalid password form: gate must close before any password write succeeds.
    status, _, page = reset.request(form.action, 'POST', dict(form.hidden, **{'password-new': '', 'password-confirm': ''}), form=True)
    if status != 200:
        diagnostic = runtime / 'recovery-unexpected-response.html'
        diagnostic.write_text(page); diagnostic.chmod(0o600)
        print('Unexpected password validation response status:', status, flush=True)
    assert status == 200
    for old in (session_one, session_two):
        assert wallet(old, 'credentials')[0] == 401
        assert wallet(old, 'present', dict(context_id=pending['context_id'], summary_hash=pending['summary_hash'], consent=True))[0] == 401
        assert json_request(Browser(), '/auth/me', headers={'Authorization': 'Bearer ' + old})[0] == 401
    passed('Gate closes before password acceptance and blocks two old sessions, reads and pending sign/send')
    abandoned = None
    if a.restart_validated_flow:
        abandoned = (reset, Form(page))
        if a.restart_keycloak_after_gate:
            subprocess.run(['docker', 'restart', P6_PROJECT+'-keycloak-1'], check=True, stdout=subprocess.DEVNULL)
            for _ in range(60):
                try:
                    if admin_request('GET', '/realms/' + REALM + '/.well-known/openid-configuration')[0] == 200: break
                except Exception: pass
                time.sleep(1)
            else: raise AssertionError('Keycloak did not restart')
            tokens(user, expected_session=401)
            for old in (session_one, session_two): assert wallet(old, 'credentials')[0] == 401
            passed('Keycloak container interruption after gate acknowledgement preserves closed wallet access')
        reset, _, page, link = email_reset_form(user)
    old_password = user['password']
    new_password = secrets.token_urlsafe(32)
    # Persist the next candidate privately so interrupted runs do not lose the synthetic account password.
    (runtime / 'recovery-next-password').write_text(new_password); (runtime / 'recovery-next-password').chmod(0o600)
    form = Form(page); assert form.action
    status, headers, page = reset.request(form.action, 'POST', dict(form.hidden, **{
        'password-new': new_password, 'password-confirm': new_password}), form=True)
    assert status in (200, 302, 303), 'Password update request failed'
    status, _, detail = admin_request('GET', base + '/users/' + user['id'], token=admin); assert status == 200
    assert detail.get('attributes', {}).get('nusacred_recovery_commit'), 'Guarded provider commit marker missing'
    user['password'] = new_password; fixture.write_text(json.dumps(user)); fixture.chmod(0o600)
    passed('Password update committed through the guard and recorded a reconciliation marker')
    for old in (session_one, session_two): assert wallet(old, 'credentials')[0] == 401
    status, _, _ = one.request(ISSUER + '/protocol/openid-connect/token', 'POST', {
        'grant_type': 'refresh_token', 'client_id': 'android-wallet-p2', 'refresh_token': old_tokens['refresh_token']}, form=True)
    assert status == 400
    status, _, fresh_flow = json_request(Browser(), '/auth/native/start', 'POST', {}); assert status == 200
    assert json_request(Browser(), '/auth/native/session', 'POST', dict(ticket=fresh_flow['ticket'],
        access_token=old_tokens['access_token'], id_token=old_tokens['id_token']))[0] == 401
    passed('Old refresh token and old OIDC tokens cannot reopen an application session')
    if a.expect_lost_completion:
        tokens(user, expected_session=401)
        subprocess.run(['docker', 'restart', P6_PROJECT+'-custodian-1'], check=True, stdout=subprocess.DEVNULL)
        for _ in range(30):
            try:
                if json_request(Browser(), '/auth/native/start', 'POST', {})[0] == 200: break
            except Exception: pass
            time.sleep(1)
        else: raise AssertionError('Custodian did not restart')
        tokens(user, expected_session=401)
        passed('Lost completion remains closed through a real custodian process/container restart')
        operation, revision = detail['attributes']['nusacred_recovery_commit'][0].split(':')
        subprocess.run([sys.executable, str(Path(__file__).with_name('reconcile_p2_recovery.py')),
                        '--runtime', str(runtime), '--subject', user['id'], '--operation', operation,
                        '--revision', revision], check=True)
        passed('Offline reconciliation confirms the committed IdP marker and revokes sessions before acknowledging')
    if abandoned is not None:
        old_browser, old_form = abandoned
        late_password = secrets.token_urlsafe(32)
        old_browser.request(old_form.action, 'POST', dict(old_form.hidden, **{'password-new': late_password, 'password-confirm': late_password}), form=True)
    time.sleep(2)  # Strict freshness intentionally rejects authentication in the completion second.
    _, _, fresh = tokens(user)
    if abandoned is not None:
        passed('A new validated recovery supersedes an abandoned flow; the old browser retry cannot change password or access')
    status, _, restored = wallet(fresh, 'provision', {}); assert status == 200 and restored['wallet_id'] == wallet_id
    after = protocol.credentials(wallet_id)
    assert hashlib.sha256(json.dumps(after, sort_keys=True).encode()).hexdigest() == credential_fingerprint
    assert protocol.call('wallet', '/wallet/' + wallet_id + '/keys') == key_rows
    assert wallet(fresh, 'credentials')[0] == 200
    request = protocol.session()
    status, _, preview = wallet(fresh, 'preview', {'request_url': request['bootstrapAuthorizationRequestUrl']}); assert status == 200
    body = dict(context_id=preview['context_id'], summary_hash=preview['summary_hash'], consent=True)
    status, _, result = wallet(fresh, 'present', body)
    assert status == 200 and result['transmission_success'] is True
    assert protocol.info(request['sessionId'])['status'] == 'SUCCESSFUL'
    assert wallet(fresh, 'present', body)[0] in (401,403,404)
    passed('Fresh login retains wallet, key and credential; real holder-bound presentation succeeds without reissue')
    if link is not None:
        follow(Browser(), link)
        assert wallet(fresh, 'credentials')[0] == 200
        passed('Consumed email link cannot lock or recover the account again')
    try:
        tokens(dict(user, password=old_password))
        raise RuntimeError('Old password incorrectly accepted')
    except AssertionError:
        pass
    passed('The old password cannot authenticate after recovery')
    report = {'schemaVersion': 1, 'time': datetime.now(timezone.utc).isoformat(), 'syntheticData': True,
              'transport': 'public_verified_tls' if a.public_frontend else 'private_verified_tls',
              'checks': reports, 'credentialFingerprint': credential_fingerprint,
              'limits': ['HTTP/browser proof; release APK and fault/restart cases require separate evidence']}
    (runtime / ('recovery-public-result.json' if a.public_frontend else 'recovery-fault-result.json' if a.expect_lost_completion else 'recovery-required-action-result.json' if a.required_action else 'recovery-idp-interrupted-result.json' if a.restart_keycloak_after_gate else 'recovery-abandoned-result.json' if a.restart_validated_flow else 'recovery-result.json')).write_text(json.dumps(report, indent=2) + '\n')
    print('PASS:', len(reports), 'real-service recovery checks')

if __name__ == '__main__':
    main()
