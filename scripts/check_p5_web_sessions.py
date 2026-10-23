"""Verify one-hour BFF sessions and immediate IdP revocation via loopback TLS.

Only the IdP session newly created by each test login may be revoked. No other
user session, password, credential or key is changed. No secrets enter the report.
"""
import argparse
from datetime import datetime, timezone
from http.cookies import SimpleCookie
import json
from pathlib import Path
import time
from configure_p5_web_sessions import ENTITIES, POLICY, administrator, context
from p5_transport import Browser, login


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--env-file', type=Path, required=True)
    parser.add_argument('--identity-runtime', type=Path, required=True)
    parser.add_argument('--accounts', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    assert all('runtime' in p.resolve().parts for p in [args.env_file, args.identity_runtime, args.accounts, args.output])
    env = context(args.env_file)
    accounts = json.loads(args.accounts.read_text())
    checks = []
    lifetimes = {}
    def check(name, condition):
        assert condition, name
        checks.append(name)
    for entity, domain, realm, client_id in ENTITIES:
        call = administrator(entity, domain, realm, env, args.identity_runtime)
        status, clients = call('GET', '/clients')
        assert status == 200
        client = next(c for c in clients if c['clientId'] == client_id)
        check(entity+': one-hour client access/idle/max', all(client['attributes'].get(k) == v for k, v in POLICY.items()))
        status, sessions = call('GET', '/clients/'+client['id']+'/user-sessions')
        assert status == 200
        before_ids = {s['id'] for s in sessions}
        browser = Browser()
        origin = 'https://'+domain+'.demo.inoerawan.id'
        role = {'wallet': 'custodian-admin', 'issuer': 'issuer-admin', 'company': 'company-admin'}[entity]
        status, headers, _ = browser.request(origin+'/auth/start')
        assert status == 302
        callback = login(browser, headers['Location'], accounts[role])
        status, _, _ = browser.request(callback)
        check(entity+': real own-IdP login succeeds', status == 302)
        ages = []
        for header, value in browser.last_headers:
            if header.lower() == 'set-cookie':
                cookie = SimpleCookie();cookie.load(value)
                if '__Host-nusacred-session' in cookie:
                    item = cookie['__Host-nusacred-session']
                    ages.append(int(item['max-age']))
                    check(entity+': opaque cookie remains Secure HttpOnly SameSite', bool(item['secure']) and bool(item['httponly']) and item['samesite'] == 'Lax')
        check(entity+': browser cookie lasts one hour', len(ages) == 1 and 3570 <= ages[0] <= 3600)
        status, _, raw = browser.request(origin+'/api/v1/portal-session')
        session = json.loads(raw)
        ttl = session['expiresAt'] - int(time.time())
        check(entity+': backend session lasts one hour', status == 200 and 3570 <= ttl <= 3600)
        check(entity+': session response exposes no IdP tokens', set(session) == {'email','accountId','roles','organizationId','csrf','expiresAt'})
        lifetimes[entity] = {'cookieMaxAgeSeconds': ages[0], 'remainingSessionSeconds': ttl}
        status, sessions = call('GET', '/clients/'+client['id']+'/user-sessions')
        assert status == 200
        created = [s for s in sessions if s['id'] not in before_ids and s['username'] == accounts[role]['email']]
        assert len(created) == 1, 'Cannot safely identify a unique test-created IdP session'
        assert call('DELETE', '/sessions/'+created[0]['id'])[0] == 204
        check(entity+': revocation ends access before one hour', browser.request(origin+'/api/v1/portal-session')[0] == 401)
        if entity == 'wallet':
            native = next(c for c in clients if c['clientId'] == 'android-wallet-p2')
            check('native: five-minute access unchanged', native['attributes']['access.token.lifespan'] == '300')
            check('native: seven-day maximum and 24-hour idle unchanged', native['attributes']['client.session.max.lifespan'] == '604800' and native['attributes']['client.session.idle.timeout'] == '86400')
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps({'checkedAt': datetime.now(timezone.utc).isoformat(), 'transport': 'verified loopback TLS',
        'result': 'PASS', 'checks': checks, 'lifetimes': lifetimes,
        'limit': 'Issued expiry and revocation verified; no hour-long wall-clock observation claimed.'}, indent=2)+'\n')
    print('PASS:', len(checks), 'one-hour web session and revocation checks; native policy retained')


if __name__ == '__main__':
    main()
