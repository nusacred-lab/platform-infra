"""Verify the three separate confidential BFF clients against real Keycloak roles."""
import argparse
import json
from pathlib import Path
from test_p2_login import Browser, login

p = argparse.ArgumentParser(__doc__)
p.add_argument('--runtime', type=Path, required=True)
a = p.parse_args(); users = json.loads((a.runtime / 'login-fixtures.json').read_text()); results = []
for host, role, client in (('issuer-p2', 'issuer-admin', 'issuer-bff-p2'),
                            ('wallet-p2', 'custodian-admin', 'custodian-bff-p2'),
                            ('verifier-p2', 'company-admin', 'company-bff-p2')):
    origin = 'https://' + host + '.demo.inoerawan.id'
    for fixture, expected in ((role, 302), ('applicant', 401)):
        browser = Browser()
        status, headers, _ = browser.request(origin + '/auth/start'); assert status == 302
        assert 'client_id=' + client in headers['Location']
        callback = login(browser, headers['Location'], users[fixture])
        assert callback.startswith(origin + '/auth/callback?')
        status, headers, _ = browser.request(callback); assert status == expected
        if fixture == role:
            status, _, payload = browser.request(origin + '/auth/me'); assert status == 200
            data = json.loads(payload); assert data['email'] == users[role]['email']
            assert not any(k in data for k in ('access_token', 'id_token', 'refresh_token'))
            for other in ('https://issuer-p2.demo.inoerawan.id', 'https://wallet-p2.demo.inoerawan.id', 'https://verifier-p2.demo.inoerawan.id'):
                if other != origin:
                    # Even transplanting the host-only cookie cannot authenticate to another BFF.
                    browser.cookies[other.split('//')[1]] = dict(browser.cookies[origin.split('//')[1]])
                    assert browser.request(other + '/auth/me')[0] == 401
        message = client + ': ' + ('correct admin role accepted, cookie isolated' if fixture == role else 'applicant role denied')
        results.append(message); print('PASS:', message)
(a.runtime / 'portals-result.json').write_text(json.dumps({'schemaVersion': 1, 'checks': results,
    'limits': ['Private verified-TLS browser proof; business portal screens are outside P2']}, indent=2) + '\n')
