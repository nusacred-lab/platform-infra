"""Verify bounded native token lifetime and server-reported expiry without relaxing live authorization."""
import argparse
import base64
import json
from pathlib import Path
import time
from test_p2_recovery import tokens, wallet
from test_p2_login import Browser, json_request

p = argparse.ArgumentParser(__doc__)
p.add_argument('--runtime', type=Path, required=True)
a = p.parse_args(); runtime = a.runtime.resolve(); assert 'runtime' in runtime.parts
Browser.public_frontend = True
user = json.loads((runtime / 'recovery-fixture.json').read_text())
_, raw, session = tokens(user)
claims = raw['id_token'].split('.')[1]
claims = json.loads(base64.urlsafe_b64decode(claims + '=' * (-len(claims) % 4)))
assert raw['expires_in'] == 900 and claims['exp'] - claims['iat'] == 900
status, _, account = json_request(Browser(), '/auth/me', headers={'Authorization': 'Bearer ' + session})
assert status == 200 and 870 <= account['expires_at'] - int(time.time()) <= 900
assert account['expires_at'] <= claims['exp']
assert wallet(session, 'preview', {'request_url': 'invalid-request'})[0] == 401
# A rejected presentation does not revoke a valid account; the APK checks this distinction.
assert json_request(Browser(), '/auth/me', headers={'Authorization': 'Bearer ' + session})[0] == 200
report = {'schemaVersion': 1, 'syntheticData': True, 'checks': [
    'Native access and ID tokens have an explicit bounded 900-second lifetime',
    'Account response reports actual server expiry bounded by the IdP token',
    'Invalid presentation is rejected while the existing account session remains valid'],
    'nativeLifetimeSeconds': 900, 'refreshTokenPersisted': False}
(runtime / 'session-lifetime-result.json').write_text(json.dumps(report, indent=2) + '\n')
print('PASS:', len(report['checks']), 'public native session lifetime checks')
