"""Offline recovery reconciliation: confirm the IdP commit marker, revoke sessions, acknowledge completion."""
import argparse
import base64
import hashlib
import hmac
import http.client
import json
from pathlib import Path
import re
import time
from check_p2_identity import request, REALM, ISSUER

p = argparse.ArgumentParser(__doc__)
p.add_argument('--runtime', type=Path, required=True)
p.add_argument('--subject', required=True)
p.add_argument('--operation', required=True)
p.add_argument('--revision', required=True, type=int)
a = p.parse_args()
assert re.fullmatch(r'[A-Za-z0-9_-]{32,128}', a.operation) and a.revision > 0
runtime = a.runtime.resolve(); assert 'runtime' in runtime.parts
credentials = json.loads((runtime / 'credentials.json').read_text())
status, _, result = request('POST', '/realms/master/protocol/openid-connect/token', {
    'grant_type': 'password', 'client_id': 'admin-cli', 'username': 'p2-bootstrap',
    'password': credentials['bootstrap']}, form=True)
assert status == 200
token = result['access_token']
assert re.fullmatch(r'[A-Za-z0-9_-]{1,128}', a.subject)
base = '/admin/realms/' + REALM + '/users/' + a.subject
status, _, user = request('GET', base, token=token)
assert status == 200
assert user.get('attributes', {}).get('nusacred_recovery_commit') == [a.operation + ':' + str(a.revision)], \
    'No matching committed password change; keep gate closed'
assert request('POST', base + '/logout', token=token)[0] == 204
body = json.dumps({'issuer': ISSUER, 'subject': a.subject, 'operation': a.operation, 'revision': a.revision})
path = '/internal/recoveries/complete'; timestamp = str(int(time.time()))
secret = (runtime / 'recovery-service-secret').read_bytes().strip()
signature = base64.urlsafe_b64encode(hmac.new(secret, (timestamp + '\n' + path + '\n' + body).encode(), hashlib.sha256).digest()).decode().rstrip('=')
connection = http.client.HTTPConnection('127.0.0.1', 18080, timeout=15)
try:
    connection.request('POST', path, body, {'Content-Type': 'application/json', 'X-Recovery-Time': timestamp,
                                          'X-Recovery-Signature': signature})
    response = connection.getresponse()
    assert response.status == 200
    result = json.loads(response.read())
    assert result['operation'] == a.operation and result['revision'] == a.revision
finally:
    connection.close()
print('PASS: matching committed recovery reconciled; fresh login remains mandatory')
