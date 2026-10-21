"""Prove actual HTTP account/wallet/consent isolation against the source-built P2 services."""
import argparse
import http.client
import json
from pathlib import Path
from test_p2_recovery import tokens, wallet
from test_p2_login import Browser, json_request

p = argparse.ArgumentParser(__doc__)
p.add_argument('--runtime', type=Path, required=True)
p.add_argument('--public-frontend', action='store_true', help='Use approved public auth/wallet HTTPS')
a = p.parse_args(); r = a.runtime.resolve()
Browser.public_frontend = a.public_frontend
owner = json.loads((r / 'recovery-fixture.json').read_text())
other = json.loads((r / 'login-fixtures.json').read_text())['applicant']
_, _, one = tokens(owner); _, _, two = tokens(other)
status, _, binding = wallet(one, 'provision', {}); assert status == 200
status, _, foreign = wallet(two, 'provision', {'wallet_id': binding['wallet_id']})
assert status == 200 and foreign['wallet_id'] != binding['wallet_id']
assert wallet(one, 'credentials')[0] == 200
status, _, foreign_credentials = wallet(two, 'credentials'); assert status == 200 and not foreign_credentials
status, _, query_credentials = json_request(Browser(), '/api/v1/wallet/credentials?wallet_id=' + binding['wallet_id'],
    headers={'Authorization': 'Bearer ' + two})
assert status == 200 and query_credentials == foreign_credentials
c = http.client.HTTPConnection('127.0.0.1', 17004, timeout=15)
body = {'flow_type': 'cross_device', 'core_flow': {'dcql_query': {'credentials': [{'id': 'competency',
    'format': 'dc+sd-jwt', 'multiple': True, 'meta': {'vct_values': ['http://issuer:7005/openid4vci/competency_demo']},
    'require_cryptographic_holder_binding': True, 'claims': [{'path': [x]} for x in ['id', 'candidate_id', 'competency_code', 'assessment_result', 'exp']]}]}}}
try:
    c.request('POST', '/verification-session/create', json.dumps(body), {'Content-Type': 'application/json'})
    response = c.getresponse(); assert response.status in (200, 201); request = json.loads(response.read())
finally: c.close()
status, _, preview = wallet(one, 'preview', {'request_url': request['bootstrapAuthorizationRequestUrl']}); assert status == 200
consent = dict(context_id=preview['context_id'], summary_hash=preview['summary_hash'], consent=True)
assert wallet(two, 'present', consent)[0] == 401
assert wallet(one, 'present', dict(consent, summary_hash='tampered'))[0] == 401
assert wallet(one, 'present', dict(consent, consent=False))[0] == 401
status, _, result = wallet(one, 'present', consent); assert status == 200 and result['transmission_success'] is True
assert wallet(one, 'present', consent)[0] == 401
c = http.client.HTTPConnection('127.0.0.1', 17004, timeout=15)
try:
    c.request('GET', '/verification-session/' + request['sessionId'] + '/info'); response = c.getresponse()
    assert response.status == 200 and json.loads(response.read())['status'] == 'SUCCESSFUL'
finally: c.close()
(r / ('wallet-isolation-public-result.json' if a.public_frontend else 'wallet-isolation-result.json')).write_text(json.dumps({'schemaVersion': 1,
    'transport': 'public_verified_tls' if a.public_frontend else 'private_verified_tls', 'checks': [
    'Different OIDC accounts have different wallets', 'Caller-supplied wallet ID cannot select another account binding',
    'Credential reads remain owned when a foreign wallet ID is supplied', 'Foreign account cannot use owner consent',
    'Changed preview hash and declined consent cannot dispatch', 'Valid owner consent still succeeds once',
    'Actual verifier accepts the holder-bound result', 'Consent replay denied']}, indent=2) + '\n')
print('PASS: actual HTTP wallet ownership and one-use consent isolation with real verifier acceptance')
