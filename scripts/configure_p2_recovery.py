"""Restrict password paths and enable private email recovery after deploying the guarded provider."""
import argparse
import json
from pathlib import Path
from check_p2_identity import request, REALM

p = argparse.ArgumentParser(__doc__)
p.add_argument('--runtime', type=Path, required=True)
a = p.parse_args()
runtime = a.runtime.resolve()
assert 'runtime' in runtime.parts
credentials = json.loads((runtime / 'credentials.json').read_text())
status, _, result = request('POST', '/realms/master/protocol/openid-connect/token', {
    'grant_type': 'password', 'client_id': 'admin-cli', 'username': 'p2-bootstrap',
    'password': credentials['bootstrap']}, form=True)
assert status == 200
token = result['access_token']
base = '/admin/realms/' + REALM
# The only administrative writer is the private bootstrap operator. No runtime service gets manage-users.
status, _, clients = request('GET', base + '/clients', token=token)
assert status == 200
for client in clients:
    if client['clientId'] in ('account', 'account-console'):
        client['enabled'] = False
        assert request('PUT', base + '/clients/' + client['id'], client, token=token)[0] == 204
    if client['clientId'].endswith('-p2'):
        assert not client.get('directAccessGrantsEnabled') and not client.get('serviceAccountsEnabled')
status, _, profile = request('GET', base + '/users/profile', token=token)
assert status == 200
# Null means disabled in Keycloak 26.8.1; its enum has no DISABLED member.
profile['unmanagedAttributePolicy'] = None
if not any(x['name'] == 'nusacred_recovery_commit' for x in profile['attributes']):
    profile['attributes'].append({'name': 'nusacred_recovery_commit',
                                  'permissions': {'view': ['admin'], 'edit': ['admin']}})
assert request('PUT', base + '/users/profile', profile, token=token)[0] in (200, 204)
# Force a new login after every reset, even when the same browser opened the email.
status, _, executions = request('GET', base + '/authentication/flows/reset%20credentials/executions', token=token)
assert status == 200
email = next(x for x in executions if x.get('providerId') == 'reset-credential-email')
config = {'alias': 'nusacred-force-fresh-recovery-login', 'config': {'force-login': 'true'}}
if email.get('authenticationConfig'):
    assert request('PUT', base + '/authentication/config/' + email['authenticationConfig'], config, token=token)[0] == 204
else:
    assert request('POST', base + '/authentication/executions/' + email['id'] + '/config', config, token=token)[0] == 201
# Public Caddy allowlist still denies reset/action-token/required-action/account/admin URLs.
assert request('PUT', base, {'resetPasswordAllowed': True}, token=token)[0] == 204
print('PASS: private recovery configured; account clients disabled, marker admin-only, fresh login required')
