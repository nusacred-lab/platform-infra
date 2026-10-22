"""Apply the explicitly approved P5 mobile refresh policy and NusaCred login theme.

Requires the existing private bootstrap context and the reviewed P5 theme mount.
No account password, realm key, client credential or recovery flow is replaced.
"""
import argparse
import json
from pathlib import Path
from check_p2_identity import request, REALM

p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--runtime',type=Path,required=True)
a=p.parse_args()
runtime=a.runtime.resolve()
assert 'runtime' in runtime.parts and runtime.is_dir()
credentials=json.loads((runtime/'credentials.json').read_text())
status,_,auth=request('POST','/realms/master/protocol/openid-connect/token',{
    'grant_type':'password','client_id':'admin-cli','username':'p2-bootstrap','password':credentials['bootstrap']},form=True)
assert status==200
token=auth['access_token'];base='/admin/realms/'+REALM
status,_,realm=request('GET',base,token=token);assert status==200
status,_,clients=request('GET',base+'/clients',token=token);assert status==200
backup=runtime/'before-p5-auth.json'
if not backup.exists():
    backup.write_text(json.dumps({'realm':realm,'clients':clients},indent=2)+'\n');backup.chmod(0o600)
assert realm['revokeRefreshToken'] and realm['refreshTokenMaxReuse']==0
assert realm['resetPasswordAllowed'], 'Configure guarded recovery before P5 authentication'
settings={'loginTheme':'nusacred','displayName':'NusaCred','displayNameHtml':'NusaCred',
          'accessTokenLifespan':300,'ssoSessionIdleTimeout':86400,'ssoSessionMaxLifespan':604800,
          'revokeRefreshToken':True,'refreshTokenMaxReuse':0}
# Keycloak validates client timeouts against realm bounds, so apply those bounds first.
assert request('PUT',base,settings,token=token)[0]==204
for c in clients:
    if c['clientId'] not in ('android-wallet-p2','custodian-bff-p2','issuer-bff-p2','company-bff-p2'):continue
    assert not c.get('directAccessGrantsEnabled') and not c.get('serviceAccountsEnabled')
    attributes=c.setdefault('attributes',{})
    native=c['clientId']=='android-wallet-p2'
    attributes.update({'client.session.idle.timeout':str(86400 if native else 1800),
                       'client.session.max.lifespan':str(604800 if native else 3600)})
    if native:attributes['access.token.lifespan']='300'
    assert request('PUT',base+'/clients/'+c['id'],c,token=token)[0]==204
status,_,actual=request('GET',base,token=token);assert status==200
assert all(actual[k]==v for k,v in settings.items())
print('PASS: NusaCred theme; access 5 minutes; native refresh idle 24 hours, max 7 days; rotation and guarded recovery retained.')
