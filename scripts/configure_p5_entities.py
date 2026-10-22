"""Configure exact entity callbacks and client login themes without replacing identities.

Run during the reviewed domain cutover with a private realm backup. The realm ID,
client IDs/secrets, subjects, keys, recovery provider and token bounds are retained.
KC_HOSTNAME and RECOVERY_ISSUER must be changed by the matching P5 composition;
the offline custodian registry must be migrated before users can sign in again.
"""
import argparse
import json
from pathlib import Path
from check_p2_identity import request,REALM

p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--runtime',type=Path,required=True)
p.add_argument('--backup-directory',type=Path,required=True)
a=p.parse_args()
assert 'runtime' in a.runtime.resolve().parts and 'runtime' in a.backup_directory.resolve().parts
creds=json.loads((a.runtime/'credentials.json').read_text())
s,_,auth=request('POST','/realms/master/protocol/openid-connect/token',{'grant_type':'password','client_id':'admin-cli','username':'p2-bootstrap','password':creds['bootstrap']},form=True);assert s==200
token=auth['access_token'];base='/admin/realms/'+REALM
s,_,realm=request('GET',base,token=token);assert s==200
s,_,clients=request('GET',base+'/clients',token=token);assert s==200
a.backup_directory.mkdir(parents=True,exist_ok=True,mode=0o700)
backup=a.backup_directory/'before-entity-clients.json'
if backup.exists():
    assert json.loads(backup.read_text())['realm']['id']==realm['id']
else:
    backup.write_text(json.dumps({'realm':realm,'clients':clients},indent=2)+'\n');backup.chmod(0o600)
settings={'issuer-bff-p2':('lsp-nusantara','LSP Nusantara','lsp-nusantara'),
          'company-bff-p2':('karya-instalasi','Karya Instalasi','karya-instalasi'),
          'custodian-bff-p2':('dompet-identitas','NusaCred Wallet Administration','nusacred'),
          'android-wallet-p2':('dompet-identitas','NusaCred Wallet','nusacred')}
for c in clients:
    if c['clientId'] not in settings:continue
    host,name,theme=settings[c['clientId']];origin='https://'+host+'.demo.inoerawan.id'
    assert not c.get('directAccessGrantsEnabled') and not c.get('serviceAccountsEnabled')
    native=c['clientId']=='android-wallet-p2'
    c.update({'name':name,'rootUrl':origin,'baseUrl':origin,'webOrigins':[] if native else [origin],
              'redirectUris':[origin+'/auth/android/callback','id.nusacred.wallet.debug:/oauth2redirect'] if native else [origin+'/auth/callback']})
    c.setdefault('attributes',{})['login_theme']=theme
    assert request('PUT',base+'/clients/'+c['id'],c,token=token)[0]==204
attributes=realm.get('attributes',{})
if 'frontendUrl' in attributes:attributes['frontendUrl']='https://login-dompet-identitas.demo.inoerawan.id'
smtp=dict(realm['smtpServer']);smtp['fromDisplayName']='PT Dompet Identitas Nusantara (demo)'
assert request('PUT',base,{'displayName':'NusaCred Wallet','displayNameHtml':'NusaCred Wallet','attributes':attributes,'smtpServer':smtp},token=token)[0]==204
assert request('POST',base+'/logout-all',token=token)[0] in (200,204)
s,_,current=request('GET',base,token=token);assert s==200
assert current['id']==realm['id'] and current['resetCredentialsFlow']==realm['resetCredentialsFlow']
assert current['ssoSessionIdleTimeout']==86400 and current['ssoSessionMaxLifespan']==604800 and current['accessTokenLifespan']==300
s,_,actual=request('GET',base+'/clients',token=token);assert s==200
for c in actual:
    if c['clientId'] in settings:
        expected=next(x for x in clients if x['id']==c['id'])
        assert set(c['redirectUris'])==set(expected['redirectUris']) and c['attributes']['login_theme']==settings[c['clientId']][2]
print('PASS: exact entity callbacks/themes configured; realm identity, recovery and approved token bounds retained; old IdP sessions logged out.')
