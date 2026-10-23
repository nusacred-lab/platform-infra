"""Verify preserved wallet/credential/final results after an external upgrade/restart/rollback.

This check only logs into its disposable P6 installation. Changing image pins,
stopping containers and restoring snapshots are separate explicit operator steps.
"""
import argparse
import base64
import hashlib
import importlib.util
import json
from pathlib import Path
import secrets
import sys
import time
from urllib.parse import parse_qs,urlencode,urlsplit

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'release'))
from acceptance_transport import Browser,login
from install import env_read

p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--runtime',type=Path,required=True)
p.add_argument('--label',required=True)
p.add_argument('--output',type=Path,required=True)
a=p.parse_args();runtime=a.runtime.resolve()
if 'runtime' not in runtime.parts or 'runtime' not in a.output.resolve().parts:p.error('Use private disposable runtime')
env=env_read(runtime/'compose.env')
if not env['P6_PROJECT_NAME'].startswith('competency-proof-p6'):p.error('Refuse active demo')
Browser.loopback_port=int(env['P6_HTTPS_PORT']);Browser.cafile=str(runtime/'tls/fullchain.pem')
state=json.loads((runtime/'installation.json').read_text())
before=json.loads((runtime/'continuity-private.json').read_text())
wallet='https://dompet-identitas.demo.inoerawan.id';company='https://karya-instalasi.demo.inoerawan.id'
auth='https://login-dompet-identitas.demo.inoerawan.id/realms/competency-proof-p2'
redirect=wallet+'/auth/android/callback'
def req(browser,origin,path,method='GET',body=None,headers=None):
 status,head,raw=browser.request(origin+path,method,body,headers)
 return status,head,json.loads(raw) if raw else None
b=Browser()
for attempt in range(90):
 try:
  if req(b,wallet,'/api/v1/portal-config')[0]==200:break
 except OSError:pass
 time.sleep(1)
else:raise RuntimeError('Portal readiness timeout after change')
status,_,flow=req(b,wallet,'/auth/native/start','POST',{});assert status==200
v=secrets.token_urlsafe(48);s=secrets.token_urlsafe(32)
c=base64.urlsafe_b64encode(hashlib.sha256(v.encode()).digest()).decode().rstrip('=')
cb=login(b,auth+'/protocol/openid-connect/auth?'+urlencode(dict(client_id='android-wallet-p2',redirect_uri=redirect,response_type='code',scope='openid profile email',state=s,nonce=flow['nonce'],code_challenge=c,code_challenge_method='S256',prompt='login',max_age='0')),state['users']['applicant'])
q=parse_qs(urlsplit(cb).query);assert q['state']==[s]
status,_,raw=b.request(auth+'/protocol/openid-connect/token','POST',dict(grant_type='authorization_code',client_id='android-wallet-p2',redirect_uri=redirect,code=q['code'][0],code_verifier=v),form=True);assert status==200
tokens=json.loads(raw)
status,_,native=req(Browser(),wallet,'/auth/native/session','POST',dict(ticket=flow['ticket'],access_token=tokens['access_token'],id_token=tokens['id_token']));assert status==200
nh={'Authorization':'Bearer '+native['session']}
status,_,binding=req(Browser(),wallet,'/api/v1/wallet/provision','POST',{},nh);assert status==200 and binding['wallet_id']==before['walletId']
status,_,credentials=req(Browser(),wallet,'/api/v1/wallet/credentials',headers=nh);assert status==200
assert hashlib.sha256(json.dumps(credentials,sort_keys=True).encode()).hexdigest()==before['credentialDigest']
admin=Browser();status,headers,_=admin.request(company+'/auth/start');assert status==302
callback=login(admin,headers['Location'],state['users']['company-admin']);assert admin.request(callback)[0]==302
for row in before['finals']:
 status,_,result=req(admin,company,row['path']);assert status==200 and result==row['result']
report={'label':a.label,'passed':True,'walletMappingUnchanged':True,'credentialBytesUnchanged':True,'finalResultsUnchanged':True,'finalCount':len(before['finals']),
 'images':{k:v for k,v in env.items() if k.endswith('_IMAGE')},'limits':['Read-back continuity only; old credential presentation is checked separately by acceptance/protocol test','Fresh login after restart; no claim that browser sessions survive']}
a.output.write_text(json.dumps(report,indent=2)+'\n')
print('PASS: wallet mapping, credential bytes and '+str(len(before['finals']))+' immutable results after '+a.label)
