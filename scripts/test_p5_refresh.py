"""Prove mobile refresh rotation and recovery-aware renewal against real Keycloak.

Uses existing private synthetic fixtures, verified loopback TLS and real PKCE.
No passwords, tokens, subjects or session IDs are written into the report.
"""
import argparse
import base64
import hashlib
import json
from pathlib import Path
import secrets
import time
from urllib.parse import parse_qs, urlencode, urlsplit
from check_p2_identity import request as admin_request, REALM
from p5_transport import Browser, ISSUER, REDIRECT, json_request, login

p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--runtime',type=Path,required=True)
p.add_argument('--output',type=Path,required=True)
p.add_argument('--wait-for-access-expiry',action='store_true')
a=p.parse_args()
runtime=a.runtime.resolve()
assert 'runtime' in runtime.parts and 'runtime' in a.output.resolve().parts
fixture=json.loads((runtime/'login-fixtures.json').read_text())['applicant']
Browser.loopback_port=8443
checks=[]
def passed(name):
    checks.append(name);print('PASS:',name,flush=True)

def enrolled():
    browser=Browser()
    status,_,flow=json_request(browser,'/auth/native/start','POST',{})
    assert status==200
    verifier=secrets.token_urlsafe(48)
    challenge=base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip('=')
    state=secrets.token_urlsafe(32)
    redirect=login(browser,ISSUER+'/protocol/openid-connect/auth?'+urlencode({
        'client_id':'android-wallet-p2','redirect_uri':REDIRECT,'response_type':'code',
        'scope':'openid profile email','state':state,'nonce':flow['nonce'],
        'code_challenge':challenge,'code_challenge_method':'S256','prompt':'login','max_age':'0'}),fixture)
    query=parse_qs(urlsplit(redirect).query);assert query['state']==[state]
    status,_,body=browser.request(ISSUER+'/protocol/openid-connect/token','POST',{
        'grant_type':'authorization_code','client_id':'android-wallet-p2','redirect_uri':REDIRECT,
        'code':query['code'][0],'code_verifier':verifier},form=True)
    assert status==200;tokens=json.loads(body)
    assert 0<tokens['expires_in']<=300 and 86000<tokens['refresh_expires_in']<=86400
    status,_,value=json_request(browser,'/auth/native/session','POST',{
        'ticket':flow['ticket'],'access_token':tokens['access_token'],'id_token':tokens['id_token']})
    assert status==200
    return browser,tokens,value['session']

def refresh(browser,tokens):
    status,_,body=browser.request(ISSUER+'/protocol/openid-connect/token','POST',{
        'grant_type':'refresh_token','client_id':'android-wallet-p2','refresh_token':tokens['refresh_token']},form=True)
    assert status==200,'Real refresh failed'
    replacement=json.loads(body)
    assert replacement['refresh_token']!=tokens['refresh_token']
    return replacement

def renew(browser,opaque,tokens):
    return json_request(browser,'/api/v1/sessions/renew','POST',{
        'session':opaque,'access_token':tokens['access_token'],'id_token':tokens['id_token']})

browser,tokens,opaque=enrolled()
passed('Real PKCE login issues five-minute access and 24-hour idle refresh')
fresh=refresh(browser,tokens)
status,_,result=renew(browser,opaque,fresh);assert status==200
previous=opaque;opaque=result['session'];assert previous!=opaque
assert json_request(browser,'/auth/me',headers={'Authorization':'Bearer '+previous})[0]==401
assert renew(browser,previous,fresh)[0] in (401,404)
assert json_request(browser,'/auth/me',headers={'Authorization':'Bearer '+opaque})[0]==200
passed('Refreshed proofs rotate the opaque session and close the previous handle')

other,alien,_=enrolled()
assert renew(browser,opaque,alien)[0] in (401,404)
passed('Different IdP session cannot renew an existing wallet session')

if a.wait_for_access_expiry:
    part=fresh['access_token'].split('.')[1]
    expires=json.loads(base64.urlsafe_b64decode(part+'='*(-len(part)%4)))['exp']
    while time.time()<=expires+1:
        print('Waiting for the real five-minute access deadline; no password login is performed.',flush=True)
        time.sleep(min(30,max(1,expires+2-time.time())))
    assert json_request(browser,'/auth/me',headers={'Authorization':'Bearer '+opaque})[0]==401
    fresh=refresh(browser,fresh)
    status,_,result=renew(browser,opaque,fresh);assert status==200
    opaque=result['session']
    assert json_request(browser,'/auth/me',headers={'Authorization':'Bearer '+opaque})[0]==200
    passed('Expired access is renewed with refresh without another username/password login')

assert json_request(browser,'/auth/logout','POST',{},headers={'Authorization':'Bearer '+opaque})[0]==200
fresh=refresh(browser,fresh)
assert renew(browser,opaque,fresh)[0] in (401,404)
passed('Wallet logout rejects renewal even with valid refreshed IdP proofs')

replay_browser,replay_tokens,_=enrolled()
refresh(replay_browser,replay_tokens)
status,_,_=replay_browser.request(ISSUER+'/protocol/openid-connect/token','POST',{
    'grant_type':'refresh_token','client_id':'android-wallet-p2','refresh_token':replay_tokens['refresh_token']},form=True)
assert status==400
passed('Previously used refresh token is rejected by real Keycloak')

revoker,revoke_tokens,revoke_session=enrolled()
status,_,_=revoker.request(ISSUER+'/protocol/openid-connect/revoke','POST',{
    'client_id':'android-wallet-p2','token_type_hint':'refresh_token','token':revoke_tokens['refresh_token']},form=True)
assert status==200
status,_,_=revoker.request(ISSUER+'/protocol/openid-connect/token','POST',{
    'grant_type':'refresh_token','client_id':'android-wallet-p2','refresh_token':revoke_tokens['refresh_token']},form=True)
assert status==400
assert json_request(revoker,'/auth/me',headers={'Authorization':'Bearer '+revoke_session})[0]==401
passed('IdP refresh-token revocation closes refresh and wallet access')

credentials=json.loads((runtime/'credentials.json').read_text())
status,_,admin=admin_request('POST','/realms/master/protocol/openid-connect/token',{
    'grant_type':'password','client_id':'admin-cli','username':'p2-bootstrap','password':credentials['bootstrap']},form=True)
assert status==200
status,_,realm=admin_request('GET','/admin/realms/'+REALM,token=admin['access_token']);assert status==200
assert realm['ssoSessionMaxLifespan']==604800 and realm['ssoSessionIdleTimeout']==86400
assert realm['revokeRefreshToken'] and realm['refreshTokenMaxReuse']==0
passed('Approved seven-day absolute limit and zero-reuse rotation are configured')
a.output.write_text(json.dumps({'result':'PASS','checks':checks,'accessSeconds':300,'refreshIdleSeconds':86400,
    'refreshMaxSeconds':604800,'waitedForRealAccessExpiry':a.wait_for_access_expiry,
    'limits':['Seven-day bound verified from live configuration, not elapsed seven-day observation',
              'Actual password reset is not performed by this test; registry recovery exclusion has a separate JVM test']},indent=2)+'\n')
