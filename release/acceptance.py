"""Run real HTTP acceptance on the isolated installed release; never claim APK UI evidence.

All mutable accounts/data belong to the prepared private P6 runtime. No active
P2/P5 containers, DNS, volumes, credentials or public tunnel are touched.
"""
import argparse
import base64
import hashlib
import json
from pathlib import Path
import secrets
import time
from urllib.parse import parse_qs,urlencode,urlsplit
import uuid
from acceptance_transport import Browser,login
from install import env_read

WALLET='https://dompet-identitas.demo.inoerawan.id'
ISSUER='https://lsp-nusantara.demo.inoerawan.id'
COMPANY='https://karya-instalasi.demo.inoerawan.id'
AUTH='https://login-dompet-identitas.demo.inoerawan.id/realms/competency-proof-p2'
REDIRECT=WALLET+'/auth/android/callback'


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--runtime',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True)
    a=p.parse_args();runtime=a.runtime.resolve()
    if 'runtime' not in runtime.parts or 'runtime' not in a.output.resolve().parts:p.error('Use private disposable runtime paths')
    env=env_read(runtime/'compose.env')
    if not env['P6_PROJECT_NAME'].startswith('competency-proof-p6'):p.error('Refuse an active demo project')
    Browser.loopback_port=int(env['P6_HTTPS_PORT']);Browser.cafile=str(runtime/'tls/fullchain.pem')
    state=json.loads((runtime/'installation.json').read_text());checks=[]
    def check(id,condition):
        if not condition:raise AssertionError('Acceptance failed: '+id)
        checks.append({'id':id,'result':'PASS'});print('PASS:',id,flush=True)
    def request(browser,origin,path,method='GET',body=None,headers=None):
        status,returned,raw=browser.request(origin+path,method,body,headers)
        try:data=json.loads(raw)
        except ValueError:data=raw
        return status,returned,data
    anonymous=Browser()
    for origin in [WALLET,ISSUER,COMPANY]:
        for attempt in range(90):
            try:
                if request(anonymous,origin,'/api/v1/portal-config')[0]==200:break
            except OSError:pass
            time.sleep(1)
        else:raise RuntimeError('Portal readiness timeout')
        check('P6-HTTP-portal-'+urlsplit(origin).hostname,request(anonymous,origin,'/')[0]==200)
    for path in ['/admin/','/internal/recoveries/begin','/wallet','/api/v1/me']:
        check('P6-HTTP-anonymous-'+path,request(anonymous,WALLET,path)[0] in (401,403,404))
    for domain,realm in [('dompet-identitas','competency-proof-p2'),('lsp-nusantara','lsp-nusantara'),('karya-instalasi','karya-instalasi')]:
        host='https://login-'+domain+'.demo.inoerawan.id'
        check('P6-HTTP-private-admin-'+domain,request(anonymous,host,'/admin/realms/'+realm)[0]==404)
    def bff(origin,role):
        browser=Browser();status,headers,_=request(browser,origin,'/auth/start');check('P6-login-start-'+role,status==302)
        callback=login(browser,headers['Location'],state['users'][role])
        check('P6-login-callback-'+role,browser.request(callback)[0]==302)
        status,_,me=request(browser,origin,'/auth/me');check('P6-login-me-'+role,status==200)
        return browser,{'Origin':origin,'X-CSRF-Token':me['csrf']}
    issuer,ih=bff(ISSUER,'issuer-admin');company,ch=bff(COMPANY,'company-admin')
    def mutate(browser,origin,path,body,headers,method='POST',key=None):
        return request(browser,origin,path,method,body,dict(headers,**{'Idempotency-Key':key or str(uuid.uuid4())}))
    status,_,flow=request(anonymous,WALLET,'/auth/native/start','POST',{});check('P6-native-start',status==200)
    native=Browser();verifier=secrets.token_urlsafe(48);nonce=secrets.token_urlsafe(32)
    challenge=base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip('=')
    callback=login(native,AUTH+'/protocol/openid-connect/auth?'+urlencode(dict(client_id='android-wallet-p2',redirect_uri=REDIRECT,
        response_type='code',scope='openid profile email',state=nonce,nonce=flow['nonce'],code_challenge=challenge,code_challenge_method='S256',prompt='login',max_age='0')),state['users']['applicant'])
    query=parse_qs(urlsplit(callback).query);check('P6-native-state',query.get('state')==[nonce])
    status,_,raw=native.request(AUTH+'/protocol/openid-connect/token','POST',dict(grant_type='authorization_code',client_id='android-wallet-p2',redirect_uri=REDIRECT,code=query['code'][0],code_verifier=verifier),form=True)
    check('P6-native-pkce',status==200);tokens=json.loads(raw)
    check('P6-native-token-bounds',0<tokens['expires_in']<=300 and 86000<tokens['refresh_expires_in']<=86400)
    status,_,session=request(anonymous,WALLET,'/auth/native/session','POST',dict(ticket=flow['ticket'],access_token=tokens['access_token'],id_token=tokens['id_token']))
    check('P6-native-enrollment',status==200)
    nh={'Authorization':'Bearer '+session['session']};wallet=Browser()
    check('P6-native-enrollment-replay',request(anonymous,WALLET,'/auth/native/session','POST',dict(ticket=flow['ticket'],access_token=tokens['access_token'],id_token=tokens['id_token']))[0]==401)
    status,_,me=request(wallet,WALLET,'/api/v1/me',headers=nh);check('P6-native-account',status==200)
    account=me['accountId']
    status,_,provision=request(wallet,WALLET,'/api/v1/wallet/provision','POST',{},nh);check('P6-wallet-provision',status==200 and provision['state']=='READY')
    status,_,profile=request(anonymous,ISSUER,'/api/v1/issuer-profile');check('P6-issuer-profile',status==200 and profile['publicationStatus']=='SELF_PUBLISHED')
    def approve():
        status,_,review=mutate(company,COMPANY,'/api/v1/issuer-reviews',{'issuerId':profile['id']},ch)
        check('P6-trust-review',status==201)
        status,_,approval=mutate(company,COMPANY,'/api/v1/trusted-issuers',{'reviewId':review['id'],'verificationMethod':'demo-walkthrough','verificationNote':'Synthetic candidate acceptance only; no real accreditation.','confirmed':'true'},ch)
        check('P6-trust-approval',status==201)
        return approval
    approve()
    status,_,trust=request(company,COMPANY,'/api/v1/trusted-issuers');check('P6-trust-list',status==200 and len(trust['items'])==1)
    trusted_id=trust['items'][0]['id']
    candidate='p6-'+secrets.token_hex(6)
    assessment_body=dict(candidateAccountId=account,candidateId=candidate,competencyCode='DEMO-ELEC-001',assessmentResult='competent')
    key=str(uuid.uuid4())
    status,_,assessment=mutate(issuer,ISSUER,'/api/v1/assessments',assessment_body,ih,key=key);check('P6-assessment',status==201)
    check('P6-idempotent-assessment',mutate(issuer,ISSUER,'/api/v1/assessments',assessment_body,ih,key=key)[2]==assessment)
    check('P6-idempotency-conflict',mutate(issuer,ISSUER,'/api/v1/assessments',dict(assessment_body,competencyCode='DIFFERENT'),ih,key=key)[0]==409)
    check('P6-CSRF-denial',mutate(issuer,ISSUER,'/api/v1/assessments',assessment_body,{'Origin':ISSUER})[0]==403)
    check('P6-origin-denial',mutate(issuer,ISSUER,'/api/v1/assessments',assessment_body,dict(ih,Origin='https://foreign.example'))[0]==403)
    status,_,offer=mutate(issuer,ISSUER,'/api/v1/assessments/'+assessment['id']+'/offers',{},ih);check('P6-offer',status==202 and offer['state']=='COMPLETED')
    status,_,preview=mutate(wallet,WALLET,'/api/v1/exchange-contexts',{'reference':offer['offerUrl']},nh);check('P6-receive-preview',status==201 and preview['consentRequired'] is True)
    accept='/api/v1/exchange-contexts/'+preview['id']+'/accept'
    body=dict(previewHash=preview['previewHash'],consent=True,disclosures=[])
    check('P6-receive-no-consent',mutate(wallet,WALLET,accept,dict(body,consent=False),nh)[0]==400)
    check('P6-receive-tampered-preview',mutate(wallet,WALLET,accept,dict(body,previewHash='incorrect'),nh)[0] in (401,403))
    key=str(uuid.uuid4());status,_,received=mutate(wallet,WALLET,accept,body,nh,key=key);check('P6-receive-consented',status==202 and received['state']=='COMPLETED')
    check('P6-receive-idempotent',mutate(wallet,WALLET,accept,body,nh,key=key)[2]==received)
    status,_,credentials=request(wallet,WALLET,'/api/v1/wallet/credentials',headers=nh);check('P6-credential-readback',status==200)
    before=hashlib.sha256(json.dumps(credentials,sort_keys=True).encode()).hexdigest()
    finals=[]
    def present(job,competency,expected):
        status,_,_=mutate(company,COMPANY,'/api/v1/jobs/'+job,dict(title='Synthetic release acceptance',competencyCode=competency,assessmentResult='competent'),ch,method='PUT')
        check('P6-job-'+job,status==200)
        viewer=Browser();status,_,viewer_session=request(viewer,COMPANY,'/api/v1/browser-session');check('P6-viewer-'+job,status==200)
        vh={'Origin':COMPANY,'X-CSRF-Token':viewer_session['csrf']}
        status,_,result=mutate(viewer,COMPANY,'/api/v1/jobs/'+job+'/verification-sessions',{},vh);check('P6-request-'+job,status==202 and result.get('requestUrl'))
        path='/api/v1/verification-sessions/'+result['id']
        check('P6-viewer-isolation-'+job,request(Browser(),COMPANY,path)[0]==401)
        status,_,context=mutate(wallet,WALLET,'/api/v1/exchange-contexts',{'reference':result['requestUrl']},nh)
        check('P6-present-preview-'+job,status==201 and context['consentRequired'] is True)
        submit='/api/v1/exchange-contexts/'+context['id']+'/present'
        values=dict(previewHash=context['previewHash'],consent=True,credentialId=context['credentialId'],disclosures=context['details']['disclosures'])
        check('P6-present-no-consent-'+job,mutate(wallet,WALLET,submit,dict(values,consent=False),nh)[0]==400)
        key=str(uuid.uuid4());status,_,sent=mutate(wallet,WALLET,submit,values,nh,key=key)
        check('P6-present-sent-'+job,status==202 and sent['state']=='COMPLETED')
        check('P6-present-idempotent-'+job,mutate(wallet,WALLET,submit,values,nh,key=key)[2]==sent)
        status,_,final=request(viewer,COMPANY,path)
        check('P6-business-'+job,status==200 and final['final'] is True and final['decision']==expected)
        finals.append({'path':path,'result':final})
    present('matching-'+candidate,'DEMO-ELEC-001','FULFILLED')
    present('different-'+candidate,'OTHER-COMPETENCY','NOT_FULFILLED')
    check('P6-trust-remove',mutate(company,COMPANY,'/api/v1/trusted-issuers/'+trusted_id,{},ch,method='DELETE')[0]==200)
    present('untrusted-'+candidate,'DEMO-ELEC-001','NOT_FULFILLED')
    approve()
    for row in finals:check('P6-final-immutable',request(company,COMPANY,row['path'])[2]==row['result'])
    status,_,after=request(wallet,WALLET,'/api/v1/wallet/credentials',headers=nh)
    check('P6-credential-bytes-unchanged',status==200 and hashlib.sha256(json.dumps(after,sort_keys=True).encode()).hexdigest()==before)
    # Continuity records stay private: opaque handles and holder data are not public evidence.
    (runtime/'continuity-private.json').write_text(json.dumps(dict(finals=finals,credentialDigest=before,walletId=provision['wallet_id'],nativeSession=session['session'])))
    manifest=json.loads((runtime/'release-manifest.json').read_text())
    report=dict(schemaVersion=1,result='PASS',checks=checks,candidate=manifest,
        limitations=['Real HTTP/Keycloak/protocol and consent APIs; no physical APK/QR or elapsed expiry claim',
                      'Preverified synthetic login fixtures do not prove email-link verification',
                      'Fault/recovery/concurrency and upgrade/rollback require separate evidence'])
    a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text(json.dumps(report,indent=2)+'\n')
    print('PASS:',len(checks),'installed-stack HTTP acceptance checks')

if __name__=='__main__':main()
