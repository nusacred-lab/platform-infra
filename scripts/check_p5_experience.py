"""Read-only P5 boundary checks through real BFF logins and verified local TLS.

No credentials, cookies or applicant contents enter the report. Separate physical
Android and browser evidence remains mandatory for G5.
"""
import argparse
from datetime import datetime, timezone
import http.client
from http.cookies import SimpleCookie
import json
from pathlib import Path
import socket
import ssl
from urllib.parse import urlencode, urlsplit
from test_p2_login import login

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--identity-runtime', type=Path, required=True)
p.add_argument('--output', type=Path, required=True)
a = p.parse_args()
assert 'runtime' in a.identity_runtime.resolve().parts
fixtures = json.loads((a.identity_runtime/'login-fixtures.json').read_text())
checks = []

class Browser:
    def __init__(self):
        self.cookies = {}
        self.last_headers = []
    def request(self, url, method='GET', body=None, headers=None, form=False):
        uri = urlsplit(url)
        assert uri.scheme == 'https' and uri.hostname in {
            role+'.demo.inoerawan.id' for role in ('login-dompet-identitas','dompet-identitas','lsp-nusantara','karya-instalasi','login-lsp-nusantara','login-karya-instalasi')}
        c = http.client.HTTPSConnection(uri.hostname, timeout=10)
        def connect():
            c.sock = ssl.create_default_context().wrap_socket(
                socket.create_connection(('127.0.0.1',8443), timeout=10), server_hostname=uri.hostname)
        c.connect = connect
        outgoing = dict(headers or {})
        cookies = self.cookies.setdefault(uri.hostname,{})
        if cookies:
            outgoing['Cookie'] = '; '.join(k+'='+v for k,v in cookies.items())
        payload = None if body is None else urlencode(body) if form else json.dumps(body)
        if body is not None:
            outgoing['Content-Type'] = 'application/x-www-form-urlencoded' if form else 'application/json'
        try:
            c.request(method,uri.path+('?' + uri.query if uri.query else ''),payload,outgoing)
            response = c.getresponse()
            self.last_headers = response.getheaders()
            for key,value in self.last_headers:
                if key.lower() == 'set-cookie':
                    for name,item in SimpleCookie(value.split(';',1)[0]).items():
                        if any(part.strip().lower()=='max-age=0' for part in value.split(';')[1:]):
                            cookies.pop(name,None)
                        else:
                            cookies[name] = item.value
            raw = response.read(2_097_153)
            assert len(raw)<=2_097_152
            return response.status,dict(self.last_headers),raw.decode()
        finally:
            c.close()

def check(name,condition):
    assert condition,name
    checks.append(name)

sessions = []
for service,host,role,path in [('issuer','lsp-nusantara','issuer-admin','/api/v1/assessments'),
                             ('company','karya-instalasi','company-admin','/api/v1/verification-sessions'),
                             ('custodian','dompet-identitas','custodian-admin','/api/v1/service-status')]:
    origin = 'https://'+host+'.demo.inoerawan.id'
    anonymous = Browser()
    status,_,raw = anonymous.request(origin+'/api/v1/portal-config')
    check(service+': correct live portal identity',status==200 and json.loads(raw)['service']==service)
    check(service+': private records require authentication',anonymous.request(origin+path)[0]==401)
    stale = Browser()
    stale.cookies[urlsplit(origin).hostname] = {'__Host-nusacred-session':'expired-synthetic-session'}
    stale_status,stale_headers,_ = stale.request(origin+'/api/v1/portal-session')
    check(service+': stale browser cookie is removed',stale_status==401 and
          '__Host-nusacred-session' not in stale.cookies[urlsplit(origin).hostname] and
          'Max-Age=0' in stale_headers.get('Set-Cookie',''))
    browser = Browser();status,headers,_ = browser.request(origin+'/auth/start')
    assert status==302
    callback = login(browser,headers['Location'],fixtures[role])
    check(service+': real role-specific BFF login',browser.request(callback)[0]==302)
    status,headers,raw = browser.request(origin+'/api/v1/portal-session');session = json.loads(raw)
    check(service+': session contains no IdP token',status==200 and set(session)=={'email','accountId','roles','organizationId','csrf','expiresAt'})
    sessions.append(browser.cookies[urlsplit(origin).hostname]['__Host-nusacred-session'])
    status,headers,raw = browser.request(origin+path)
    check(service+': authorized view available and not cached',status==200 and headers['Cache-Control']=='no-store')
    if service=='custodian':
        check('custodian: aggregate-only response',set(json.loads(raw))=={'registryAvailable','accounts','walletsReady','recoveryPending','operationsUncertain'})
    if service=='company':
        status,_,raw = anonymous.request(origin+'/api/v1/jobs')
        check('public jobs: requirements only',status==200 and all(set(j)=={'id','title','competencyCode','assessmentResult','revision'} for j in json.loads(raw)['items']))
    for forbidden in ['/wallets','/api/v1/keys','/internal/recoveries/begin']:
        check(service+': no private route '+forbidden,anonymous.request(origin+forbidden)[0]==404)
    status,_,_ = browser.request(origin+'/auth/logout','POST',{}, {'Origin':origin,'X-CSRF-Token':session['csrf']})
    check(service+': explicit logout closes access',status==200 and browser.request(origin+path)[0]==401)
check('portal BFF sessions are distinct',len(set(sessions))==3)
a.output.parent.mkdir(parents=True,exist_ok=True)
a.output.write_text(json.dumps({'checkedAt':datetime.now(timezone.utc).isoformat(),'transport':'verified local TLS','checks':checks,'result':'PASS','limit':'Read-only HTTP checks; separate physical/browser evidence required'},indent=2)+'\n')
print('PASS:',len(checks),'P5 portal boundaries; no credentials or applicant contents recorded')
