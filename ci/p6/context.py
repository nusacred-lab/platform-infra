"""Private transport for P6 fault/recovery tests; rejects active demo projects."""
import argparse
import json
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'release'))
from acceptance_transport import Browser as BaseBrowser,login
from install import env_read

parser=argparse.ArgumentParser(add_help=False)
parser.add_argument('--runtime',type=Path,required=True)
args,_=parser.parse_known_args()
RUNTIME=args.runtime.resolve()
if 'runtime' not in RUNTIME.parts:raise ValueError('Use a private P6 runtime')
ENV=env_read(RUNTIME/'compose.env')
P6_PROJECT=ENV['P6_PROJECT_NAME']
if not P6_PROJECT.startswith('competency-proof-p6'):raise ValueError('Refuse an active demo project')
REALM='competency-proof-p2'
AUTH='https://login-dompet-identitas.demo.inoerawan.id'
WALLET='https://dompet-identitas.demo.inoerawan.id'
ISSUER=AUTH+'/realms/'+REALM
REDIRECT=WALLET+'/auth/android/callback'

class Browser(BaseBrowser):
    loopback_port=int(ENV['P6_HTTPS_PORT'])
    cafile=str(RUNTIME/'tls/fullchain.pem')

class AdminBrowser(Browser):
    loopback_port=int(ENV['P6_ADMIN_PORT'])


def json_request(browser,path,method='GET',body=None,headers=None):
    status,returned,raw=browser.request(WALLET+path,method,body,headers)
    return status,returned,json.loads(raw) if raw else None


def admin_request(method,path,payload=None,token=None,form=False,mail=False):
    headers={} if token is None else {'Authorization':'Bearer '+token}
    if mail:
        import http.client
        connection=http.client.HTTPConnection('127.0.0.1',int(ENV['P6_MAIL_PORT']),timeout=15)
        try:
            connection.request(method,path)
            response=connection.getresponse();raw=response.read(4_194_305)
            if len(raw)>4_194_304:raise ValueError('Oversized mailbox response')
            return response.status,dict(response.getheaders()),json.loads(raw) if raw else None
        finally:connection.close()
    status,returned,raw=AdminBrowser().request(AUTH+path,method,payload,headers,form=form)
    return status,returned,json.loads(raw) if raw else None

# Only the disposable P6 test runtime receives this legacy-compatible bootstrap view.
state=json.loads((RUNTIME/'installation.json').read_text())
(RUNTIME/'credentials.json').write_text(json.dumps({'bootstrap':state['entities']['wallet']['bootstrap']}))
(RUNTIME/'credentials.json').chmod(0o600)
