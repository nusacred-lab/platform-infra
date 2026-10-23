"""Verify and prepare a synthetic Compose installation without source builds."""
import argparse
import copy
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import socket
import ssl
import subprocess
import time
import uuid
from urllib.parse import urlencode

ROOT=Path(__file__).resolve().parent
KINDS={'custodian','issuer','company','walt-issuer','walt-wallet','walt-verifier','postgres','mail','edge','keycloak-staff','keycloak-recovery'}
ENTITIES=[('wallet','dompet-identitas','competency-proof-p2','custodian'),('issuer','lsp-nusantara','lsp-nusantara','issuer'),('company','karya-instalasi','karya-instalasi','company')]

def run(*args, **kwargs):
    return subprocess.run(list(map(str,args)),check=True,**kwargs)

def checksum(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream,'sha256').hexdigest()

def validate_manifest(manifest,commit,ref):
    if not re.fullmatch('[a-f0-9]{40}',commit) or ref not in ('refs/heads/main','refs/heads/codex/p6-release'):
        raise ValueError('Require an independently selected full workflow commit and approved branch')
    if manifest.get('schemaVersion')!=1 or manifest.get('scope')!='synthetic-isolated-demo-only' or manifest.get('productionEligible') is not False:
        raise ValueError('Unsupported manifest or scope')
    workflow=manifest['workflow']
    if workflow['repository']!='nusacred-lab/platform-infra' or workflow['path']!='.github/workflows/release.yml' or workflow['commit']!=commit or workflow['ref']!=ref or manifest['infrastructureRevision']!=commit:
        raise ValueError('Untrusted release workflow identity')
    if set(manifest['images'])!=KINDS:
        raise ValueError('Release image coverage is incomplete or unexpected')
    identity='https://github.com/nusacred-lab/platform-infra/.github/workflows/release.yml@'+ref
    for name,row in manifest['images'].items():
        if not re.fullmatch('ghcr.io/nusacred-lab/competency-proof-'+re.escape(name)+'@sha256:[a-f0-9]{64}',row['image']) or row['signerIdentity']!=identity:
            raise ValueError('Untrusted image repository, mutable reference or signer')
        expected=manifest['sources']['application']['commit'] if name in ('custodian','issuer','company') else manifest['sources']['fork']['commit'] if name.startswith('walt-') else commit
        if row['sourceRevision']!=expected or not re.fullmatch('[a-f0-9]{40}',expected):
            raise ValueError('Mixed source revision')
    if manifest['sources']['application']['repository']!='nusacred-lab/competency-proof' or manifest['sources']['fork']['repository']!='nusacred-lab/waltid-identity':
        raise ValueError('Untrusted source repository')
    if manifest.get('schemas') != {'custodianRegistry':5,'businessMigrations':3,'policyVersion':'competency-v1'}:
        raise ValueError('Unsupported schema compatibility contract')
    apk=manifest.get('apk',{})
    if (apk.get('sourceRevision') != manifest['sources']['application']['commit'] or apk.get('applicationId')!='id.nusacred.wallet' or
            apk.get('versionCode')!=5 or apk.get('versionName')!='0.6.0-p6' or not re.fullmatch('[a-f0-9]{64}',apk.get('unsignedSha256',''))):
        raise ValueError('APK/source binding is missing or inconsistent')
    return identity

def verify(manifest_path,commit,ref):
    manifest=json.loads(manifest_path.read_text())
    identity=validate_manifest(manifest,commit,ref)
    run('gh','attestation','verify',manifest_path,'--repo','nusacred-lab/platform-infra',
        '--signer-workflow','nusacred-lab/platform-infra/.github/workflows/release.yml',
        '--source-digest',commit,'--signer-digest',commit,'--source-ref',ref,'--deny-self-hosted-runners')
    for name,row in manifest['images'].items():
        common=['--certificate-identity',identity,'--certificate-oidc-issuer','https://token.actions.githubusercontent.com',
                '--certificate-github-workflow-sha',commit]
        run('cosign','verify',*common,row['image'],stdout=subprocess.DEVNULL)
        verified=subprocess.check_output(['cosign','verify-attestation',*common,'--type','slsaprovenance1',row['image']],text=True)
        # Verification checks signatures/identity/digest; the manifest independently pins source revisions.
        if not verified.strip():
            raise ValueError('No verified image provenance: '+name)
        run('cosign','verify-attestation',*common,'--type','cyclonedx',row['image'],stdout=subprocess.DEVNULL)
    return manifest

def env_read(path):
    return dict(line.split('=',1) for line in path.read_text().splitlines() if line and not line.startswith('#'))

def compose(env_path,*args):
    # Host shell variables must not silently override the verified env-file pins/project.
    clean={k:v for k,v in os.environ.items() if not k.startswith(('P6_','COMPOSE_'))}
    run('docker','compose','--env-file',env_path,'-f',ROOT/'compose.yaml',*args,env=clean)

def check_runtime(runtime):
    manifest_path=runtime/'release-manifest.json'
    if checksum(manifest_path)!=json.loads((runtime/'verified-release.json').read_text())['manifestSha256']:
        raise ValueError('Manifest changed since verification')
    manifest=json.loads(manifest_path.read_text())
    env=env_read(runtime/'compose.env')
    for name,row in manifest['images'].items():
        if env.get('P6_'+name.upper().replace('-','_')+'_IMAGE')!=row['image']:
            raise ValueError('Runtime image pin changed: '+name)
    if env['P6_PROJECT_NAME']!=json.loads((runtime/'installation.json').read_text())['project'] or env['P6_RUNTIME']!=str(runtime):
        raise ValueError('Runtime/project identity changed')
    return manifest

def prepare(runtime,manifest,manifest_path,certificate=None,project='competency-proof-p6'):
    if 'runtime' not in runtime.parts or any(c.isspace() for c in str(runtime)) or not re.fullmatch('[a-z0-9][a-z0-9_-]{1,50}',project):
        raise ValueError('Use a private runtime directory without spaces and a distinct Compose project name')
    # A fresh runtime may be initialized; existing identity state is retained exactly.
    os.umask(0o077)
    runtime.mkdir(parents=True,exist_ok=True,mode=0o700)
    runtime.chmod(0o700)
    state_file=runtime/'installation.json'
    if state_file.exists():
        state=json.loads(state_file.read_text())
        if state['project']!=project:
            raise ValueError('Existing runtime belongs to another Compose project')
    else:
        state={'project':project,'entities':{e:{'db':secrets.token_urlsafe(48),'bootstrap':secrets.token_urlsafe(48),'client':secrets.token_urlsafe(48)} for e,*_ in ENTITIES},
            'users':{role:{'id':str(uuid.uuid4()),'email':role+'-'+secrets.token_hex(4)+'@example.test','password':secrets.token_urlsafe(24)} for role in ['applicant','custodian-admin','issuer-admin','company-admin']},
            'recovery':secrets.token_urlsafe(48)}
        state_file.write_text(json.dumps(state,indent=2)+'\n')
    assets=ROOT/'assets'
    for name in ['ingress.caddy','private.caddy','protocol.caddy']:
        shutil.copyfile(assets/name,runtime/name)
        (runtime/name).chmod(0o644)
    shutil.copytree(assets/'themes',runtime/'themes',dirs_exist_ok=True)
    for path in (runtime/'themes').rglob('*'):
        path.chmod(0o755 if path.is_dir() else 0o644)
    (runtime/'themes').chmod(0o755)
    tls=runtime/'tls';tls.mkdir(exist_ok=True);tls.chmod(0o755)
    if not (tls/'fullchain.pem').exists():
        if certificate:
            for name in ['fullchain.pem','privkey.pem']:
                shutil.copyfile(certificate/name,tls/name)
        else:
            run('openssl','req','-x509','-newkey','rsa:3072','-nodes','-days','7',
                '-subj','/CN=Competency Proof isolated staging',
                '-addext','subjectAltName=DNS:*.demo.inoerawan.id',
                '-keyout',tls/'privkey.pem','-out',tls/'fullchain.pem',stderr=subprocess.DEVNULL)
        for name in ['fullchain.pem','privkey.pem']:
            (tls/name).chmod(0o644)
    if not (tls/'truststore.p12').exists():
        # Only a public certificate enters this truststore. The private runtime parent is 0700.
        image=manifest['images']['keycloak-staff']['image']
        run('docker','run','--rm','--network','none','--read-only','--cap-drop','ALL','--user',str(os.getuid())+':'+str(os.getgid()),
            '--mount','type=bind,source='+str(tls)+',target=/tls','--entrypoint','keytool',image,
            '-importcert','-noprompt','-alias','p6-runtime','-file','/tls/fullchain.pem','-keystore','/tls/truststore.p12',
            '-storetype','PKCS12','-storepass','changeit')
        (tls/'truststore.p12').chmod(0o644)
    template=json.loads((assets/'realm-template.json').read_text())
    for entity,domain,realm,bff in ENTITIES:
        settings=state['entities'][entity]
        roles=['applicant','custodian-admin'] if entity=='wallet' else [entity+'-admin']
        realm_data=copy.deepcopy(template)
        realm_data.update(realm=realm,displayName=domain,loginTheme='nusacred' if entity=='wallet' else realm,
            resetPasswordAllowed=True,ssoSessionIdleTimeout=86400,ssoSessionMaxLifespan=604800,users=[])
        realm_data['roles']['realm']=[{'name':role} for role in roles]
        realm_data['clients']=[c for c in realm_data['clients'] if c['clientId']==bff+'-bff-p2' or (entity=='wallet' and c['clientId']=='android-wallet-p2')]
        for client in realm_data['clients']:
            native=client['clientId']=='android-wallet-p2'
            origin='https://'+domain+'.demo.inoerawan.id'
            client.update(redirectUris=[origin+('/auth/android/callback' if native else '/auth/callback')],webOrigins=[] if native else [origin])
            if not native:client['secret']=settings['client']
            client.setdefault('attributes',{}).update({'access.token.lifespan':'300' if native else '3600',
                'client.session.idle.timeout':'86400' if native else '3600','client.session.max.lifespan':'604800' if native else '3600'})
        for role in roles:
            user=state['users'][role]
            realm_data['users'].append(dict(id=user['id'],username=user['email'],email=user['email'],emailVerified=True,
                enabled=True,firstName='Synthetic',lastName=role,realmRoles=[role],credentials=[{'type':'password','value':user['password'],'temporary':False}]))
        realm_data['smtpServer']['fromDisplayName']=domain+' (demo)'
        directory=runtime/(entity+'-import');directory.mkdir(exist_ok=True);directory.chmod(0o755)
        target=directory/(realm+'-realm.json');target.write_text(json.dumps(realm_data,indent=2)+'\n');target.chmod(0o644)
        for suffix,value in [('db-password',settings['db']),('client-secret',settings['client'])]:
            target=runtime/(entity+'-'+suffix);target.write_text(value);target.chmod(0o644)
        if entity!='wallet':
            target=runtime/(entity+'-organizations');target.write_text(json.dumps({state['users'][entity+'-admin']['id']:entity+'-synthetic-org'}));target.chmod(0o644)
    target=runtime/'recovery-service-secret';target.write_text(state['recovery']);target.chmod(0o644)
    run('python3',ROOT/'prepare_protocol.py','--runtime',runtime)
    for path in (runtime/'walt').rglob('*'):
        path.chmod(0o755 if path.is_dir() else 0o644)
    for name in ['public-issuer.json','offer-reference-key']:(runtime/name).chmod(0o644)
    # SELinux shared bind mounts remain under the private 0700 runtime parent.
    assetlinks=runtime/'assetlinks/.well-known';assetlinks.mkdir(parents=True,exist_ok=True)
    (runtime/'assetlinks').chmod(0o755);assetlinks.chmod(0o755)
    shutil.copyfile(ROOT/'assets/assetlinks.json',assetlinks/'assetlinks.json');(assetlinks/'assetlinks.json').chmod(0o644)
    env={'P6_RUNTIME':str(runtime),'P6_PROJECT_NAME':project,'P6_HTTPS_PORT':'28443','P6_ADMIN_PORT':'28444','P6_MAIL_PORT':'28025'}
    env.update({'P6_'+name.upper().replace('-','_')+'_IMAGE':row['image'] for name,row in manifest['images'].items()})
    for entity,*_ in ENTITIES:
        env['P6_'+entity.upper()+'_DB_PASSWORD']=state['entities'][entity]['db']
        env['P6_'+entity.upper()+'_BOOTSTRAP_PASSWORD']=state['entities'][entity]['bootstrap']
    existing=runtime/'compose.env'
    if existing.exists():
        previous=env_read(existing)
        for key in ['P6_HTTPS_PORT','P6_ADMIN_PORT','P6_MAIL_PORT']:env[key]=previous.get(key,env[key])
    existing.write_text(''.join(key+'='+value+'\n' for key,value in env.items()));existing.chmod(0o600)
    shutil.copyfile(manifest_path,runtime/'release-manifest.json')
    (runtime/'verified-release.json').write_text(json.dumps({'manifestSha256':checksum(manifest_path),'workflowCommit':manifest['infrastructureRevision']})+'\n')
    compose(existing,'config','--quiet')
    print('PASS: private runtime prepared; existing accounts, secrets and issuer keys preserved')

def request(runtime,domain,method,path,body=None,token=None,form=False):
    env=env_read(runtime/'compose.env')
    host='login-'+domain+'.demo.inoerawan.id'
    context=ssl.create_default_context(cafile=str(runtime/'tls/fullchain.pem'))
    connection=http.client.HTTPSConnection(host,timeout=15)
    def connect():
        connection.sock=context.wrap_socket(socket.create_connection(('127.0.0.1',int(env['P6_ADMIN_PORT'])),timeout=15),server_hostname=host)
    connection.connect=connect
    headers={} if token is None else {'Authorization':'Bearer '+token}
    if body is not None:headers['Content-Type']='application/x-www-form-urlencoded' if form else 'application/json'
    try:
        connection.request(method,path,None if body is None else urlencode(body) if form else json.dumps(body),headers)
        response=connection.getresponse();raw=response.read(2_097_153)
        if len(raw)>2_097_152:raise ValueError('Oversized admin response')
        return response.status,json.loads(raw) if raw else None
    finally:connection.close()

def start(runtime):
    check_runtime(runtime)
    env=runtime/'compose.env'
    compose(env,'config','--quiet')
    compose(env,'up','-d','--no-build','private-access','mail')
    state=json.loads((runtime/'installation.json').read_text())
    for entity,domain,realm,bff in ENTITIES:
        for attempt in range(120):
            try:
                status,discovery=request(runtime,domain,'GET','/realms/'+realm+'/.well-known/openid-configuration')
                if status==200 and discovery['issuer']=='https://login-'+domain+'.demo.inoerawan.id/realms/'+realm:break
            except (OSError,ValueError,http.client.HTTPException):pass
            time.sleep(1)
        else:raise RuntimeError('Identity discovery timeout: '+entity)
        status,auth=request(runtime,domain,'POST','/realms/master/protocol/openid-connect/token',
            {'grant_type':'password','client_id':'admin-cli','username':entity+'-bootstrap','password':state['entities'][entity]['bootstrap']},form=True)
        if status!=200:raise RuntimeError('Private bootstrap failed: '+entity)
        token=auth['access_token'];base='/admin/realms/'+realm
        status,clients=request(runtime,domain,'GET',base+'/clients',token=token)
        if status!=200:raise RuntimeError('Client inventory failed')
        for client in clients:
            if client['clientId'] in ('account','account-console'):
                client['enabled']=False
                if request(runtime,domain,'PUT',base+'/clients/'+client['id'],client,token)[0]!=204:raise RuntimeError('Account disable failed')
        if entity=='wallet':
            status,profile=request(runtime,domain,'GET',base+'/users/profile',token=token)
            profile['unmanagedAttributePolicy']=None
            if not any(x['name']=='nusacred_recovery_commit' for x in profile['attributes']):
                profile['attributes'].append({'name':'nusacred_recovery_commit','permissions':{'view':['admin'],'edit':['admin']}})
            if request(runtime,domain,'PUT',base+'/users/profile',profile,token)[0] not in (200,204):raise RuntimeError('Recovery marker policy failed')
            status,executions=request(runtime,domain,'GET',base+'/authentication/flows/reset%20credentials/executions',token=token)
            email=next(x for x in executions if x.get('providerId')=='reset-credential-email')
            config={'alias':'nusacred-force-fresh-recovery-login','config':{'force-login':'true'}}
            path=base+'/authentication/config/'+email['authenticationConfig'] if email.get('authenticationConfig') else base+'/authentication/executions/'+email['id']+'/config'
            if request(runtime,domain,'PUT' if email.get('authenticationConfig') else 'POST',path,config,token)[0] not in (201,204):raise RuntimeError('Fresh recovery login policy failed')
    compose(env,'up','-d','--no-build')
    print('Identity policies initialized. Verify portal readiness and run acceptance before G6/G7.')

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('command',choices=['prepare','verify','up','pull'])
    p.add_argument('--runtime',type=Path,default=ROOT/'runtime/p6')
    p.add_argument('--manifest',type=Path,default=ROOT/'release-manifest.json')
    p.add_argument('--trusted-commit')
    p.add_argument('--trusted-ref',default='refs/heads/main')
    p.add_argument('--certificate-directory',type=Path)
    p.add_argument('--project',default='competency-proof-p6')
    a=p.parse_args();runtime=a.runtime.resolve()
    if a.command in ['verify','prepare']:
        if not a.trusted_commit:p.error('Select the trusted workflow commit independently from the manifest')
        manifest=verify(a.manifest.resolve(),a.trusted_commit,a.trusted_ref)
        if a.command=='prepare':prepare(runtime,manifest,a.manifest.resolve(),a.certificate_directory,a.project)
    elif a.command=='up':start(runtime)
    else:
        check_runtime(runtime)
        compose(runtime/'compose.env','pull')

if __name__=='__main__':main()
