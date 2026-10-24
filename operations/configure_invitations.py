"""Provision a dedicated wallet-realm invitation client after a verified application update.

Does not start/restart services, alter image pins, invite recipients, or enable
public self-registration. No bootstrap credentials are mounted into the BFF.
"""
import argparse
import os
from pathlib import Path
import secrets
from urllib.parse import urlencode
import p7

CLIENT = 'wallet-invitations'
ROLES = ('manage-users', 'view-users', 'query-users', 'view-realm')
BASE = '/admin/realms/competency-proof-p2'


def configure(a):
    if a.runtime.stat().st_mode & 0o077:
        raise ValueError('Private runtime parent must be mode 0700')
    api, token = p7.admin(a, 'wallet', 'dompet-identitas')
    def request(method, path, body=None, expected=200):
        status, data = api.request(a.runtime, 'dompet-identitas', method, BASE+path, body, token)
        if status != expected:
            raise RuntimeError('Invitation client configuration failed; inspect private administration without exposing responses')
        return data
    clients = request('GET', '/clients?'+urlencode({'clientId': CLIENT}))
    keyfile = a.runtime/'wallet-invitations-secret'
    if clients and not keyfile.exists():
        raise ValueError('Client already exists without its local secret; reconcile before rotating')
    if not clients:
        if not keyfile.exists():
            # Durable secret before creation allows a safe retry after a lost response.
            descriptor = os.open(keyfile, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, 'w') as stream:
                stream.write(secrets.token_urlsafe(48)+'\n')
        request('POST','/clients', {'clientId':CLIENT,'enabled':True,'protocol':'openid-connect',
            'publicClient':False,'clientAuthenticatorType':'client-secret','secret':keyfile.read_text().strip(),
            'serviceAccountsEnabled':True,'standardFlowEnabled':False,'implicitFlowEnabled':False,
            'directAccessGrantsEnabled':False,'fullScopeAllowed':False,'redirectUris':[],'webOrigins':[]}, 201)
        clients = request('GET','/clients?'+urlencode({'clientId': CLIENT}))
    if len(clients) != 1:
        raise ValueError('Require exactly one dedicated invitation client')
    cid = clients[0]['id']
    client = request('GET','/clients/'+cid)
    if (client.get('fullScopeAllowed') or not client.get('serviceAccountsEnabled')
            or any(client.get(k) for k in ('publicClient','standardFlowEnabled','implicitFlowEnabled','directAccessGrantsEnabled'))):
        raise ValueError('Existing invitation client policy differs; review privately')
    remote_secret = request('GET','/clients/'+cid+'/client-secret')['value']
    if not secrets.compare_digest(remote_secret,keyfile.read_text().strip()):
        raise ValueError('Local and remote client secrets differ; no automatic rotation')
    management = request('GET','/clients?clientId=realm-management')
    if len(management) != 1:
        raise ValueError('Require wallet realm-management client')
    mid = management[0]['id']
    roles = [request('GET','/clients/'+mid+'/roles/'+name) for name in ROLES]
    uid = request('GET','/clients/'+cid+'/service-account-user')['id']
    request('POST','/users/'+uid+'/role-mappings/clients/'+mid,roles,204)
    request('POST','/clients/'+cid+'/scope-mappings/clients/'+mid,roles,204)
    # Readiness only: no real participant is created and no email is sent here.
    status, _ = api.request(a.runtime,'dompet-identitas','POST',
        '/realms/competency-proof-p2/protocol/openid-connect/token',
        {'grant_type':'client_credentials','client_id':CLIENT,'client_secret':remote_secret},form=True)
    if status != 200:
        raise RuntimeError('Dedicated invitation client token check failed')
    if a.runtime.stat().st_mode & 0o077:
        raise ValueError('Private runtime parent must be mode 0700')
    # Compose bind secrets retain host modes. Permit the unprivileged BFF to
    # read this one file inside the private 0700 parent, matching other secrets.
    keyfile.chmod(0o444)
    doc = p7.load(a.runtime/'deployment.json')
    service = doc['services']['custodian']
    service['environment'].update(WALLET_INVITATION_DB_PATH='/data/participant-invitations.sqlite',
        WALLET_INVITATION_CLIENT_SECRET_FILE='/run/secrets/wallet-invitations-secret')
    if 'wallet-invitations-secret' not in service['secrets']:
        service['secrets'].append('wallet-invitations-secret')
    doc['secrets']['wallet-invitations-secret']={'file':str(keyfile.resolve())}
    p7.save(a.runtime/'deployment.json',doc)
    ingress = a.runtime/'ingress.caddy'
    source = ingress.read_text()
    if '/api/v1/participant-invitations' not in source:
        if source.count('/api/v1/service-status') != 1:
            raise ValueError('Unexpected ingress template; no broad route added')
        source=source.replace('/api/v1/service-status','/api/v1/service-status /api/v1/participant-invitations')
        ingress.write_text(source)
    p7.compose(a,'config','--quiet')
    settings=p7.load(a.runtime/'operations.json')
    settings['derivedComposeSha256']=api.checksum(a.runtime/'deployment.json')
    settings['invitationClient']=CLIENT
    p7.save(a.runtime/'operations.json',settings)
    print('PASS: dedicated wallet invitation client prepared; services unchanged; no invitation sent')


def main():
    os.umask(0o077)
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--runtime',type=Path,required=True)
    parser.add_argument('--package',type=Path,required=True)
    parser.add_argument('--apply',action='store_true',help='Apply private client and derived configuration changes')
    a=parser.parse_args()
    if not a.apply:
        print('PLAN: create wallet-only client, mount its private secret, enable exact admin API path; no restart or email')
        return
    configure(a)


if __name__ == '__main__':
    main()
