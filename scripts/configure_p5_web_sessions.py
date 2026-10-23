"""Apply the approved one-hour browser policy to the three independent BFF clients.

Admin traffic uses verified loopback TLS. Change only three client attributes;
realm/native policy, credentials, roles, keys and recovery configuration are retained.
"""
import argparse
import http.client
import json
import os
from pathlib import Path
import socket
import ssl
from urllib.parse import urlencode

POLICY = {'access.token.lifespan': '3600', 'client.session.idle.timeout': '3600',
          'client.session.max.lifespan': '3600'}
ENTITIES = [('wallet', 'dompet-identitas', 'competency-proof-p2', 'custodian-bff-p2'),
            ('issuer', 'lsp-nusantara', 'lsp-nusantara', 'issuer-bff-p2'),
            ('company', 'karya-instalasi', 'karya-instalasi', 'company-bff-p2')]


def request(host, method, path, body=None, token=None, form=False):
    assert host in {'login-'+entry[1]+'.demo.inoerawan.id' for entry in ENTITIES}
    connection = http.client.HTTPSConnection(host, timeout=15)
    def connect():
        connection.sock = ssl.create_default_context().wrap_socket(
            socket.create_connection(('127.0.0.1', 18443), timeout=15), server_hostname=host)
    connection.connect = connect
    headers = {} if token is None else {'Authorization': 'Bearer '+token}
    if body is not None:
        headers['Content-Type'] = 'application/x-www-form-urlencoded' if form else 'application/json'
    try:
        connection.request(method, path, None if body is None else urlencode(body) if form else json.dumps(body), headers)
        response = connection.getresponse()
        raw = response.read(2_097_153)
        assert len(raw) <= 2_097_152
        return response.status, json.loads(raw) if raw else None
    finally:
        connection.close()


def administrator(entity, domain, realm, env, identity_runtime):
    host = 'login-'+domain+'.demo.inoerawan.id'
    user = 'p2-bootstrap' if entity == 'wallet' else entity+'-bootstrap'
    password = json.loads((identity_runtime/'credentials.json').read_text())['bootstrap'] if entity == 'wallet' else env['P5_'+entity.upper()+'_BOOTSTRAP_PASSWORD']
    status, auth = request(host, 'POST', '/realms/master/protocol/openid-connect/token',
                           {'grant_type': 'password', 'client_id': 'admin-cli', 'username': user, 'password': password}, form=True)
    assert status == 200, entity+' administrator authentication failed'
    def call(method, path, body=None):
        return request(host, method, '/admin/realms/'+realm+path, body, auth['access_token'])
    return call


def context(env_file):
    return dict(line.split('=', 1) for line in env_file.read_text().splitlines() if '=' in line and not line.startswith('#'))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--env-file', type=Path, required=True)
    parser.add_argument('--identity-runtime', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    assert all('runtime' in p.resolve().parts for p in [args.env_file, args.identity_runtime, args.output])
    os.umask(0o077)
    env = context(args.env_file)
    report = {}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    for entity, domain, realm, client_id in ENTITIES:
        call = administrator(entity, domain, realm, env, args.identity_runtime)
        status, before_realm = call('GET', '')
        assert status == 200
        status, clients = call('GET', '/clients')
        assert status == 200
        client = next(c for c in clients if c['clientId'] == client_id)
        assert not client.get('directAccessGrantsEnabled') and not client.get('serviceAccountsEnabled')
        original = json.loads(json.dumps(client))
        attrs = client.setdefault('attributes', {})
        before = {key: attrs.get(key) for key in POLICY}
        report[entity] = {'client': client_id, 'before': before, 'planned': POLICY, 'state': 'PENDING'}
        args.output.write_text(json.dumps(report, indent=2)+'\n')
        attrs.update(POLICY)
        assert call('PUT', '/clients/'+client['id'], client)[0] == 204
        status, actual = call('GET', '/clients/'+client['id'])
        assert status == 200 and all(actual['attributes'].get(k) == v for k, v in POLICY.items())
        expected = json.loads(json.dumps(original))
        expected.setdefault('attributes', {}).update(POLICY)
        assert actual == expected, 'Unexpected client configuration change'
        status, after_realm = call('GET', '')
        assert status == 200 and before_realm == after_realm, 'Realm policy changed unexpectedly'
        if entity == 'wallet':
            native_before = next(c for c in clients if c['clientId'] == 'android-wallet-p2')
            status, native_after = call('GET', '/clients/'+native_before['id'])
            assert status == 200 and native_after == native_before, 'Native policy changed unexpectedly'
            assert native_after['attributes']['access.token.lifespan'] == '300'
            assert native_after['attributes']['client.session.idle.timeout'] == '86400'
            assert native_after['attributes']['client.session.max.lifespan'] == '604800'
        report[entity] = {'client': client_id, 'before': before, 'after': POLICY,
                          'realmAndOtherClientPropertiesUnchanged': True}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2)+'\n')
    print('PASS: three browser clients use one-hour tokens/idle/max; native and realm policies unchanged')


if __name__ == '__main__':
    main()
