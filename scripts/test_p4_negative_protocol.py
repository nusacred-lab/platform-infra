"""Issue signed synthetic negative fixtures and submit controlled SD-JWT presentations to private fork services.

This runner owns a disposable test holder key. Application holder keys remain server-side.
Raw credentials, private fixture keys and protocol responses stay in the ignored runtime.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import time
import urllib.request
import urllib.error
import urllib.parse
import uuid
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives import hashes


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--runtime', type=Path, required=True)
    parser.add_argument('--port-base', type=int, default=27000)
    args = parser.parse_args()
    runtime = args.runtime.resolve()
    assert 'runtime' in runtime.parts
    os.umask(0o077)
    runtime.mkdir(parents=True, exist_ok=True)
    def enc(value):
        return base64.urlsafe_b64encode(value).rstrip(b'=').decode()
    def call(service, path, body=None, headers=None, form=False):
        port = args.port_base + {'issuer': 5, 'wallet': 6, 'verifier': 4}[service]
        data = None if body is None else (urllib.parse.urlencode(body) if form else json.dumps(body)).encode()
        request = urllib.request.Request(f'http://127.0.0.1:{port}'+path, data=data,
                    headers=dict({'Content-Type': 'application/x-www-form-urlencoded' if form else 'application/json'}, **(headers or {})))
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                data = response.read()
                return response.status, json.loads(data) if data else None
        except urllib.error.HTTPError as e:
            # Bodies can contain credential material; never include them in an exception or stdout.
            (runtime/'last-error.txt').write_bytes(e.read())
            return e.code, None
    key = ec.generate_private_key(ec.SECP256R1())
    pub = key.public_key().public_numbers()
    jwk = dict(kty='EC', crv='P-256', x=enc(pub.x.to_bytes(32, 'big')), y=enc(pub.y.to_bytes(32, 'big')))
    def jwt(payload, typ, with_key=False, signing_key=None):
        header = dict(alg='ES256', typ=typ)
        if with_key:
            header['jwk'] = jwk
        message = enc(json.dumps(header, separators=(',', ':')).encode())+'.'+enc(json.dumps(payload, separators=(',', ':')).encode())
        r, s = decode_dss_signature((signing_key or key).sign(message.encode(), ec.ECDSA(hashes.SHA256())))
        return message+'.'+enc(r.to_bytes(32, 'big')+s.to_bytes(32, 'big'))
    def issue(overrides, wrong_type=False):
        status, offer = call('issuer', '/issuer2/credential-offers', {'profileId': 'competencyWrongTypeFixture' if wrong_type else 'competencyNegativeFixture', 'authMethod': 'PRE_AUTHORIZED', 'runtimeOverrides': overrides})
        assert status in (200, 201), 'Fixture offer failed: HTTP '+str(status)
        status, wallet = call('wallet', '/wallet', {})
        wid = wallet['walletId']
        path = '/wallet/'+wid+'/credentials/receive/'
        status, resolved = call('wallet', path+'resolve-offer', {'offerUrl': offer['credentialOffer']})
        assert status == 200, 'Fixture resolution failed'
        status, token = call('wallet', path+'request-token', {'tokenEndpoint': resolved['tokenEndpoint'],
                    'preAuthorizedCode': resolved['preAuthorizedCode'], 'credentialIssuer': resolved['credentialIssuer']})
        assert status == 200, 'Fixture token failed'
        status, nonce = call('issuer', '/openid4vci/nonce', {})
        proof = jwt({'aud': resolved['credentialIssuer'], 'iat': int(time.time()), 'nonce': nonce['c_nonce']}, 'openid4vci-proof+jwt', True)
        status, fetched = call('wallet', path+'fetch-credential', {'credentialEndpoint': resolved['credentialEndpoint'],
                   'accessToken': token['accessToken'], 'credentialConfigurationId': resolved['credentialConfigurationIds'][0], 'proofJwt': proof, 'storeInWallet': False})
        if status != 200:
            return None
        return fetched['rawCredentials'][0]
    def session():
        required = ['id', 'candidate_id', 'competency_code', 'assessment_result', 'iss', 'cnf', 'iat', 'nbf', 'exp']
        status, created = call('verifier', '/verification-session/create', {'flow_type': 'cross_device', 'core_flow': {
            'dcql_query': {'credentials': [{'id': 'competency', 'format': 'dc+sd-jwt', 'multiple': True,
                'meta': {'vct_values': ['http://issuer:7005/openid4vci/competency_demo']}, 'require_cryptographic_holder_binding': True,
                'claims': [{'path': [claim]} for claim in required]}]},
            'policies': {'vc_policies': [{'policy': 'signature'}, {'policy': 'expiration', 'requireField': True}, {'policy': 'not-before'}]}}})
        assert status in (200, 201), 'Fixture verifier creation failed'
        status, info = call('verifier', '/verification-session/'+created['sessionId']+'/info')
        return created['sessionId'], info['authorizationRequest']
    checks = []
    cases = [('valid', None, None)]
    for field in ('id', 'candidate_id', 'competency_code', 'assessment_result', 'iat', 'nbf', 'exp'):
        cases += [(field+'_missing', field, None), (field+'_wrong_type', field, 'invalid' if field in ('iat', 'nbf', 'exp') else 123)]
    cases += [('expired', 'exp', 1), ('future_nbf', 'nbf', int(time.time())+3600), ('fractional_exp', 'exp', time.time()+3600),
              ('assessment_not_competent', 'assessment_result', 'not_competent'), ('wrong_vct', 'vct', 'https://example.invalid/type')]
    baseline = dict(id='fixture-'+str(uuid.uuid4()), candidate_id='candidate-synthetic', competency_code='DEMO-ELEC-001', assessment_result='competent',
                    iat=int(time.time())-10, nbf=int(time.time())-10, exp=int(time.time())+3600)
    signed = None
    for name, field, value in cases:
        claims = dict(baseline)
        if field:
            if value is None:
                # The isolated fixture profile has no default claims or mappings.
                claims.pop(field, None)
            else:
                claims[field] = value
        raw = issue({'credentialData': claims, 'mapping': {}}, wrong_type=name == 'wrong_vct')
        if raw is None:
            checks.append({'id': name, 'status': 'ISSUER_REJECTED', 'responseHttp': 500})
            continue
        if name == 'valid':
            signed = raw
        sid, request = session()
        prefix = raw if raw.endswith('~') else raw+'~'
        kb = jwt({'aud': request['client_id'], 'nonce': request['nonce'], 'iat': int(time.time()), 'sd_hash': enc(hashlib.sha256(prefix.encode()).digest())}, 'kb+jwt')
        response_path = urllib.parse.urlsplit(request['response_uri']).path
        status, _ = call('verifier', response_path, {'vp_token': json.dumps({'competency': [prefix+kb]}), 'state': request['state']}, form=True)
        _, info = call('verifier', '/verification-session/'+sid+'/info')
        (runtime/(name+'.json')).write_text(json.dumps(info))
        checks.append({'id': name, 'status': info['status'], 'responseHttp': status})
    assert checks[0]['status'] == 'SUCCESSFUL', 'Controlled positive fixture must validate first'
    for mutation in ('nonce', 'audience', 'binding', 'hash', 'freshness', 'tamper'):
        sid, request = session()
        prefix = signed if signed.endswith('~') else signed+'~'
        payload = {'aud': request['client_id'], 'nonce': request['nonce'], 'iat': int(time.time()), 'sd_hash': enc(hashlib.sha256(prefix.encode()).digest())}
        if mutation == 'nonce': payload['nonce'] = 'wrong'
        if mutation == 'audience': payload['aud'] = 'https://wrong.invalid/'
        if mutation == 'freshness': payload['iat'] = 1
        if mutation == 'hash': payload['sd_hash'] = 'wrong'
        kb = jwt(payload, 'kb+jwt')
        if mutation == 'binding': kb = jwt(payload, 'kb+jwt', signing_key=ec.generate_private_key(ec.SECP256R1()))
        if mutation == 'tamper': prefix = prefix[:50]+('A' if prefix[50] != 'A' else 'B')+prefix[51:]
        status, _ = call('verifier', urllib.parse.urlsplit(request['response_uri']).path,
                         {'vp_token': json.dumps({'competency': [prefix+kb]}), 'state': request['state']}, form=True)
        _, info = call('verifier', '/verification-session/'+sid+'/info')
        assert info['status'] == 'FAILED', 'Controlled negative proof was not rejected: '+mutation
        (runtime/(mutation+'.json')).write_text(json.dumps(info))
        checks.append({'id': mutation, 'status': info['status'], 'responseHttp': status})
    (runtime/'index.json').write_text(json.dumps({'checks': checks}, indent=2)+'\n')
    print('PASS: '+str(len(checks))+' real credential/protocol cases recorded privately with explicit rejection layers')

if __name__ == '__main__':
    main()
