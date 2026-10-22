"""Verify an existing synthetic credential after isolated issuer restart/profile reload, without rotating keys."""
import argparse
import hashlib
import json
from pathlib import Path
import sqlite3
import subprocess
import time
import urllib.request


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--runtime', type=Path, required=True)
    parser.add_argument('--registry', type=Path, required=True)
    parser.add_argument('--issuer-config', type=Path, required=True)
    args = parser.parse_args()
    runtime = args.runtime.resolve()
    assert all('runtime' in p.resolve().parts for p in (runtime, args.registry, args.issuer_config))
    runtime.mkdir(parents=True, exist_ok=True)
    def call(port, path, body=None):
        req = urllib.request.Request(f'http://127.0.0.1:{port}'+path, data=None if body is None else json.dumps(body).encode(), headers={'Content-Type': 'application/json'})
        with urllib.request.urlopen(req, timeout=30) as response:
            return json.load(response)
    with sqlite3.connect('file:'+str(args.registry.resolve())+'?mode=ro', uri=True) as db:
        wallet, key = db.execute("SELECT wallet_id,key_id FROM wallet_bindings WHERE state='READY'").fetchone()
    entries = call(27006, f'/wallet/{wallet}/credentials')
    cid = entries[0]['id']
    def credential_hash():
        raw = call(27006, f'/wallet/{wallet}/credentials/{cid}')['credential']['signedWithDisclosures']
        return hashlib.sha256(raw.encode()).hexdigest()
    before = credential_hash()
    profiles = json.loads(args.issuer_config.read_text())
    profile = profiles['profiles']['competencyDemo']
    identity = profile['issuerDid']
    private_hash = hashlib.sha256(json.dumps(profile['issuerKey'], sort_keys=True).encode()).hexdigest()
    profile['name'] = 'Competency Proof (profile reload verified)'
    args.issuer_config.write_text(json.dumps(profiles, indent=2)+'\n')
    subprocess.run(['docker', 'restart', 'competency-proof-p4-issuer-1'], check=True, stdout=subprocess.DEVNULL)
    for _ in range(60):
        try:
            loaded = call(27005, '/issuer2/profiles/competencyDemo')
            assert loaded['name'] == profile['name']
            break
        except Exception:
            time.sleep(0.5)
    else:
        raise RuntimeError('Isolated issuer did not reload its supported profile')
    current = json.loads(args.issuer_config.read_text())['profiles']['competencyDemo']
    assert current['issuerDid'] == identity
    assert hashlib.sha256(json.dumps(current['issuerKey'], sort_keys=True).encode()).hexdigest() == private_hash
    assert credential_hash() == before
    created = call(27004, '/verification-session/create', {'flow_type': 'cross_device', 'core_flow': {
        'dcql_query': {'credentials': [{'id': 'competency', 'format': 'dc+sd-jwt', 'multiple': True,
            'meta': {'vct_values': ['http://issuer:7005/openid4vci/competency_demo']}, 'require_cryptographic_holder_binding': True,
            'claims': [{'path': [x]} for x in ['id', 'candidate_id', 'competency_code', 'assessment_result', 'iss', 'cnf', 'iat', 'nbf', 'exp']]}]},
        'policies': {'vc_policies': [{'policy': 'signature'}, {'policy': 'expiration', 'requireField': True}, {'policy': 'not-before'}]}}})
    url = created['bootstrapAuthorizationRequestUrl']
    preview = call(27006, f'/wallet/{wallet}/credentials/present/preview', {'requestUrl': url})
    assert preview['keyId'] == key
    vp = call(27006, f'/wallet/{wallet}/credentials/present/build-vp-token', {'requestUrl': url, 'keyId': key,
        'selectedCredentialOptions': [{'queryId': 'competency', 'credentialId': cid}]})
    sent = call(27006, f'/wallet/{wallet}/credentials/present/send-response', {'requestUrl': url, 'vpToken': vp['vpToken']})
    assert sent['transmission_success'] is True
    info = call(27004, '/verification-session/'+created['sessionId']+'/info')
    assert info['status'] == 'SUCCESSFUL'
    assert credential_hash() == before
    result = {'passed': True, 'profileReload': True, 'issuerIdentityUnchanged': True, 'issuerKeyUnchanged': True,
              'credentialBytesUnchanged': True, 'oldCredentialVerification': 'SUCCESSFUL'}
    (runtime/'result.json').write_text(json.dumps(result, indent=2)+'\n')
    print('PASS: profile reload, stable identity/key, unchanged old credential and actual verification after issuer restart')

if __name__ == '__main__':
    main()
