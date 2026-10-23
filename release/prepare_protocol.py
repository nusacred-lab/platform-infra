"""Prepare private P4 issuer identity/profile and recipient-capability key; never rotate existing keys."""
import argparse
import base64
import json
import os
from pathlib import Path
import secrets
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--runtime', type=Path, required=True)
    parser.add_argument('--negative-fixtures', action='store_true', help='Add a private fixture-only profile with empty claims/mapping')
    args = parser.parse_args()
    runtime = args.runtime.resolve()
    if 'runtime' not in runtime.parts:
        parser.error('Use an ignored private runtime outside public repositories.')
    os.umask(0o077)
    runtime.mkdir(parents=True, exist_ok=True, mode=0o700)
    def encode(value):
        return base64.urlsafe_b64encode(value).rstrip(b'=').decode()
    def key():
        with tempfile.TemporaryDirectory(prefix='p6-ec-') as temporary:
            private = Path(temporary) / 'key.pem'
            subprocess.run(['openssl', 'ecparam', '-name', 'prime256v1', '-genkey', '-noout', '-out', str(private)], check=True)
            der = subprocess.check_output(['openssl', 'ec', '-in', str(private), '-outform', 'DER'], stderr=subprocess.DEVNULL)
            public = subprocess.check_output(['openssl', 'pkey', '-in', str(private), '-pubout', '-outform', 'DER'], stderr=subprocess.DEVNULL)[-65:]
            # OpenSSL SEC1 P-256: sequence, INTEGER version=1, OCTET STRING d.
            offset = 2 if der[1] < 128 else 2 + (der[1] & 127)
            if der[offset:offset+5] != bytes.fromhex('0201010420') or public[0] != 4:
                raise ValueError('Unexpected OpenSSL P-256 encoding')
            scalar = der[offset+5:offset+37]
            return dict(kty='EC', crv='P-256', x=encode(public[1:33]), y=encode(public[33:65]), d=encode(scalar))
    keys_path = runtime / 'issuer-keys.json'
    if not keys_path.exists():
        keys_path.write_text(json.dumps({'issuer': key(), 'token': key()}))
    keys = json.loads(keys_path.read_text())
    public = {k: v for k, v in keys['issuer'].items() if k != 'd'}
    did = 'did:jwk:' + encode(json.dumps(public, separators=(',', ':')).encode())
    reference_key = runtime / 'offer-reference-key'
    if not reference_key.exists():
        reference_key.write_bytes(secrets.token_bytes(32))
    assert len(reference_key.read_bytes()) == 32
    config = runtime / 'walt/issuer'
    config.mkdir(parents=True, exist_ok=True)
    def write(name, value):
        (config / name).write_text(json.dumps(value, indent=2) + '\n')
    write('web.conf', {'webHost': '0.0.0.0', 'webPort': 7005})
    write('_features.conf', {'enabledFeatures': [], 'disabledFeatures': []})
    write('issuer-service.conf', {'baseUrl': 'http://issuer:7005', 'enforcePushedAuthorizationRequests': False,
                                 'ciTokenKey': json.dumps({'type': 'jwk', 'jwk': keys['token']})})
    write('authentication-service.conf', {'name': 'unused-preauthorized-demo', 'authorizeUrl': 'http://issuer:7005/unused',
          'accessTokenUrl': 'http://issuer:7005/unused', 'clientId': 'unused', 'clientSecret': 'unused', 'defaultScopes': ['openid']})
    write('issuer2-profiles.conf', {'profiles': {'competencyDemo': {
        'name': 'Competency Proof (synthetic demo)', 'credentialConfigurationId': 'competency_demo',
        'issuerKey': {'type': 'jwk', 'jwk': keys['issuer']}, 'issuerDid': did,
        'credentialData': {'candidate_id': 'candidate-synthetic', 'competency_code': 'DEMO-ELEC-001', 'assessment_result': 'competent'},
        'mapping': {'id': '<uuid>', 'iat': '<timestamp-seconds>', 'nbf': '<timestamp-seconds>', 'exp': '<timestamp-in-seconds:365d>'}}}})
    claims = ['id', 'candidate_id', 'competency_code', 'assessment_result', 'iss', 'cnf', 'iat', 'nbf', 'exp']
    if args.negative_fixtures:
        profile_path = config / 'issuer2-profiles.conf'
        profiles = json.loads(profile_path.read_text())
        fixture = dict(profiles['profiles']['competencyDemo'], name='Private negative acceptance fixture', credentialData={}, mapping={})
        profiles['profiles']['competencyNegativeFixture'] = fixture
        profiles['profiles']['competencyWrongTypeFixture'] = dict(fixture, credentialConfigurationId='competency_wrong_type')
        profile_path.write_text(json.dumps(profiles, indent=2) + '\n')
    write('credential-issuer-metadata.conf', {'issuerDisplay': [{'name': 'LSP Teknik Ketenagalistrikan Nusantara (demo)', 'locale': 'en'}],
          'credentialConfigurations': {'competency_demo': {'format': 'dc+sd-jwt', 'scope': 'competency_demo', 'vct': 'vctBaseUrl',
          'credential_signing_alg_values_supported': ['ES256'], 'cryptographic_binding_methods_supported': ['jwk', 'did:jwk'],
          'proof_types_supported': {'jwt': {'proof_signing_alg_values_supported': ['ES256']}},
          'credential_metadata': {'display': [{'name': 'Competency Proof (synthetic demo)', 'locale': 'en'}],
                                  'claims': [{'path': [c], 'mandatory': True} for c in claims]}}}})
    if args.negative_fixtures:
        metadata_path = config / 'credential-issuer-metadata.conf'
        metadata = json.loads(metadata_path.read_text())
        metadata['credentialConfigurations']['competency_wrong_type'] = dict(metadata['credentialConfigurations']['competency_demo'], scope='competency_wrong_type', vct='https://example.invalid/wrong-type')
        metadata_path.write_text(json.dumps(metadata, indent=2) + '\n')
    for service, port in [('wallet', 7006), ('verifier', 7004)]:
        folder = runtime / 'walt' / service
        folder.mkdir(parents=True, exist_ok=True)
        (folder / 'web.conf').write_text(json.dumps({'webHost': '0.0.0.0', 'webPort': port}))
        (folder / '_features.conf').write_text(json.dumps({'enabledFeatures': ['wallet2-persistence'] if service == 'wallet' else [], 'disabledFeatures': []}))
    (runtime / 'walt/wallet/wallet-service.conf').write_text(json.dumps({'publicBaseUrl': 'http://wallet:7006'}))
    (runtime / 'walt/wallet/wallet2-persistence.conf').write_text(json.dumps({'jdbcUrl': 'jdbc:sqlite:/data/wallet2.db', 'driverClassName': 'org.sqlite.JDBC'}))
    (runtime / 'walt/verifier/verifier-service.conf').write_text(json.dumps({'clientMetadata': {'client_name': 'PT Karya Instalasi Nusantara (demo)'}, 'urlPrefix': 'http://verifier:7004/verification-session', 'urlHost': 'openid4vp://authorize'}))
    (runtime / 'data').mkdir(exist_ok=True)
    (runtime / 'public-issuer.json').write_text(json.dumps({'identity': did, 'publicJwk': public,
        'profileId': 'competencyDemo', 'configurationId': 'competency_demo',
        'vct': 'http://issuer:7005/openid4vci/competency_demo'}, indent=2) + '\n')
    print('PASS: private P4 issuer profile, persistent identity and offer-reference key prepared; no existing key rotated')

if __name__ == '__main__':
    main()
