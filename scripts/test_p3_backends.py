"""Exercise P3 JVM BFFs with real Keycloak, isolated databases and loopback listeners.

No active container, ingress route, realm setting, password or wallet is changed.
Fixture credentials and tokens stay in the private runtime and process memory.
"""
import argparse
from contextlib import contextmanager
from http.cookies import SimpleCookie
import http.client
import json
import os
import secrets
from pathlib import Path
import subprocess
import time
from urllib.parse import urlsplit
from test_p2_login import Browser, login


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--runtime', type=Path, required=True)
    parser.add_argument('--application', type=Path, required=True)
    parser.add_argument('--java-home', type=Path, required=True)
    args = parser.parse_args()
    runtime = args.runtime.resolve()
    assert 'runtime' in runtime.parts
    work = runtime.parent / 'p3-bff-proof'
    work.mkdir(mode=0o700, exist_ok=True)
    reference_key = work / 'offer-reference-key'
    if not reference_key.exists():
        reference_key.write_bytes(secrets.token_bytes(32))
        reference_key.chmod(0o600)
    fixtures = json.loads((runtime / 'login-fixtures.json').read_text())
    hosts = work / 'hosts'
    hosts.write_text('127.0.0.1 localhost auth-p2.demo.inoerawan.id\n')
    checks = []

    class LocalBrowser(Browser):
        def __init__(self, host, port):
            super().__init__()
            self.host, self.port = host, port

        def request(self, url, method='GET', body=None, headers=None, form=False):
            uri = urlsplit(url)
            if uri.hostname != self.host:
                return super().request(url, method, body, headers, form)
            outgoing = dict(headers or {})
            outgoing['Host'] = self.host
            cookies = self.cookies.setdefault(self.host, {})
            if cookies:
                outgoing['Cookie'] = '; '.join(k+'='+v for k, v in cookies.items())
            data = None
            if body is not None:
                data = json.dumps(body)
                outgoing['Content-Type'] = 'application/json'
            connection = http.client.HTTPConnection('127.0.0.1', self.port, timeout=15)
            try:
                connection.request(method, uri.path + ('?'+uri.query if uri.query else ''), data, outgoing)
                response = connection.getresponse()
                self.last_headers = response.getheaders()
                for key, value in self.last_headers:
                    if key.lower() == 'set-cookie':
                        for name, item in SimpleCookie(value.split(';', 1)[0]).items():
                            cookies[name] = item.value
                return response.status, dict(self.last_headers), response.read().decode()
            finally:
                connection.close()

    @contextmanager
    def backend(service, assigned, port):
        role = service+'-admin'
        origin = 'https://' + ('issuer-p2' if service == 'issuer' else 'verifier-p2') + '.demo.inoerawan.id'
        assignments = work / (service+'-organizations.json')
        assignments.write_text(json.dumps({fixtures[role]['id']: 'synthetic-org-a'} if assigned else {}))
        assignments.chmod(0o600)
        db = work / (service+('-assigned' if assigned else '-unassigned')+'.sqlite')
        # A new proof starts with disposable application state, never a wallet database.
        for suffix in ('', '-wal', '-shm'):
            Path(str(db)+suffix).unlink(missing_ok=True)
        env = dict(os.environ, HTTP_HOST='127.0.0.1', HTTP_PORT=str(port),
                   APPLICATION_DB_PATH=str(db), OFFER_REFERENCE_KEY_FILE=str(reference_key),
                   OIDC_ISSUER='https://auth-p2.demo.inoerawan.id/realms/competency-proof-p2',
                   OIDC_BACKCHANNEL_ORIGIN='https://auth-p2.demo.inoerawan.id:18443',
                   OIDC_PORTAL_ORIGIN=origin, OIDC_CLIENT_ID=service+'-bff-p2',
                   OIDC_CLIENT_SECRET_FILE=str(runtime/(service+'-client-secret')),
                   OIDC_ORGANIZATION_ASSIGNMENTS_FILE=str(assignments))
        library = args.application.resolve()/(service+'-backend')/'build/install'/(service+'-backend')/'lib/*'
        with (work/(service+'-process.log')).open('w') as log:
            process = subprocess.Popen([str(args.java_home.resolve()/'bin/java'),
                '-Djdk.net.hosts.file='+str(hosts), '-cp', str(library), 'id.nusacred.'+service+'.MainKt'],
                env=env, stdout=log, stderr=log)
            try:
                for _ in range(50):
                    if process.poll() is not None:
                        raise RuntimeError('Temporary BFF failed; inspect the private process log')
                    try:
                        connection = http.client.HTTPConnection('127.0.0.1', port, timeout=1)
                        connection.request('GET', '/not-a-route')
                        connection.getresponse().read()
                        connection.close()
                        break
                    except OSError:
                        time.sleep(0.2)
                else:
                    raise RuntimeError('Temporary BFF readiness timeout')
                yield origin, LocalBrowser(urlsplit(origin).hostname, port)
            finally:
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()

    def sign_in(browser, origin, role, expected=302):
        status, headers, _ = browser.request(origin+'/auth/start')
        assert status == 302
        callback = login(browser, headers['Location'], fixtures[role])
        assert browser.request(callback)[0] == expected
        if expected == 302:
            status, _, data = browser.request(origin+'/auth/me')
            assert status == 200
            return json.loads(data)['csrf']

    for service, port in (('issuer', 18881), ('company', 18882)):
        with backend(service, True, port) as (origin, browser):
            role = service+'-admin'
            csrf = sign_in(browser, origin, role)
            headers = {'Origin': origin, 'X-CSRF-Token': csrf, 'Idempotency-Key': 'p3-proof-key-00000000001'}
            if service == 'issuer':
                path = '/api/v1/assessments'
                body = {'candidateAccountId': 'synthetic-p3-recipient', 'candidateId': 'synthetic-p3-001',
                        'competencyCode': 'DEMO-ELEC-001', 'assessmentResult': 'competent'}
                method, expected = 'POST', 201
            else:
                path = '/api/v1/jobs/p3-electrician'
                body = {'title': 'Synthetic electrician', 'competencyCode': 'DEMO-ELEC-001', 'assessmentResult': 'competent'}
                method, expected = 'PUT', 200
            status, response_headers, payload = browser.request(origin+path, method, body, headers)
            assert status == expected and response_headers['Cache-Control'] == 'no-store'
            assert browser.request(origin+path, method, body, headers)[0] == expected
            changed = dict(body, competencyCode='DIFFERENT')
            assert browser.request(origin+path, method, changed, headers)[0] == 409
            assert browser.request(origin+path, method, body, dict(headers, Origin='https://foreign.example'))[0] == 403
            assert browser.request(origin+path, method, body, {'Origin': origin})[0] == 403
            other = LocalBrowser(browser.host, port)
            sign_in(other, origin, 'applicant', 401)
            checks.append(service+': real admin login, organization-scoped mutation, retry/conflict, origin/CSRF and applicant-role denial')
            if service == 'company':
                viewer = LocalBrowser(browser.host, port)
                status, _, payload = viewer.request(origin+'/api/v1/browser-session')
                assert status == 200
                viewer_headers = {'Origin': origin, 'X-CSRF-Token': json.loads(payload)['csrf'],
                                  'Idempotency-Key': 'p3-proof-key-00000000002'}
                status, _, payload = viewer.request(origin+'/api/v1/jobs/p3-electrician/verification-sessions', 'POST', {}, viewer_headers)
                assert status == 202
                result_path = '/api/v1/verification-sessions/'+json.loads(payload)['id']
                assert viewer.request(origin+result_path)[0] == 200
                assert browser.request(origin+result_path)[0] == 200
                assert LocalBrowser(browser.host, port).request(origin+result_path)[0] == 401
                checks.append('company: public viewer ownership and authorized company admin result read')
        with backend(service, False, port) as (origin, browser):
            csrf = sign_in(browser, origin, service+'-admin')
            headers = {'Origin': origin, 'X-CSRF-Token': csrf, 'Idempotency-Key': 'p3-proof-key-00000000003'}
            assert browser.request(origin+path, method, body, headers)[0] == 403
            checks.append(service+': real admin role without a server-side organization assignment denied')
    result = {'schemaVersion': 1, 'checks': checks,
              'limits': ['Real Keycloak TLS, loopback HTTP as the private BFF transport; no public P3 ingress',
                         'Issuer mutation records a synthetic recipient reference; P4 recipient/protocol validation is not claimed',
                         'No active credential, key, password, realm or container is changed']}
    (work/'result.json').write_text(json.dumps(result, indent=2)+'\n')
    for check in checks:
        print('PASS:', check)


if __name__ == '__main__':
    main()
