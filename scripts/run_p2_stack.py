"""Start the private P2 stack in a consistent composition and wait for real listener readiness."""
import argparse
import http.client
from pathlib import Path
import subprocess
import time
from check_p2_identity import request, REALM

p = argparse.ArgumentParser(__doc__)
p.add_argument('--runtime', type=Path, required=True)
p.add_argument('--mode', choices=('normal', 'lost-completion'), default='normal')
p.add_argument('--public-credential-testing', action='store_true', help='Apply only after explicit approval beyond login-only ingress')
a = p.parse_args(); runtime = a.runtime.resolve(); assert 'runtime' in runtime.parts
root = Path(__file__).resolve().parents[1]
cmd = ['docker', 'compose', '--env-file', str(runtime / 'compose.env')]
for file in ('compose.yaml', 'application.compose.yaml', 'prerelease.compose.yaml', 'recovery.compose.yaml',
             'portals.compose.yaml', 'walt.compose.yaml'):
    cmd += ['-f', str(root / 'p2' / file)]
if a.public_credential_testing: cmd += ['-f', str(root / 'p2/credential-testing.compose.yaml')]
if a.mode == 'lost-completion': cmd += ['-f', str(root / 'p2/recovery-fault.compose.yaml')]
subprocess.run(cmd + ['config', '--quiet'], check=True)
subprocess.run(cmd + ['up', '-d', '--no-build'], check=True)
if a.mode == 'normal':
    # This disposable proxy owns no state. Do not leave the injected failure running.
    ids = subprocess.check_output(['docker', 'ps', '-aq', '--filter', 'name=^/competency-proof-p2-recovery-fault-1$'], text=True).split()
    for container in ids:
        subprocess.run(['docker', 'rm', '-f', container], check=True, stdout=subprocess.DEVNULL)
for _ in range(90):
    try:
        assert request('GET', f'/realms/{REALM}/.well-known/openid-configuration')[0] == 200
        for port, path in ((18080, '/health/live'), (17005, '/'), (17006, '/wallet'), (17004, '/')):
            c = http.client.HTTPConnection('127.0.0.1', port, timeout=3)
            try:
                c.request('GET', path); response = c.getresponse(); assert response.status < 400; response.read()
            finally: c.close()
        break
    except (OSError, ValueError, AssertionError, http.client.HTTPException): time.sleep(1)
else: raise SystemExit('FAIL: private P2 readiness timeout')
print('PASS: private P2 listeners ready; mode=' + a.mode)
