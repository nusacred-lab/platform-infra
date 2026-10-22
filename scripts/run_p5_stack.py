"""Activate the synthetic P5 UI on the existing prerelease stack, preserving identity and wallet volumes.

Build/scan the application images and take a consistent private backup before using this command.
This retains wallet identities, keys and protocol configuration. Independent staff
identity stores must already be prepared with scoped imports and distinct secrets.
"""
import argparse
from pathlib import Path
import subprocess
import http.client
import socket
import ssl
import json
import time

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--env-file', required=True, type=Path)
parser.add_argument('--storage-overlay', type=Path, help='Preserve the active walkthrough business volumes')
a = parser.parse_args()
env = a.env_file.resolve()
assert 'runtime' in env.parts and env.is_file(), 'Use a private prepared runtime environment'
root = Path(__file__).resolve().parents[1]
command = ['docker', 'compose', '--env-file', str(env)]
for file in ('p2/compose.yaml', 'p2/application.compose.yaml', 'p2/prerelease.compose.yaml',
             'p2/recovery.compose.yaml', 'p2/portals.compose.yaml', 'p2/walt.compose.yaml',
             'p3/backends.compose.yaml', 'p4/backends.compose.yaml', 'p5/experience.compose.yaml','p5/independent-identity.compose.yaml'):
    command += ['-f', str(root/file)]
if a.storage_overlay:
    overlay = a.storage_overlay.resolve()
    assert 'runtime' in overlay.parts and overlay.is_file()
    command += ['-f', str(overlay)]
subprocess.run(command+['config', '--quiet'], check=True)
subprocess.run(command+['up', '-d', '--no-build', 'keycloak', 'issuer-keycloak',
                       'company-keycloak', 'mail', 'access', 'p2-ingress'], check=True)
# BFF discovery must not race cold identity database/import startup.
for hostname, realm in [('login-dompet-identitas.demo.inoerawan.id', 'competency-proof-p2'),
                        ('login-lsp-nusantara.demo.inoerawan.id', 'lsp-nusantara'),
                        ('login-karya-instalasi.demo.inoerawan.id', 'karya-instalasi')]:
    for attempt in range(60):
        connection = http.client.HTTPSConnection(hostname, timeout=3)
        def connect():
            connection.sock = ssl.create_default_context().wrap_socket(
                socket.create_connection(('127.0.0.1', 8443), timeout=3), server_hostname=hostname)
        connection.connect = connect
        try:
            connection.request('GET', f'/realms/{realm}/.well-known/openid-configuration')
            response = connection.getresponse()
            payload = response.read(16384)
            if response.status == 200 and json.loads(payload).get('issuer') == f'https://{hostname}/realms/{realm}':
                break
        except (OSError, ValueError, http.client.HTTPException):
            pass
        finally:
            connection.close()
        time.sleep(1)
    else:
        raise SystemExit('Identity discovery not ready: ' + hostname)
subprocess.run(command+['up', '-d', '--no-build'], check=True)
for service, hostname in [('custodian', 'dompet-identitas.demo.inoerawan.id'), ('issuer', 'lsp-nusantara.demo.inoerawan.id'), ('company', 'karya-instalasi.demo.inoerawan.id')]:
    ready = False
    for attempt in range(30):
        connection = http.client.HTTPSConnection(hostname, timeout=3)
        def connect():
            connection.sock = ssl.create_default_context().wrap_socket(
                socket.create_connection(('127.0.0.1', 8443), timeout=3), server_hostname=hostname)
        connection.connect = connect
        try:
            connection.request('GET', '/api/v1/portal-config')
            response = connection.getresponse()
            ready = response.status == 200 and json.loads(response.read(4096)).get('service') == service
            if ready:
                break
        except (OSError, ValueError, http.client.HTTPException):
            pass
        finally:
            connection.close()
        time.sleep(1)
    if not ready:
        raise SystemExit('P5 '+service+' readiness failed; inspect private process/configuration permissions and edge routes')
print('P5 synthetic preview ready over verified local TLS. Verify public browser and signed APK journeys.')
