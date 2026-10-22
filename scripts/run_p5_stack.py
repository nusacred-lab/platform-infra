"""Activate the synthetic P5 UI on the existing prerelease stack, preserving identity and wallet volumes.

Build/scan the application images and take a consistent private backup before using this command.
This reuses P2 identities, signing keys and protocol configuration; it never prepares fresh keys.
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
a = parser.parse_args()
env = a.env_file.resolve()
assert 'runtime' in env.parts and env.is_file(), 'Use a private prepared runtime environment'
root = Path(__file__).resolve().parents[1]
command = ['docker', 'compose', '--env-file', str(env)]
for file in ('p2/compose.yaml', 'p2/application.compose.yaml', 'p2/prerelease.compose.yaml',
             'p2/recovery.compose.yaml', 'p2/portals.compose.yaml', 'p2/walt.compose.yaml',
             'p3/backends.compose.yaml', 'p4/backends.compose.yaml', 'p5/experience.compose.yaml'):
    command += ['-f', str(root/file)]
subprocess.run(command+['config', '--quiet'], check=True)
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
