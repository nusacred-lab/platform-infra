"""Check public asset compression/cache boundaries without sending user credentials."""
import argparse
from datetime import datetime, timezone
import gzip
import hashlib
import http.client
import json
from pathlib import Path
import re
import socket
import ssl
import time

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--output', type=Path, required=True)
parser.add_argument('--public', action='store_true')
args = parser.parse_args()
checks = []
sizes = []
def check(name, condition):
    assert condition, name
    checks.append(name)
def request(host, path, encoding=None):
    c = http.client.HTTPSConnection(host, timeout=30)
    if not args.public:
        def connect():
            c.sock = ssl.create_default_context().wrap_socket(socket.create_connection(('127.0.0.1', 8443), timeout=15), server_hostname=host)
        c.connect = connect
    start = time.monotonic()
    c.request('GET', path, headers={'Accept-Encoding': encoding or 'identity'})
    r = c.getresponse()
    body = r.read()
    result = (r.status, r.getheaders(), body, time.monotonic() - start)
    c.close()
    return result
for host in ['lsp-nusantara.demo.inoerawan.id', 'dompet-identitas.demo.inoerawan.id', 'karya-instalasi.demo.inoerawan.id']:
    status, raw_headers, html, _ = request(host, '/')
    headers = dict(raw_headers)
    check(host + ': initial HTML includes visible loading shell', status == 200 and b'id="portal-boot"' in html and b'Opening your workspace.' in html)
    check(host + ': HTML is not cached', headers.get('Cache-Control') == 'no-store')
    scripts = re.findall(rb'src="([a-z-]+-[a-f0-9]{20}\.js)"', html)
    check(host + ': both scripts are content addressed', len(scripts) == 2)
    wasm = set()
    for script in scripts:
        name = script.decode()
        status, raw_headers, encoded, elapsed = request(host, '/' + name, 'gzip')
        headers = dict(raw_headers)
        check(host + ': script gzip ' + name, status == 200 and headers.get('Content-Encoding') == 'gzip')
        body = gzip.decompress(encoded)
        check(host + ': script digest ' + name, hashlib.sha256(body).hexdigest()[:20] == name.rsplit('-', 1)[1][:-3])
        check(host + ': one public script cache header ' + name, [v for k,v in raw_headers if k.lower() == 'cache-control'] == ['public, max-age=31536000, immutable'])
        check(host + ': compression varies correctly ' + name, 'accept-encoding' in headers.get('Vary', '').lower() and 'Set-Cookie' not in headers)
        wasm.update(re.findall(rb'[a-f0-9]{20}\.wasm', body))
    check(host + ': WebAssembly dependencies identified', len(wasm) == 2)
    for asset in sorted(wasm):
        name = asset.decode()
        status, raw_headers, encoded, elapsed = request(host, '/' + name, 'gzip')
        headers = dict(raw_headers)
        check(host + ': wasm gzip ' + name, status == 200 and headers.get('Content-Encoding') == 'gzip')
        body = gzip.decompress(encoded)
        check(host + ': decoded WebAssembly ' + name, body.startswith(b'\x00asm'))
        check(host + ': public immutable wasm ' + name, [v for k,v in raw_headers if k.lower() == 'cache-control'] == ['public, max-age=31536000, immutable'])
        sizes.append({'host':host,'asset':name,'uncompressedBytes':len(body),'gzipBytes':len(encoded),'elapsedSeconds':round(elapsed,3)})
    for path in ['/api/v1/portal-session', '/auth/start', '/api/v1/wallet/credentials', '/ffffffffffffffffffff.wasm', '/web-portals.js', '/api/v1/portal-session?asset=web-portals-ffffffffffffffffffff.js']:
        status, headers, body, _ = request(host, path)
        check(host + ': private/error/unversioned response not cached ' + path, dict(headers).get('Cache-Control') == 'no-store')
args.output.write_text(json.dumps({'checkedAt':datetime.now(timezone.utc).isoformat(),'result':'PASS','transport':'public HTTPS without credentials' if args.public else 'verified loopback TLS without credentials','checks':checks,'assets':sizes},indent=2)+'\n')
print('PASS:',len(checks),'startup delivery, compression, content addressing and cache privacy checks')
print(json.dumps(sizes,indent=2))
