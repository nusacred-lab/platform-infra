"""Prove the source-built wallet retains the original credential and holder key after container restart."""
import argparse
import hashlib
import http.client
import json
from pathlib import Path
import subprocess
import time
from test_p2_recovery import tokens, wallet

p = argparse.ArgumentParser(__doc__)
p.add_argument('--runtime', type=Path, required=True)
a = p.parse_args(); r = a.runtime.resolve(); user = json.loads((r / 'recovery-fixture.json').read_text())
_, _, session = tokens(user)
status, _, binding = wallet(session, 'provision', {}); assert status == 200
wallet_id = binding['wallet_id']
def upstream(path):
    c = http.client.HTTPConnection('127.0.0.1', 17006, timeout=10)
    try:
        c.request('GET', '/wallet/' + wallet_id + path); response = c.getresponse()
        assert response.status == 200
        return json.loads(response.read())
    finally: c.close()
before = {'keys': upstream('/keys'), 'credentials': upstream('/credentials')}
assert before['credentials'] and len(before['keys']) == 1
subprocess.run(['docker', 'restart', 'competency-proof-p2-wallet-1'], check=True, stdout=subprocess.DEVNULL)
for _ in range(45):
    try:
        after = {'keys': upstream('/keys'), 'credentials': upstream('/credentials')}
        break
    except (OSError, ValueError, AssertionError, http.client.HTTPException): time.sleep(1)
else: raise AssertionError('Wallet did not restart')
assert after == before
assert wallet(session, 'credentials')[0] == 200
report = {'schemaVersion': 1, 'checks': ['Actual source-built Wallet2 container restart',
    'Identical holder key metadata and stored credential', 'Authorized custodian read still succeeds'],
    'stateFingerprint': hashlib.sha256(json.dumps(before, sort_keys=True).encode()).hexdigest()}
(r / 'wallet-restart-result.json').write_text(json.dumps(report, indent=2) + '\n')
print('PASS: source-built wallet restart preserves original key and credential and authorized access')
