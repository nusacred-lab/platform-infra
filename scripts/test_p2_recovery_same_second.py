"""Prove a real nonce-bound login in the recovery completion second on the local P2 stack."""
import argparse
import base64
from datetime import datetime, timezone
import json
from pathlib import Path
import secrets
import sqlite3
import subprocess
import time
from test_p2_recovery import email_reset_form, tokens, wallet

p = argparse.ArgumentParser(__doc__)
p.add_argument('--runtime', type=Path, required=True)
a = p.parse_args(); runtime = a.runtime.resolve(); assert 'runtime' in runtime.parts
fixture = runtime / 'recovery-fixture.json'
user = json.loads(fixture.read_text())
checks = []
for attempt in range(4):
    _, old_tokens, old_session = tokens(user)
    status, _, original = wallet(old_session, 'provision', {}); assert status == 200
    browser, form, _, _ = email_reset_form(user)
    password = secrets.token_urlsafe(32)
    candidate = runtime / 'same-second-next-password'
    candidate.write_text(password); candidate.chmod(0o600)
    # Begin near the start of a wall-clock second; tokens still come from real Keycloak.
    time.sleep((1.02 - time.time() % 1) % 1)
    status, _, _ = browser.request(form.action, 'POST', dict(form.hidden, **{
        'password-new': password, 'password-confirm': password}), form=True)
    assert status in (200, 302, 303)
    _, raw, fresh = tokens(dict(user, password=password))
    user['password'] = password; fixture.write_text(json.dumps(user)); fixture.chmod(0o600)
    assert wallet(old_session, 'credentials')[0] == 401
    status, _, retained = wallet(fresh, 'provision', {}); assert status == 200 and retained == original
    # Copy a quiescent SQLite database and WAL only into ignored private runtime.
    snapshot = runtime / 'same-second-registry-snapshot'; snapshot.mkdir(mode=0o700, exist_ok=True)
    for suffix in ('', '-wal'):
        target = snapshot / ('access.db' + suffix)
        if target.exists(): target.unlink()
        result = subprocess.run(['docker', 'cp', 'competency-proof-p2-custodian-1:/data/access.db' + suffix,
                                 str(target)], capture_output=True)
        assert result.returncode == 0, 'Registry evidence snapshot unavailable'
        target.chmod(0o600)
    with sqlite3.connect(snapshot / 'access.db') as db:
        assert db.execute('PRAGMA user_version').fetchone()[0] == 2
        boundary, milliseconds, gate = db.execute(
            'SELECT fresh_after,fresh_flow_after_ms,gate FROM accounts WHERE issuer=? AND subject=?',
            ('https://auth-p2.demo.inoerawan.id/realms/competency-proof-p2', user['id'])).fetchone()
    payload = raw['id_token'].split('.')[1]
    auth_time = json.loads(base64.urlsafe_b64decode(payload + '=' * (-len(payload) % 4)))['auth_time']
    assert gate == 'OPEN' and auth_time >= boundary and milliseconds // 1000 == boundary
    if auth_time == boundary:
        checks = ['Actual Keycloak auth_time equals durable recovery completion second',
                  'A server-issued nonce flow started after completion and registered a fresh session',
                  'Old application session remains denied', 'Wallet and holder key binding unchanged',
                  'Registry schema two and millisecond completion boundary verified']
        break
else:
    raise SystemExit('INCOMPLETE: real service latency prevented same-second authentication; do not claim acceptance')
report = {'schemaVersion': 1, 'time': datetime.now(timezone.utc).isoformat(), 'syntheticData': True,
          'checks': checks, 'attempts': attempt + 1, 'sameSecondAuthentication': True}
(runtime / 'recovery-same-second-result.json').write_text(json.dumps(report, indent=2) + '\n')
print('PASS:', len(checks), 'real same-second recovery authentication checks')
