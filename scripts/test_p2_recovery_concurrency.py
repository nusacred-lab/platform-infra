"""Observe a real PostgreSQL transaction fence while two validated password changes run concurrently."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import secrets
import subprocess
import time
from test_p2_recovery import email_reset_form, tokens, wallet

p = argparse.ArgumentParser(__doc__)
p.add_argument('--runtime', type=Path, required=True)
a = p.parse_args(); r = a.runtime.resolve(); user = json.loads((r / 'recovery-fixture.json').read_text())
_, _, old = tokens(user)
first, form_one, _, _ = email_reset_form(user)
second, form_two, _, _ = email_reset_form(user)
passwords = [secrets.token_urlsafe(32), secrets.token_urlsafe(32)]
(r / 'concurrent-password-candidates.json').write_text(json.dumps(passwords)); (r / 'concurrent-password-candidates.json').chmod(0o600)
def update(item):
    browser, form, password = item
    return browser.request(form.action, 'POST', dict(form.hidden, **{'password-new': password, 'password-confirm': password}), form=True)[0]
subprocess.run(['docker', 'pause', 'competency-proof-p2-custodian-1'], check=True, stdout=subprocess.DEVNULL)
held = False
with ThreadPoolExecutor(max_workers=2) as pool:
    futures = [pool.submit(update, x) for x in ((first, form_one, passwords[0]), (second, form_two, passwords[1]))]
    try:
        for _ in range(20):
            result = subprocess.check_output(['docker', 'exec', 'competency-proof-p2-postgres-1', 'psql',
                '-U', 'keycloak_p2', '-d', 'keycloak_p2', '-Atc',
                "SELECT count(*) FILTER (WHERE granted),count(*) FILTER (WHERE NOT granted) FROM pg_locks WHERE locktype='advisory'"], text=True).strip()
            granted, waiting = map(int, result.split('|'))
            if granted >= 1 and waiting >= 1: held = True; break
            time.sleep(0.1)
    finally:
        subprocess.run(['docker', 'unpause', 'competency-proof-p2-custodian-1'], check=True, stdout=subprocess.DEVNULL)
    statuses = [f.result(timeout=20) for f in futures]
assert held, 'Did not observe the first transaction holding and second waiting on the IdP account fence'
assert all(status in (200, 302, 303, 400, 403) for status in statuses), 'Unexpected concurrent password response'
time.sleep(2)
accepted = []
for password in passwords:
    try:
        _, _, session = tokens(dict(user, password=password))
        accepted.append((password, session))
    except AssertionError: pass
assert len(accepted) == 1, 'Exactly one final password must authenticate and pass the persistent gate'
user['password'], session = accepted[0]
(r / 'recovery-fixture.json').write_text(json.dumps(user)); (r / 'recovery-fixture.json').chmod(0o600)
assert wallet(session, 'credentials')[0] == 200 and wallet(old, 'credentials')[0] == 401
(r / 'recovery-concurrency-result.json').write_text(json.dumps({'schemaVersion': 1,
    'checks': ['Two actual email-validated password requests', 'PostgreSQL account transaction lock held and second request waited',
               'Exactly one final password accepted', 'Old application session denied and original credential readable'],
    'httpStatuses': statuses}, indent=2) + '\n')
print('PASS: actual concurrent recovery requests are fenced by PostgreSQL and leave one valid final password')
