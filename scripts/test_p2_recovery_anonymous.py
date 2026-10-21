"""Check public forgotten-password responses for known and unknown synthetic users without locking access."""
import argparse
from html.parser import HTMLParser
import json
from pathlib import Path
import secrets
from urllib.parse import urlencode, urljoin
from test_p2_recovery import Form, follow, tokens, wallet
from test_p2_login import Browser, AUTH, ISSUER, REDIRECT

class Feedback(HTMLParser):
    def __init__(self, text):
        super().__init__(); self.depth = 0; self.parts = []; self.feed(text)
    def handle_starttag(self, tag, attrs):
        if self.depth: self.depth += 1
        elif 'kc-feedback-text' in dict(attrs).get('class', '').split(): self.depth = 1
    def handle_endtag(self, tag):
        if self.depth: self.depth -= 1
    def handle_data(self, data):
        if self.depth: self.parts.append(data)
    def message(self): return ' '.join(' '.join(self.parts).split())

p = argparse.ArgumentParser(__doc__)
p.add_argument('--runtime', type=Path, required=True)
a = p.parse_args(); runtime = a.runtime.resolve(); assert 'runtime' in runtime.parts
Browser.public_frontend = True
user = json.loads((runtime / 'recovery-fixture.json').read_text())
_, _, session = tokens(user)
assert wallet(session, 'credentials')[0] == 200
messages = []
for email in (user['email'], 'unknown-' + secrets.token_hex(12) + '@example.test'):
    browser = Browser()
    url = ISSUER + '/protocol/openid-connect/auth?' + urlencode({'client_id': 'android-wallet-p2',
        'redirect_uri': REDIRECT, 'response_type': 'code', 'scope': 'openid',
        'code_challenge': secrets.token_urlsafe(32), 'code_challenge_method': 'S256'})
    status, _, page = follow(browser, url); assert status == 200
    link = next(x for x in Form(page).links if '/login-actions/reset-credentials' in x)
    status, _, page = follow(browser, urljoin(AUTH, link)); assert status == 200
    form = Form(page); assert form.action
    status, _, page = browser.request(form.action, 'POST', dict(form.hidden, username=email), form=True)
    assert status == 200
    message = Feedback(page).message(); assert message and email not in message
    messages.append(message)
    assert wallet(session, 'credentials')[0] == 200
assert messages[0] == messages[1], 'Known and unknown user feedback differed'
report = {'schemaVersion': 1, 'syntheticData': True, 'transport': 'public_verified_tls', 'checks': [
    'Known user forgotten-password response is successful and generic',
    'Unknown user receives the identical generic feedback and HTTP status',
    'Neither feedback message reveals the submitted address or account existence',
    'Existing authenticated wallet access survives both anonymous requests']}
(runtime / 'recovery-anonymous-result.json').write_text(json.dumps(report, indent=2) + '\n')
print('PASS:', len(report['checks']), 'public anonymous recovery checks')
