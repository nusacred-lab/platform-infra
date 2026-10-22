"""Check issuer publication and a real company review without granting company trust.

Credentials and sessions use verified loopback TLS only. Unit/HTTP tests exercise
successful approval in disposable databases; this live check leaves trust intact.
"""
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import uuid
from p5_transport import Browser, login


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--accounts', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    assert 'runtime' in args.accounts.resolve().parts
    accounts = json.loads(args.accounts.read_text())
    issuer = 'https://lsp-nusantara.demo.inoerawan.id'
    company = 'https://karya-instalasi.demo.inoerawan.id'
    checks = []

    def check(name, condition):
        assert condition, name
        checks.append(name)

    browser = Browser()
    status, headers, raw = browser.request(issuer+'/api/v1/issuer-profile')
    profile = json.loads(raw)
    check('LSP publication is anonymous and not cached', status == 200 and headers['Cache-Control'] == 'no-store')
    check('publication names independent LSP and does not claim accreditation',
          profile['id'] == 'lsp-nusantara' and profile['publicationStatus'] == 'SELF_PUBLISHED'
          and 'No real accreditation' in profile['disclaimer'])
    check('company discovery requires login', browser.request(company+'/api/v1/issuer-candidates')[0] == 401)
    status, headers, _ = browser.request(company+'/auth/start')
    assert status == 302
    callback = login(browser, headers['Location'], accounts['company-admin'])
    check('company administrator signs in at its own IdP', browser.request(callback)[0] == 302)
    status, _, raw = browser.request(company+'/api/v1/portal-session')
    assert status == 200
    session = json.loads(raw)
    mutations = {'Origin': company, 'X-CSRF-Token': session['csrf']}

    def mutate(path, body, extra=None):
        return browser.request(company+path, 'POST', body,
                               dict(mutations, **{'Idempotency-Key': str(uuid.uuid4())}, **(extra or {})))

    before = browser.request(company+'/api/v1/trusted-issuers')[2]
    status, headers, raw = browser.request(company+'/api/v1/issuer-candidates')
    check('company fetches the same exact LSP publication over verified HTTPS',
          status == 200 and json.loads(raw)['items'] == [profile] and headers['Cache-Control'] == 'no-store')
    status, headers, raw = mutate('/api/v1/issuer-reviews', {'issuerId': profile['id']})
    review = json.loads(raw)
    check('review snapshots source without granting trust', status == 201 and review['profile'] == profile and headers['Cache-Control'] == 'no-store')
    check('review expires after fifteen minutes', review['expiresAt'] - review['reviewedAt'] == 900)
    status, _, raw = browser.request(company+'/api/v1/issuer-reviews/'+review['id'])
    check('owned review can be retrieved', status == 200 and json.loads(raw) == review)
    check('arbitrary source IDs are rejected', mutate('/api/v1/issuer-reviews', {'issuerId': 'https://169.254.169.254/'})[0] == 404)
    check('raw DID shortcut is rejected', mutate('/api/v1/trusted-issuers', {'identity': profile['identity']})[0] == 400)
    check('approval without explicit confirmation is rejected', mutate('/api/v1/trusted-issuers', {
        'reviewId': review['id'], 'verificationMethod': 'demo-walkthrough',
        'verificationNote': 'Live negative test; this must never grant company trust.', 'confirmed': 'false'})[0] == 400)
    check('browser review rejects a foreign origin', mutate('/api/v1/issuer-reviews', {'issuerId': profile['id']}, {'Origin': 'https://attacker.example'})[0] == 403)
    check('discovery and negative approval checks leave trust unchanged', browser.request(company+'/api/v1/trusted-issuers')[2] == before)
    status, _, _ = browser.request(company+'/auth/logout', 'POST', {}, mutations)
    check('company logout closes review access', status == 200 and browser.request(company+'/api/v1/issuer-reviews/'+review['id'])[0] == 401)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps({'checkedAt': datetime.now(timezone.utc).isoformat(),
        'transport': 'verified loopback TLS', 'result': 'PASS', 'checks': checks,
        'trustChanged': False, 'limitation': 'Successful approval is tested in disposable HTTP/storage tests; live company approval is left to its administrator.'}, indent=2)+'\n')
    print('PASS:', len(checks), 'issuer publication/review checks; company trust unchanged')


if __name__ == '__main__':
    main()
