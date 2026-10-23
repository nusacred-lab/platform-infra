"""Verify real logins and cross-entity isolation using private walkthrough accounts."""
import argparse
from datetime import datetime, timezone
from html.parser import HTMLParser
import json
from pathlib import Path
from urllib.parse import urlsplit, urljoin

from p5_transport import Browser, login
from test_p2_login import LoginForm


class Inputs(HTMLParser):
    def __init__(self, page):
        super().__init__()
        self.username = None
        self.links = []
        self.feed(page)

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "input" and attrs.get("name") == "username":
            self.username = attrs.get("value", "")
        if tag == "a" and attrs.get("href"):
            self.links.append(attrs["href"])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--accounts", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--public", action="store_true")
    args = parser.parse_args()
    accounts = json.loads(args.accounts.read_text())
    browser = Browser()
    browser.public_frontend = args.public
    checks = []

    def check(name, condition):
        assert condition, name
        checks.append(name)

    entities = [
        ("wallet", "dompet-identitas", "login-dompet-identitas", "competency-proof-p2", "custodian-admin"),
        ("company", "karya-instalasi", "login-karya-instalasi", "karya-instalasi", "company-admin"),
        ("issuer", "lsp-nusantara", "login-lsp-nusantara", "lsp-nusantara", "issuer-admin"),
    ]
    keys = []
    sessions = {}
    for name, portal, identity, realm, role in entities:
        origin = f"https://{portal}.demo.inoerawan.id"
        auth = f"https://{identity}.demo.inoerawan.id"
        status, _, payload = browser.request(auth + f"/realms/{realm}/.well-known/openid-configuration")
        metadata = json.loads(payload)
        check(name + ": own issuer", status == 200 and metadata["issuer"] == auth + "/realms/" + realm)
        status, _, payload = browser.request(metadata["jwks_uri"])
        keys.append({k["n"] for k in json.loads(payload)["keys"] if "n" in k})
        check(name + ": administrative routes stay private", browser.request(auth + "/admin/master/console/")[0] == 404)
        check(name + ": another realm stays unavailable", browser.request(auth + "/realms/master/.well-known/openid-configuration")[0] == 404)
        status, headers, _ = browser.request(origin + "/auth/start")
        check(name + ": own login domain", status == 302 and urlsplit(headers["Location"]).hostname == urlsplit(auth).hostname)
        status, _, page = browser.request(headers["Location"])
        check(name + ": no identity inherited from previous entity", status == 200 and Inputs(page).username == "")
        check(name + ": correct authentication operator", (
            "Authentication provided by PT Dompet Identitas Nusantara" in page if name == "wallet"
            else "Authentication managed independently by " in page and
            "Authentication provided by PT Dompet Identitas Nusantara" not in page))
        callback = login(browser, headers["Location"], accounts[role])
        check(name + ": original account/password retained", browser.request(callback)[0] == 302)
        status, _, payload = browser.request(origin + "/api/v1/portal-session")
        session = json.loads(payload)
        check(name + ": correct account", status == 200 and session["email"] == accounts[role]["email"])
        sessions[name] = (origin, session)
        # Wrong-entity credentials must fail at the IdP itself, before the BFF.
        for other_role in (r for r in ("custodian-admin", "issuer-admin", "company-admin") if r != role):
            isolated = Browser()
            isolated.public_frontend = args.public
            _, h, _ = isolated.request(origin + "/auth/start")
            _, _, page = isolated.request(h["Location"])
            form = LoginForm(page)
            status, h, _ = isolated.request(form.action, "POST", dict(form.hidden,
                username=accounts[other_role]["email"], password=accounts[other_role]["password"]), form=True)
            check(name + ": rejects " + other_role, status == 200 and "Location" not in h)
        recovery = Browser()
        recovery.public_frontend = args.public
        _, h, _ = recovery.request(origin + "/auth/start")
        _, _, page = recovery.request(h["Location"])
        forgot = next(link for link in Inputs(page).links if "/login-actions/reset-credentials" in link)
        target = urljoin(auth, forgot)
        check(name + ": recovery stays with owner", urlsplit(target).hostname == urlsplit(auth).hostname)
        status, _, page = recovery.request(target)
        check(name + ": recovery form available", status == 200 and 'name="username"' in page)
    check("independent signing keys", all(keys[i] and keys[i].isdisjoint(keys[j])
          for i in range(3) for j in range(i)))
    company_origin, company_session = sessions["company"]
    status, _, _ = browser.request(company_origin + "/auth/logout", "POST", {},
        {"Origin": company_origin, "X-CSRF-Token": company_session["csrf"]})
    check("company logout succeeds", status == 200)
    check("company session closed", browser.request(company_origin + "/api/v1/portal-session")[0] == 401)
    for entity in ("wallet", "issuer"):
        check(entity + ": unaffected by company logout", browser.request(sessions[entity][0] + "/api/v1/portal-session")[0] == 200)
    args.output.write_text(json.dumps({"checkedAt": datetime.now(timezone.utc).isoformat(),
        "transport": "public HTTPS" if args.public else "verified local TLS", "checks": checks, "result": "PASS"}, indent=2) + "\n")
    print(f"PASS: {len(checks)} independent identity checks; no secrets or cookies recorded")


if __name__ == "__main__":
    main()
