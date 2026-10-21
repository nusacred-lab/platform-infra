"""Run real Keycloak PKCE/BFF login checks through verified local or public TLS."""
import argparse
from datetime import datetime, timezone
import hashlib
from html.parser import HTMLParser
import http.client
from http.cookies import SimpleCookie
import json
from pathlib import Path
import secrets
import socket
import ssl
import time
from urllib.parse import parse_qs, urlencode, urlsplit
from check_p2_identity import request as admin_request, REALM

AUTH = "https://auth-p2.demo.inoerawan.id"
WALLET = "https://wallet-p2.demo.inoerawan.id"
ISSUER = AUTH + "/realms/" + REALM
REDIRECT = "id.nusacred.wallet.debug:/oauth2redirect"


class Browser:
    public_frontend = False

    def __init__(self):
        self.cookies = {}
        self.last_headers = []

    def request(self, url, method="GET", body=None, headers=None, form=False):
        uri = urlsplit(url)
        assert uri.scheme == "https" and uri.netloc in (urlsplit(AUTH).netloc, urlsplit(WALLET).netloc,
            "issuer-p2.demo.inoerawan.id", "verifier-p2.demo.inoerawan.id")
        conn = http.client.HTTPSConnection(uri.hostname, timeout=15)
        def connect():
            conn.sock = ssl.create_default_context().wrap_socket(
                socket.create_connection(("127.0.0.1", 18443), timeout=15), server_hostname=uri.hostname)
        if not self.public_frontend:
            conn.connect = connect
        outgoing = dict(headers or {})
        cookies = self.cookies.setdefault(uri.hostname, {})
        if cookies:
            outgoing["Cookie"] = "; ".join(k + "=" + v for k, v in cookies.items())
        data = None
        if body is not None:
            data = urlencode(body) if form else json.dumps(body)
            outgoing["Content-Type"] = "application/x-www-form-urlencoded" if form else "application/json"
        try:
            conn.request(method, uri.path + ("?" + uri.query if uri.query else ""), data, outgoing)
            r = conn.getresponse()
            self.last_headers = r.getheaders()
            for key, value in self.last_headers:
                if key.lower() == "set-cookie":
                    # Browsers ignore unknown cookie extensions, including Ktor's $x-enc marker.
                    parsed = SimpleCookie(value.split(";", 1)[0])
                    expired = any(part.strip().lower() == "max-age=0" for part in value.split(";")[1:])
                    for name, item in parsed.items():
                        if expired:
                            cookies.pop(name, None)
                        else:
                            cookies[name] = item.value
            payload = r.read(1_048_577)
            assert len(payload) <= 1_048_576
            return r.status, dict(self.last_headers), payload.decode()
        finally:
            conn.close()


class LoginForm(HTMLParser):
    def __init__(self, text):
        super().__init__()
        self.action = None
        self.hidden = {}
        self.inside = False
        self.feed(text)
    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "form" and attrs.get("id") == "kc-form-login":
            self.action = attrs["action"]
            self.inside = True
        if self.inside and tag == "input" and attrs.get("type") == "hidden" and attrs.get("name"):
            self.hidden[attrs["name"]] = attrs.get("value", "")
    def handle_endtag(self, tag):
        if tag == "form":
            self.inside = False


def login(browser, url, user):
    status, headers, page = browser.request(url)
    for _ in range(5):
        if status not in (302, 303, 307):
            break
        status, headers, page = browser.request(headers["Location"])
    assert status == 200
    parsed = LoginForm(page)
    assert parsed.action, "Expected the real Keycloak username/password page"
    fields = dict(parsed.hidden, username=user["email"], password=user["password"])
    status, headers, _ = browser.request(parsed.action, "POST", fields, form=True)
    assert status in (302, 303), "Real Keycloak login did not return an authorization code"
    return headers["Location"]


def json_request(browser, path, method="GET", body=None, headers=None):
    status, result_headers, payload = browser.request(WALLET + path, method, body, headers)
    return status, result_headers, json.loads(payload)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime", type=Path, required=True)
    parser.add_argument("--public-frontend", action="store_true",
                        help="Use public HTTPS for login; administrative revocation stays private")
    args = parser.parse_args()
    Browser.public_frontend = args.public_frontend
    runtime = args.runtime.resolve()
    fixtures = json.loads((runtime / "login-fixtures.json").read_text())
    credentials = json.loads((runtime / "credentials.json").read_text())
    results = []
    def passed(name):
        results.append(name)
        print("PASS:", name, flush=True)

    for _ in range(30):
        try:
            status, _, _ = json_request(Browser(), "/auth/native/start", "POST", {})
            if status == 200:
                break
        except (OSError, ValueError, http.client.HTTPException):
            pass
        time.sleep(1)
    else:
        raise SystemExit("FAIL: configured application did not become ready")
    assert json_request(Browser(), "/auth/me")[0] == 401
    passed("Anonymous account access denied")

    def native_tokens(nonce_override=None, wrong_verifier=False):
        browser = Browser()
        status, _, flow = json_request(browser, "/auth/native/start", "POST", {})
        assert status == 200
        verifier = secrets.token_urlsafe(48)
        challenge = __import__("base64").urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
        state = secrets.token_urlsafe(32)
        url = ISSUER + "/protocol/openid-connect/auth?" + urlencode({
            "client_id": "android-wallet-p2", "redirect_uri": REDIRECT, "response_type": "code",
            "scope": "openid profile email", "state": state, "nonce": nonce_override or flow["nonce"],
            "code_challenge": challenge, "code_challenge_method": "S256", "prompt": "login", "max_age": "0"})
        redirect = login(browser, url, fixtures["applicant"])
        assert redirect.startswith(REDIRECT + "?")
        query = parse_qs(urlsplit(redirect).query)
        assert query["state"] == [state]
        status, _, data = browser.request(ISSUER + "/protocol/openid-connect/token", "POST", {
            "grant_type": "authorization_code", "client_id": "android-wallet-p2",
            "redirect_uri": REDIRECT, "code": query["code"][0], "code_verifier": secrets.token_urlsafe(48) if wrong_verifier else verifier}, form=True)
        if wrong_verifier:
            assert status == 400
            return
        assert status == 200
        return browser, flow, json.loads(data)

    browser, flow, tokens = native_tokens()
    status, _, data = json_request(browser, "/auth/native/session", "POST", dict(ticket=flow["ticket"],
        access_token=tokens["access_token"], id_token=tokens["id_token"]))
    if status != 200:
        import base64
        def claims(t):
            part=t.split(".")[1];return json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))
        a,i=claims(tokens["access_token"]),claims(tokens["id_token"])
        print("Sanitized login diagnostics:", {"access_audience":a.get("aud"),"access_type":a.get("typ"),
            "access_client":a.get("azp"),"id_audience":i.get("aud"),"id_client":i.get("azp"),
            "nonce_matches":i.get("nonce")==flow["nonce"],"sid_matches":i.get("sid")==a.get("sid"),
            "email_verified":i.get("email_verified"),"auth_time_type":type(i.get("auth_time")).__name__,
            "roles":a.get("realm_access",{}).get("roles",[])},flush=True)
    assert status == 200, "Native code/PKCE tokens were not accepted"
    opaque = data["session"]
    assert len(opaque) == 43 and "." not in opaque
    native_header = {"Authorization": "Bearer " + opaque}
    status, _, me = json_request(browser, "/auth/me", headers=native_header)
    assert status == 200 and me["subject"] == fixtures["applicant"]["id"]
    assert set(me) == {"email", "subject", "csrf", "wallet_access"}
    passed("Real native public-client PKCE login and opaque application session")
    assert json_request(browser, "/auth/native/session", "POST", dict(ticket=flow["ticket"],
        access_token=tokens["access_token"], id_token=tokens["id_token"]))[0] == 401
    passed("Native transaction replay rejected")
    native_tokens(wrong_verifier=True)
    passed("Incorrect PKCE verifier rejected by real Keycloak")
    forged_browser, forged_flow, forged_tokens = native_tokens()
    parts = forged_tokens["access_token"].split(".")
    parts[2] = ("A" if parts[2][0] != "A" else "B") + parts[2][1:]
    assert json_request(forged_browser, "/auth/native/session", "POST", dict(ticket=forged_flow["ticket"],
        access_token=".".join(parts), id_token=forged_tokens["id_token"]))[0] == 401
    passed("Tampered token signature rejected before issuing an application session")
    for token in [tokens["access_token"], tokens["id_token"]]:
        assert json_request(Browser(), "/auth/me", headers={"Authorization": "Bearer " + token})[0] == 401
    passed("IdP access and ID tokens cannot bypass opaque-session registration")
    other_browser, other_flow, other_tokens = native_tokens("incorrect-nonce")
    assert json_request(other_browser, "/auth/native/session", "POST", dict(ticket=other_flow["ticket"],
        access_token=other_tokens["access_token"], id_token=other_tokens["id_token"]))[0] == 401
    passed("Valid signed tokens with wrong nonce rejected")
    other_browser, other_flow, other_tokens = native_tokens()
    assert json_request(other_browser, "/auth/native/session", "POST", dict(ticket=other_flow["ticket"],
        access_token=other_tokens["id_token"], id_token=other_tokens["id_token"]))[0] == 401
    passed("ID token cannot substitute for an access token or API audience")

    web = Browser()
    status, headers, _ = web.request(WALLET + "/auth/start")
    assert status == 302
    cookie_headers = [v for k, v in web.last_headers if k.lower() == "set-cookie"]
    assert any("__Host-nusacred-flow=" in v and "Secure" in v and "HttpOnly" in v and "SameSite=Lax" in v for v in cookie_headers)
    callback = login(web, headers["Location"], fixtures["custodian-admin"])
    status, _, _ = web.request(callback)
    assert status == 302
    status, _, me = json_request(web, "/auth/me")
    assert status == 200 and me["subject"] == fixtures["custodian-admin"]["id"]
    status, headers, page = web.request(WALLET + "/auth/account")
    assert status == 200 and "You are signed in" in page and "access_token" not in page and "id_token" not in page
    assert "frame-ancestors 'none'" in headers["Content-Security-Policy"]
    passed("Real BFF code/PKCE login with host-only Secure HttpOnly cookie and server-only IdP tokens")
    assert web.request(callback)[0] == 401
    passed("BFF authorization callback replay rejected")
    for extra in [{}, {"Origin": "https://untrusted.example", "X-CSRF-Token": me["csrf"]},
                  {"Origin": WALLET, "X-CSRF-Token": "incorrect"}]:
        assert json_request(web, "/auth/logout", "POST", {}, extra)[0] == 401
    assert json_request(web, "/auth/me")[0] == 200
    passed("Missing or wrong Origin/CSRF does not sign out the victim")
    assert json_request(web, "/auth/logout", "POST", {}, {"Origin": WALLET, "X-CSRF-Token": me["csrf"]})[0] == 200
    assert json_request(web, "/auth/me")[0] == 401
    passed("Valid BFF logout revokes its application session")

    victim = Browser()
    status, headers, _ = victim.request(WALLET + "/auth/start")
    callback = login(victim, headers["Location"], fixtures["custodian-admin"])
    assert Browser().request(callback)[0] == 401
    attacker = Browser()
    assert attacker.request(WALLET + "/auth/start")[0] == 302
    assert attacker.request(callback)[0] == 401
    wrong_issuer = {k: v[0] for k,v in parse_qs(urlsplit(callback).query).items()}
    wrong_issuer["iss"] = "https://untrusted.example/realm"
    assert victim.request(WALLET + "/auth/callback?" + urlencode(wrong_issuer))[0] == 401
    assert victim.request(callback)[0] == 302
    assert victim.request(callback)[0] == 401
    passed("Missing/wrong browser binding and wrong response issuer rejected; legitimate callback remains usable once")
    applicant = Browser()
    status, headers, _ = applicant.request(WALLET + "/auth/start")
    callback = login(applicant, headers["Location"], fixtures["applicant"])
    assert applicant.request(callback)[0] == 401
    passed("Applicant cannot obtain custodian administrator BFF session")

    # Revoke only this run's dedicated synthetic applicant at the real IdP.
    status, _, admin = admin_request("POST", "/realms/master/protocol/openid-connect/token", {
        "grant_type": "password", "client_id": "admin-cli", "username": "p2-bootstrap",
        "password": credentials["bootstrap"]}, form=True)
    assert status == 200
    status, _, _ = admin_request("POST", f"/admin/realms/{REALM}/users/{fixtures['applicant']['id']}/logout", token=admin["access_token"])
    assert status == 204
    assert json_request(browser, "/auth/me", headers=native_header)[0] == 401
    passed("Real IdP session revocation invalidates the application session on the next check")
    report = {"time": datetime.now(timezone.utc).isoformat(),
              "frontend_transport": "public_verified_tls" if args.public_frontend else "private_verified_tls",
              "checks": results,
              "limits": ["Synthetic fixtures were preverified, not email-link verified",
                         "HTTP PKCE exercises the backend contract, not physical APK browser completion",
                         "Private recovery and credential proof require separate reports; public credential/recovery routing remains disabled"]}
    filename = "oidc-public-login-result.json" if args.public_frontend else "oidc-login-result.json"
    (runtime / filename).write_text(json.dumps(report, indent=2) + "\n")
    print("PASS:", len(results), "real-service login/rejection checks")


if __name__ == "__main__":
    main()
