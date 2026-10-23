"""Restricted verified-TLS browser transport for disposable P6 acceptance only."""
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
REALM = "competency-proof-p2"

AUTH = "https://auth-p2.demo.inoerawan.id"
WALLET = "https://wallet-p2.demo.inoerawan.id"
ISSUER = AUTH + "/realms/" + REALM
REDIRECT = "id.nusacred.wallet.debug:/oauth2redirect"


class Browser:
    cafile = None
    public_frontend = False
    loopback_port = 28443
    allowed_hosts = frozenset(("login-dompet-identitas.demo.inoerawan.id", "dompet-identitas.demo.inoerawan.id",
                              "lsp-nusantara.demo.inoerawan.id", "karya-instalasi.demo.inoerawan.id",
                              "login-lsp-nusantara.demo.inoerawan.id", "login-karya-instalasi.demo.inoerawan.id"))

    def __init__(self):
        self.cookies = {}
        self.last_headers = []

    def request(self, url, method="GET", body=None, headers=None, form=False):
        uri = urlsplit(url)
        assert uri.scheme == "https" and uri.netloc in self.allowed_hosts
        conn = http.client.HTTPSConnection(uri.hostname, timeout=15)
        def connect():
            conn.sock = ssl.create_default_context(cafile=self.cafile).wrap_socket(
                socket.create_connection(("127.0.0.1", self.loopback_port), timeout=15), server_hostname=uri.hostname)
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

