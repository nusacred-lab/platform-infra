"""Verified-TLS transport for the exact independent-entity demo origins."""
import json
from test_p2_login import Browser as LegacyBrowser, login
AUTH = "https://login-dompet-identitas.demo.inoerawan.id"
WALLET = "https://dompet-identitas.demo.inoerawan.id"
ISSUER = AUTH + "/realms/competency-proof-p2"
REDIRECT = "id.nusacred.wallet.debug:/oauth2redirect"
class Browser(LegacyBrowser):
    loopback_port = 8443
    allowed_hosts = frozenset(("login-dompet-identitas.demo.inoerawan.id", "dompet-identitas.demo.inoerawan.id",
                              "lsp-nusantara.demo.inoerawan.id", "karya-instalasi.demo.inoerawan.id"))
def json_request(browser,path,method="GET",body=None,headers=None):
    status,headers,payload=browser.request(WALLET+path,method,body,headers)
    return status,headers,json.loads(payload)
