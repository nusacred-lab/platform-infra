"""Exercise real private Keycloak discovery, clients, SMTP and persistence."""
import argparse
from datetime import datetime, timezone
import http.client
import json
from pathlib import Path
import secrets
import socket
import ssl
import time
from urllib.parse import urlencode

HOST = "auth-p2.demo.inoerawan.id"
REALM = "competency-proof-p2"
ISSUER = f"https://{HOST}/realms/{REALM}"


def request(method, path, payload=None, token=None, form=False, mail=False):
    headers = {}
    if token:
        headers["Authorization"] = "Bearer " + token
    if payload is not None:
        payload = urlencode(payload) if form else json.dumps(payload)
        headers["Content-Type"] = "application/x-www-form-urlencoded" if form else "application/json"
    if mail:
        connection = http.client.HTTPConnection("127.0.0.1", 18025, timeout=15)
    else:
        connection = http.client.HTTPSConnection(HOST, timeout=15)

        def connect():
            connection.sock = ssl.create_default_context().wrap_socket(
                socket.create_connection(("127.0.0.1", 18443), timeout=15), server_hostname=HOST)

        connection.connect = connect
    try:
        connection.request(method, path, payload, headers)
        response = connection.getresponse()
        body = response.read()
        return response.status, dict(response.getheaders()), json.loads(body) if body else None
    finally:
        connection.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime", required=True, type=Path)
    parser.add_argument("--check-restart", action="store_true")
    args = parser.parse_args()
    runtime = args.runtime.resolve()
    credentials = json.loads((runtime / "credentials.json").read_text())
    for attempt in range(30):
        try:
            status, _, discovery = request("GET", f"/realms/{REALM}/.well-known/openid-configuration")
            if status == 200:
                break
        except (OSError, ValueError, http.client.HTTPException):
            pass
        time.sleep(1)
    else:
        raise SystemExit("FAIL: Keycloak did not become ready within 30 attempts.")
    assert discovery["issuer"] == ISSUER
    assert discovery["jwks_uri"] == ISSUER + "/protocol/openid-connect/certs"
    status, _, jwks = request("GET", f"/realms/{REALM}/protocol/openid-connect/certs")
    assert status == 200 and jwks["keys"]
    assert all("d" not in key for key in jwks["keys"])
    status, _, auth = request("POST", "/realms/master/protocol/openid-connect/token", {
        "grant_type": "password", "client_id": "admin-cli", "username": "p2-bootstrap",
        "password": credentials["bootstrap"],
    }, form=True)
    assert status == 200
    token = auth["access_token"]
    base = f"/admin/realms/{REALM}"
    status, _, realm = request("GET", base, token=token)
    assert status == 200 and realm["verifyEmail"] and not realm["registrationAllowed"]
    assert not realm["resetPasswordAllowed"]  # Gate provider is not implemented yet.
    status, _, clients = request("GET", base + "/clients", token=token)
    assert status == 200
    clients = {client["clientId"]: client for client in clients}
    native = clients["android-wallet-p2"]
    assert native["publicClient"] and not native.get("secret")
    assert native["redirectUris"] == ["id.nusacred.wallet.debug:/oauth2redirect"]
    for client_id in ("android-wallet-p2", "issuer-bff-p2", "custodian-bff-p2", "company-bff-p2"):
        client = clients[client_id]
        assert client["attributes"]["pkce.code.challenge.method"] == "S256"
        assert not client["directAccessGrantsEnabled"] and not client["implicitFlowEnabled"]
        assert not client["serviceAccountsEnabled"]
        assert all("*" not in redirect for redirect in client["redirectUris"])
    assert len(set(credentials["bff"].values())) == 3
    status, _, roles = request("GET", base + "/roles", token=token)
    assert status == 200
    assert {"applicant", "issuer-admin", "custodian-admin", "company-admin"} <= {r["name"] for r in roles}
    snapshot_path = runtime / "identity-snapshot.json"
    key_ids = sorted(key["kid"] for key in jwks["keys"])
    if args.check_restart:
        snapshot = json.loads(snapshot_path.read_text())
        assert snapshot["realm_id"] == realm["id"] and snapshot["key_ids"] == key_ids
        status, _, user = request("GET", base + "/users/" + snapshot["user_id"], token=token)
        assert status == 200 and user["email"] == snapshot["email"]
        result = {"restart_persistence": True}
    else:
        email = "p2-" + secrets.token_hex(8) + "@example.test"
        status, headers, _ = request("POST", base + "/users", {
            "username": email, "email": email, "enabled": True, "emailVerified": False,
            "credentials": [{"type": "password", "value": secrets.token_urlsafe(24), "temporary": False}],
        }, token=token)
        assert status == 201
        user_id = headers["Location"].rsplit("/", 1)[1]
        for endpoint, payload in (("send-verify-email", None), ("execute-actions-email", ["UPDATE_PASSWORD"])):
            status, _, _ = request("PUT", base + f"/users/{user_id}/{endpoint}", payload, token=token)
            assert status == 204
        for attempt in range(15):
            status, _, inbox = request("GET", "/api/v1/messages", mail=True)
            assert status == 200
            delivered = [m for m in inbox["messages"] if any(r["Address"] == email for r in m["To"])]
            if len(delivered) >= 2:
                break
            time.sleep(1)
        else:
            raise SystemExit("FAIL: verification/reset messages did not reach private SMTP.")
        for message in delivered:
            status, _, full = request("GET", "/api/v1/message/" + message["ID"], mail=True)
            assert status == 200
            assert "https://" + HOST + "/realms/" + REALM in (full["Text"] + full["HTML"])
        snapshot_path.write_text(json.dumps({"realm_id": realm["id"], "key_ids": key_ids,
                                           "user_id": user_id, "email": email}, indent=2))
        snapshot_path.chmod(0o600)
        result = {"discovery_jwks": True, "client_separation_pkce": True, "roles": True,
                  "verification_and_password_action_email_delivered": True,
                  "password_change_and_recovery_gate": "NOT_TESTED"}
    report = {"time": datetime.now(timezone.utc).isoformat(), "issuer": ISSUER, "checks": result}
    (runtime / ("restart-result.json" if args.check_restart else "identity-result.json")).write_text(
        json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
