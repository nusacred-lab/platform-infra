"""Apply the explicit P2 OIDC audience migration and prepare private synthetic login fixtures."""
import argparse
import json
from pathlib import Path
import secrets
from urllib.parse import urlencode
from check_p2_identity import request, REALM

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--runtime", type=Path, required=True)
args = parser.parse_args()
runtime = args.runtime.resolve()
if "runtime" not in runtime.parts or not runtime.is_dir():
    parser.error("Use an existing ignored private runtime directory.")
runtime.chmod(0o700)
credentials = json.loads((runtime / "credentials.json").read_text())
status, _, result = request("POST", "/realms/master/protocol/openid-connect/token", {
    "grant_type": "password", "client_id": "admin-cli", "username": "p2-bootstrap",
    "password": credentials["bootstrap"],
}, form=True)
assert status == 200
token = result["access_token"]
base = f"/admin/realms/{REALM}"
status, _, clients = request("GET", base + "/clients", token=token)
assert status == 200
status, _, scopes = request("GET", base + "/client-scopes", token=token)
assert status == 200
basic = next(scope for scope in scopes if scope["name"] == "basic")
expected = json.loads((Path(__file__).resolve().parents[1] / "p2/realm-template.json").read_text())
native_expected = next(c for c in expected["clients"] if c["clientId"] == "android-wallet-p2")
native_actual = next(c for c in clients if c["clientId"] == "android-wallet-p2")
native_actual["redirectUris"] = native_expected["redirectUris"]
native_actual.setdefault("attributes", {}).update(native_expected["attributes"])
assert request("PUT", base + "/clients/" + native_actual["id"], native_actual, token=token)[0] == 204
for client in expected["clients"]:
    if not client.get("protocolMappers"):
        continue
    actual = next(c for c in clients if c["clientId"] == client["clientId"])
    status, _, _ = request("PUT", base + f"/clients/{actual['id']}/default-client-scopes/{basic['id']}", token=token)
    assert status == 204
    endpoint = base + f"/clients/{actual['id']}/protocol-mappers/models"
    status, _, mappers = request("GET", endpoint, token=token)
    assert status == 200
    for mapper in client["protocolMappers"]:
        old = next((m for m in mappers if m["name"] == mapper["name"]), None)
        status, _, _ = request("PUT" if old else "POST", endpoint + ("/" + old["id"] if old else ""), mapper, token=token)
        assert status in (201, 204)
fixture_path = runtime / "login-fixtures.json"
if fixture_path.exists():
    fixtures = json.loads(fixture_path.read_text())
else:
    suffix = secrets.token_hex(6)
    fixtures = {role: {"email": f"p2-{role}-{suffix}@example.test", "password": secrets.token_urlsafe(24)}
                for role in ("applicant", "custodian-admin")}
    fixture_path.write_text(json.dumps(fixtures, indent=2))
    fixture_path.chmod(0o600)
for role in ("applicant", "custodian-admin", "issuer-admin", "company-admin"):
    if role not in fixtures:
        fixtures[role] = {"email": f"p2-{role}-{secrets.token_hex(6)}@example.test", "password": secrets.token_urlsafe(24)}
for role, user in fixtures.items():
    status, _, found = request("GET", base + "/users?" + urlencode({"username": user["email"], "exact": "true"}), token=token)
    assert status == 200
    if not found:
        status, _, _ = request("POST", base + "/users", {"username": user["email"], "email": user["email"],
            "firstName": "Synthetic", "lastName": role, "enabled": True, "emailVerified": True,
            "credentials": [{"type": "password", "value": user["password"], "temporary": False}]}, token=token)
        assert status == 201
        status, _, found = request("GET", base + "/users?" + urlencode({"username": user["email"], "exact": "true"}), token=token)
    assert len(found) == 1
    user["id"] = found[0]["id"]
    status, _, role_info = request("GET", base + "/roles/" + role, token=token)
    assert status == 200
    status, _, _ = request("POST", base + f"/users/{user['id']}/role-mappings/realm", [role_info], token=token)
    assert status == 204
fixture_path.write_text(json.dumps(fixtures, indent=2))
fixture_path.chmod(0o600)
print("PASS: exact audience mappers applied and four private synthetic role fixtures prepared.")
print("Fixtures are preverified for login tests; this is not evidence of email-link verification.")
