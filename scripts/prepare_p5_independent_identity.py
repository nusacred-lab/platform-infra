"""Split an offline realm export into independently stored staff identities.

Keep the source realm and wallet issuer unchanged. Import the generated files
only into new, empty databases; remove migrated staff identities from the wallet
realm only after successful login, recovery and cross-entity denial checks.
Private exports contain password hashes and must never enter source control.
"""
import argparse
import copy
import json
import os
from pathlib import Path
import secrets
import uuid


def split_realm(source, entity, realm_name, roles, client_id, secret):
    target = copy.deepcopy(source)
    target.update(id=str(uuid.uuid4()), realm=realm_name, displayName=(
        "LSP Nusantara" if entity == "issuer" else "Karya Instalasi"),
        loginTheme=realm_name, resetCredentialsFlow="reset credentials",
        eventsListeners=["jboss-logging"], identityProviders=[],
        identityProviderMappers=[], userFederationProviders=[],
        userFederationMappers=[])
    for field in ("privateKey", "publicKey", "certificate", "codeSecret"):
        target.pop(field, None)
    # Fresh signing keys ensure one entity cannot mint another entity's tokens.
    target.get("components", {}).pop("org.keycloak.keys.KeyProvider", None)
    target["authenticationFlows"] = [f for f in target.get("authenticationFlows", [])
                                     if f.get("builtIn")]
    referenced_configs = {e.get("authenticatorConfig")
                          for f in target["authenticationFlows"]
                          for e in f.get("authenticationExecutions", [])}
    target["authenticatorConfig"] = [c for c in source.get("authenticatorConfig", [])
                                     if c.get("alias") in referenced_configs]
    target["attributes"].pop("frontendUrl", None)
    target["smtpServer"]["fromDisplayName"] = (
        "LSP Teknik Ketenagalistrikan Nusantara (demo)" if entity == "issuer"
        else "PT Karya Instalasi Nusantara (demo)")
    target["smtpServer"]["from"] = f"{realm_name}@example.test"
    target["users"] = []
    moved = []
    for user in source.get("users", []):
        assigned = set(user.get("realmRoles", []))
        if not assigned.intersection(roles):
            continue
        assert not assigned.intersection({"applicant", "custodian-admin"})
        clone = copy.deepcopy(user)
        clone["realmRoles"] = sorted(assigned.intersection(roles))
        clone["clientRoles"] = {}
        clone.pop("federatedIdentities", None)
        assert clone.get("credentials"), "Refuse an identity without exported credentials"
        target["users"].append(clone)
        moved.append(user["id"])
    assert moved, "No staff identities found; check the source export"
    # Retain built-in clients, but no other business application's client/secret.
    business = {"issuer-bff-p2", "company-bff-p2", "custodian-bff-p2", "android-wallet-p2"}
    target["clients"] = [c for c in target["clients"]
                         if c["clientId"] not in business or c["clientId"] == client_id]
    client = next(c for c in target["clients"] if c["clientId"] == client_id)
    client["secret"] = secret
    client.setdefault("attributes", {}).update({"access.token.lifespan": "3600",
        "client.session.idle.timeout": "3600", "client.session.max.lifespan": "3600"})
    assert not client.get("directAccessGrantsEnabled")
    assert not client.get("serviceAccountsEnabled")
    target["roles"]["realm"] = [r for r in target["roles"]["realm"] if r["name"] in roles]
    target["defaultRole"] = {"name": "default-roles-" + realm_name,
                             "description": "${role_default-roles}", "composite": True}
    target["roles"]["client"] = {k: v for k, v in target["roles"].get("client", {}).items()
                                  if k not in business or k == client_id}
    target["groups"] = []
    target["scopeMappings"] = []
    target["clientScopeMappings"] = {}
    return target, moved


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--export", required=True, type=Path)
    parser.add_argument("--runtime", required=True, type=Path)
    args = parser.parse_args()
    assert "runtime" in args.runtime.resolve().parts
    os.umask(0o077)
    args.runtime.mkdir(parents=True, exist_ok=True)
    source = json.loads(args.export.read_text())
    assert source["realm"] == "competency-proof-p2"
    report = {}
    for entity, name, roles, client in (
        ("issuer", "lsp-nusantara", {"issuer-admin", "issuer-operator"}, "issuer-bff-p2"),
        ("company", "karya-instalasi", {"company-admin"}, "company-bff-p2"),
    ):
        folder = args.runtime / (entity + "-import")
        folder.mkdir(mode=0o755)
        folder.chmod(0o755)
        secret = secrets.token_urlsafe(48)
        (args.runtime / (entity + "-client-secret")).write_text(secret)
        target, moved = split_realm(source, entity, name, roles, client, secret)
        destination = folder / (name + "-realm.json")
        destination.write_text(json.dumps(target, indent=2) + "\n")
        # The private parent remains 0700; the container must read the bind mount.
        destination.chmod(0o644)
        report[entity] = {"realm": name, "moved_subjects": moved,
                          "users": len(moved), "fresh_signing_keys": True}
    (args.runtime / "migration-plan.json").write_text(json.dumps(report, indent=2) + "\n")
    print("Prepared scoped staff imports with preserved subjects/hashes and fresh client secrets/signing keys.")


if __name__ == "__main__":
    main()
