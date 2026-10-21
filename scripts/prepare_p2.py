"""Prepare private, restart-safe P2 configuration; never print credentials."""
import argparse
import json
import os
from pathlib import Path
import re
import secrets
import shutil


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime", type=Path, required=True)
    parser.add_argument("--tls", type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    runtime = args.runtime.resolve()
    if "runtime" not in runtime.parts:
        parser.error("Use an ignored runtime directory, outside public source.")
    os.umask(0o077)
    runtime.mkdir(parents=True, exist_ok=True)
    runtime.chmod(0o700)
    for name in ("import", "tls"):
        (runtime / name).mkdir(exist_ok=True)
        (runtime / name).chmod(0o755)
    state_path = runtime / "credentials.json"
    if state_path.exists():
        state = json.loads(state_path.read_text())
    else:
        state = {"database": secrets.token_urlsafe(36), "bootstrap": secrets.token_urlsafe(36),
                 "bff": {role: secrets.token_urlsafe(36) for role in ("issuer", "custodian", "company")}}
        state_path.write_text(json.dumps(state))
        state_path.chmod(0o600)
    realm = json.loads((root / "p2/realm-template.json").read_text())
    for client in realm["clients"]:
        for role, secret in state["bff"].items():
            if client["clientId"] == f"{role}-bff-p2":
                client["secret"] = secret
    imported = runtime / "import/competency-proof-p2-realm.json"
    imported.write_text(json.dumps(realm, indent=2) + "\n")
    # The directory is private on the host; the non-root Keycloak UID needs read access.
    imported.chmod(0o644)
    for name in ("fullchain.pem", "privkey.pem"):
        target = runtime / "tls" / name
        shutil.copyfile(args.tls / name, target)
        target.chmod(0o644)
    (runtime / "postgres-password").write_text(state["database"])
    (runtime / "postgres-password").chmod(0o644)
    images = json.loads((root / "p2/images.json").read_text())
    env = {
        "P2_RUNTIME": str(runtime), "P2_DB_PASSWORD": state["database"],
        "P2_BOOTSTRAP_PASSWORD": state["bootstrap"],
        "KEYCLOAK_IMAGE": images["keycloak"], "POSTGRES_IMAGE": images["postgres"],
        "MAILPIT_IMAGE": images["mailpit"],
    }
    runtime_images = runtime / "runtime-images.json"
    if runtime_images.exists():
        pinned = json.loads(runtime_images.read_text())
        for name in ("P2_POSTGRES_IMAGE", "P2_MAILPIT_IMAGE", "P2_KEYCLOAK_IMAGE", "P2_EDGE_IMAGE"):
            if not re.fullmatch(r"sha256:[a-f0-9]{64}", pinned[name]):
                parser.error("Runtime images must be scanned immutable image IDs.")
            env[name] = pinned[name]
        if "P2_CUSTODIAN_IMAGE" in pinned:
            if not re.fullmatch(r"sha256:[a-f0-9]{64}", pinned["P2_CUSTODIAN_IMAGE"]):
                parser.error("The application image must be a scanned immutable image ID.")
            env["P2_CUSTODIAN_IMAGE"] = pinned["P2_CUSTODIAN_IMAGE"]
    if any("\n" in value or " " in value for value in env.values()):
        parser.error("Runtime paths must not contain spaces or newlines.")
    env_path = runtime / "compose.env"
    env_path.write_text("".join(f"{key}={value}\n" for key, value in env.items()))
    env_path.chmod(0o600)
    print("Prepared private P2 configuration; existing credentials preserved.")


if __name__ == "__main__":
    main()
