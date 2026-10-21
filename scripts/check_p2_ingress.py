#!/usr/bin/env python3
"""Check the public P2 ingress contract using verified HTTPS and no credentials."""
import argparse
from datetime import datetime, timezone
import http.client
import json
from pathlib import Path
import socket
import ssl


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--loopback", action="store_true", help="Connect to the local edge on 8443 instead of public DNS")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    checks = []

    def check(host, path, expected, method="GET", body=None):
        hostname = host + ".demo.inoerawan.id"
        connection = http.client.HTTPSConnection(hostname, timeout=30)
        if args.loopback:
            def connect():
                connection.sock = ssl.create_default_context().wrap_socket(
                    socket.create_connection(("127.0.0.1", 8443), timeout=30),
                    server_hostname=hostname)
            connection.connect = connect
        try:
            connection.request(method, path, body, {"Content-Type": "application/json"})
            response = connection.getresponse()
            payload = response.read(1_048_577)
            assert response.status == expected, (host, path, response.status, expected)
            assert len(payload) <= 1_048_576
            if "openid-configuration" in path and expected == 200:
                assert json.loads(payload)["issuer"] == "https://auth-p2.demo.inoerawan.id/realms/competency-proof-p2"
            if host in ("auth-p2", "wallet-p2"):
                assert response.getheader("X-Content-Type-Options") == "nosniff"
            checks.append({"host": hostname, "path": path, "method": method, "status": response.status})
        finally:
            connection.close()

    for path in ("/.well-known/openid-configuration", "/protocol/openid-connect/certs"):
        check("auth-p2", "/realms/competency-proof-p2" + path, 200)
    for path in ("/admin/", "/realms/master/.well-known/openid-configuration",
                 "/realms/competency-proof-p2/account/",
                 "/realms/competency-proof-p2/login-actions/reset-credentials",
                 "/realms/competency-proof-p2/login-actions/required-action",
                 "/realms/competency-proof-p2/login-actions/action-token", "/api/v1/messages"):
        check("auth-p2", path, 404)
    check("wallet-p2", "/", 200)
    check("wallet-p2", "/auth/native/start", 200, "POST", b"{}")
    check("wallet-p2", "/auth/me", 401)
    check("wallet-p2", "/.well-known/assetlinks.json", 200)
    for action in ("provision", "reconcile", "credentials", "preview", "present"):
        check("wallet-p2", "/api/v1/wallet/" + action, 404,
              "GET" if action == "credentials" else "POST", None if action == "credentials" else b"{}")
    for action in ("begin", "complete"):
        check("wallet-p2", "/internal/recoveries/" + action, 404, "POST", b"{}")
    for path in ("/health/live", "/wallets", "/credentials", "/recoveries", "/admin/", "/api/v1/messages"):
        check("wallet-p2", path, 404)
    for host in ("issuer", "wallet", "auth", "verifier"):
        check(host, "/", 200)
    args.output.write_text(json.dumps({
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "transport": "loopback_verified_tls" if args.loopback else "public_verified_tls",
        "count": len(checks), "checks": checks,
    }, indent=2) + "\n")
    print(f"PASS: {len(checks)} ingress checks ({'loopback' if args.loopback else 'public'} verified TLS)")


if __name__ == "__main__":
    main()
