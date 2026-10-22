#!/usr/bin/env python3
"""Prepare and operate the isolated local connectivity probe, not the full stack."""
import argparse
import getpass
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import ssl
import subprocess
import sys
import time
import urllib.parse
import urllib.request

REPO = Path(__file__).resolve().parents[1]
RUNTIME = Path(os.environ.get("LOCAL_DEMO_RUNTIME", REPO / "runtime/local-demo")).resolve()
HOSTS = [f"{role}.demo.inoerawan.id" for role in ("issuer", "wallet", "auth", "verifier")]
os.umask(0o077)


def run(args, **kwargs):
    return subprocess.run([str(a) for a in args], check=True, **kwargs)


def compose(*args):
    return run(["docker", "compose", "--env-file", RUNTIME / "edge.env",
                "-f", REPO / "local-demo/compose.yaml", *args])


def prepare():
    for name in ("proxy/tls", "acme/config", "acme/work", "acme/logs", "acme-handoff", "reports", "ssh"):
        (RUNTIME / name).mkdir(parents=True, exist_ok=True, mode=0o700)
    RUNTIME.chmod(0o700)
    print(f"Private runtime prepared: {RUNTIME}")


def dns(name, kind):
    query = urllib.parse.urlencode({"name": name, "type": kind})
    with urllib.request.urlopen("https://dns.google/resolve?" + query, timeout=20) as response:
        result = json.load(response)
    if result.get("Status") != 0:
        raise SystemExit(f"DNS lookup failed for {name}; status={result.get('Status')}")
    return result.get("Answer", [])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("prepare")
    sub.add_parser("test-certificate")
    edge = sub.add_parser("configure-edge")
    edge.add_argument("--image", required=True)
    cert = sub.add_parser("request-certificate")
    cert.add_argument("--email", required=True)
    cert.add_argument("--agree-tos", action="store_true", help="Accept the Let's Encrypt subscriber agreement")
    sub.add_parser("certificate-status")
    sub.add_parser("confirm-dns")
    sub.add_parser("install-certificate")
    tunnel_config = sub.add_parser("configure-tunnel")
    tunnel_config.add_argument("--include-p2", action="store_true",
                               help="Add the two P2 TLS forwards after owner approval of public login")
    tunnel_config.add_argument("--include-entities", action="store_true", help="Include the reviewed independent organization domains")
    sub.add_parser("tunnel")
    for name in ("up", "down", "validate", "check"):
        sub.add_parser(name)
    args = parser.parse_args()
    prepare()
    if args.command == "prepare":
        return
    if args.command == "test-certificate":
        key, chain = RUNTIME / "proxy/tls/privkey.pem", RUNTIME / "proxy/tls/fullchain.pem"
        if key.exists() or chain.exists():
            raise SystemExit("Refusing to overwrite an existing certificate or key.")
        run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
             "-nodes", "-days", "2", "-subj", "/CN=Local connectivity test",
             "-addext", "subjectAltName=" + ",".join("DNS:" + host for host in HOSTS),
             "-keyout", key, "-out", chain], stdout=subprocess.DEVNULL)
        (RUNTIME / "proxy/certificate-mode").write_text("local-test\n")
        print("Untrusted test certificate created for loopback checks only.")
    elif args.command == "configure-edge":
        if not re.fullmatch(r"(?:[a-zA-Z0-9_./:-]+@)?sha256:[a-f0-9]{64}", args.image):
            raise SystemExit("An immutable image digest is required.")
        (RUNTIME / "edge.env").write_text(f"CADDY_IMAGE={args.image}\nLOCAL_UID={os.getuid()}\nLOCAL_GID={os.getgid()}\nDEMO_RUNTIME={RUNTIME}\n")
    elif args.command == "request-certificate":
        if not args.agree_tos:
            raise SystemExit("Read https://letsencrypt.org/repository/ and pass --agree-tos to accept the subscriber agreement.")
        hook = shlex.join([sys.executable, str(REPO / "scripts/dns_challenge.py"), str(RUNTIME)])
        run([Path(sys.executable).parent / "certbot", "certonly", "--manual", "--preferred-challenges", "dns",
             "--manual-auth-hook", hook, "--non-interactive", "--agree-tos", "--email", args.email,
             "--server", "https://acme-v02.api.letsencrypt.org/directory",
             "--config-dir", RUNTIME / "acme/config", "--work-dir", RUNTIME / "acme/work",
             "--logs-dir", RUNTIME / "acme/logs", "--cert-name", "demo-wildcard",
             "--key-type", "ecdsa", "-d", "*.demo.inoerawan.id"])
        for name in ("pending.json", "dns-ready"):
            (RUNTIME / "acme-handoff" / name).unlink(missing_ok=True)
    elif args.command == "certificate-status":
        chain = RUNTIME / "acme/config/live/demo-wildcard/fullchain.pem"
        if chain.exists():
            run(["openssl", "x509", "-in", chain, "-noout", "-subject", "-issuer", "-dates"])
        pending = RUNTIME / "acme-handoff/pending.json"
        print(pending.read_text() if pending.exists() else "No pending DNS challenge.")
    elif args.command == "confirm-dns":
        challenge = json.loads((RUNTIME / "acme-handoff/pending.json").read_text())
        if time.time() >= challenge["expires_at"]:
            raise SystemExit("Challenge expired; request a new certificate.")
        answers = dns(challenge["name"], "TXT")
        values = []
        for answer in answers:
            if answer["type"] == 16:
                chunks = re.findall(r'"([^"]*)"', answer["data"])
                values.append("".join(chunks) if chunks else answer["data"])
        if challenge["value"] not in values:
            raise SystemExit("Expected TXT is not visible yet; the certificate request remains waiting.")
        (RUNTIME / "acme-handoff/dns-ready").write_text(challenge["value"] + "\n")
        print("Public DNS matches. The waiting Certbot process can continue.")
    elif args.command == "install-certificate":
        source = RUNTIME / "acme/config/live/demo-wildcard"
        context = ssl.create_default_context()
        context.load_cert_chain(source / "fullchain.pem", source / "privkey.pem")
        run(["openssl", "x509", "-in", source / "fullchain.pem", "-noout", "-checkend", "86400"])
        for name in ("fullchain.pem", "privkey.pem"):
            dest = RUNTIME / "proxy/tls" / name
            temp = dest.with_suffix(".new")
            shutil.copyfile(source / name, temp)
            temp.chmod(0o600)
            temp.replace(dest)
        (RUNTIME / "proxy/certificate-mode").write_text("acme\n")
        print("Certificate installed. Restart the edge if it is already running.")
    elif args.command == "configure-tunnel":
        token = getpass.getpass("Pinggy token (hidden; stored only in the private SSH config): ").strip()
        if not re.fullmatch(r"[A-Za-z0-9]+", token):
            raise SystemExit("Expected an alphanumeric Pinggy token.")
        identity = RUNTIME / "ssh/id_ed25519"
        if not identity.exists():
            run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "competency-proof-local-tunnel", "-f", identity])
        config = ["Host competency-proof-pinggy", "  HostName pro.pinggy.io", "  Port 443",
                  "  User " + token, "  StrictHostKeyChecking ask", "  UserKnownHostsFile " + str(RUNTIME / "ssh/known_hosts"),
                  "  IdentityFile " + str(identity), "  IdentitiesOnly yes",
                  "  ServerAliveInterval 30", "  ServerAliveCountMax 3", "  ExitOnForwardFailure yes",
                  "  LogLevel ERROR"]
        hosts = HOSTS + (["auth-p2.demo.inoerawan.id", "wallet-p2.demo.inoerawan.id"] if args.include_p2 else [])
        if args.include_entities:
            hosts += ["lsp-nusantara.demo.inoerawan.id", "dompet-identitas.demo.inoerawan.id",
                      "login-dompet-identitas.demo.inoerawan.id", "karya-instalasi.demo.inoerawan.id"]
        for host in hosts:
            config.append(f"  RemoteForward tls//{host}:1 127.0.0.1:8443")
        (RUNTIME / "ssh/config").write_text("\n".join(config) + "\n")
        print("Private SSH configuration saved. No tunnel has been started.")
    elif args.command == "tunnel":
        if (RUNTIME / "proxy/certificate-mode").read_text().strip() != "acme":
            raise SystemExit("Install a public certificate before starting the tunnel.")
        config = (RUNTIME / "ssh/config").read_text()
        token = re.search(r"^\s*User\s+(\S+)", config, re.MULTILINE).group(1)
        print("Verify the SSH host fingerprint on the first connection. Ctrl-C stops the tunnel.")
        while True:
            try:
                process = subprocess.Popen(["ssh", "-T", "-F", str(RUNTIME / "ssh/config"), "competency-proof-pinggy"],
                                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
                fatal = False
                for line in process.stdout:
                    text = line.replace(token, "[REDACTED]")
                    print(text, end="", flush=True)
                    if any(reason in text.lower() for reason in ("permission denied", "host key verification failed", "identification has changed", "remote port forwarding failed", "bad configuration", "login is not allowed", "a tunnel with the same token")):
                        fatal = True
                code = process.wait()
                if fatal or code not in (0, 255):
                    raise SystemExit("Tunnel stopped for diagnosis; no automatic retry of credential, host-key or configuration errors.")
                print("Tunnel disconnected; retrying in five seconds. Ctrl-C stops retries.")
                time.sleep(5)
            except KeyboardInterrupt:
                if "process" in locals() and process.poll() is None:
                    process.terminate()
                    process.wait()
                break
    elif args.command == "validate":
        compose("config", "--quiet")
        compose("run", "--rm", "--no-deps", "edge", "caddy", "validate", "--config", "/etc/caddy/Caddyfile", "--adapter", "caddyfile")
    elif args.command == "up":
        compose("up", "-d", "--no-build")
    elif args.command == "down":
        compose("down")
    elif args.command == "check":
        import http.client
        context = ssl.create_default_context(cafile=str(RUNTIME / "proxy/tls/fullchain.pem"))
        # Connect to loopback while retaining the real hostname for SNI and verification.
        import socket
        for host in HOSTS:
            for method, path, expected in (("GET", "/healthz", 200), ("GET", "/admin/", 404), ("POST", "/healthz", 404)):
                conn = http.client.HTTPSConnection(host, 8443, context=context, timeout=10)
                conn.sock = context.wrap_socket(socket.create_connection(("127.0.0.1", 8443), timeout=10), server_hostname=host)
                conn.request(method, path, headers={"Host": host})
                response = conn.getresponse()
                response.read()
                if response.status != expected or response.getheader("Cache-Control") != "no-store":
                    raise SystemExit(f"Probe check failed: {host} {method} {path} => {response.status}")
                conn.close()
            print(f"PASS: {host}: TLS name, probe, blocked admin and blocked mutation")


if __name__ == "__main__":
    main()
