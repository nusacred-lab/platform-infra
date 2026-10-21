#!/usr/bin/env python3
"""Certbot manual hook: persist the DNS handoff and wait for verified approval."""
import json
import os
from pathlib import Path
import sys
import time

os.umask(0o077)
handoff = Path(sys.argv[1]) / "acme-handoff"
handoff.mkdir(parents=True, exist_ok=True)
ready = handoff / "dns-ready"
ready.unlink(missing_ok=True)
domain = os.environ["CERTBOT_DOMAIN"].removeprefix("*.")
value = os.environ["CERTBOT_VALIDATION"]
challenge = {"name": "_acme-challenge." + domain, "type": "TXT", "value": value,
             "created_at": int(time.time()), "expires_at": int(time.time()) + 86400}
(handoff / "pending.json").write_text(json.dumps(challenge, indent=2) + "\n")
print(json.dumps(challenge), flush=True)
print("Waiting for local_demo.py confirm-dns after the operator saves the TXT record.", flush=True)
for _ in range(8640):
    if ready.exists() and ready.read_text().strip() == value:
        sys.exit(0)
    time.sleep(10)
raise SystemExit("DNS handoff timed out after 24 hours; start a new certificate request.")
