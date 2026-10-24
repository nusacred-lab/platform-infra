"""Run the private Pinggy SSH profile with strict keys and redacted diagnostics."""
import argparse
from pathlib import Path
import re
import subprocess
import sys

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--config', type=Path, required=True)
a = p.parse_args()
config = a.config.read_text()
match = re.search(r'^\s*User\s+(\S+)', config, re.MULTILINE)
if not match:
    raise SystemExit('Missing private Pinggy user')
secret = match.group(1)
process = subprocess.Popen(['ssh', '-T', '-F', str(a.config), 'competency-proof-pinggy'],
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
try:
    for line in process.stdout:
        safe = line.replace(secret, '[REDACTED]').replace(secret.removesuffix('+force'), '[REDACTED]')
        # Never output arbitrary server text or request/debug URLs.
        for message in ('permission denied', 'host key verification failed', 'remote port forwarding failed',
                        'connection closed', 'connection reset', 'connection timed out', 'a tunnel with the same token'):
            if message in safe.lower():
                print('Pinggy: '+message, flush=True)
finally:
    if process.poll() is None:
        process.terminate()
    code = process.wait()
sys.exit(code if code else 1)  # systemd reconnects even after a clean remote close.
