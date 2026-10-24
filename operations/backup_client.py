"""Receive a consistent, VM-encrypted snapshot on the operator laptop.

The private decryption key never goes to the VM. Acknowledgement is written on
VM only after the complete encrypted file is durable on the laptop.
"""
import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import shlex
import subprocess
import time


def main():
    os.umask(0o077)
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--host', required=True)
    p.add_argument('--identity', type=Path, required=True)
    p.add_argument('--destination', type=Path, required=True)
    p.add_argument('--vm-root', default='/home/ubuntu/competency-proof')
    a = p.parse_args()
    ssh = ['ssh', '-F', '/dev/null', '-i', str(a.identity), '-o', 'BatchMode=yes',
           '-o', 'StrictHostKeyChecking=yes', '-o', 'ConnectTimeout=10',
           '-o', 'ServerAliveInterval=15', '-o', 'ServerAliveCountMax=2', a.host]
    now = dt.datetime.now(dt.timezone.utc)
    if now >= dt.datetime(2026, 11, 1, tzinfo=dt.timezone(dt.timedelta(hours=7))):
        raise SystemExit('Scheduled demo backup period has ended')
    a.destination.mkdir(parents=True, exist_ok=True, mode=0o700)
    name = 'p7-'+now.strftime('%Y%m%dT%H%M%SZ')+'.cms'
    temporary = a.destination/(name+'.partial')
    target = a.destination/name
    root = a.vm_root
    command = ['sudo', '-n', 'python3', root+'/operations/p7.py', '--runtime', root+'/runtime/p7',
               '--package', root+'/package', '--smtp', '/home/ubuntu/.config/competency-proof/p7/smtp.json', 'snapshot']
    try:
        with temporary.open('xb') as stream:
            subprocess.run([*ssh, shlex.join(command)], stdout=stream, check=True, timeout=600)
            stream.flush()
            os.fsync(stream.fileno())
        if temporary.stat().st_size < 1024:
            raise ValueError('Encrypted archive is unexpectedly small')
        digest = hashlib.sha256(temporary.read_bytes()).hexdigest()
        temporary.replace(target)
        fd = os.open(a.destination, os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
        ack = {'completedEpoch': time.time(), 'sha256': digest, 'file': name,
               'bytes': target.stat().st_size, 'destination': 'operator laptop; outside VM'}
        # JSON is stdin data; shell arguments are individually quoted.
        script = "import json,pathlib,sys; p=pathlib.Path("+repr(root+'/runtime/p7/backup-ack.json')+"); d=json.load(sys.stdin); p.write_text(json.dumps(d)+'\\n'); p.chmod(0o600)"
        subprocess.run([*ssh, shlex.join(['sudo', '-n', 'python3', '-c', script])],
                       input=json.dumps(ack), text=True, check=True, timeout=20)
        print(json.dumps(ack))
    finally:
        temporary.unlink(missing_ok=True)


if __name__ == '__main__':
    main()
