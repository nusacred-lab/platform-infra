"""Atomically store an encrypted stopped-writer P7 snapshot on the local host."""
import argparse
import datetime as dt
import fcntl
import hashlib
import os
from pathlib import Path
import subprocess
import sys
import time
import p7


def main():
    os.umask(0o077)
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--runtime',type=Path,required=True)
    parser.add_argument('--package',type=Path,required=True)
    parser.add_argument('--smtp',type=Path,required=True)
    parser.add_argument('--destination',type=Path,required=True)
    a=parser.parse_args()
    cfg=p7.load(a.runtime/'operations.json')
    if dt.datetime.now(dt.timezone.utc) >= dt.datetime.fromisoformat(cfg['closesAt']):
        raise ValueError('Demo backup period ended')
    if cfg.get('hostMode')!='workstation':
        raise ValueError('Local backup requires an explicitly selected workstation installation')
    a.destination.mkdir(parents=True,exist_ok=True,mode=0o700)
    with (a.destination/'.backup.lock').open('w') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        name='p7-local-'+dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%SZ')+'.cms'
        temporary=a.destination/(name+'.partial')
        target=a.destination/name
        maintenance=a.runtime/'maintenance.json'
        p7.save(maintenance,{'startedEpoch':time.time(),'reason':'consistent encrypted backup','maxSeconds':600})
        try:
            with temporary.open('xb') as stream:
                subprocess.run([sys.executable,str(Path(__file__).with_name('p7.py')),
                    '--runtime',str(a.runtime),'--package',str(a.package),'--smtp',str(a.smtp),
                    '--host-mode','workstation','snapshot'],stdout=stream,check=True,timeout=600)
                stream.flush();os.fsync(stream.fileno())
            if temporary.stat().st_size<1024:
                raise ValueError('Snapshot is unexpectedly small')
            with temporary.open('rb') as stream:
                digest=hashlib.file_digest(stream,'sha256').hexdigest()
            temporary.replace(target)
            fd=os.open(a.destination,os.O_DIRECTORY)
            try:os.fsync(fd)
            finally:os.close(fd)
            ack={'completedEpoch':time.time(),'file':name,'sha256':digest,'bytes':target.stat().st_size,
                 'destination':'same-host encrypted backup on operator workstation; not off-host'}
            p7.save(a.runtime/'backup-ack.json',ack)
            print(__import__('json').dumps(ack))
        finally:
            temporary.unlink(missing_ok=True)
            maintenance.unlink(missing_ok=True)


if __name__=='__main__':main()
