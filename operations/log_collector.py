"""Collect only P7 container syslog on loopback with redaction and 14-day retention."""
import argparse
import datetime as dt
import json
import os
from pathlib import Path
import re
import socketserver
import threading
import time
import p7


def redact(message, secrets=()):
    for secret in secrets:
        if len(secret)>=8:
            message=message.replace(secret,'[REDACTED]')
    message=re.sub(r'(?i)(Bearer\s+)[A-Za-z0-9._~+/-]+',r'\1[REDACTED]',message)
    message=re.sub(r'\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+','[REDACTED-JWT]',message)
    message=re.sub(r'(?i)([?&](?:code|token|key|access_token|refresh_token|id_token)=)[^&\s"<>]+',r'\1[REDACTED]',message)
    message=re.sub(r'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}', '[REDACTED-EMAIL]',message)
    return message


def prune(folder, now=None):
    now=now or time.time()
    for path in folder.glob('p7-????????-*.jsonl'):
        if now-path.stat().st_mtime>14*86400:
            path.unlink()


def main():
    os.umask(0o077)
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--runtime',type=Path,required=True)
    parser.add_argument('--smtp',type=Path,required=True)
    a=parser.parse_args()
    folder=a.runtime/'logs';folder.mkdir(mode=0o700,exist_ok=True)
    values=[]
    def inventory(value):
        if isinstance(value,dict):
            for key,item in value.items():
                if isinstance(item,str) and key in ('password','bootstrap','db','client','recovery','username'):
                    values.append(item)
                else:inventory(item)
        elif isinstance(value,list):
            for item in value:inventory(item)
    inventory(p7.load(a.runtime/'installation.json'));inventory(p7.load(a.smtp))
    invitation_secret=a.runtime/'wallet-invitations-secret'
    if invitation_secret.exists():values.append(invitation_secret.read_text().strip())
    lock=threading.Lock()
    class Handler(socketserver.StreamRequestHandler):
        def handle(self):
            self.request.settimeout(120)
            try:
                while True:
                    line=self.rfile.readline(65537)
                    if not line:return
                    if len(line)>65536:continue
                    message=line.decode(errors='replace')
                    if 'competency-proof-p7-' not in message:continue
                    now=dt.datetime.now(dt.timezone.utc)
                    row=json.dumps({'at':now.isoformat(),'message':redact(message.rstrip(),values)})+'\n'
                    with lock:
                        day=now.strftime('%Y%m%d')
                        files=sorted(folder.glob('p7-'+day+'-*.jsonl'))
                        path=files[-1] if files else folder/('p7-'+day+'-000.jsonl')
                        if path.exists() and path.stat().st_size>=5*1024*1024:
                            index=int(path.stem.rsplit('-',1)[1])+1
                            path=folder/('p7-'+day+'-'+str(index).zfill(3)+'.jsonl')
                        with path.open('a') as stream:stream.write(row)
                        files=sorted(folder.glob('p7-'+day+'-*.jsonl'))
                        for old in files[:-3]:old.unlink()
            except (OSError,ValueError):
                return
    class Server(socketserver.ThreadingTCPServer):
        allow_reuse_address=True
        daemon_threads=True
    def cleanup():
        while True:
            with lock:prune(folder)
            time.sleep(60)
    threading.Thread(target=cleanup,daemon=True).start()
    with Server(('127.0.0.1',15140),Handler) as server:
        print('P7 log collector ready on loopback; bounded rotation and 14-day retention',flush=True)
        server.serve_forever()


if __name__=='__main__':main()
