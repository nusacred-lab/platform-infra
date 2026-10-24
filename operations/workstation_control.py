"""Start, stop, or inspect the single P7 workstation stack without deleting data."""
import argparse
import datetime as dt
import fcntl
import json
import http.client
from pathlib import Path
import shlex
import subprocess
import sys
import time

PREFIX = 'competency-proof-p7-'
APP = 'competency-proof-p7.service'
TUNNEL = PREFIX+'tunnel.service'
BACKUP = PREFIX+'backup.service'
TIMERS = [PREFIX+x+'.timer' for x in ('health', 'public', 'backup')]
CHECKS = [PREFIX+x+'.service' for x in ('health', 'public')]
AUXILIARY = [PREFIX+'smtp-relay.service', PREFIX+'logs.service']
WORKSPACE = Path(__file__).resolve().parents[3]
RUNTIME = WORKSPACE/'runtime/p7/active'
PACKAGE = WORKSPACE/'runtime/p6/final-distribution/competency-proof'


def run(args, dry_run=False):
    if dry_run:
        print('Would run: '+shlex.join(map(str, args)))
        return
    subprocess.run(list(map(str,args)), check=True)


def active(unit):
    # A running oneshot is "activating"; do not interrupt an in-progress backup.
    result = subprocess.run(['systemctl','--user','show',unit,'--property=ActiveState','--value'],
                            capture_output=True,text=True,check=True)
    return result.stdout.strip() in ('active','activating','reloading')


def systemctl(action, *units, dry_run=False):
    run(['systemctl','--user',action,*units],dry_run)


def compose_stop(dry_run=False):
    run(['docker','compose','--env-file',RUNTIME/'compose.env',
         '-f',RUNTIME/'deployment.json','stop'],dry_run)


def stop(dry_run=False):
    previous = {unit: active(unit) for unit in [*TIMERS,TUNNEL]}
    systemctl('stop',*TIMERS,*CHECKS,dry_run=dry_run)
    try:
        # Repeated "start" joins an already activating oneshot instead of killing it.
        backup_completed = False
        if active(BACKUP):
            print('Waiting for the current backup to finish.')
            systemctl('start',BACKUP,dry_run=dry_run)
            backup_completed = True
        systemctl('stop',TUNNEL,dry_run=dry_run)
        if active(APP) and not backup_completed:
            print('Creating an encrypted backup before stopping P7.')
            systemctl('start',BACKUP,dry_run=dry_run)
        elif not active(APP) and not dry_run:
            # A stopped app service with live containers needs operator inspection.
            ids = subprocess.check_output(['docker','ps','-q','--filter',
                'label=com.docker.compose.project=competency-proof-p7'],text=True).strip()
            if ids:
                raise RuntimeError('P7 containers are running outside their service; start P7 normally before stopping')
    except BaseException:
        # A failed backup must not silently shut down the only live copy.
        for unit,was_active in previous.items():
            if was_active:
                systemctl('start',unit,dry_run=dry_run)
        raise
    systemctl('stop',APP,dry_run=dry_run)
    # Also cover an already inactive service, without removing containers or volumes.
    compose_stop(dry_run)
    systemctl('stop',*AUXILIARY,dry_run=dry_run)
    print('Dry run complete; no services changed.' if dry_run else 'P7 is stopped. Data and keys are retained; the laptop can now be shut down.')


def ready():
    sys.path.insert(0,str(PACKAGE))
    import p7
    from types import SimpleNamespace
    import acceptance_transport
    acceptance_transport.ssl=SimpleNamespace(create_default_context=p7.trusted_context)
    from acceptance_transport import Browser
    api=p7.installer(PACKAGE)
    Browser.loopback_port=int(api.env_read(RUNTIME/'compose.env')['P6_HTTPS_PORT'])
    Browser.cafile=str(RUNTIME/'tls/fullchain.pem')
    for attempt in range(60):
        try:
            for _,domain,realm in p7.ENTITIES:
                status,_=api.request(RUNTIME,domain,'GET','/realms/'+realm+'/.well-known/openid-configuration')
                if status!=200:raise RuntimeError('Identity not ready')
                status,_,body=Browser().request('https://'+domain+'.demo.inoerawan.id/api/v1/portal-config')
                if status!=200 or not isinstance(json.loads(body),dict):raise RuntimeError('Portal not ready')
            return
        except (OSError,ValueError,RuntimeError,http.client.HTTPException):
            time.sleep(1)
    raise RuntimeError('P7 did not become ready; public tunnel has not been started')


def start(dry_run=False):
    cfg=json.loads((RUNTIME/'operations.json').read_text())
    if dt.datetime.now(dt.timezone.utc)>=dt.datetime.fromisoformat(cfg['closesAt']) or (RUNTIME/'closed.json').exists():
        raise RuntimeError('Demo period is closed; normal startup is blocked')
    if not dry_run:
        subprocess.run(['docker','info','--format','{{.ServerVersion}}'],check=True,stdout=subprocess.DEVNULL)
    systemctl('start',PREFIX+'logs.service',dry_run=dry_run)
    systemctl('start',APP,dry_run=dry_run)
    if not dry_run:
        print('Waiting for identity and application readiness.')
        ready()
    systemctl('start',TUNNEL,dry_run=dry_run)
    systemctl('start',*TIMERS,PREFIX+'close.timer',dry_run=dry_run)
    print('Dry run complete; no services changed.' if dry_run else 'P7 is running. Public tunnel, monitoring and backup schedule are active.')


def status():
    for unit in [APP,TUNNEL,*AUXILIARY,*TIMERS,PREFIX+'close.timer']:
        print(('active  ' if active(unit) else 'stopped ')+unit)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command',choices=['start','stop','status'])
    parser.add_argument('--dry-run',action='store_true',help='Show lifecycle commands without changing services')
    args=parser.parse_args()
    if args.command=='status':
        status();return
    lock_path=RUNTIME.parent/'control.lock'
    with lock_path.open('w') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        globals()[args.command](args.dry_run)


if __name__=='__main__':
    try:
        main()
    except (OSError,RuntimeError,subprocess.CalledProcessError) as error:
        print('P7 operation did not complete: '+type(error).__name__+'. Check service status before proceeding.',file=sys.stderr)
        raise SystemExit(1)
