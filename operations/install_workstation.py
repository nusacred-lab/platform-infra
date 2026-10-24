"""Install user services for the single P7 stack on the operator workstation."""
import argparse
from pathlib import Path
import shlex
import subprocess
import sys

p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--runtime',type=Path,required=True)
p.add_argument('--package',type=Path,required=True)
p.add_argument('--smtp',type=Path,required=True)
a=p.parse_args()
operations=Path(__file__).resolve().parent
python=sys.executable
args=['--runtime',str(a.runtime.resolve()),'--package',str(a.package.resolve()),'--smtp',str(a.smtp.resolve()),'--host-mode','workstation']
ops=shlex.join([python,str(operations/'p7.py'),*args])
relay=shlex.join([python,str(operations/'smtp_relay.py'),'--smtp',str(a.smtp.resolve())])
folder=Path.home()/'.config/systemd/user';folder.mkdir(parents=True,exist_ok=True)
units={
'competency-proof-p7-logs.service':f'''[Unit]
Description=P7 redacted log collector with 14-day retention
[Service]
ExecStart={shlex.join([python,str(operations/'log_collector.py'),'--runtime',str(a.runtime.resolve()),'--smtp',str(a.smtp.resolve())])}
Restart=on-failure
RestartSec=5
NoNewPrivileges=yes
[Install]
WantedBy=default.target
''',
'competency-proof-p7-smtp-relay.service':f'''[Unit]
Description=Bounded P7 SMTP relay on internal Docker bridge
[Service]
ExecStart={relay}
Restart=on-failure
RestartSec=5
NoNewPrivileges=yes
[Install]
WantedBy=default.target
''',
'competency-proof-p7.service':f'''[Unit]
Description=Single P7 runtime on the operator workstation
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart={ops} start
ExecStop=/usr/bin/docker compose --env-file {a.runtime.resolve()}/compose.env -f {a.runtime.resolve()}/deployment.json stop
ExecStopPost=/usr/bin/systemctl --user stop competency-proof-p7-smtp-relay.service
TimeoutStartSec=600
TimeoutStopSec=120
[Install]
WantedBy=default.target
''',
'competency-proof-p7-health.service':f'''[Unit]
Description=P7 readiness and resource checks
After=competency-proof-p7.service
ConditionPathExists={a.runtime.resolve()}/operations.json
[Service]
Type=oneshot
ExecStart={ops} health
SuccessExitStatus=1
TimeoutStartSec=120
''',
'competency-proof-p7-health.timer':'''[Unit]
Description=P7 readiness every two minutes
[Timer]
OnBootSec=3min
OnUnitActiveSec=2min
[Install]
WantedBy=timers.target
''',
'competency-proof-p7-tunnel.service':f'''[Unit]
Description=P7 Pinggy TLS passthrough
After=competency-proof-p7.service
ConditionPathExists={a.runtime.resolve()}/ssh/config
[Service]
ExecStart={shlex.join([python,str(operations/'tunnel.py'),'--config',str(a.runtime.resolve()/'ssh/config')])}
Restart=on-failure
RestartSec=10
TimeoutStopSec=15
[Install]
WantedBy=default.target
'''
}
backup=shlex.join([python,str(operations/'backup_local.py'),'--runtime',str(a.runtime.resolve()),'--package',str(a.package.resolve()),'--smtp',str(a.smtp.resolve()),'--destination',str(a.runtime.resolve().parents[1]/'backups/p7')])
units['competency-proof-p7-backup.service']=f'''[Unit]
Description=Encrypted P7 backup to selected same-host folder
Requires=competency-proof-p7.service
After=competency-proof-p7.service
[Service]
Type=oneshot
ExecStart={backup}
TimeoutStartSec=700
'''
units['competency-proof-p7-backup.timer']='''[Unit]
Description=Daily P7 backup during approved demo dates
[Timer]
OnCalendar=2026-10-24..31 02:00:00 Asia/Jakarta
Persistent=true
[Install]
WantedBy=timers.target
'''
for action,deadline in [('close','2026-11-01 00:00:00 Asia/Jakarta'),('delete','2026-11-01 12:00:00 Asia/Jakarta')]:
    command=shlex.join([python,str(operations/'lifecycle.py'),*args,action])
    units['competency-proof-p7-'+action+'.service']=f'''[Unit]
Description=P7 {action}, exact project and path guards
[Service]
Type=oneshot
ExecStart={command}
TimeoutStartSec=300
'''
    units['competency-proof-p7-'+action+'.timer']=f'''[Unit]
Description=Scheduled P7 {action}
[Timer]
OnCalendar={deadline}
Persistent=true
[Install]
WantedBy=timers.target
'''
monitor=shlex.join([python,str(operations/'external_monitor.py'),'--runtime',str(a.runtime.resolve()),'--package',str(a.package.resolve()),'--smtp',str(a.smtp.resolve())])
units['competency-proof-p7-public.service']=f'''[Unit]
Description=P7 public HTTPS and synthetic login monitor on this workstation
After=competency-proof-p7.service
[Service]
Type=oneshot
ExecStart={monitor}
SuccessExitStatus=1
TimeoutStartSec=180
'''
units['competency-proof-p7-public.timer']='''[Unit]
Description=P7 public-path checks every three minutes
[Timer]
OnBootSec=4min
OnUnitActiveSec=3min
[Install]
WantedBy=timers.target
'''
for name,text in units.items():(folder/name).write_text(text)
subprocess.run(['systemctl','--user','daemon-reload'],check=True)
subprocess.run(['systemd-analyze','--user','verify',*[str(folder/x) for x in units]],check=True)
print('PASS: user service definitions installed; no root firewall changes; activation follows checks')
