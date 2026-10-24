"""Install reviewed P7 units on the dedicated Ubuntu VM (root required)."""
from pathlib import Path
import subprocess

root = '/home/ubuntu/competency-proof'
args = '--runtime '+root+'/runtime/p7 --package '+root+'/package --smtp /home/ubuntu/.config/competency-proof/p7/smtp.json'
ops = '/usr/bin/python3 '+root+'/operations/p7.py '+args
units = {
'competency-proof-p7-egress.service': f'''[Unit]
Description=Restrict P7 identity SMTP egress before Docker
Wants=network-online.target
After=network-online.target
Before=docker.service
[Service]
Type=oneshot
ExecStart={ops} firewall
RemainAfterExit=yes
[Install]
WantedBy=multi-user.target
''',
'competency-proof-p7.service': f'''[Unit]
Description=Competency Proof P7 verified runtime
Requires=docker.service competency-proof-p7-egress.service
After=docker.service competency-proof-p7-egress.service network-online.target
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart={ops} start
ExecStop=/usr/bin/docker compose --env-file {root}/runtime/p7/compose.env -f {root}/runtime/p7/deployment.json stop
TimeoutStartSec=600
TimeoutStopSec=120
[Install]
WantedBy=multi-user.target
''',
'competency-proof-p7-health.service': f'''[Unit]
Description=Check P7 application, capacity, TLS and external backup
After=competency-proof-p7.service
ConditionPathExists={root}/runtime/p7/operations.json
[Service]
Type=oneshot
ExecStart={ops} health
SuccessExitStatus=1
TimeoutStartSec=120
''',
'competency-proof-p7-health.timer': '''[Unit]
Description=Check P7 every two minutes
[Timer]
OnBootSec=3min
OnUnitActiveSec=2min
[Install]
WantedBy=timers.target
''',
'competency-proof-p7-tunnel.service': f'''[Unit]
Description=Private Pinggy TLS passthrough for P7
Requires=competency-proof-p7.service
After=competency-proof-p7.service network-online.target
ConditionPathExists={root}/runtime/p7/ssh/config
[Service]
Type=simple
User=ubuntu
ExecStart=/usr/bin/python3 {root}/operations/tunnel.py --config {root}/runtime/p7/ssh/config
Restart=on-failure
RestartSec=10
TimeoutStopSec=15
[Install]
WantedBy=multi-user.target
''',
}
for action, deadline in [('close', '2026-11-01 00:00:00 Asia/Jakarta'), ('delete', '2026-11-01 12:00:00 Asia/Jakarta')]:
    name = 'competency-proof-p7-'+action
    units[name+'.service'] = f'''[Unit]
Description=Scheduled P7 {action}; exact P7 project only
[Service]
Type=oneshot
ExecStart=/usr/bin/python3 {root}/operations/lifecycle.py {args} {action}
TimeoutStartSec=300
'''
    units[name+'.timer'] = f'''[Unit]
Description=Scheduled P7 {action}
[Timer]
OnCalendar={deadline}
Persistent=true
[Install]
WantedBy=timers.target
'''
for name, text in units.items():
    (Path('/etc/systemd/system')/name).write_text(text)
dropin = Path('/etc/systemd/system/docker.service.d'); dropin.mkdir(exist_ok=True)
(dropin/'p7-egress.conf').write_text('[Unit]\nRequires=competency-proof-p7-egress.service\nAfter=competency-proof-p7-egress.service\n')
journal = Path('/etc/systemd/journald.conf.d'); journal.mkdir(exist_ok=True)
(journal/'p7-retention.conf').write_text('[Journal]\nStorage=persistent\nMaxRetentionSec=14day\nMaxFileSec=1day\nSystemMaxUse=256M\nRuntimeMaxUse=64M\nForwardToSyslog=no\n')
subprocess.run(['systemctl', 'restart', 'systemd-journald'], check=True)
subprocess.run(['systemctl', 'daemon-reload'], check=True)
subprocess.run(['systemd-analyze', 'verify', *[str(Path('/etc/systemd/system')/x) for x in units]], check=True)
# Tunnel and deletion are enabled separately after their acceptance/rehearsal.
subprocess.run(['systemctl', 'enable', 'competency-proof-p7-egress.service', 'competency-proof-p7.service',
                'competency-proof-p7-health.timer', 'competency-proof-p7-close.timer'], check=True)
print('PASS: boot, monitoring, log retention and closure units installed; tunnel/deletion require tested activation')
