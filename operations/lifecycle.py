"""Close or delete only the explicitly identified P7 installation after its deadline."""
import argparse
import datetime as dt
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess


def validate_target(runtime, project, rehearsal, workstation=False):
    expected = 'competency-proof-p7-rehearsal' if rehearsal else 'competency-proof-p7'
    folder = 'p7-rehearsal' if rehearsal else 'p7'
    if workstation:
        workspace = Path(__file__).resolve().parents[3]
        allowed = workspace/'runtime/p7'/('rehearsal' if rehearsal else 'active')
    else:
        allowed = Path('/home/ubuntu/competency-proof/runtime')/folder
    if project != expected or Path(runtime).resolve() != allowed:
        raise ValueError('Lifecycle refuses this project or runtime')
    return expected


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--runtime', type=Path, required=True)
    p.add_argument('--package', type=Path, required=True)
    p.add_argument('--smtp', type=Path, required=True)
    p.add_argument('--rehearsal', action='store_true')
    p.add_argument('--host-mode', choices=['vm', 'workstation'], default='vm')
    p.add_argument('command', choices=['close', 'delete'])
    a = p.parse_args()
    spec = importlib.util.spec_from_file_location('p7', Path(__file__).with_name('p7.py'))
    ops = importlib.util.module_from_spec(spec); spec.loader.exec_module(ops)
    cfg = ops.load(a.runtime/'operations.json')
    env = ops.installer(a.package).env_read(a.runtime/'compose.env')
    workstation = a.host_mode == 'workstation'
    project = validate_target(a.runtime, env['P6_PROJECT_NAME'], a.rehearsal, workstation)
    systemctl = ['systemctl', '--user'] if workstation else ['systemctl']
    if a.rehearsal and a.smtp.resolve() != a.runtime.resolve()/'smtp.json':
        raise ValueError('Rehearsal SMTP path must stay inside the disposable runtime')
    now = dt.datetime.now(dt.timezone.utc)
    deadline = dt.datetime.fromisoformat(cfg['closesAt' if a.command == 'close' else 'deleteAfter'])
    if not a.rehearsal and now < deadline:
        raise ValueError('Scheduled deadline has not arrived')
    if a.command == 'close':
        # Close public ingress first, even if a private revocation later fails.
        if not a.rehearsal:
            subprocess.run(systemctl+['stop', 'competency-proof-p7-tunnel.service'], check=True)
        for entity, domain, realm in ops.ENTITIES:
            api, token = ops.admin(a, entity, domain)
            status, _ = api.request(a.runtime, domain, 'POST', '/admin/realms/'+realm+'/logout-all', token=token)
            if status not in (200, 204):
                raise RuntimeError('Session revocation failed; investigate before deleting data')
        ops.compose(a, 'stop', stdout=subprocess.DEVNULL)
        ops.save(a.runtime/'closed.json', {'closedAt': now.isoformat(), 'sessionsRevoked': True})
        print('PASS: P7 closed; sessions revoked and writers stopped')
    else:
        if not (a.runtime/'closed.json').exists():
            raise ValueError('Close and revoke access before deletion')
        ids = subprocess.check_output(['docker', 'ps', '-q', '--filter', 'label=com.docker.compose.project='+project], text=True).split()
        if ids:
            raise ValueError('A P7 writer is still running')
        if not a.rehearsal:
            subprocess.run(systemctl+['stop', 'competency-proof-p7-health.timer', 'competency-proof-p7-backup.timer', 'competency-proof-p7.service'], check=True)
        ops.compose(a, 'down', stdout=subprocess.DEVNULL)
        volumes = subprocess.check_output(['docker', 'volume', 'ls', '--filter', 'label=com.docker.compose.project='+project, '--format', '{{.Name}}'], text=True).split()
        if any(not x.startswith(project+'_') for x in volumes):
            raise ValueError('Unexpected volume identity')
        for volume in volumes:
            ops.run('docker', 'volume', 'rm', volume, stdout=subprocess.DEVNULL)
        audit = a.runtime.parent/(project+'-deletion-audit.json')
        ops.save(audit, {'deletedAt': now.isoformat(), 'project': project, 'volumeCount': len(volumes)})
        shutil.rmtree(a.runtime)
        a.smtp.unlink(missing_ok=True)
        a.smtp.with_name('smtp.before-host-fix.json').unlink(missing_ok=True)
        if workstation and not a.rehearsal:
            workspace = Path(__file__).resolve().parents[3]
            backups = workspace/'runtime/backups/p7'
            if backups.exists():
                shutil.rmtree(backups)
            for name in ('prepared', 'local-restore-input'):
                path = workspace/'runtime/p7'/name
                if path.exists():
                    shutil.rmtree(path)
            for name in ('backup-decryption-key.pem', 'backup-recipient.pem'):
                (workspace/'runtime/p7'/name).unlink(missing_ok=True)
        print('PASS: exact P7 runtime and project volumes deleted; sanitized audit retained')


if __name__ == '__main__':
    os.umask(0o077)
    main()
