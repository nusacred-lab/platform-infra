"""Restore a private backup to a fixed isolated rehearsal project; never overwrite P7."""
import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import time
import p7


def safe_archive(path):
    with tarfile.open(path) as archive:
        for member in archive:
            name = Path(member.name)
            if name.is_absolute() or '..' in name.parts:
                raise ValueError('Unsafe archive path')
            if member.issym() or member.islnk():
                link = Path(member.linkname)
                if link.is_absolute() or '..' in link.parts:
                    raise ValueError('Unsafe archive link')


def main():
    os.umask(0o077)
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--archive', type=Path, required=True)
    p.add_argument('--package', type=Path, required=True)
    a = p.parse_args()
    started = time.monotonic()
    root = Path('/home/ubuntu/competency-proof/runtime')
    runtime = root/'p7-rehearsal'
    if runtime.exists():
        raise ValueError('Refuse to overwrite an existing rehearsal')
    extraction = root/'restore-input/extracted'
    extraction.mkdir(mode=0o700)
    safe_archive(a.archive)
    subprocess.run(['tar', '--same-permissions', '-xzf', str(a.archive), '-C', str(extraction)], check=True)
    snapshot = p7.load(extraction/'snapshot.json')
    assert snapshot['project'] == 'competency-proof-p7' and snapshot['writersStopped'] is True
    runtime.mkdir(mode=0o700)
    shutil.copytree(extraction/'configuration', runtime, dirs_exist_ok=True)
    shutil.copyfile(extraction/'smtp.json', runtime/'smtp.json')
    i = p7.installer(a.package)
    env = i.env_read(runtime/'compose.env')
    project = 'competency-proof-p7-rehearsal'
    env.update(P6_RUNTIME=str(runtime), P6_PROJECT_NAME=project, P6_HTTPS_PORT='39443', P6_ADMIN_PORT='39444')
    (runtime/'compose.env').write_text(''.join(k+'='+v+'\n' for k,v in env.items()))
    installation = p7.load(runtime/'installation.json');installation['project'] = project;p7.save(runtime/'installation.json', installation)
    compose = p7.load(runtime/'deployment.json')
    del compose['networks']['smtp-egress']
    # Restored identities are identical but cannot deliver any email externally.
    for service in ('keycloak','issuer-keycloak','company-keycloak'):
        compose['services'][service]['networks'].remove('smtp-egress')
    p7.save(runtime/'deployment.json', compose)
    a.runtime = runtime
    a.smtp = runtime/'smtp.json'
    p7.compose(a, 'create', stdout=subprocess.DEVNULL)
    for row in snapshot['volumes']:
        source = extraction/row['archive']
        assert i.checksum(source) == row['sha256']
        safe_archive(source)
        name = row['volume'].replace('competency-proof-p7_', project+'_', 1)
        assert name.startswith(project+'_')
        mount = p7.load_json_command(['docker', 'volume', 'inspect', name])[0]['Mountpoint']
        subprocess.run(['tar', '--same-permissions', '--numeric-owner', '-xzf', str(source), '-C', mount], check=True)
    p7.compose(a, 'up', '-d', '--no-build', stdout=subprocess.DEVNULL)
    for attempt in range(120):
        try:
            if all(i.request(runtime,d,'GET','/realms/'+realm+'/.well-known/openid-configuration')[0] == 200 for _,d,realm in p7.ENTITIES):
                break
        except Exception:
            pass
        time.sleep(1)
    else:
        raise RuntimeError('Restored identity readiness timeout')
    integrity = []
    for row in snapshot['volumes']:
        name = row['volume'].replace('competency-proof-p7_', project+'_', 1)
        mount = Path(p7.load_json_command(['docker', 'volume', 'inspect', name])[0]['Mountpoint'])
        import sqlite3
        for database in list(mount.rglob('*.sqlite'))+list(mount.rglob('*.db')):
            # This inspection is read-only and never changes the restored database.
            with sqlite3.connect('file:'+str(database)+'?mode=ro',uri=True) as connection:
                assert connection.execute('PRAGMA integrity_check').fetchone()[0] == 'ok'
            integrity.append(database.name)
    checks = {'result': 'PASS', 'snapshotCreatedAt': snapshot['createdAt'],
              'volumeChecksumsVerified': len(snapshot['volumes']), 'sqliteIntegrity': integrity,
              'restorePreparationSeconds': round(time.monotonic()-started,3),
              'issuerKeysIdentical': i.checksum(runtime/'issuer-keys.json') == i.checksum(extraction/'configuration/issuer-keys.json'),
              'offerKeyIdentical': i.checksum(runtime/'offer-reference-key') == i.checksum(extraction/'configuration/offer-reference-key'),
              'credentialPresentation': 'pending separate post-restore protocol test',
              'isolation': 'separate project/volumes/networks, loopback 39443/39444, no SMTP egress'}
    p7.save(root/'p7/restore-rehearsal.json', checks)
    shutil.rmtree(extraction)
    a.archive.unlink()
    print(json.dumps(checks))


if __name__ == '__main__':
    main()
