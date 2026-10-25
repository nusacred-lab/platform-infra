"""Operate a private P7 deployment using the verified P6 distribution.

Never print credentials, tokens, SMTP responses, or action links. Public
registration stays closed: operator-issued invitations let wallet users verify
email and choose their own password.
"""
import argparse
import datetime as dt
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import smtplib
import socket
import ssl
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
from email.message import EmailMessage

SUBNET = '172.30.77.0/24'
ENTITIES = [('wallet', 'dompet-identitas', 'competency-proof-p2'),
            ('issuer', 'lsp-nusantara', 'lsp-nusantara'),
            ('company', 'karya-instalasi', 'karya-instalasi')]


def run(*args, **kw):
    return subprocess.run(list(map(str, args)), check=True, **kw)


def load(path):
    return json.loads(Path(path).read_text())


def save(path, value):
    path = Path(path)
    temporary = path.with_suffix(path.suffix + '.new')
    temporary.write_text(json.dumps(value, indent=2) + '\n')
    temporary.chmod(0o600)
    temporary.replace(path)


def trusted_context(cafile=None):
    context = ssl.create_default_context()
    if cafile:
        context.load_verify_locations(cafile=str(cafile))
    return context


def installer(package):
    sys.path.insert(0, str(package))
    spec = importlib.util.spec_from_file_location('p7_installer', package/'install.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    # The signed P6 helper expects a self-signed staging CA. Public TLS must also
    # retain system root CAs instead of trusting only the presented chain.
    module.ssl = SimpleNamespace(create_default_context=trusted_context)
    return module


def compose(a, *args, **kw):
    clean = {k: v for k, v in os.environ.items() if not k.startswith(('P6_', 'COMPOSE_'))}
    return run('docker', 'compose', '--env-file', a.runtime/'compose.env',
               '-f', a.runtime/'deployment.json', *args, env=clean, **kw)


def smtp_config(path):
    c = load(path)
    if any(not c.get(k) for k in ('host', 'port', 'tls_mode', 'username', 'password', 'from_address')):
        raise ValueError('Incomplete private SMTP configuration')
    if c['tls_mode'] not in ('starttls', 'tls'):
        raise ValueError('Require explicit TLS or STARTTLS; plaintext is forbidden')
    if int(c['port']) not in (465, 587):
        raise ValueError('SMTP egress is restricted to submission ports')
    return c


def smtp_settings(c, relay=False):
    return {'host': c['host'], 'port': '1587' if relay else str(c['port']), 'from': c['from_address'],
            'fromDisplayName': c.get('from_display_name', 'Competency Proof (demo)'),
            'auth': 'true', 'user': c['username'], 'password': c['password'],
            'ssl': str(c['tls_mode'] == 'tls').lower(),
            'starttls': str(c['tls_mode'] == 'starttls').lower(),
            'connectionTimeout': '10000', 'timeout': '10000', 'writeTimeout': '10000'}


def prepare(a):
    """Derive a recorded operational configuration; do not mutate the signed package."""
    i = installer(a.package)
    i.check_runtime(a.runtime)
    c = smtp_config(a.smtp)
    workstation = a.host_mode == 'workstation'
    doc = load(a.package/'compose.yaml')
    del doc['services']['mail']
    doc['services']['private-access']['ports'] = ['127.0.0.1:${P6_ADMIN_PORT:-28444}:8443']
    doc['networks']['smtp-egress'] = {'enable_ipv6': False, 'ipam': {'config': [{'subnet': SUBNET}]}}
    if workstation:
        # Explicit small networks avoid exhausting Docker's default /16 pools.
        for index, (name, network) in enumerate(doc['networks'].items()):
            network['ipam'] = {'config': [{'subnet': '10.203.70.'+str(index*16)+'/28'}]}
        doc['networks']['smtp-egress']['internal'] = True
        doc['networks']['smtp-egress']['ipam']['config'] = [{'subnet': '10.203.77.0/28', 'gateway': '10.203.77.1'}]
    for service in ('keycloak', 'issuer-keycloak', 'company-keycloak'):
        doc['services'][service]['networks'].append('smtp-egress')
        if workstation:
            doc['services'][service]['extra_hosts'] = [c['host']+':10.203.77.1']
    for service in doc['services'].values():
        service['logging'] = ({'driver': 'syslog', 'options': {'syslog-address': 'tcp://127.0.0.1:15140', 'syslog-format': 'rfc5424micro', 'tag': '{{.Name}}', 'cache-disabled': 'true', 'mode': 'non-blocking', 'max-buffer-size': '1m'}} if workstation else {'driver': 'journald', 'options': {'tag': '{{.Name}}'}})
    save(a.runtime/'deployment.json', doc)
    ingress = (a.package/'assets/ingress.caddy').read_text()
    ingress = ingress.replace('header {', 'header {\n        X-Competency-Environment p7-active')
    (a.runtime/'ingress.caddy').write_text(ingress)
    private = (a.runtime/'private.caddy').read_text()
    (a.runtime/'private.caddy').write_text(private.split('http://:8025')[0])
    for entity, _, realm in ENTITIES:
        path = a.runtime/(entity+'-import')/(realm+'-realm.json')
        row = load(path)
        row.update(smtpServer=smtp_settings(c, workstation), registrationAllowed=False, verifyEmail=True,
                   bruteForceProtected=True, failureFactor=5, waitIncrementSeconds=60,
                   maxFailureWaitSeconds=900, actionTokenGeneratedByAdminLifespan=900,
                   actionTokenGeneratedByUserLifespan=900)
        path.write_text(json.dumps(row, indent=2)+'\n')
    selected = load(a.operator_config) if a.operator_config else load(a.runtime/'operations.json')
    required = ('owner', 'alertRecipient', 'startsAt', 'closesAt', 'deleteAfter')
    if any(not selected.get(key) for key in required):
        raise ValueError('Select operator, alert recipient and explicit lifecycle dates privately')
    dates = [dt.datetime.fromisoformat(selected[key]) for key in required[2:]]
    if any(date.tzinfo is None for date in dates) or not dates[0] < dates[1] <= dates[2]:
        raise ValueError('Require ordered timezone-aware lifecycle dates')
    save(a.runtime/'operations.json', {
        **{key: selected[key] for key in required},
        'hostMode': a.host_mode,
        'timezone': 'Asia/Jakarta',
        'registration': 'operator-invitation-only', 'concurrentFlowTarget': 5,
        'logRetentionDays': 14, 'backupMaxAgeHours': 26,
        'backupRetention': 'until demo deletion on 2026-11-01',
        'smtpConfiguration': str(a.smtp),
        'backupLocation': 'operator laptop runtime/backups/p7; same-host backup when running on workstation',
        'sourceManifestSha256': i.checksum(a.runtime/'release-manifest.json'),
        'derivedComposeSha256': i.checksum(a.runtime/'deployment.json'),
        'gateG7': 'pending'})
    compose(a, 'config', '--quiet')
    print('PASS: operational configuration prepared; Mailpit removed; invitations only')


def firewall(a):
    c = smtp_config(a.smtp)
    addresses = sorted({row[4][0] for row in socket.getaddrinfo(c['host'], c['port'], socket.AF_INET, socket.SOCK_STREAM)})
    # Docker's own iptables backend owns this documented filter chain.
    if subprocess.run(['iptables', '-nL', 'DOCKER-USER'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode:
        run('iptables', '-N', 'DOCKER-USER')
    exists = subprocess.run(['iptables', '-nL', 'CP-P7-SMTP'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0
    if not exists:
        run('iptables', '-N', 'CP-P7-SMTP')
        run('iptables', '-A', 'CP-P7-SMTP', '-j', 'REJECT')
    # Add new allow rules before removing stale rules, preserving the final reject.
    for address in addresses:
        rule = ['-d', address+'/32', '-p', 'tcp', '--dport', str(c['port']), '-j', 'ACCEPT']
        if subprocess.run(['iptables', '-C', 'CP-P7-SMTP', *rule], stderr=subprocess.DEVNULL).returncode:
            run('iptables', '-I', 'CP-P7-SMTP', '1', *rule)
    jump = ['-s', SUBNET, '-j', 'CP-P7-SMTP']
    if subprocess.run(['iptables', '-C', 'DOCKER-USER', *jump], stderr=subprocess.DEVNULL).returncode:
        run('iptables', '-I', 'DOCKER-USER', '1', *jump)
    save(a.runtime/'smtp-egress.json', {'addresses': addresses, 'port': int(c['port']), 'subnet': SUBNET})
    print('PASS: identity egress limited to configured SMTP addresses and port')


def admin(a, entity, domain):
    i = installer(a.package)
    settings = load(a.runtime/'installation.json')['entities'][entity]
    status, result = i.request(a.runtime, domain, 'POST', '/realms/master/protocol/openid-connect/token',
        {'grant_type': 'password', 'client_id': 'admin-cli', 'username': entity+'-bootstrap',
         'password': settings['bootstrap']}, form=True)
    if status != 200:
        raise RuntimeError('Private identity administration failed: '+entity)
    return i, result['access_token']


def require_cached_images(a, installer_api, manifest):
    """Check exact verified default-profile images without contacting a registry."""
    env = installer_api.env_read(a.runtime/'compose.env')
    approved = {row['image'] for row in manifest['images'].values()}
    required = set()
    for service in load(a.runtime/'deployment.json')['services'].values():
        if service.get('profiles'):
            continue
        reference = service['image']
        variable = re.fullmatch(r'\$\{([A-Z][A-Z0-9_]*)(?::[^}]*)?\}', reference)
        image = env.get(variable.group(1)) if variable else reference
        if image not in approved or not re.fullmatch(r'.+@sha256:[a-f0-9]{64}', image):
            raise ValueError('Runtime service image is outside the verified manifest')
        required.add(image)
    if not required:
        raise ValueError('No default-profile runtime images selected')
    for image in sorted(required):
        inspected = subprocess.run(['docker', 'image', 'inspect', image],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if inspected.returncode:
            raise RuntimeError('Verified runtime image missing locally; preload the verified package before startup')
    return len(required)


def start(a):
    if dt.datetime.now(dt.timezone.utc) >= dt.datetime.fromisoformat(load(a.runtime/'operations.json')['closesAt']):
        raise ValueError('Demo period has ended; refuse startup')
    if (a.runtime/'closed.json').exists():
        raise ValueError('Demo is closed; explicit operator review is required before reopening')
    i = installer(a.package)
    manifest = i.check_runtime(a.runtime)
    require_cached_images(a, i, manifest)
    # Create the Docker chains before restricting egress; no IdP starts yet.
    workstation = load(a.runtime/'operations.json').get('hostMode') == 'workstation'
    if workstation:
        compose(a, 'create', '--pull', 'never', stdout=subprocess.DEVNULL)
        run('systemctl', '--user', 'start', 'competency-proof-p7-logs.service', 'competency-proof-p7-smtp-relay.service')
    else:
        compose(a, 'create', '--pull', 'never', 'postgres', stdout=subprocess.DEVNULL)
        firewall(a)
    def invoke(env_path, *args):
        args = tuple(x for x in args if x != 'mail')
        if args and args[0] in ('create', 'up'):
            args = (args[0], '--pull', 'never', *args[1:])
        compose(a, *args, stdout=subprocess.DEVNULL)
    i.compose = invoke
    i.start(a.runtime)
    c = smtp_config(a.smtp)
    for entity, domain, realm in ENTITIES:
        api, token = admin(a, entity, domain)
        status, row = api.request(a.runtime, domain, 'GET', '/admin/realms/'+realm, token=token)
        if status != 200:
            raise RuntimeError('Realm read failed')
        row.update(smtpServer=smtp_settings(c, workstation), registrationAllowed=False, verifyEmail=True,
                   bruteForceProtected=True, failureFactor=5, waitIncrementSeconds=60,
                   maxFailureWaitSeconds=900, actionTokenGeneratedByAdminLifespan=900,
                   actionTokenGeneratedByUserLifespan=900)
        if api.request(a.runtime, domain, 'PUT', '/admin/realms/'+realm, row, token)[0] != 204:
            raise RuntimeError('SMTP policy update failed')
    print('PASS: stack started; three identity realms use authenticated TLS SMTP')


def invite(a):
    """Create one controlled wallet account, then email verification/password setup."""
    email = a.email.strip()
    if '@' not in email or any(x in email for x in '\r\n'):
        raise ValueError('Require a valid operator-approved recipient')
    journal = a.runtime/'invitation-state.json'
    state = load(journal) if journal.exists() else {'lastSent': 0, 'sent': []}
    if time.time()-state['lastSent'] < 60:
        raise ValueError('Wait at least 60 seconds between invitations')
    i, token = admin(a, 'wallet', 'dompet-identitas')
    base = '/admin/realms/competency-proof-p2'
    from urllib.parse import urlencode
    status, users = i.request(a.runtime, 'dompet-identitas', 'GET', base+'/users?'+urlencode({'email': email, 'exact': 'true'}), token=token)
    if status != 200 or users:
        raise ValueError('Recipient is already registered or inventory unavailable; no blind resend')
    row = {'username': email, 'email': email, 'enabled': True, 'emailVerified': False,
           'firstName': 'Demo', 'lastName': 'Participant',
           'requiredActions': ['VERIFY_EMAIL', 'UPDATE_PASSWORD']}
    if i.request(a.runtime, 'dompet-identitas', 'POST', base+'/users', row, token)[0] != 201:
        raise RuntimeError('Invitation account creation failed')
    status, users = i.request(a.runtime, 'dompet-identitas', 'GET', base+'/users?'+urlencode({'email': email, 'exact': 'true'}), token=token)
    if status != 200 or len(users) != 1:
        raise RuntimeError('Invitation account reconciliation required')
    uid = users[0]['id']
    status, role = i.request(a.runtime, 'dompet-identitas', 'GET', base+'/roles/applicant', token=token)
    if status != 200 or i.request(a.runtime, 'dompet-identitas', 'POST', base+'/users/'+uid+'/role-mappings/realm', [role], token)[0] != 204:
        raise RuntimeError('Participant role assignment failed; reconcile account before sending')
    status, _ = i.request(a.runtime, 'dompet-identitas', 'PUT', base+'/users/'+uid+'/execute-actions-email?lifespan=900',
                          ['VERIFY_EMAIL', 'UPDATE_PASSWORD'], token)
    state['lastSent'] = time.time()
    state['sent'].append({'userId': uid, 'smtpAccepted': status == 204, 'at': dt.datetime.now(dt.timezone.utc).isoformat()})
    save(journal, state)
    if status != 204:
        raise RuntimeError('Invitation email failed; reconcile account before retrying')
    print('PASS: invitation accepted by SMTP; user must verify email and choose password; expires in 15 minutes')


def notify(a, subject, body):
    c = smtp_config(a.smtp)
    m = EmailMessage()
    m['From'] = c['from_address']
    m['To'] = load(a.runtime/'operations.json')['alertRecipient']
    m['Subject'] = 'Competency Proof P7 - '+subject
    m.set_content(body)
    ctx = ssl.create_default_context()
    smtp = smtplib.SMTP_SSL(c['host'], int(c['port']), timeout=10, context=ctx) if c['tls_mode'] == 'tls' else smtplib.SMTP(c['host'], int(c['port']), timeout=10)
    with smtp as s:
        s.ehlo()
        if c['tls_mode'] == 'starttls':
            s.starttls(context=ctx)
            s.ehlo()
        s.login(c['username'], c['password'])
        if s.send_message(m):
            raise RuntimeError('Operational alert recipient rejected')


def health(a):
    maintenance = a.runtime/'maintenance.json'
    if maintenance.exists() and time.time()-load(maintenance)['startedEpoch'] < 600:
        print(json.dumps({'status': 'planned-backup-maintenance', 'maximumSeconds': 600}))
        return 0
    i = installer(a.package)
    issues = []
    checks = {}
    for _, domain, realm in ENTITIES:
        try:
            status, data = i.request(a.runtime, domain, 'GET', '/realms/'+realm+'/.well-known/openid-configuration')
            ok = status == 200 and data['issuer'] == 'https://login-'+domain+'.demo.inoerawan.id/realms/'+realm
        except Exception:
            ok = False
        checks[domain+'-discovery'] = ok
        if not ok:
            issues.append(domain+'-discovery')
    import acceptance_transport
    acceptance_transport.ssl = SimpleNamespace(create_default_context=trusted_context)
    from acceptance_transport import Browser
    Browser.loopback_port = int(i.env_read(a.runtime/'compose.env')['P6_HTTPS_PORT'])
    Browser.cafile = str(a.runtime/'tls/fullchain.pem')
    for _, domain, _ in ENTITIES:
        try:
            status, _, raw = Browser().request('https://'+domain+'.demo.inoerawan.id/api/v1/portal-config')
            ok = status == 200 and isinstance(json.loads(raw), dict)
        except Exception:
            ok = False
        checks[domain+'-portal'] = ok
        if not ok:
            issues.append(domain+'-portal')
    memory = dict(line.split(':', 1) for line in Path('/proc/meminfo').read_text().splitlines())
    available = int(memory['MemAvailable'].split()[0])/int(memory['MemTotal'].split()[0])
    disk = shutil.disk_usage(a.runtime)
    if available < .25:
        issues.append('memory-below-25-percent')
    if disk.free/disk.total < .20:
        issues.append('disk-free-below-20-percent')
    cert = subprocess.run(['openssl', 'x509', '-checkend', '1209600', '-noout', '-in', str(a.runtime/'tls/fullchain.pem')], capture_output=True)
    if cert.returncode:
        issues.append('tls-expires-within-14-days')
    project = i.env_read(a.runtime/'compose.env')['P6_PROJECT_NAME']
    ids = subprocess.check_output(['docker', 'ps', '-aq', '--filter', 'label=com.docker.compose.project='+project], text=True).split()
    containers = load_json_command(['docker', 'inspect', *ids]) if ids else []
    metrics = []
    for row in containers:
        service = row['Config']['Labels']['com.docker.compose.service']
        if service == 'init-storage':
            continue
        metrics.append({'service': service, 'running': row['State']['Running'], 'oom': row['State']['OOMKilled'], 'restarts': row['RestartCount']})
        if not row['State']['Running'] or row['State']['OOMKilled'] or row['RestartCount']:
            issues.append('container-'+service)
    log_errors = 0
    smtp_errors = 0
    if load(a.runtime/'operations.json').get('hostMode') == 'workstation':
        collector = subprocess.run(['systemctl', '--user', 'is-active', '--quiet', 'competency-proof-p7-logs.service']).returncode == 0
        checks['log-collector'] = collector
        if not collector:
            issues.append('log-collector-down')
        cutoff = dt.datetime.now(dt.timezone.utc)-dt.timedelta(minutes=2)
        for path in sorted((a.runtime/'logs').glob('p7-*.jsonl'))[-3:]:
            from collections import deque
            with path.open() as stream:
                for line in deque(stream, maxlen=1000):
                    try:
                        record = json.loads(line)
                        if dt.datetime.fromisoformat(record['at']) < cutoff:
                            continue
                        message = record['message'].lower()
                        if ' error ' in message or '"level":"error"' in message:
                            log_errors += 1
                            if any(word in message for word in ('smtp', 'email', 'quota')):
                                smtp_errors += 1
                    except (ValueError, KeyError):
                        continue
        if smtp_errors:
            issues.append('smtp-delivery-errors')
        if log_errors >= 10:
            issues.append('elevated-application-errors')
    ack = a.runtime/'backup-ack.json'
    if not ack.exists() or time.time()-load(ack)['completedEpoch'] > 26*3600:
        issues.append('backup-missing-or-stale')
    result = {'at': dt.datetime.now(dt.timezone.utc).isoformat(), 'checks': checks,
              'issues': sorted(set(issues)), 'availableMemoryFraction': round(available, 3),
              'diskFreeBytes': disk.free, 'loadAverage': os.getloadavg(), 'containers': metrics,
              'applicationErrorsLast2Minutes': log_errors, 'smtpErrorsLast2Minutes': smtp_errors,
              'backupProtection': load(a.runtime/'operations.json').get('backupLocation')}
    prior = getattr(a, 'monitor_state', a.runtime/'monitor-state.json')
    old = load(prior).get('issues', []) if prior.exists() else []
    if sorted(old) != sorted(result['issues']):
        simulation = getattr(a, 'simulation_label', None)
        subject = ('[TEST '+simulation+'] ' if simulation else '')+('operational alert' if result['issues'] else 'recovered')
        notify(a, subject, json.dumps({'issues': result['issues'], 'previous': old, 'simulation': simulation}, indent=2))
        result['alertAcceptedBySmtp'] = True
    save(prior, result)
    print(json.dumps(result))
    return 1 if result['issues'] else 0


def load_json_command(args):
    return json.loads(subprocess.check_output(args, text=True))


def snapshot(a):
    """Stop all writers, snapshot every retained volume/config, then resume exactly those writers."""
    i = installer(a.package)
    project = i.env_read(a.runtime/'compose.env')['P6_PROJECT_NAME']
    ids = subprocess.check_output(['docker', 'ps', '-q', '--filter', 'label=com.docker.compose.project='+project], text=True).split()
    if not ids:
        raise ValueError('No running installation to snapshot')
    volumes = subprocess.check_output(['docker', 'volume', 'ls', '--filter', 'label=com.docker.compose.project='+project, '--format', '{{.Name}}'], text=True).split()
    if not volumes or any(not v.startswith(project+'_') for v in volumes):
        raise ValueError('Unexpected volume inventory')
    with tempfile.TemporaryDirectory(prefix='p7-snapshot-') as folder:
        target = Path(folder)
        os.chmod(target, 0o700)
        run('docker', 'stop', '--time', '30', *ids, stdout=subprocess.DEVNULL)
        try:
            if any(c['State']['Running'] for c in load_json_command(['docker', 'inspect', *ids])):
                raise RuntimeError('A writer is still running')
            shutil.copytree(a.runtime, target/'configuration', ignore=shutil.ignore_patterns('*.cms', 'backup-ack.json'))
            # Include the private SMTP input so identity recovery is complete.
            shutil.copyfile(a.smtp, target/'smtp.json')
            rows = []
            for volume in volumes:
                details = load_json_command(['docker', 'volume', 'inspect', volume])[0]
                mount = Path(details['Mountpoint'])
                filename = volume+'.tar.gz'
                if load(a.runtime/'operations.json').get('hostMode') == 'workstation':
                    image = load(a.runtime/'release-manifest.json')['images']['postgres']['image']
                    run('docker', 'run', '--rm', '--network', 'none', '--read-only',
                        '--security-opt', 'no-new-privileges:true', '--cap-drop', 'ALL',
                        '--cap-add', 'DAC_OVERRIDE', '--user', '0:0',
                        '-v', volume+':/snapshot:ro', '-v', str(target)+':/backup:z',
                        '--entrypoint', '/bin/sh', image, '-c',
                        'tar czf /backup/"$1" -C /snapshot .', 'sh', filename)
                else:
                    run('tar', '--numeric-owner', '-czf', target/filename, '-C', mount, '.')
                rows.append({'volume': volume, 'archive': filename, 'sha256': i.checksum(target/filename)})
            save(target/'snapshot.json', {'project': project, 'createdAt': dt.datetime.now(dt.timezone.utc).isoformat(),
                 'writersStopped': True, 'volumes': rows, 'releaseManifestSha256': i.checksum(a.runtime/'release-manifest.json')})
            # AES-GCM CMS authenticates the encrypted archive; only the operator holds the private key.
            tar = subprocess.Popen(['tar', '-czf', '-', '-C', folder, '.'], stdout=subprocess.PIPE)
            try:
                run('openssl', 'cms', '-encrypt', '-binary', '-aes-256-gcm', '-outform', 'DER',
                    a.runtime/'backup-recipient.pem', stdin=tar.stdout, stdout=sys.stdout.buffer)
            finally:
                tar.stdout.close()
                if tar.wait() != 0:
                    raise RuntimeError('Snapshot archive failed')
        finally:
            # Resume dependencies before BFFs so a consistent backup does not
            # induce application restart loops while identity discovery is cold.
            rows = load_json_command(['docker', 'inspect', *ids])
            infrastructure = {'postgres', 'issuer-postgres', 'company-postgres',
                              'keycloak', 'issuer-keycloak', 'company-keycloak',
                              'private-access', 'issuer', 'wallet', 'verifier'}
            first = [row['Id'] for row in rows if row['Config']['Labels']['com.docker.compose.service'] in infrastructure]
            rest = [row['Id'] for row in rows if row['Id'] not in first]
            run('docker', 'start', *first, stdout=subprocess.DEVNULL)
            for attempt in range(120):
                try:
                    if all(i.request(a.runtime, domain, 'GET', '/realms/'+realm+'/.well-known/openid-configuration')[0] == 200 for _, domain, realm in ENTITIES):
                        break
                except (OSError, ValueError, __import__('http.client', fromlist=['HTTPException']).HTTPException):
                    pass
                time.sleep(1)
            else:
                # Resume every original writer even when readiness needs operator attention.
                run('docker', 'start', *rest, stdout=subprocess.DEVNULL)
                raise RuntimeError('Identity readiness did not recover after backup')
            if rest:
                run('docker', 'start', *rest, stdout=subprocess.DEVNULL)


def main():
    os.umask(0o077)
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--runtime', type=Path, required=True)
    p.add_argument('--package', type=Path, required=True)
    p.add_argument('--smtp', type=Path, required=True)
    p.add_argument('--host-mode', choices=['vm', 'workstation'], default='vm')
    p.add_argument('--operator-config', type=Path)
    sub = p.add_subparsers(dest='command', required=True)
    for name in ('prepare', 'start', 'firewall', 'snapshot'):
        sub.add_parser(name)
    sub.add_parser('health')
    inv = sub.add_parser('invite'); inv.add_argument('--email', required=True)
    a = p.parse_args()
    if a.command == 'health':
        raise SystemExit(health(a))
    globals()[a.command](a)


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, RuntimeError, smtplib.SMTPException, subprocess.CalledProcessError) as error:
        # API/SMTP error payloads may contain private addresses, passwords or action links.
        print('P7 operation failed: '+type(error).__name__, file=sys.stderr)
        raise SystemExit(1)
