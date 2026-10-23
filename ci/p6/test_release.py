"""Exercise release verification rejection and source-free Compose boundaries."""
import copy
import importlib.util
import json
from pathlib import Path
import unittest
import contextlib
import io
import subprocess
import sys
import tempfile
from scan_gate import scan

ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('installer',ROOT/'release/install.py')
installer=importlib.util.module_from_spec(spec);spec.loader.exec_module(installer)

class ReleasePolicyTest(unittest.TestCase):
    def setUp(self):
        self.commit='a'*40
        self.ref='refs/heads/codex/p6-release'
        self.manifest=dict(schemaVersion=1,scope='synthetic-isolated-demo-only',productionEligible=False,
            infrastructureRevision=self.commit,workflow=dict(repository='nusacred-lab/platform-infra',path='.github/workflows/release.yml',commit=self.commit,ref=self.ref),
            sources=dict(application=dict(repository='nusacred-lab/competency-proof',commit='b'*40),fork=dict(repository='nusacred-lab/waltid-identity',commit='c'*40)),images={})
        self.manifest['schemas']={'custodianRegistry':5,'businessMigrations':3,'policyVersion':'competency-v1'}
        self.manifest['apk']={'sourceRevision':'b'*40,'applicationId':'id.nusacred.wallet','versionCode':5,'versionName':'0.6.0-p6','unsignedSha256':'f'*64}
        for name in installer.KINDS:
            revision='b'*40 if name in ('custodian','issuer','company') else 'c'*40 if name.startswith('walt-') else self.commit
            self.manifest['images'][name]=dict(image='ghcr.io/nusacred-lab/competency-proof-'+name+'@sha256:'+'d'*64,
                sourceRevision=revision,signerIdentity='https://github.com/nusacred-lab/platform-infra/.github/workflows/release.yml@'+self.ref)

    def test_expected_manifest(self):
        installer.validate_manifest(self.manifest,self.commit,self.ref)

    def test_reject_wrong_workflow_repository_commit_and_ref(self):
        for field,value in [('repository','attacker/repo'),('path','.github/workflows/other.yml'),('commit','e'*40),('ref','refs/heads/untrusted')]:
            candidate=copy.deepcopy(self.manifest);candidate['workflow'][field]=value
            with self.subTest(field=field), self.assertRaises(ValueError):installer.validate_manifest(candidate,self.commit,self.ref)

    def test_reject_mutable_wrong_registry_missing_image_mixed_sources_and_signer(self):
        for field,value in [('image','ghcr.io/nusacred-lab/competency-proof-custodian:latest'),('image','ghcr.io/attacker/custodian@sha256:'+'d'*64),('sourceRevision','e'*40),('signerIdentity','https://github.com/attacker/repo')]:
            candidate=copy.deepcopy(self.manifest);candidate['images']['custodian'][field]=value
            with self.subTest(field=field,value=value), self.assertRaises(ValueError):installer.validate_manifest(candidate,self.commit,self.ref)
        del self.manifest['images']['edge']
        with self.assertRaises(ValueError):installer.validate_manifest(self.manifest,self.commit,self.ref)

    def test_reject_unknown_schema_and_unbound_apk(self):
        for section, field, value in [('schemas','custodianRegistry',6),('apk','sourceRevision','e'*40),('apk','unsignedSha256',''),('apk','versionCode',4)]:
            candidate=copy.deepcopy(self.manifest);candidate[section][field]=value
            with self.subTest(section=section,field=field),self.assertRaises(ValueError):
                installer.validate_manifest(candidate,self.commit,self.ref)

    def test_compose_has_no_build_external_network_or_public_admin(self):
        compose=json.loads((ROOT/'release/compose.yaml').read_text())
        self.assertFalse(any(n.get('external') for n in compose['networks'].values()))
        for name,service in compose['services'].items():
            with self.subTest(service=name):
                self.assertNotIn('build',service)
                self.assertTrue(service['image'].startswith('${P6_'))
                for port in service.get('ports',[]):self.assertTrue(port.startswith('127.0.0.1:'))
                self.assertNotIn('/var/run/docker.sock',json.dumps(service))
        self.assertEqual(compose['services']['protocol-access']['profiles'],['acceptance'])
        self.assertEqual(compose['services']['init-storage']['cap_add'],['CHOWN'])

class ScannerHealthTest(unittest.TestCase):
    def run_fixture(self, program, previous=False):
        with tempfile.TemporaryDirectory() as directory:
            report=Path(directory)/'scan.json'
            if previous:report.write_text('{"Results": []}')
            command=[sys.executable,'-c',program,'--severity','HIGH,CRITICAL','--output',str(report)]
            with contextlib.redirect_stderr(io.StringIO()):
                return scan(command)

    @staticmethod
    def fixture(findings=None, warning=''):
        data={'SchemaVersion':2,'Results':[{'Packages':[{'Name':'fixture'}],'Vulnerabilities':findings or []}]}
        return ('import json,sys;from pathlib import Path;'
                'assert "UNKNOWN" in sys.argv[sys.argv.index("--severity")+1];'
                'Path(sys.argv[sys.argv.index("--output")+1]).write_text('+repr(json.dumps(data))+');'
                'sys.stderr.write('+repr(warning)+')')

    def test_complete_clean_scan_succeeds(self):
        self.assertEqual(self.run_fixture(self.fixture()).returncode,0)

    def test_zero_exit_with_missing_vulnerability_details_is_rejected(self):
        with self.assertRaisesRegex(RuntimeError,'details are incomplete'):
            self.run_fixture(self.fixture(warning='WARN Unable to get vulnerability details (CVE may be rejected)'))

    def test_zero_exit_with_unclassified_finding_is_rejected(self):
        with self.assertRaisesRegex(RuntimeError,'unclassified'):
            self.run_fixture(self.fixture([{'Severity':'UNKNOWN','VulnerabilityID':'CVE-fixture'}]))

    def test_failed_or_missing_scan_cannot_reuse_old_clean_report(self):
        with self.assertRaises(subprocess.CalledProcessError):
            self.run_fixture('import sys;sys.exit(7)',previous=True)
        with self.assertRaises(FileNotFoundError):
            self.run_fixture('pass',previous=True)

if __name__=='__main__':unittest.main()
