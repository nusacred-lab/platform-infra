"""Exercise release verification rejection and source-free Compose boundaries."""
import copy
import importlib.util
import json
from pathlib import Path
import unittest

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

if __name__=='__main__':unittest.main()
