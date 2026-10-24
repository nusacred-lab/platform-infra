"""Private configuration boundary checks; no real identity or SMTP calls."""
import importlib.util
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

spec=importlib.util.spec_from_file_location('configure_invitations',Path(__file__).with_name('configure_invitations.py'))
config=importlib.util.module_from_spec(spec);spec.loader.exec_module(config)


class InvitationConfigTest(unittest.TestCase):
    def test_unprotected_runtime_is_rejected_before_administration(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);root.chmod(0o755)
            with patch.object(config.p7,'admin') as admin:
                with self.assertRaises(ValueError):config.configure(SimpleNamespace(runtime=root))
                admin.assert_not_called()

    def test_dedicated_client_only_mounts_its_secret_and_enables_exact_route(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder)
            (root/'deployment.json').write_text(json.dumps({'services':{'custodian':{'environment':{},'secrets':[]}},'secrets':{}}))
            (root/'operations.json').write_text('{}')
            (root/'ingress.caddy').write_text('path /api/v1/service-status')
            calls=[];created=False;secret=None
            class Api:
                @staticmethod
                def checksum(path):return 'test-digest'
                @staticmethod
                def request(runtime,domain,method,path,body=None,token=None,form=False):
                    nonlocal created,secret
                    calls.append((method,path,body))
                    if path.endswith('/clients?clientId=wallet-invitations'):return 200,[{'id':'invitation-client'}] if created else []
                    if method=='POST' and path.endswith('/clients'):
                        created=True;secret=body['secret']
                        assert body['fullScopeAllowed'] is False
                        assert body['standardFlowEnabled'] is False
                        return 201,None
                    if path.endswith('/client-secret'):return 200,{'value':secret}
                    if path.endswith('/clients/invitation-client'):return 200,{'serviceAccountsEnabled':True,'fullScopeAllowed':False}
                    if path.endswith('/clients?clientId=realm-management'):return 200,[{'id':'management'}]
                    if '/roles/' in path:return 200,{'id':'role-id','name':path.rsplit('/',1)[1]}
                    if path.endswith('/service-account-user'):return 200,{'id':'service-user'}
                    if path.endswith('/token'):return 200,{'access_token':'synthetic-token'}
                    return 204,None
            args=SimpleNamespace(runtime=root,package=Path('/verified/package'))
            with patch.object(config.p7,'admin',return_value=(Api,'synthetic-admin')),patch.object(config.p7,'compose'):
                config.configure(args)
                config.configure(args)
            doc=json.loads((root/'deployment.json').read_text())
            service=doc['services']['custodian']
            self.assertEqual(service['secrets'],['wallet-invitations-secret'])
            self.assertEqual(service['environment']['WALLET_INVITATION_DB_PATH'],'/data/participant-invitations.sqlite')
            self.assertEqual((root/'wallet-invitations-secret').stat().st_mode & 0o777,0o444)
            self.assertEqual((root/'ingress.caddy').read_text().count('/api/v1/participant-invitations'),1)
            self.assertFalse(any('execute-actions-email' in path for _,path,_ in calls))
            self.assertFalse(any('realm-admin' in str(body) for _,_,body in calls))
            self.assertEqual(sum(method=='POST' and path.endswith('/clients') for method,path,_ in calls),1)


if __name__=='__main__':unittest.main()
