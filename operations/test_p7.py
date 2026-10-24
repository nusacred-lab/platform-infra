"""Test operational boundaries that must fail closed before live deployment."""
import importlib.util
import json
from pathlib import Path
import tempfile
import subprocess
import datetime as dt
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('p7', Path(__file__).with_name('p7.py'))
p7 = importlib.util.module_from_spec(spec); spec.loader.exec_module(p7)


class SmtpBoundaryTest(unittest.TestCase):
    def test_plaintext_missing_auth_and_non_submission_ports_are_rejected(self):
        base = dict(host='smtp.invalid', port=587, tls_mode='starttls', username='test',
                    password='test-only', from_address='demo@example.test')
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder)/'smtp.json'
            for changes in ({'tls_mode': 'none'}, {'password': ''}, {'port': 25}):
                path.write_text(json.dumps(dict(base, **changes)))
                with self.subTest(changes=changes), self.assertRaises(ValueError):
                    p7.smtp_config(path)

    def test_public_tls_keeps_system_roots_and_adds_operator_ca(self):
        fake = unittest.mock.Mock()
        with patch.object(p7.ssl, 'create_default_context', return_value=fake) as create:
            self.assertIs(p7.trusted_context('/private/pinned-chain.pem'), fake)
        create.assert_called_once_with()
        fake.load_verify_locations.assert_called_once_with(cafile='/private/pinned-chain.pem')

    def test_tls_modes_are_exclusive_and_auth_is_mandatory(self):
        base = dict(host='smtp.invalid', port=587, username='test', password='test-only', from_address='demo@example.test')
        for mode in ('starttls', 'tls'):
            result = p7.smtp_settings(dict(base, tls_mode=mode))
            self.assertEqual(result['auth'], 'true')
            self.assertNotEqual(result['ssl'], result['starttls'])

    def test_failed_snapshot_transfer_cannot_acknowledge_success(self):
        spec = importlib.util.spec_from_file_location('backup_client', Path(__file__).with_name('backup_client.py'))
        client = importlib.util.module_from_spec(spec); spec.loader.exec_module(client)
        with tempfile.TemporaryDirectory() as folder:
            argv = ['backup_client', '--host', 'ubuntu@vm.invalid', '--identity', '/private/test-key', '--destination', folder]
            fixed = unittest.mock.Mock(wraps=dt.datetime)
            fixed.now.return_value = dt.datetime(2026, 10, 24, tzinfo=dt.timezone.utc)
            with patch('sys.argv', argv), patch.object(client.dt, 'datetime', fixed), patch.object(client.subprocess, 'run', side_effect=subprocess.CalledProcessError(1, 'ssh')) as call:
                with self.assertRaises(subprocess.CalledProcessError):
                    client.main()
            self.assertEqual(call.call_count, 1)
            self.assertEqual(list(Path(folder).iterdir()), [])



class LifecycleBoundaryTest(unittest.TestCase):
    def test_rehearsal_cannot_target_production_or_development(self):
        spec = importlib.util.spec_from_file_location('lifecycle', Path(__file__).with_name('lifecycle.py'))
        lifecycle = importlib.util.module_from_spec(spec); spec.loader.exec_module(lifecycle)
        root = '/home/ubuntu/competency-proof/runtime/'
        for project, folder, rehearsal in [('competency-proof-p7', 'p7', True),
                                            ('competency-proof-p7-rehearsal', 'p7', True),
                                            ('competency-proof-p2', 'p7', False),
                                            ('competency-proof-p7', 'p7-rehearsal', False)]:
            with self.subTest(project=project, folder=folder), self.assertRaises(ValueError):
                lifecycle.validate_target(root+folder, project, rehearsal)
        self.assertEqual(lifecycle.validate_target(root+'p7-rehearsal','competency-proof-p7-rehearsal',True),'competency-proof-p7-rehearsal')
        self.assertEqual(lifecycle.validate_target(root+'p7','competency-proof-p7',False),'competency-proof-p7')


class LogBoundaryTest(unittest.TestCase):
    def test_credentials_action_links_and_jwts_are_redacted(self):
        spec = importlib.util.spec_from_file_location('log_collector', Path(__file__).with_name('log_collector.py'))
        collector = importlib.util.module_from_spec(spec); spec.loader.exec_module(collector)
        dummy_jwt = '.'.join(['eyJ'+'hbGciOiJIUzI1NiJ9', 'eyJ'+'zdWIiOiJ4In0', 'c2ln'])
        text = 'secret-for-test-only Bearer opaque-token https://demo.invalid/?key=private-link&other=safe '+dummy_jwt+' user@example.test'
        result = collector.redact(text, ['secret-for-test-only'])
        for secret in ('secret-for-test-only','opaque-token','private-link','eyJhbGci','user@example.test'):
            self.assertNotIn(secret,result)
        self.assertIn('other=safe',result)

    def test_retention_deletes_only_old_collector_files(self):
        spec = importlib.util.spec_from_file_location('log_collector', Path(__file__).with_name('log_collector.py'))
        collector = importlib.util.module_from_spec(spec); spec.loader.exec_module(collector)
        import os
        with tempfile.TemporaryDirectory() as folder:
            folder = Path(folder)
            old = folder/'p7-20261001-000.jsonl';old.write_text('old')
            keep = folder/'p7-20261023-000.jsonl';keep.write_text('current')
            unrelated = folder/'other-app.log';unrelated.write_text('unrelated')
            os.utime(old,(0,0))
            collector.prune(folder)
            self.assertFalse(old.exists())
            self.assertTrue(keep.exists())
            self.assertTrue(unrelated.exists())


class WorkstationControlTest(unittest.TestCase):
    def controller(self):
        spec = importlib.util.spec_from_file_location('workstation_control', Path(__file__).with_name('workstation_control.py'))
        module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        return module

    def test_backup_failure_does_not_stop_application_and_restores_tunnel(self):
        control = self.controller()
        calls = []
        def command(action,*units,**kw):
            calls.append((action,units))
            if action == 'start' and units == (control.BACKUP,):
                raise subprocess.CalledProcessError(1,'backup')
        with patch.object(control,'active',side_effect=lambda unit: unit != control.BACKUP), patch.object(control,'systemctl',side_effect=command), patch.object(control,'compose_stop') as compose:
            with self.assertRaises(subprocess.CalledProcessError):control.stop()
        self.assertNotIn(('stop',(control.APP,)),calls)
        self.assertIn(('start',(control.TUNNEL,)),calls)
        compose.assert_not_called()

    def test_stop_orders_tunnel_backup_application_and_auxiliaries(self):
        control = self.controller()
        calls = []
        def command(action,*units,**kw):calls.append((action,units))
        with patch.object(control,'active',side_effect=lambda unit: unit != control.BACKUP), patch.object(control,'systemctl',side_effect=command), patch.object(control,'compose_stop'):
            control.stop()
        self.assertLess(calls.index(('stop',(control.TUNNEL,))),calls.index(('start',(control.BACKUP,))))
        self.assertLess(calls.index(('start',(control.BACKUP,))),calls.index(('stop',(control.APP,))))
        self.assertLess(calls.index(('stop',(control.APP,))),calls.index(('stop',tuple(control.AUXILIARY))))

    def test_in_progress_backup_is_joined_without_starting_another(self):
        control = self.controller()
        calls = []
        def command(action,*units,**kw):calls.append((action,units))
        with patch.object(control,'active',return_value=True), patch.object(control,'systemctl',side_effect=command), patch.object(control,'compose_stop'):
            control.stop()
        self.assertEqual(calls.count(('start',(control.BACKUP,))),1)


if __name__ == '__main__':
    unittest.main()
