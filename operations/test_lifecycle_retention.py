"""Verify retirement of P7 private artifacts without touching a real deployment."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch


class WorkstationRetirementTest(unittest.TestCase):
    def module(self):
        spec = importlib.util.spec_from_file_location('retention_module', Path(__file__).with_name('lifecycle.py'))
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def test_inventory_refuses_links_to_another_project(self):
        module = self.module()
        with tempfile.TemporaryDirectory() as folder:
            workspace = Path(folder)
            root = workspace/'runtime/p7'
            root.mkdir(parents=True)
            legacy = workspace/'legacy'
            legacy.mkdir()
            marker = legacy/'keep'
            marker.write_text('preserve')
            (root/'invitation-release').symlink_to(legacy, target_is_directory=True)
            with self.assertRaises(ValueError):
                module.workstation_private_artifacts(workspace)
            self.assertEqual(marker.read_text(), 'preserve')

    def test_cleanup_failure_does_not_claim_all_private_copies_were_removed(self):
        module = self.module()
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder)/'private-copy'
            path.mkdir()
            with patch.object(module.shutil, 'rmtree', side_effect=OSError('fixture refusal')):
                with self.assertRaises(OSError):
                    module.remove_private_artifacts([path])
            self.assertTrue(path.exists())

    def test_retirement_removes_p7_copies_stops_monitors_and_preserves_legacy(self):
        with tempfile.TemporaryDirectory() as folder:
            workspace = Path(folder)
            operations = workspace / 'repo/platform-infra/operations'
            operations.mkdir(parents=True)
            for name in ('lifecycle.py', 'p7.py'):
                shutil.copyfile(Path(__file__).with_name(name), operations / name)
            package = workspace / 'package'
            package.mkdir()
            (package / 'install.py').write_text(
                "def env_read(path):\n"
                "    return dict(line.split('=', 1) for line in path.read_text().splitlines() if line)\n"
            )
            root = workspace / 'runtime/p7'
            runtime = root / 'active'
            runtime.mkdir(parents=True)
            (runtime / 'compose.env').write_text('P6_PROJECT_NAME=competency-proof-p7\n')
            (runtime / 'closed.json').write_text('{}')
            (runtime / 'operations.json').write_text(json.dumps({
                'closesAt': '2000-01-01T00:00:00+00:00',
                'deleteAfter': '2000-01-01T12:00:00+00:00',
            }))
            smtp = root / 'smtp.json'
            smtp.write_text('{}')
            artifacts = [
                root / 'invitation-release/rollback-configuration/test-only-secret',
                root / 'closure-suite/test-only-mailbox.json',
                root / 'company-results-private.json',
                root / 'decline-registry-private.json',
                root / 'backup-decryption-key.pem',
                workspace / 'runtime/backups/p7/test-only.cms',
            ]
            for path in artifacts:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text('disposable fixture')
            legacy = root / 'pre-local-p7-complete/checkpoint'
            legacy.parent.mkdir()
            legacy.write_text('preserve older project data')
            unknown = root / 'unrelated-operator-file'
            unknown.write_text('preserve unclassified files')
            spec = importlib.util.spec_from_file_location('retirement_fixture', operations / 'lifecycle.py')
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            argv = ['lifecycle', '--runtime', str(runtime), '--package', str(package),
                    '--smtp', str(smtp), '--host-mode', 'workstation', 'delete']
            def retained_rehearsal_volume(command, **kwargs):
                return 'competency-proof-p7-rehearsal_protocol-wallet-data\n' if command[:3] == ['docker', 'volume', 'ls'] else ''
            with patch('sys.argv', argv), patch('subprocess.run') as run, \
                    patch('subprocess.check_output', side_effect=retained_rehearsal_volume):
                with self.assertRaisesRegex(ValueError, 'disposable volume deletion'):
                    module.main()
                run.assert_not_called()
            self.assertTrue(runtime.exists(), 'Incomplete rehearsal cleanup must block retirement before mutations')
            with patch('sys.argv', argv), patch('subprocess.run') as run, \
                    patch('subprocess.check_output', return_value=''), contextlib.redirect_stdout(io.StringIO()):
                module.main()
            self.assertFalse(runtime.exists())
            self.assertFalse(smtp.exists())
            for path in artifacts:
                with self.subTest(path=path.relative_to(workspace)):
                    self.assertFalse(path.exists(), 'Retired P7 data must not survive in a rollback/test copy')
            self.assertEqual(legacy.read_text(), 'preserve older project data')
            self.assertEqual(unknown.read_text(), 'preserve unclassified files')
            invoked = [arg for call in run.call_args_list for arg in call.args[0]]
            for unit in ('competency-proof-p7-public.timer', 'competency-proof-p7-logs.service',
                         'competency-proof-p7-smtp-relay.service', 'competency-proof-p7-tunnel.service'):
                with self.subTest(unit=unit):
                    self.assertIn(unit, invoked, 'Retired monitors and helpers must not keep running')
            audit = json.loads((root / 'competency-proof-p7-deletion-audit.json').read_text())
            self.assertEqual(audit['project'], 'competency-proof-p7')
            self.assertNotIn('secret', json.dumps(audit))


if __name__ == '__main__':
    unittest.main()
