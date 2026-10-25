"""Keep verified daily startup independent of registry availability."""
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

spec = importlib.util.spec_from_file_location('cached_startup_p7', Path(__file__).with_name('p7.py'))
p7 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(p7)


class CachedStartupTest(unittest.TestCase):
    def test_start_uses_only_present_verified_pins_and_never_pulls_implicitly(self):
        image = 'ghcr.io/example/runtime@sha256:' + 'a' * 64
        manifest = {'images': {'edge': {'image': image}}}
        smtp = dict(host='smtp.example.test', port=587, tls_mode='starttls', username='fixture',
                    password='fixture-only', from_address='fixture@example.test')
        installer = Mock()
        installer.check_runtime.return_value = manifest
        installer.env_read.return_value = {'P6_EDGE_IMAGE': image}
        installer.start.side_effect = lambda runtime: installer.compose(runtime/'compose.env', 'up', '-d', '--no-build', 'mail')
        api = Mock()
        api.request.side_effect = lambda runtime, domain, method, *args, **kw: (200, {}) if method == 'GET' else (204, None)
        with tempfile.TemporaryDirectory() as folder:
            runtime = Path(folder)
            (runtime/'operations.json').write_text(json.dumps({'closesAt': '2099-01-01T00:00:00+00:00', 'hostMode': 'workstation'}))
            (runtime/'deployment.json').write_text(json.dumps({'services': {
                'edge': {'image': '${P6_EDGE_IMAGE:?Verified pin}'},
                'fixture-mail': {'image': 'fixture:unused', 'profiles': ['acceptance']},
            }}))
            args = SimpleNamespace(runtime=runtime, package=runtime, smtp=runtime/'smtp.json')
            with patch.object(p7, 'installer', return_value=installer), \
                    patch.object(p7, 'compose') as compose, patch.object(p7, 'run'), \
                    patch.object(p7, 'smtp_config', return_value=smtp), \
                    patch.object(p7, 'admin', return_value=(api, 'fixture-token')), \
                    patch.object(p7.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0)) as inspect:
                p7.start(args)
            self.assertFalse(any('pull' in call.args[1:] for call in compose.call_args_list))
            inspect.assert_called_once()
            self.assertEqual(inspect.call_args.args[0], ['docker', 'image', 'inspect', image])
            for call in compose.call_args_list:
                if call.args[1] in ('create', 'up'):
                    self.assertIn('--pull', call.args)
                    self.assertIn('never', call.args)
                    self.assertNotIn('mail', call.args)

    def test_missing_cached_image_fails_before_compose_or_identity_mutations(self):
        image = 'ghcr.io/example/runtime@sha256:' + 'a' * 64
        with tempfile.TemporaryDirectory() as folder:
            runtime = Path(folder)
            (runtime/'deployment.json').write_text(json.dumps({'services': {'edge': {'image': '${P6_EDGE_IMAGE}'}}}))
            args = SimpleNamespace(runtime=runtime)
            installer = SimpleNamespace(env_read=lambda path: {'P6_EDGE_IMAGE': image})
            with patch.object(p7.subprocess, 'run', return_value=subprocess.CompletedProcess([], 1)), \
                    patch.object(p7, 'compose') as compose:
                with self.assertRaisesRegex(RuntimeError, 'preload'):
                    p7.require_cached_images(args, installer, {'images': {'edge': {'image': image}}})
                compose.assert_not_called()

    def test_runtime_overlay_cannot_add_an_unverified_image(self):
        with tempfile.TemporaryDirectory() as folder:
            runtime = Path(folder)
            (runtime/'deployment.json').write_text(json.dumps({'services': {'rogue': {'image': 'example/rogue:latest'}}}))
            args = SimpleNamespace(runtime=runtime)
            installer = SimpleNamespace(env_read=lambda path: {})
            with patch.object(p7.subprocess, 'run') as inspect:
                with self.assertRaises(ValueError):
                    p7.require_cached_images(args, installer, {'images': {}})
                inspect.assert_not_called()


if __name__ == '__main__':
    unittest.main()
