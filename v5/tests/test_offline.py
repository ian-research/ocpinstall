import importlib.util
import json
import os
from pathlib import Path
from types import SimpleNamespace
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('offline', ROOT / 'lib/offline.py')
offline = importlib.util.module_from_spec(spec)
spec.loader.exec_module(offline)


def args(**changes):
    values = dict(version='5.0.1', channel=None, arch='amd64', operator=[],
                  all_operators=False, catalog='registry.redhat.io/redhat/redhat-operator-index:v5.0', image=[], archive_size=20,
                  authfile=None, cache_dir=None, parallel_images=4, parallel_layers=5,
                  dry_run=False, registry=None)
    values.update(changes)
    return SimpleNamespace(**values)


class OfflineTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name).resolve()
        self.bundle = self.base / 'bundle with spaces'
        self.auth = self.base / 'auth.json'
        self.auth.write_text('{"auths":{"registry.redhat.io":{"auth":"test"}}}')
        self.plugin = self.base / 'oc-mirror'
        self.plugin.write_bytes(b'mocked plugin')
        self.options = args(authfile=str(self.auth), cache_dir=str(self.base / 'cache'))

    def bundle_fixture(self):
        config = offline.config_for_bundle(self.options, self.bundle)
        image_dir = self.bundle / 'images'
        image_dir.mkdir()
        archive = image_dir / 'mirror_000001.tar'
        archive.write_bytes(b'test archive')
        record = self.bundle / 'mirror-tool.json'
        offline.save_json(record, {'sha256': offline.digest(self.plugin)})
        offline.save_json(self.bundle / 'checksums.json', {
            str(p.relative_to(self.bundle)): offline.digest(p) for p in (config, archive, record)})
        return archive

    def test_exact_release_and_catalog(self):
        config = offline.make_config(args(operator=['local-storage-operator:stable']))
        platform = config['mirror']['platform']
        self.assertEqual(platform['channels'][0], {'name': 'stable-5.0', 'minVersion': '5.0.1', 'maxVersion': '5.0.1'})
        self.assertEqual(config['mirror']['operators'][0]['catalog'], 'registry.redhat.io/redhat/redhat-operator-index:v5.0')
        self.assertEqual(config['mirror']['operators'][0]['packages'][0]['channels'], [{'name': 'stable'}])

    def test_platform_only_does_not_download_catalog(self):
        self.assertNotIn('operators', offline.make_config(args())['mirror'])

    def test_full_catalog_requires_explicit_selection(self):
        self.assertTrue(offline.make_config(args(all_operators=True))['mirror']['operators'][0]['full'])
        with self.assertRaises(ValueError):
            offline.make_config(args(all_operators=True, operator=['foo']))

    def test_reject_invalid_inputs(self):
        for option in (args(version='4.22'), args(channel='stable-4.21'), args(operator=['bad\nname'])):
            with self.assertRaises(ValueError):
                offline.make_config(option)

    def test_reuse_config_but_reject_changed_selection(self):
        offline.config_for_bundle(self.options, self.bundle)
        offline.config_for_bundle(self.options, self.bundle)
        with self.assertRaises(ValueError):
            offline.config_for_bundle(args(operator=['foo']), self.bundle)

    def test_archive_tampering_and_version(self):
        archive = self.bundle_fixture()
        offline.verify(self.bundle, '5.0.1')
        with self.assertRaises(ValueError):
            offline.verify(self.bundle, '4.21.1')
        archive.write_bytes(b'corrupted')
        with self.assertRaises(ValueError):
            offline.verify(self.bundle)

    def test_reject_missing_or_extra_archive(self):
        archive = self.bundle_fixture()
        extra = archive.with_name('unexpected.tar')
        extra.write_bytes(b'extra')
        with self.assertRaises(ValueError):
            offline.verify(self.bundle)
        extra.unlink()
        archive.unlink()
        with self.assertRaises(ValueError):
            offline.verify(self.bundle)

    def test_reject_manifest_path_escape(self):
        self.bundle_fixture()
        manifest = json.loads((self.bundle / 'checksums.json').read_text())
        manifest['../auth.json'] = offline.digest(self.auth)
        offline.save_json(self.bundle / 'checksums.json', manifest)
        with self.assertRaises(ValueError):
            offline.verify(self.bundle)

    def test_reject_credentials_in_bundle(self):
        self.bundle.mkdir()
        inside = self.bundle / 'auth.json'
        inside.write_text(self.auth.read_text())
        with self.assertRaises(ValueError):
            offline.auth_file(args(authfile=str(inside)), self.bundle)

    def run_mirror(self, callback, exporting=True):
        with patch.object(offline.sys, 'platform', 'linux'), \
             patch.object(offline.shutil, 'which', return_value=str(self.plugin)), \
             patch.object(offline.subprocess, 'run', side_effect=callback), \
             patch.object(offline.os, 'umask'):
            offline.mirror(self.options, self.bundle, exporting)

    def test_export_command_and_checksum(self):
        commands = []
        def run(command, **kwargs):
            commands.append(command)
            if '--help' not in command:
                (self.bundle / 'images/mirror_000001.tar').write_bytes(b'mocked')
        self.run_mirror(run)
        offline.verify(self.bundle)
        command = commands[-1]
        self.assertIn('file://' + str(self.bundle / 'images'), command)
        self.assertIn(str(self.auth), command)
        self.assertNotIn('--dest-tls-verify=false', command)
        self.assertFalse((self.bundle / 'auth.json').exists())

    def test_failed_retry_removes_success_marker(self):
        self.bundle_fixture()
        def run(command, **kwargs):
            if '--help' not in command:
                raise subprocess.CalledProcessError(1, command)
        with self.assertRaises(subprocess.CalledProcessError):
            self.run_mirror(run)
        self.assertFalse((self.bundle / 'checksums.json').exists())

    def test_dry_run_is_not_a_completed_bundle(self):
        self.options.dry_run = True
        self.run_mirror(lambda *a, **kw: None)
        self.assertFalse((self.bundle / 'checksums.json').exists())

    def test_import_uses_transferred_configuration(self):
        self.bundle_fixture()
        self.options.registry = 'harbor.example.com:8443/openshift501'
        commands = []
        self.run_mirror(lambda cmd, **kw: commands.append(cmd), exporting=False)
        self.assertIn('--from', commands[-1])
        self.assertEqual(commands[-1][-1], 'docker://' + self.options.registry)

    def test_operator_error_log_blocks_success(self):
        def run(command, **kwargs):
            if '--help' not in command:
                logs = self.bundle / 'images/working-dir/logs'
                logs.mkdir(parents=True)
                (logs / 'mirroring_errors.txt').write_text('failed operator')
        with self.assertRaises(ValueError):
            self.run_mirror(run)
        self.assertFalse((self.bundle / 'checksums.json').exists())

    def test_successful_retry_preserves_but_ignores_unchanged_old_errors(self):
        logs = self.bundle / 'images/working-dir/logs'
        logs.mkdir(parents=True)
        old = logs / 'mirroring_errors.txt'
        old.write_text('previous failed attempt')
        def run(command, **kwargs):
            if '--help' not in command:
                (self.bundle / 'images/mirror_000001.tar').write_bytes(b'mocked successful archive')
        self.run_mirror(run)
        offline.verify(self.bundle)
        self.assertEqual(old.read_text(), 'previous failed attempt')

    def test_setup_environment_cannot_override_embedded_registry_storage(self):
        calls = []
        def run(command, **kwargs):
            calls.append((command, kwargs))
            if '--help' not in command:
                (self.bundle / 'images/mirror_000001.tar').write_bytes(b'mocked')
        with patch.dict(offline.os.environ, {'REGISTRY_STORAGE': 'unchanged', 'OCP_REGISTRY_STORAGE': 'pvc'}):
            self.run_mirror(run)
            self.assertEqual(offline.os.environ['REGISTRY_STORAGE'], 'unchanged')
        mirror_env = calls[-1][1]['env']
        self.assertNotIn('REGISTRY_STORAGE', mirror_env)
        self.assertEqual(mirror_env['OCP_REGISTRY_STORAGE'], 'pvc')


if __name__ == '__main__':
    unittest.main()
