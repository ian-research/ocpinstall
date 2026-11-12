import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'lib'))
import delivery
import offline
import operator_profile


class DeliveryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = (Path(self.temp.name) / 'delivery with spaces').resolve()
        self.root.mkdir()

    def fixture(self):
        platform = self.root / 'platform'
        (platform / 'images').mkdir(parents=True)
        config = {'mirror': {'platform': {'architectures': ['amd64'], 'channels': [
            {'minVersion': operator_profile.release(), 'maxVersion': operator_profile.release()}]}}}
        offline.save_json(platform / 'imagesetconfiguration.json', config)
        offline.save_json(platform / 'mirror-tool.json', {'sha256': 'fixture'})
        (platform / 'images/mirror_000001.tar').write_bytes(b'archive fixture')
        files = [platform / p for p in ('imagesetconfiguration.json', 'mirror-tool.json', 'images/mirror_000001.tar')]
        offline.save_json(platform / 'checksums.json', {str(p.relative_to(platform)): offline.digest(p) for p in files})
        for folder in ('helper', 'platform/tools', 'platform/boot'):
            (self.root / folder).mkdir(parents=True, exist_ok=True)
        offline.save_json(self.root / 'helper/requirements.json', {'mode': 'existing'})
        (self.root / 'platform/boot/rhcos-live.iso').write_bytes(b'iso fixture')
        offline.save_json(self.root / 'platform/tools/checksums.json', {})
        (self.root / 'helper/harbor-offline-installer.tgz').write_bytes(b'harbor fixture')
        offline.save_json(self.root / 'delivery-plan.json', {'version': operator_profile.release()})
        delivery.snapshot_scripts(self.root)
        delivery.seal(self.root, False)

    def test_moved_bundle_is_independent_of_original_path(self):
        self.fixture()
        moved = Path(self.temp.name) / 'different offline destination'
        shutil.move(self.root, moved)
        self.assertEqual(delivery.verify(moved)['version'], operator_profile.release())
        for name in ('install.sh', 'configure.sh', 'verify.sh'):
            self.assertNotIn(str(self.root), (moved / name).read_text())
            self.assertIn('$ROOT', (moved / name).read_text())

    def test_boot_tools_and_script_corruption_blocks_changes(self):
        self.fixture()
        for name in ('platform/boot/rhcos-live.iso', 'scripts/install-cluster.sh', 'helper/harbor-offline-installer.tgz', 'platform/images/mirror_000001.tar'):
            path = self.root / name
            original = path.read_bytes()
            path.write_bytes(b'corrupt')
            with patch.object(delivery, 'run') as run:
                with self.assertRaisesRegex(ValueError, 'SHA256'):
                    delivery.execute(SimpleNamespace(action='install'), self.root)
                run.assert_not_called()
            path.write_bytes(original)

    def test_large_archive_is_hashed_once_without_skipping_integrity(self):
        self.fixture()
        archive = (self.root / 'platform/images/mirror_000001.tar').resolve()
        with patch.object(offline, 'digest', wraps=offline.digest) as digest:
            delivery.verify(self.root)
        self.assertEqual(sum(call.args[0].resolve() == archive for call in digest.call_args_list), 1)

    def test_parent_cannot_disagree_with_child_archive_hash(self):
        self.fixture()
        path = self.root / 'delivery.json'
        record = json.loads(path.read_text())
        record['files']['platform/images/mirror_000001.tar'] = '0' * 64
        offline.save_json(path, record)
        with self.assertRaisesRegex(ValueError, '子包校验清单不一致'):
            delivery.verify(self.root)

    def test_wrong_version_rejected(self):
        self.fixture()
        path = self.root / 'delivery.json'
        record = json.loads(path.read_text())
        record['version'] = '4.18.10'
        offline.save_json(path, record)
        with self.assertRaisesRegex(ValueError, '版本'):
            delivery.verify(self.root)

    def test_manifest_path_escape_and_symlink_rejected(self):
        for name in ('../outside', '/etc/passwd'):
            with self.assertRaises(ValueError):
                delivery.safe_path(self.root, name)
        target = self.root / 'link'
        target.symlink_to('/etc/passwd')
        with self.assertRaises(ValueError):
            delivery.safe_path(self.root, 'link')

    def test_same_bundle_concurrent_operation_blocked(self):
        with delivery.locked(self.root):
            with self.assertRaisesRegex(ValueError, '已有任务'):
                with delivery.locked(self.root):
                    self.fail('Concurrent lock admitted')

    def test_installer_uses_relative_platform_and_helper_locations(self):
        args = SimpleNamespace(action='install', state_root=str(self.root.parent / 'private-state'), script_args=['--skip-firewalld'])
        with patch.object(delivery, 'verify', return_value={'version': operator_profile.release(), 'helperMode': 'existing'}), \
             patch.object(delivery, 'run') as run:
            (self.root / 'helper').mkdir()
            offline.save_json(self.root / 'helper/requirements.json', {'mode': 'existing'})
            delivery.execute(args, self.root)
        command = list(map(str, run.call_args.args[0]))
        self.assertEqual(command[-3:], ['--repo-mode', 'existing', '--skip-firewalld'])
        env = run.call_args.kwargs['env']
        self.assertEqual(env['BUNDLE_DIR'], str(self.root / 'platform'))
        self.assertEqual(env['STATE_ROOT'], args.state_root)

    def test_configure_waits_for_install_before_import_and_setup(self):
        state = self.root.parent / 'private-state'
        state.mkdir()
        offline.save_json(state / 'handoff.json', {'version': operator_profile.release(), 'OCP_DOMAIN': 'poc.test',
            'NFS_SERVER': 'helper.poc.test', 'NFS_SC_DIR': '/mnt/nfs', 'registry': 'helper.poc.test:8443/local'})
        args = SimpleNamespace(action='configure', state_root=str(state), kubeconfig='/private/admin.conf',
            authfile='/private/registry-auth.json', script_args=[])
        with patch.object(delivery, 'verify', return_value={'version': operator_profile.release(), 'operators': True}), \
             patch.object(delivery, 'run') as run:
            delivery.execute(args, self.root)
        commands = [list(map(str, c.args[0])) for c in run.call_args_list]
        self.assertEqual(commands[0][1:3], ['wait-for', 'bootstrap-complete'])
        self.assertIn('--remove-bootstrap', commands[1])
        self.assertEqual(commands[2][1:3], ['wait-for', 'install-complete'])
        self.assertTrue(commands[3][1].endswith('prepare-offline.sh'))
        self.assertIn('import', commands[3])
        self.assertTrue(commands[4][1].endswith('prepare-operators.sh'))
        self.assertTrue(commands[5][1].endswith('setup-cluster.sh'))
        self.assertEqual(run.call_args.kwargs['env']['OPERATOR_BUNDLE_DIR'], str(self.root / 'operators'))

    def test_failed_install_never_starts_configuration(self):
        import subprocess
        args = SimpleNamespace(action='install', state_root=None, script_args=[])
        (self.root / 'helper').mkdir()
        offline.save_json(self.root / 'helper/requirements.json', {'mode': 'existing'})
        with patch.object(delivery, 'verify', return_value={'version': operator_profile.release(), 'helperMode': 'existing'}), \
             patch.object(delivery, 'run', side_effect=subprocess.CalledProcessError(1, ['installer'])) as run:
            with self.assertRaises(subprocess.CalledProcessError):
                delivery.execute(args, self.root)
            self.assertEqual(run.call_count, 1)


if __name__ == '__main__':
    unittest.main()
