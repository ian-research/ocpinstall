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

    def test_foreign_helper_fails_before_large_archive_verification(self):
        foreign = self.root.parent / 'previous helper'
        foreign.mkdir()
        marker = foreign / 'preserved-data'; marker.write_text('original')
        target = self.root.parent / 'new helper'
        with patch.object(delivery, 'KNOWN_HELPER_STATES', (str(foreign),)), patch.object(delivery, 'verify') as verify:
            with self.assertRaisesRegex(ValueError, 'Helper 状态'):
                delivery.execute(SimpleNamespace(action='install', state_root=str(target)), self.root)
            verify.assert_not_called()
        self.assertEqual(marker.read_text(), 'original')
        self.assertFalse(target.exists())

    def test_same_helper_state_is_allowed_and_configure_keeps_normal_verification(self):
        current = self.root.parent / 'current helper'
        current.mkdir()
        with patch.object(delivery, 'KNOWN_HELPER_STATES', (str(current),)):
            delivery.preflight_helper_state(current)
            with patch.object(delivery, 'verify', side_effect=ValueError('normal integrity check')) as verify:
                with self.assertRaisesRegex(ValueError, 'normal integrity check'):
                    delivery.execute(SimpleNamespace(action='configure', state_root='/different/helper'), self.root)
                verify.assert_called_once()

    def test_moved_bundle_is_independent_of_original_path(self):
        self.fixture()
        moved = Path(self.temp.name) / 'different offline destination'
        shutil.move(self.root, moved)
        self.assertEqual(delivery.verify(moved)['version'], operator_profile.release())
        for name in ('install.sh', 'configure.sh', 'verify.sh'):
            self.assertNotIn(str(self.root), (moved / name).read_text())
            self.assertIn('$ROOT', (moved / name).read_text())

    def test_snapshot_excludes_local_auth_and_removes_retired_files_on_retry(self):
        source = self.root.parent / 'public source'
        contents = {'install-cluster.sh': '#!/bin/bash\n', 'README.md': 'public',
                    'lib/offline.py': '# public code', 'config/versions.sh': '# public profile',
                    'RHEL10-HELPER.md': 'public Helper guide',
                    'config/ocp-4.22.22-gateway-images.json': '{"images": []}',
                    'pull-secret.json': 'fixture credential', 'notes.md': 'fixture private note',
                    'config/auth.json': 'fixture credential', 'lib/auth.json': 'fixture credential'}
        for name, content in contents.items():
            p = source / name; p.parent.mkdir(parents=True, exist_ok=True); p.write_text(content)
        stale = self.root / 'scripts/retired-auth.json'
        stale.parent.mkdir(); stale.write_text('fixture credential')
        with patch.object(delivery, 'SOURCE', source):
            delivery.snapshot_scripts(self.root)
        copied = {str(p.relative_to(self.root / 'scripts')) for p in (self.root / 'scripts').rglob('*') if p.is_file()}
        self.assertEqual(copied, {'install-cluster.sh', 'README.md', 'lib/offline.py', 'config/versions.sh',
                                 'RHEL10-HELPER.md', 'config/ocp-4.22.22-gateway-images.json'})

    def test_snapshot_rejects_destination_symlink_before_writing(self):
        outside = self.root.parent / 'outside'
        outside.mkdir()
        marker = outside / 'unchanged'; marker.write_text('fixture')
        (self.root / 'scripts').symlink_to(outside, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, '普通目录'):
            delivery.snapshot_scripts(self.root)
        self.assertEqual(list(outside.iterdir()), [marker])

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

    def test_input_failure_can_retry_the_same_directory(self):
        auth = self.root.parent / 'source-auth.json'
        command = ['delivery.py', 'export', '--bundle', str(self.root), '--platform-only', '--authfile', str(auth)]
        with patch.object(delivery.sys, 'argv', command), patch.object(delivery.sys, 'platform', 'linux'), \
             patch.object(delivery.sys.stdin, 'isatty', return_value=False):
            with self.assertRaises(FileNotFoundError):
                delivery.main()
            self.assertEqual(json.loads((self.root / 'delivery-state.json').read_text())['failedAt'], 'input-validation')
            auth.write_text('{"auths":{"registry.test":{"auth":"fixture"}}}')
            with patch.object(delivery, 'prepare_tools', side_effect=ValueError('reached-tools')):
                with self.assertRaisesRegex(ValueError, 'reached-tools'):
                    delivery.main()
        self.assertEqual(json.loads((self.root / 'delivery-state.json').read_text())['failedAt'], 'tools')
        self.assertFalse((self.root / 'delivery.json').exists())

    def test_input_retry_still_rejects_unrelated_existing_files(self):
        auth = self.root.parent / 'source-auth.json'
        auth.write_text('{"auths":{"registry.test":{"auth":"fixture"}}}')
        (self.root / 'unrelated-private-file').write_text('fixture')
        command = ['delivery.py', 'export', '--bundle', str(self.root), '--platform-only', '--authfile', str(auth)]
        with patch.object(delivery.sys, 'argv', command), patch.object(delivery.sys, 'platform', 'linux'), \
             patch.object(delivery.sys.stdin, 'isatty', return_value=False), patch.object(delivery, 'prepare_tools') as tools:
            for attempt in range(2):
                with self.assertRaisesRegex(ValueError, '请选择空目录'):
                    delivery.main()
            tools.assert_not_called()
        self.assertFalse((self.root / 'delivery-plan.json').exists())

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
