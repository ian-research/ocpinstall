import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'lib'))
import delivery


class HelperRPMTests(unittest.TestCase):
    def test_installed_language_packs_join_the_download_roots(self):
        with patch.object(delivery, 'run', return_value=SimpleNamespace(
                stdout='glibc-langpack-en\nglibc-langpack-de\nglibc-langpack-en\n')):
            packages = delivery.helper_packages()
        self.assertIn('glibc-langpack-zh', packages)
        self.assertIn('glibc-langpack-en', packages)
        self.assertIn('glibc-langpack-de', packages)
        self.assertEqual(packages.count('glibc-langpack-en'), 1)

    def test_unexpected_installed_package_name_fails_closed(self):
        with patch.object(delivery, 'run', return_value=SimpleNamespace(stdout='--allowerasing\n')):
            with self.assertRaises(ValueError):
                delivery.helper_packages()

    def helper(self, parent):
        root = Path(parent) / 'offline helper with spaces'
        (root / 'rpms').mkdir(parents=True)
        (root / 'rpms/fixture.rpm').write_bytes(b'fixture rpm')
        (root / 'keys').mkdir()
        (root / 'keys/RPM-GPG-KEY-fixture').write_text('fixture public key')
        (root / 'requirements.json').write_text(json.dumps({
            'mode': 'rpm', 'packages': ['glibc-langpack-zh', 'glibc-langpack-en', 'python3']}))
        return root

    def test_transaction_check_uses_only_local_repo_and_never_installs(self):
        with tempfile.TemporaryDirectory() as parent:
            root = self.helper(parent)
            def inspect(command):
                self.assertIn('--disableplugin=amazon-id', command)
                self.assertNotIn('--noplugins', command)
                self.assertNotIn('--nogpgcheck', command)
                self.assertIn('--setopt=tsflags=test', command)
                self.assertIn('--setopt=keepcache=1', command)
                self.assertIn('--disablerepo=*', command)
                self.assertIn('--enablerepo=ocpinstall-helper-preflight', command)
                directory = next(x.split('=', 2)[2] for x in command if x.startswith('--setopt=reposdir='))
                repo = (Path(directory) / 'helper.repo').read_text()
                self.assertIn('baseurl=' + (root / 'rpms').resolve().as_uri(), repo)
                self.assertIn('gpgcheck=1', repo)
                self.assertNotIn('https://', repo)
                self.assertNotIn('--allowerasing', command)
            with patch.object(delivery, 'run', side_effect=inspect) as run:
                delivery.preflight_helper_rpms(root)
            run.assert_called_once()

    def test_downloadonly_cache_cleanup_cannot_remove_delivered_packages(self):
        with tempfile.TemporaryDirectory() as parent:
            root = self.helper(parent)
            cache = Path(parent) / 'private cache'; cache.mkdir()
            downloads = []
            def download(command):
                folder = Path(next(x.split('=', 1)[1] for x in command if x.startswith('--downloaddir=')))
                self.assertNotEqual(folder, root / 'rpms')
                self.assertIn(cache, folder.parents)
                (folder / 'reverse-dependency.rpm').write_bytes(b'reverse dependency fixture')
                downloads.append(folder)
            with patch.object(delivery, 'run', side_effect=download):
                delivery.download_helper_transaction(Path(parent), root / 'rpms', cache, ['fixture'])
            self.assertFalse(downloads[0].exists())
            self.assertEqual((root / 'rpms/reverse-dependency.rpm').read_bytes(), b'reverse dependency fixture')
            self.assertEqual((root / 'rpms/fixture.rpm').read_bytes(), b'fixture rpm')

    def test_successful_transaction_cannot_silently_delete_payloads(self):
        with tempfile.TemporaryDirectory() as parent:
            root = self.helper(parent)
            with patch.object(delivery, 'run', side_effect=lambda command: (root / 'rpms/fixture.rpm').unlink()):
                with self.assertRaisesRegex(ValueError, '修改了交付文件'):
                    delivery.preflight_helper_rpms(root)

    def test_conflicting_same_name_download_is_rejected(self):
        with tempfile.TemporaryDirectory() as parent:
            root = self.helper(parent)
            cache = Path(parent) / 'cache'; cache.mkdir()
            def download(command):
                folder = Path(next(x.split('=', 1)[1] for x in command if x.startswith('--downloaddir=')))
                (folder / 'fixture.rpm').write_bytes(b'different package with same name')
            with patch.object(delivery, 'run', side_effect=download):
                with self.assertRaisesRegex(ValueError, '同名 Helper RPM'):
                    delivery.download_helper_transaction(Path(parent), root / 'rpms', cache, ['fixture'])
            self.assertEqual((root / 'rpms/fixture.rpm').read_bytes(), b'fixture rpm')

    def test_transaction_failure_is_not_ignored_or_retried_with_weaker_flags(self):
        with tempfile.TemporaryDirectory() as parent:
            root = self.helper(parent)
            with patch.object(delivery, 'run', side_effect=subprocess.CalledProcessError(1, ['dnf'])) as run:
                with self.assertRaises(subprocess.CalledProcessError):
                    delivery.preflight_helper_rpms(root)
            run.assert_called_once()

    def test_existing_helper_mode_does_not_run_a_package_transaction(self):
        with tempfile.TemporaryDirectory() as parent:
            root = self.helper(parent)
            (root / 'requirements.json').write_text(json.dumps({'mode': 'existing'}))
            with patch.object(delivery, 'run') as run:
                delivery.preflight_helper_rpms(root)
            run.assert_not_called()

    def test_aws_metadata_plugin_is_skipped_only_for_bundle_install(self):
        common = Path(delivery.SOURCE) / 'lib/common.sh'
        program = ('source "$1"; YUM_REPO_MODE=$2; '
                   'dnf() { printf "%s\\n" "$@"; }; dnf_install python3')
        for mode in ('bundle', 'existing', 'iso'):
            with self.subTest(mode=mode):
                result = subprocess.run(['bash', '-c', program, 'bash', str(common), mode],
                                        capture_output=True, text=True, check=True)
                argv = result.stdout.splitlines()
                self.assertEqual('--disableplugin=amazon-id' in argv, mode == 'bundle')
                self.assertNotIn('--noplugins', argv)
                self.assertNotIn('--nogpgcheck', argv)
                if mode == 'bundle':
                    self.assertIn('--disablerepo=*', argv)
                    self.assertIn('--enablerepo=ocp-delivery', argv)
                    self.assertIn('--setopt=keepcache=1', argv)

    def test_legacy_cached_rpm_slice_requires_new_preparation(self):
        with tempfile.TemporaryDirectory() as parent:
            root = Path(parent)
            helper = root / 'helper'; helper.mkdir()
            requirements = helper / 'requirements.json'
            requirements.write_text(json.dumps({'mode': 'rpm', 'packages': delivery.PACKAGES}))
            (helper / 'checksums.json').write_text(json.dumps({
                'requirements.json': delivery.offline.digest(requirements)}))
            with patch.object(delivery, 'run') as run:
                with self.assertRaisesRegex(ValueError, '缓存隔离修复'):
                    delivery.prepare_helper(SimpleNamespace(harbor_sha256=None), root, root / 'cache')
            run.assert_not_called()


if __name__ == '__main__':
    unittest.main()
