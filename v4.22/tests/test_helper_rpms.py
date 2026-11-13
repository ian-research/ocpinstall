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
        (root / 'keys').mkdir()
        (root / 'keys/RPM-GPG-KEY-fixture').write_text('fixture public key')
        (root / 'requirements.json').write_text(json.dumps({
            'mode': 'rpm', 'packages': ['glibc-langpack-zh', 'glibc-langpack-en', 'python3']}))
        return root

    def test_transaction_check_uses_only_local_repo_and_never_installs(self):
        with tempfile.TemporaryDirectory() as parent:
            root = self.helper(parent)
            def inspect(command):
                self.assertIn('--setopt=tsflags=test', command)
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


if __name__ == '__main__':
    unittest.main()
