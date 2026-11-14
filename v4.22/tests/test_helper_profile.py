import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'lib'))
import delivery
import helper_profile


def install_function(name):
    text = (ROOT / 'install-cluster.sh').read_text()
    start = text.index(name + '() {')
    return text[start:text.index('\n}', start) + 2]


def shell(program, **environment):
    return subprocess.run(['bash', '-c', program], capture_output=True, text=True,
                          env=dict(os.environ, ROOT=str(ROOT), **environment))


def profile(major, version):
    return helper_profile.profile_from(
        {'ID': 'rhel', 'VERSION_ID': version}, 'x86_64')


class HelperProfileTests(unittest.TestCase):
    def test_identity_accepts_rhel9_and_rhel10_x86_64(self):
        for version, major in (('9', '9'), ('9.6', '9'), ('10', '10'), ('10.0', '10')):
            with self.subTest(version=version):
                detected = helper_profile.profile_from(
                    {'ID': 'rhel', 'VERSION_ID': version}, 'x86_64')
                self.assertEqual((detected.id, detected.major, detected.version,
                                  detected.arch, detected.name),
                                 ('rhel', major, version, 'x86_64', 'rhel' + major))

    def test_identity_rejects_other_distro_unsupported_major_or_arch(self):
        cases = [
            ({'ID': 'centos', 'VERSION_ID': '9.6'}, 'x86_64'),
            ({'ID': 'rhel', 'VERSION_ID': '8.10'}, 'x86_64'),
            ({'ID': 'rhel', 'VERSION_ID': '11.0'}, 'x86_64'),
            ({'ID': 'rhel', 'VERSION_ID': '9.6'}, 'aarch64'),
            ({'ID': 'rhel', 'VERSION_ID': '9.x'}, 'x86_64'),
            ({'ID': 'rhel', 'VERSION_ID': ''}, 'x86_64'),
        ]
        for values, machine in cases:
            with self.subTest(values=values, machine=machine):
                with self.assertRaises(ValueError):
                    helper_profile.profile_from(values, machine)

    def test_rhel9_keeps_python311_and_rhel10_uses_default_python3(self):
        rhel9 = profile('9', '9.6')
        rhel10 = profile('10', '10.0')
        self.assertIn('python3.11', helper_profile.manifest_packages(rhel9))
        self.assertIn('python3.11', helper_profile.install_packages(rhel9))
        self.assertNotIn('python3.11', helper_profile.manifest_packages(rhel10))
        self.assertNotIn('python3.11', helper_profile.install_packages(rhel10))
        self.assertIn('python3', helper_profile.manifest_packages(rhel10))
        self.assertIn('python3', helper_profile.install_packages(rhel10))
        for name in ('python3-pyyaml', 'python3-pip'):
            self.assertIn(name, helper_profile.install_packages(rhel10))
        self.assertEqual(
            set(helper_profile.install_packages(rhel10)),
            (set(helper_profile.install_packages(rhel9)) - {'python3.11'}) | {'python3'})
        # The legacy RHEL 9 view used by older callers must stay frozen.
        self.assertEqual(delivery.PACKAGES, helper_profile.manifest_packages(rhel9))

    def test_helper_packages_selects_profile(self):
        with patch.object(delivery, 'run', return_value=SimpleNamespace(stdout='')):
            rhel9 = delivery.helper_packages(profile('9', '9.6'))
            rhel10 = delivery.helper_packages(profile('10', '10.0'))
        self.assertIn('python3.11', rhel9)
        self.assertNotIn('python3.11', rhel10)
        self.assertIn('python3', rhel10)

    def test_requirements_record_keeps_exact_version_and_small_profile_fields(self):
        rhel10 = profile('10', '10.0')
        record = helper_profile.requirements(
            rhel10, helper_profile.manifest_packages(rhel10))
        self.assertEqual(record['mode'], 'rpm')
        self.assertEqual(record['rhelVersion'], '10.0')
        self.assertEqual(record['osMajor'], '10')
        self.assertEqual(record['osVersion'], '10.0')
        self.assertEqual(record['arch'], 'x86_64')
        self.assertEqual(record['profile'], 'rhel10')
        self.assertNotIn('python3.11', record['packages'])

    def test_legacy_9_requirements_reuse_only_on_exact_9_host_and_packages(self):
        rhel96 = profile('9', '9.6')
        legacy = {'mode': 'rpm', 'rhelVersion': '9.6',
                  'packages': helper_profile.manifest_packages(rhel96)}
        helper_profile.validate_cached(legacy, rhel96)
        with self.assertRaisesRegex(ValueError, '精确版本'):
            helper_profile.validate_cached(legacy, profile('9', '9.7'))
        with self.assertRaisesRegex(ValueError, 'RHEL'):
            helper_profile.validate_cached(legacy, profile('10', '10.0'))
        missing = dict(legacy, packages=['python3'])
        with self.assertRaisesRegex(ValueError, '缺少当前依赖'):
            helper_profile.validate_cached(missing, rhel96)

    def test_rhel10_requirements_cannot_be_reused_on_rhel9(self):
        rhel10 = profile('10', '10.0')
        record = helper_profile.requirements(
            rhel10, helper_profile.manifest_packages(rhel10))
        with self.assertRaisesRegex(ValueError, 'RHEL'):
            helper_profile.validate_cached(record, profile('9', '9.6'))

    def test_cached_el9_slice_is_rejected_before_hashing_on_rhel10(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            helper = root / 'helper'
            helper.mkdir()
            (helper / 'checksums.json').write_text('{}')
            (helper / 'requirements.json').write_text(json.dumps({
                'mode': 'rpm', 'rhelVersion': '9.6',
                'rpmCollection': 'isolated-transaction-cache-v1',
                'packages': helper_profile.manifest_packages(profile('9', '9.6'))}))
            with patch.object(delivery.helper_profile, 'detect_host',
                              return_value=profile('10', '10.0')), \
                 patch.object(delivery.offline, 'digest',
                              side_effect=AssertionError('hash before profile check')):
                with self.assertRaisesRegex(ValueError, 'RHEL'):
                    delivery.prepare_helper(
                        SimpleNamespace(helper_mode='rpm', harbor_sha256=None),
                        root, root / 'cache')

    def test_legacy_9_cached_helper_is_reused_without_profile_fields(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            helper = root / 'helper'
            helper.mkdir()
            (helper / 'checksums.json').write_text('{}')
            (helper / 'requirements.json').write_text(json.dumps({
                'mode': 'rpm', 'rhelVersion': '9.6',
                'rpmCollection': 'isolated-transaction-cache-v1',
                'packages': helper_profile.manifest_packages(profile('9', '9.6'))}))
            with patch.object(delivery.helper_profile, 'detect_host',
                              return_value=profile('9', '9.6')), \
                 patch.object(delivery.offline, 'digest',
                              side_effect=AssertionError('unexpected hash')):
                delivery.prepare_helper(
                    SimpleNamespace(helper_mode='rpm', harbor_sha256=None),
                    root, root / 'cache')

    def test_conflicting_version_fields_cannot_override_legacy_version(self):
        current = profile('10', '10.0')
        record = helper_profile.requirements(current, helper_profile.manifest_packages(current))
        for changes in ({'rhelVersion': '9.6'}, {'osMajor': '9'}):
            with self.subTest(changes=changes):
                with self.assertRaisesRegex(ValueError, '记录不一致'):
                    helper_profile.validate_cached(dict(record, **changes), current)

    def test_rhel10_rpm_audit_rejects_foreign_el_but_rhel9_is_unchanged(self):
        with tempfile.TemporaryDirectory() as directory:
            rpms = Path(directory)
            (rpms / 'good-1.el10.x86_64.rpm').write_bytes(b'fixture')
            (rpms / 'bad-1.el9.x86_64.rpm').write_bytes(b'fixture')
            helper_profile.audit_rpms(rpms, profile('9', '9.6'))
            with self.assertRaisesRegex(ValueError, '非 el10'):
                helper_profile.audit_rpms(rpms, profile('10', '10.0'))
            (rpms / 'bad-1.el9.x86_64.rpm').unlink()
            (rpms / 'bad-1.el8.x86_64.rpm').write_bytes(b'fixture')
            with self.assertRaisesRegex(ValueError, '非 el10'):
                helper_profile.audit_rpms(rpms, profile('10', '10.0'))

    def test_shell_gate_accepts_9_and_10_and_rejects_unsupported(self):
        accepted = [('rhel', '9', 'x86_64', '9:9'),
                    ('rhel', '9.6', 'x86_64', '9:9.6'),
                    ('rhel', '10.0', 'x86_64', '10:10.0')]
        for identifier, version, arch, expected in accepted:
            with self.subTest(version=version):
                result = subprocess.run(
                    ['bash', '-c',
                     'source "$1/lib/common.sh"; validate_helper_identity "$2" "$3" "$4"; '
                     'printf "%s:%s" "$OCP_HELPER_MAJOR" "$OCP_HELPER_VERSION"',
                     'bash', str(ROOT), identifier, version, arch],
                    capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout, expected)
        for identifier, version, arch in (
                ('centos', '9.6', 'x86_64'), ('rhel', '8.10', 'x86_64'),
                ('rhel', '11.0', 'x86_64'), ('rhel', '10.0', 'aarch64')):
            with self.subTest(identifier=identifier, version=version, arch=arch):
                result = subprocess.run(
                    ['bash', '-c', 'source "$1/lib/common.sh"; validate_helper_identity "$2" "$3" "$4"',
                     'bash', str(ROOT), identifier, version, arch],
                    capture_output=True, text=True)
                self.assertNotEqual(result.returncode, 0)

    def test_install_dependencies_uses_profile_package_split(self):
        code = install_function('install_dependencies')
        for major, has_311, has_python3 in (('9', True, False), ('10', False, True)):
            with self.subTest(major=major):
                program = ('set -euo pipefail\n'
                           'log() { :; }\n'
                           'die() { echo "$*" >&2; exit 1; }\n'
                           'dnf_install() { printf "%s\\n" "$@"; }\n'
                           'sudo() { "$@"; }\n'
                           'systemctl() { :; }\n'
                           'python3() { "$REAL_PYTHON" "$@"; }\n'
                           'SKIP_FIREWALLD=true\nYUM_REPO_MODE=bundle\n'
                           'SCRIPT_DIR=$ROOT\n'
                           f'OCP_HELPER_MAJOR={major}\n'
                           + code + '\ninstall_dependencies\n')
                result = shell(program, REAL_PYTHON=sys.executable)
                self.assertEqual(result.returncode, 0, result.stderr)
                packages = result.stdout.splitlines()
                self.assertEqual('python3.11' in packages, has_311)
                self.assertEqual('python3' in packages, has_python3)
                self.assertIn('python3-pyyaml', packages)
                self.assertIn('python3-pip', packages)
                self.assertNotIn('firewalld', packages)

    def test_official_rhel9_tool_archive_names_are_not_rewritten(self):
        versions = (ROOT / 'config/versions.sh').read_text()
        offline = (ROOT / 'lib/offline.py').read_text()
        self.assertIn('openshift-client-linux-amd64-rhel9-', versions)
        self.assertIn("openshift-client-linux-amd64-rhel9-", offline)
        self.assertNotIn('rhel10', versions.lower())
        self.assertNotIn('rhel10', offline.lower())


if __name__ == '__main__':
    unittest.main()
