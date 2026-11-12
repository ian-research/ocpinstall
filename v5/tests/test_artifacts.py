import base64
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('v5artifacts', ROOT / 'lib/artifacts.py')
a = importlib.util.module_from_spec(spec)
spec.loader.exec_module(a)


class ArtifactTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.resources = self.root / 'resources'
        self.resources.mkdir()
        self.sources = ['quay.io/openshift-release-dev/ocp-release',
                        'quay.io/openshift-release-dev/ocp-v5.0-art-dev']
        self.registry = 'helper.lab.example.com:8443'
        self.prefix = self.registry + '/openshift501'
        self.mapping = {'apiVersion': 'config.openshift.io/v1', 'kind': 'ImageDigestMirrorSet',
            'spec': {'imageDigestMirrors': [
                {'source': source, 'mirrors': [self.prefix + '/actual-path-' + str(i)]}
                for i, source in enumerate(self.sources)]}}
        (self.resources / 'idms.yaml').write_text(json.dumps(self.mapping))

    def test_mapping_uses_real_paths(self):
        values = a.mirror_sources(self.resources, self.sources, self.prefix)
        self.assertEqual(values[1]['mirrors'], [self.prefix + '/actual-path-1'])

    def test_missing_component_mapping_fails(self):
        self.mapping['spec']['imageDigestMirrors'].pop()
        (self.resources / 'idms.yaml').write_text(json.dumps(self.mapping))
        with self.assertRaises(ValueError):
            a.mirror_sources(self.resources, self.sources, self.prefix)

    def test_foreign_registry_mapping_fails(self):
        with self.assertRaises(ValueError):
            a.mirror_sources(self.resources, self.sources, 'other.registry/project')

    def test_install_config_preserves_secret_and_network(self):
        secret = self.root / 'pull-secret.json'
        data = {'auths': {self.registry: {'auth': 'YWJjOmRlZg==', 'email': "a'b@example.com"}}}
        secret.write_text(json.dumps(data))
        ssh = self.root / 'key'
        ssh.with_suffix('.pub').write_text('ssh-ed25519 public-key')
        (self.root / 'ca.crt').write_text('TEST CA')
        env = {'OCP_DOMAIN': 'lab.example.com', 'LOCAL_REGISTRY': self.registry,
               'LOCAL_REPOSITORY': 'openshift501', 'CLUSTER_PULL_SECRET': str(secret),
               'SSH_KEY': str(ssh), 'CERT_DIR': str(self.root), 'HELPER_IP_ADDRESS': '192.168.1.10',
               'RELEASE_SOURCE': self.sources[0], 'COMPONENT_SOURCE': self.sources[1]}
        output = self.root / 'install-config.yaml'
        with patch.dict(os.environ, env, clear=True):
            a.install_config(self.resources, output)
        config = json.loads(output.read_text())
        self.assertEqual(json.loads(config['pullSecret']), data)
        self.assertEqual(config['compute'][0]['replicas'], 0)
        self.assertEqual(config['platform'], {'none': {}})
        self.assertEqual(config['networking']['machineNetwork'], [{'cidr': '192.168.1.0/24'}])
        self.assertEqual(output.stat().st_mode & 0o777, 0o600)

    def test_master_ntp_and_scheduler_before_ignition(self):
        scheduler = self.root / 'manifests/cluster-scheduler-02-config.yml'
        scheduler.parent.mkdir()
        scheduler.write_text('apiVersion: config.openshift.io/v1\nkind: Scheduler\nspec:\n  mastersSchedulable: false\n')
        with patch.dict(os.environ, {'OCP_DOMAIN': 'lab.example.com'}):
            a.prepare_manifests(self.root)
        self.assertTrue(json.loads(scheduler.read_text())['spec']['mastersSchedulable'])
        mc = json.loads((self.root / 'openshift/99-master-chrony.yaml').read_text())
        encoded = mc['spec']['config']['storage']['files'][0]['contents']['source'].split(',', 1)[1]
        self.assertIn('server helper.lab.example.com', base64.b64decode(encoded).decode())

    def test_bootstrap_ntp_is_idempotent(self):
        path = self.root / 'bootstrap.ign'
        path.write_text('{"ignition":{"version":"3.5.0"},"storage":{"files":[{"path":"/etc/other"}]}}')
        with patch.dict(os.environ, {'OCP_DOMAIN': 'lab.example.com'}):
            a.bootstrap_ntp(self.root)
            a.bootstrap_ntp(self.root)
        files = json.loads(path.read_text())['storage']['files']
        self.assertEqual(len(files), 2)
        self.assertEqual(files[-1]['path'], '/etc/chrony.conf')

    def test_helper_rejects_self_referencing_ntp(self):
        for address in ('192.168.1.10', '127.0.0.1', '0.0.0.0'):
            with patch.object(a.socket, 'getaddrinfo', return_value=[(2, 2, 17, '', (address, 123))]):
                with self.assertRaisesRegex(ValueError, '自身'):
                    a.helper_chrony_config('ntp.example.com', '192.168.1.0/24', '192.168.1.10')

    def test_helper_local_ntp_requires_explicit_mode_without_upstream(self):
        config = a.helper_chrony_config('', '192.168.1.0/24', '192.168.1.10', 'local')
        self.assertIn('local stratum 10', config)
        self.assertNotIn('server ', config)
        self.assertIn('allow 192.168.1.0/24', config)
        with self.assertRaises(ValueError):
            a.helper_chrony_config('ntp.example.com', '192.168.1.0/24', '192.168.1.10', 'local')

    def test_helper_upstream_dns_failure_and_network_are_checked(self):
        with patch.object(a.socket, 'getaddrinfo', side_effect=a.socket.gaierror):
            with self.assertRaisesRegex(ValueError, '无法解析'):
                a.helper_chrony_config('missing.example.com', '192.168.1.0/24', '192.168.1.10')
        with self.assertRaises(ValueError):
            a.helper_chrony_config('', '192.168.2.0/24', '192.168.1.10', 'local')

    def test_helper_upstream_has_no_silent_local_fallback(self):
        with patch.object(a.socket, 'getaddrinfo', return_value=[(2, 2, 17, '', ('192.168.1.1', 123))]):
            config = a.helper_chrony_config('ntp.example.com', '192.168.1.0/24', '192.168.1.10')
        self.assertIn('server ntp.example.com iburst', config)
        self.assertNotIn('local stratum', config)

    def test_published_commands_have_correct_hash_and_offline_flag(self):
        public = self.root / 'public'
        public.mkdir()
        for role in ('bootstrap', 'master'):
            (self.root / (role + '.ign')).write_bytes(role.encode())
            (public / (role + '.ign')).write_bytes(role.encode())
        output = self.root / 'commands.txt'
        a.commands(self.root, public, 'helper.lab.example.com', output)
        text = output.read_text()
        self.assertIn('--ignition-hash=sha512-' + hashlib.sha512(b'master').hexdigest(), text)
        self.assertIn('--offline --copy-network', text)
        self.assertNotIn('--insecure', text)
        (public / 'master.ign').write_bytes(b'changed')
        with self.assertRaises(ValueError):
            a.commands(self.root, public, 'helper.lab.example.com', output)

    def archive(self, name, members):
        path = self.root / name
        with tarfile.open(path, 'w:gz') as stream:
            for filename in members:
                entry = tarfile.TarInfo(filename)
                entry.size = 4
                stream.addfile(entry, io.BytesIO(b'tool'))
        return path

    def test_tool_extraction_requires_all_four_verified_binaries(self):
        archive = self.archive('tools.tar.gz', ['oc', 'kubectl', 'openshift-install', 'oc-mirror'])
        (self.root / 'checksums.json').write_text(json.dumps({archive.name: hashlib.sha256(archive.read_bytes()).hexdigest()}))
        output = self.root / 'bin'
        a.extract_tools(self.root, output)
        self.assertEqual((output / 'oc').stat().st_mode & 0o777, 0o755)
        archive.write_bytes(b'corrupted')
        with self.assertRaises(ValueError):
            a.extract_tools(self.root, output)

    def test_tool_archive_path_escape_rejected(self):
        archive = self.archive('tools.tar.gz', ['../oc'])
        (self.root / 'checksums.json').write_text(json.dumps({archive.name: hashlib.sha256(archive.read_bytes()).hexdigest()}))
        with self.assertRaises(ValueError):
            a.extract_tools(self.root, self.root / 'bin')

    def link_archive(self, target='oc', link_type=tarfile.LNKTYPE):
        path = self.root / 'tools.tar.gz'
        with tarfile.open(path, 'w:gz') as stream:
            # Exercise an alias before its target as well as the real tar type.
            alias = tarfile.TarInfo('kubectl')
            alias.type = link_type
            alias.linkname = target
            stream.addfile(alias)
            for name in ('oc', 'openshift-install', 'oc-mirror'):
                entry = tarfile.TarInfo(name)
                entry.size = 4
                stream.addfile(entry, io.BytesIO(b'tool'))
        (self.root / 'checksums.json').write_text(json.dumps({path.name: a.sha256(path)}))

    def test_official_kubectl_hardlink_and_permissions_preserved(self):
        self.link_archive()
        output = self.root / 'bin'
        for _ in range(2):
            a.extract_tools(self.root, output)
            self.assertTrue((output / 'oc').samefile(output / 'kubectl'))
            self.assertEqual((output / 'kubectl').stat().st_mode & 0o777, 0o755)
            self.assertEqual((output / 'oc').read_bytes(), b'tool')

    def test_other_link_targets_rejected_before_writing(self):
        for target, kind in (('../oc', tarfile.LNKTYPE), ('/etc/passwd', tarfile.LNKTYPE),
                             ('openshift-install', tarfile.LNKTYPE), ('oc', tarfile.SYMTYPE)):
            self.link_archive(target, kind)
            with self.assertRaises(ValueError):
                a.extract_tools(self.root, self.root / 'bin')
            self.assertFalse((self.root / 'bin').exists())

    def test_remove_bootstrap_checks_candidate_before_replace(self):
        path = self.root / 'haproxy.cfg'
        original = 'listen api\n  server bootstrap 1.2.3.4:6443 check\n  server master1 1.2.3.5:6443 check\n'
        path.write_text(original)
        with patch.object(a.subprocess, 'run', side_effect=subprocess.CalledProcessError(1, ['haproxy'])):
            with self.assertRaises(subprocess.CalledProcessError):
                a.remove_bootstrap(path)
        self.assertEqual(path.read_text(), original)
        with patch.object(a.subprocess, 'run'):
            a.remove_bootstrap(path)
        self.assertNotIn('server bootstrap', path.read_text())
        self.assertIn('server master1', path.read_text())

    def test_no_parent_script_runtime_dependency(self):
        for filename in ('install-cluster.sh', 'setup-cluster.sh', 'prepare-offline.sh'):
            program = ROOT / filename
            result = subprocess.run(['bash', str(program), '--help'], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == '__main__':
    unittest.main()
