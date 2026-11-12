import json
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'lib'))
import registry_trust


class RegistryTrustTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.root = Path(cls.temp.name)
        cls.certs = []
        for name in ('original', 'harbor'):
            path = cls.root / (name + '.crt')
            subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                '-subj', '/CN=' + name, '-keyout', str(cls.root / (name + '.key')), '-out', str(path)],
                capture_output=True, check=True)
            cls.certs.append(path.read_text())

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def setUp(self):
        self.incoming = self.root / 'harbor.crt'
        self.proxy = {'metadata': {'resourceVersion': '5'}, 'spec': {'httpProxy': 'https://proxy.example.com',
                       'noProxy': '.internal', 'trustedCA': {'name': 'corporate-ca'}}}
        self.existing = {'metadata': {'resourceVersion': '7'}, 'data': {'ca-bundle.crt': '# Corporate anchor\n' + self.certs[0], 'other-key': 'keep'}}

    def test_merges_existing_certificates_without_replacing_proxy_settings(self):
        with patch.object(registry_trust, 'oc', side_effect=[self.proxy, self.existing, {}]) as oc:
            report = registry_trust.ensure(self.incoming)
        self.assertEqual(report['certificateCount'], 2)
        command = oc.call_args_list[-1].args[0]
        self.assertEqual(command[:3], ['patch', 'configmap', 'corporate-ca'])
        payload = json.loads(command[command.index('-p') + 1])
        self.assertEqual(payload['metadata']['resourceVersion'], '7')
        self.assertEqual(len(registry_trust.certificates(payload['data']['ca-bundle.crt'])), 2)
        self.assertNotIn('spec', payload)
        self.assertNotIn('other-key', payload['data'])

    def test_retry_with_same_ca_has_no_cluster_mutations(self):
        self.existing['data']['ca-bundle.crt'] = self.certs[0] + self.certs[1]
        with patch.object(registry_trust, 'oc', side_effect=[self.proxy, self.existing]) as oc:
            report = registry_trust.ensure(self.incoming)
        self.assertFalse(report['bundleChanged'])
        self.assertEqual(oc.call_count, 2)

    def test_initial_configuration_only_patches_the_trust_reference(self):
        self.proxy['spec']['trustedCA']['name'] = ''
        with patch.object(registry_trust, 'oc', side_effect=[self.proxy, None, {}, {}]) as oc:
            report = registry_trust.ensure(self.incoming)
        self.assertEqual(report['configMap'], 'ocpinstall-registry-ca')
        created = oc.call_args_list[2].args[2]
        self.assertEqual(created['kind'], 'ConfigMap')
        command = oc.call_args_list[-1].args[0]
        payload = json.loads(command[command.index('-p') + 1])
        self.assertEqual(payload['spec'], {'trustedCA': {'name': 'ocpinstall-registry-ca'}})
        self.assertEqual(payload['metadata']['resourceVersion'], '5')

    def test_preview_never_writes_cluster_resources(self):
        with patch.object(registry_trust, 'oc', side_effect=[self.proxy, self.existing]) as oc:
            report = registry_trust.ensure(self.incoming, dry_run=True)
        self.assertTrue(report['dryRun'])
        self.assertTrue(all(call.args[0][0] == 'get' for call in oc.call_args_list))

    def test_invalid_ca_or_private_key_fails_before_cluster_access(self):
        bad = self.root / 'bad-ca.pem'
        for content in ('invalid', self.certs[1] + '-----BEGIN PRIVATE KEY-----\nfixture\n-----END PRIVATE KEY-----'):
            bad.write_text(content)
            with patch.object(registry_trust, 'oc') as oc:
                with self.assertRaises(ValueError):
                    registry_trust.ensure(bad)
                oc.assert_not_called()

    def test_missing_existing_trust_configmap_is_not_silently_replaced(self):
        with patch.object(registry_trust, 'oc', side_effect=[self.proxy, None]) as oc:
            with self.assertRaisesRegex(ValueError, '不存在'):
                registry_trust.ensure(self.incoming)
        self.assertEqual(oc.call_count, 2)

    def test_idempotent_or_preview_configuration_never_restarts_components(self):
        with patch.object(registry_trust, 'oc') as oc:
            result = registry_trust.reload_components({'dryRun': True}, {})
        self.assertEqual(result, [])
        oc.assert_not_called()

    def test_unchanged_completed_cache_refresh_has_no_mutations(self):
        deployment = {'metadata': {'annotations': {registry_trust.CACHE_ANNOTATION: 'a'*64}}}
        with patch.object(registry_trust, 'oc', return_value=deployment) as oc:
            result = registry_trust.reload_components({'dryRun': False, 'bundleChanged': False,
                'proxyReferenceChanged': False, 'caBundleSha256': 'a'*64,
                'incomingCertificateFingerprints': []}, {})
        self.assertEqual(result, [])
        self.assertEqual(oc.call_count, 2)
        self.assertTrue(all(call.args[0][:2] == ['get', 'deployment'] for call in oc.call_args_list))

    def test_components_reload_only_after_the_actual_ca_is_injected(self):
        receipt = {'dryRun': False, 'bundleChanged': True, 'proxyReferenceChanged': False,
                   'caBundleSha256': 'a'*64,
                   'incomingCertificateFingerprints': list(registry_trust.certificates(self.certs[1]))}
        commands = []
        deployment = {'spec': {'template': {'spec': {'volumes': [{'projected': {'sources': [
            {'configMap': {'name': 'trusted-ca', 'items': [{'key': 'ca-bundle.crt', 'path': 'ca-bundle.crt'}]}}
        ]}}]}}}}
        def oc(command, env, **kwargs):
            commands.append(command)
            if command[:2] == ['get', 'deployment']:
                return deployment
            if command[:2] == ['get', 'configmap']:
                return {'data': {'ca-bundle.crt': self.certs[1]}}
            return ''
        with patch.object(registry_trust, 'oc', side_effect=oc):
            restarted = registry_trust.reload_components(receipt, {})
        self.assertEqual(len(restarted), 2)
        first_restart = next(i for i, c in enumerate(commands) if c[:2] == ['rollout', 'restart'])
        self.assertEqual(sum(c[:2] == ['get', 'configmap'] for c in commands[:first_restart]), 2)

    def test_unchanged_ca_resumes_only_the_refresh_that_did_not_complete(self):
        namespaces = ['openshift-catalogd', 'openshift-operator-controller']
        deployments = {ns: {'metadata': {'annotations': {}}, 'spec': {'template': {'spec': {
            'volumes': [{'configMap': {'name': 'trusted-ca', 'items': [{'key': 'ca-bundle.crt'}]}}]}}}}
            for ns in namespaces}
        receipt = {'dryRun': False, 'bundleChanged': False, 'proxyReferenceChanged': False,
                   'caBundleSha256': 'a'*64,
                   'incomingCertificateFingerprints': list(registry_trust.certificates(self.certs[1]))}
        failed = False
        restarts = []
        def oc(command, env, **kwargs):
            nonlocal failed
            ns = command[command.index('-n')+1]
            if command[:2] == ['get', 'deployment']:
                return deployments[ns]
            if command[:2] == ['get', 'configmap']:
                return {'data': {'ca-bundle.crt': self.certs[1]}}
            if command[:2] == ['rollout', 'restart']:
                restarts.append(ns)
            if command[:2] == ['rollout', 'status'] and ns == namespaces[1] and not failed:
                failed = True
                raise subprocess.CalledProcessError(1, ['oc'])
            if command[0] == 'annotate':
                deployments[ns]['metadata']['annotations'][registry_trust.CACHE_ANNOTATION] = 'a'*64
            return ''
        with patch.object(registry_trust, 'oc', side_effect=oc):
            with self.assertRaises(subprocess.CalledProcessError):
                registry_trust.reload_components(receipt, {})
            self.assertNotIn(registry_trust.CACHE_ANNOTATION, deployments[namespaces[1]]['metadata']['annotations'])
            resumed = registry_trust.reload_components(receipt, {})
        self.assertEqual(resumed, ['openshift-operator-controller/operator-controller-controller-manager'])
        self.assertEqual(restarts.count(namespaces[0]), 1)
        self.assertEqual(restarts.count(namespaces[1]), 2)

    def test_api_calls_are_bounded_without_truncating_the_rollout_wait(self):
        for arguments, request_timeout, process_timeout in [
                (['get', 'proxy', 'cluster', '-o', 'json'], '30s', 45),
                (['rollout', 'status', 'deployment/example', '--timeout=180s'], '0', 195)]:
            with self.subTest(arguments=arguments), patch.object(registry_trust.subprocess, 'run',
                    return_value=SimpleNamespace(stdout='{}')) as run:
                registry_trust.oc(arguments, {}, structured=False)
            self.assertIn('--request-timeout='+request_timeout, run.call_args.args[0])
            self.assertEqual(run.call_args.kwargs['timeout'], process_timeout)


if __name__ == '__main__':
    unittest.main()
