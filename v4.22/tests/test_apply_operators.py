import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'lib'))
import apply_operators
import operator_profile


class ApplyOperatorTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.bundle = Path(self.temp.name) / 'operator bundle'
        self.bundle.mkdir()
        self.version = operator_profile.release()
        self.cluster = {'status': {'desired': {'version': self.version}, 'conditions': [
            {'type': 'Available', 'status': 'True'}, {'type': 'Progressing', 'status': 'False'},
            {'type': 'Failing', 'status': 'False'}]}}

    def run_apply(self, dry_run=False, registry_ca=None):
        command = ['apply_operators.py', '--bundle', str(self.bundle), '--kubeconfig', '/private/admin.conf']
        if dry_run:
            command.append('--dry-run')
        if registry_ca:
            command += ['--registry-ca', registry_ca]
        with patch.object(sys, 'argv', command), \
             patch.object(apply_operators, 'load_plan', return_value={'targetVersion': self.version}), \
             patch.object(apply_operators, 'prepare') as prepare, \
             patch.object(apply_operators, 'require_ready') as health, \
             patch.object(apply_operators, 'disable_default_sources') as disable, \
             patch.object(apply_operators.subprocess, 'run', return_value=SimpleNamespace(stdout=json.dumps(self.cluster))) as run:
            try:
                apply_operators.main()
            finally:
                self.prepare = prepare
                self.run = run
                self.disable = disable
                self.health = health

    def test_wrong_minor_is_blocked_before_preparation_or_mutation(self):
        self.cluster['status']['desired']['version'] = '4.18.10'
        with self.assertRaisesRegex(ValueError, '不匹配'):
            self.run_apply()
        self.prepare.assert_not_called()
        self.assertEqual(self.run.call_count, 1)

    def test_unready_cluster_is_blocked_before_mutation(self):
        self.cluster['status']['conditions'][1]['status'] = 'True'
        with self.assertRaisesRegex(ValueError, '尚未安装完成'):
            self.run_apply()
        self.prepare.assert_not_called()
        self.assertEqual(self.run.call_count, 1)

    def test_dry_run_uses_server_validation_without_disabling_default_catalogs(self):
        self.run_apply(True)
        commands = [call.args[0] for call in self.run.call_args_list]
        self.assertEqual(len(commands), 2)
        self.assertEqual(self.run.call_args_list[0].kwargs['timeout'], 45)
        self.assertEqual(self.run.call_args_list[-1].kwargs['timeout'], 90)
        self.assertIn('--dry-run=server', commands[-1])
        self.assertFalse(any('patch' in command for command in commands))
        self.disable.assert_not_called()
        self.health.assert_called_once()
        self.assertEqual(self.run.call_args.kwargs['env']['KUBECONFIG'], '/private/admin.conf')

    def test_apply_preserves_explicit_basic_availability(self):
        with patch.dict(os.environ, {'ACM_AVAILABILITY': 'Basic'}):
            self.run_apply()
        self.assertEqual(self.prepare.call_args.args[-1], 'Basic')
        commands = [call.args[0] for call in self.run.call_args_list]
        self.disable.assert_called_once()
        self.assertEqual(commands[-1][:2], ['oc', 'apply'])

    def test_explicit_ca_uses_preview_mode_for_server_dry_run(self):
        with patch.object(apply_operators, 'ensure_registry_trust') as trust, \
             patch.object(apply_operators, 'reload_components') as reload:
            self.run_apply(True, '/public/harbor-ca.crt')
        self.assertEqual(trust.call_args.args[0], '/public/harbor-ca.crt')
        self.assertTrue(trust.call_args.args[2])
        self.assertEqual(trust.call_args.args[1]['KUBECONFIG'], '/private/admin.conf')
        reload.assert_called_once()

    def test_failed_bundle_verification_cannot_disable_default_catalogs(self):
        command = ['apply_operators.py', '--bundle', str(self.bundle), '--kubeconfig', '/private/admin.conf']
        with patch.object(sys, 'argv', command), \
             patch.object(apply_operators, 'load_plan', return_value={'targetVersion': self.version}), \
             patch.object(apply_operators, 'prepare', side_effect=ValueError('corrupt archive')), \
             patch.object(apply_operators, 'require_ready'), \
             patch.object(apply_operators.subprocess, 'run', return_value=SimpleNamespace(stdout=json.dumps(self.cluster))) as run:
            with self.assertRaisesRegex(ValueError, 'corrupt archive'):
                apply_operators.main()
            self.assertEqual(run.call_count, 1)

    def test_runtime_health_failure_prevents_ca_policy_and_resource_changes(self):
        command = ['apply_operators.py', '--bundle', str(self.bundle), '--kubeconfig', '/private/admin.conf']
        with patch.object(sys, 'argv', command), \
             patch.object(apply_operators, 'load_plan', return_value={'targetVersion': self.version}), \
             patch.object(apply_operators, 'require_ready', side_effect=ValueError('MCP updating')), \
             patch.object(apply_operators, 'prepare') as prepare, \
             patch.object(apply_operators, 'ensure_registry_trust') as trust, \
             patch.object(apply_operators, 'disable_default_sources') as disable, \
             patch.object(apply_operators.subprocess, 'run', return_value=SimpleNamespace(stdout=json.dumps(self.cluster))) as run:
            with self.assertRaisesRegex(ValueError, 'MCP updating'):
                apply_operators.main()
            self.assertEqual(run.call_count, 1)
            prepare.assert_not_called()
            trust.assert_not_called()
            disable.assert_not_called()


if __name__ == '__main__':
    unittest.main()
