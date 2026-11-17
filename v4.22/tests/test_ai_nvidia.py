from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'lib'))
import operators


class AINvidiaSelectionTests(unittest.TestCase):
    def args(self, **kwargs):
        return SimpleNamespace(**dict({'ai_nvidia': None, 'authfile': '/private/auth.json',
                                       'target_version': '4.22.22'}, **kwargs))

    def run_selection(self, args, selections, packages, interactive=False, sources=None):
        self.sources = sources or [{'alias': 'redhat'}]
        return operators.ai_nvidia_selection(args, self.sources, SimpleNamespace(packages=packages),
            selections, None, '/private/auth.json', Path('/bundle'), Path('/cache'), interactive)

    def test_new_ai_plan_defaults_to_the_verified_gpu_channel_without_mutating_user_roots(self):
        roots = ['redhat/rhods-operator']
        _, selected, _, enabled = self.run_selection(self.args(), roots, {('certified', 'gpu-operator-certified'): {}})
        self.assertEqual(roots, ['redhat/rhods-operator'])
        self.assertIn('certified/gpu-operator-certified:v26.7', selected)
        self.assertTrue(enabled)

    def test_explicit_cpu_mode_does_not_access_a_certified_catalog(self):
        with patch.object(operators, 'cached_catalog') as fetch:
            _, roots, _, enabled = self.run_selection(self.args(ai_nvidia=False), ['redhat/rhods-operator'], {})
        fetch.assert_not_called()
        self.assertEqual(roots, ['redhat/rhods-operator'])
        self.assertFalse(enabled)

    def test_missing_gpu_catalog_is_added_from_the_correct_platform(self):
        source = {'alias': 'nvidia-certified', 'pinned': 'registry.test/catalog@sha256:' + 'a' * 64}
        with patch.object(operators, 'cached_catalog', return_value=source) as fetch, \
             patch.object(operators, 'Catalogs', return_value=SimpleNamespace(packages={})):
            _, roots, _, _ = self.run_selection(self.args(), ['redhat/rhods-operator'], {})
        self.assertEqual(fetch.call_args.args[1], 'registry.redhat.io/redhat/certified-operator-index:v4.22')
        self.assertIn(source, self.sources)
        self.assertIn('nvidia-certified/gpu-operator-certified:v26.7', roots)

    def test_preview_and_ambiguous_gpu_catalogs_are_explicit_errors(self):
        with self.assertRaisesRegex(ValueError, '5.0'):
            self.run_selection(self.args(target_version='5.0.1'), ['redhat/rhods-operator'], {})
        with self.assertRaisesRegex(ValueError, '多个目录'):
            self.run_selection(self.args(), ['redhat/rhods-operator'], {
                ('one', 'gpu-operator-certified'): {}, ('two', 'gpu-operator-certified'): {}})

    def test_interactive_cpu_choice_and_irrelevant_option(self):
        with patch.object(operators, 'prompt', return_value='no'):
            _, _, _, enabled = self.run_selection(self.args(), ['redhat/rhods-operator'], {}, True)
        self.assertFalse(enabled)
        with self.assertRaisesRegex(ValueError, '需要选择 rhods-operator'):
            self.run_selection(self.args(ai_nvidia=True), ['redhat/web-terminal'], {})


if __name__ == '__main__':
    unittest.main()
