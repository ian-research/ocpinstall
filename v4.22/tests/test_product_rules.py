import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'lib'))
import product_rules


class CatalogFixture:
    def __init__(self, packages):
        self.bundles = [{'package': name, 'version': version} for name, version in packages]
        self.packages = {('redhat', b['package']): {} for b in self.bundles}

    def root(self, spec):
        name = product_rules.package_of(spec)
        return {'allowed': {next(i for i, b in enumerate(self.bundles) if b['package'] == name)}}


class ProductRuleTests(unittest.TestCase):
    def test_acm_adds_runtime_mce_not_present_in_catalog_dependencies(self):
        catalogs = CatalogFixture([('advanced-cluster-management', '5.0.0'), ('multicluster-engine', '5.0.0')])
        roots, _, requirements = product_rules.expand(catalogs, ['redhat/advanced-cluster-management'], '5.0.1')
        self.assertIn('redhat/multicluster-engine:stable-5.0', roots)
        self.assertEqual(requirements[0]['runtimeDependency'], 'multicluster-engine')

    def test_wrong_mce_pair_fails(self):
        catalogs = CatalogFixture([('advanced-cluster-management', '5.0.0'), ('multicluster-engine', '2.17.0')])
        with self.assertRaisesRegex(ValueError, 'MCE 5.0'):
            product_rules.expand(catalogs, ['redhat/advanced-cluster-management'], '4.22.22')

    def test_ai_on_5_is_blocked_before_missing_package_lookup(self):
        with self.assertRaisesRegex(ValueError, '支持矩阵'):
            product_rules.expand(CatalogFixture([]), ['redhat/rhods-operator'], '5.0.1')

    def test_ai_cpu_images_pinned_and_scope_explicit(self):
        catalogs = CatalogFixture([('rhods-operator', '3.5.3')])
        _, images, requirements = product_rules.expand(catalogs, ['redhat/rhods-operator'], '4.22.22')
        self.assertGreater(len(images), 0)
        self.assertTrue(all('@sha256:' in i for i in images))
        self.assertIn('GPU', requirements[0]['excludedFeatures'])

    def test_virtualization_5_cannot_be_used_on_422(self):
        catalogs = CatalogFixture([('kubevirt-hyperconverged', '5.0.0')])
        with self.assertRaisesRegex(ValueError, '官方支持组合'):
            product_rules.expand(catalogs, ['redhat/kubevirt-hyperconverged'], '4.22.22')

    def test_catalog_available_ai_352_uses_its_own_runtime_manifest(self):
        catalogs = CatalogFixture([('rhods-operator', '3.5.2')])
        _, images, requirements = product_rules.expand(catalogs, ['redhat/rhods-operator:stable-3.5=3.5.2'], '4.22.22')
        self.assertTrue(images)
        self.assertIn('rhoai-3.5.2-imagesetconfig.yaml', requirements[0]['runtimeImageSource'])

    def test_virtualization_422_includes_guest_boot_image(self):
        catalogs = CatalogFixture([('kubevirt-hyperconverged', '4.22.16')])
        _, images, requirements = product_rules.expand(catalogs, ['redhat/kubevirt-hyperconverged'], '4.22.22')
        self.assertIn('registry.redhat.io/rhel9/rhel-guest-image:latest', images)
        self.assertEqual(requirements[0]['bootSourcePolicy'], 'manual-offline')


if __name__ == '__main__':
    unittest.main()
