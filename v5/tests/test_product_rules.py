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

    def test_ai_includes_both_platform_managed_gateway_operands(self):
        catalogs = CatalogFixture([('rhods-operator', '3.5.2')])
        _, images, requirements = product_rules.expand(catalogs, ['redhat/rhods-operator'], '4.22.22')
        self.assertTrue(any('/istio-pilot-rhel9@sha256:' in image for image in images))
        self.assertTrue(any('/istio-proxyv2-rhel9@sha256:' in image for image in images))
        self.assertEqual(requirements[0]['gatewayPlatformVersion'], '4.22.22')

    def test_ai_rejects_unverified_platform_patch_instead_of_reusing_gateway_images(self):
        catalogs = CatalogFixture([('rhods-operator', '3.5.2')])
        with self.assertRaisesRegex(ValueError, '网关运行镜像尚未核实'):
            product_rules.expand(catalogs, ['redhat/rhods-operator'], '4.22.23')

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

    def odf_catalog(self, platform='4.22'):
        return CatalogFixture([(name, '4.22.7-rhodf') for name in product_rules.ODF_PACKAGES]
                              + [('local-storage-operator', platform + '.0')])

    def test_odf_adds_every_paired_operator_even_without_declared_edges(self):
        roots, _, requirements = product_rules.expand(self.odf_catalog(), ['redhat/odf-operator'], '4.22.22')
        self.assertEqual({product_rules.package_of(s) for s in roots},
                         set(product_rules.ODF_PACKAGES) | {'local-storage-operator'})
        self.assertTrue(all(s.endswith('=4.22.7-rhodf') for s in roots if s != 'redhat/odf-operator'
                            and product_rules.package_of(s) != 'local-storage-operator'))
        self.assertTrue(requirements[0]['localStorageIncluded'])

    def test_odf_dynamic_storage_omits_only_the_optional_local_storage_operator(self):
        roots, _, _ = product_rules.expand(self.odf_catalog(), ['redhat/odf-operator'],
                                           '4.22.22', odf_local_storage=False)
        self.assertEqual({product_rules.package_of(s) for s in roots}, set(product_rules.ODF_PACKAGES))

    def test_missing_odf_package_or_different_release_is_not_silently_accepted(self):
        catalogs = self.odf_catalog()
        del catalogs.packages['redhat', 'ocs-tls-profiles']
        with self.assertRaisesRegex(ValueError, '配套包'):
            product_rules.expand(catalogs, ['redhat/odf-operator'], '4.22.22')
        catalogs = self.odf_catalog()
        next(b for b in catalogs.bundles if b['package'] == 'ocs-operator')['version'] = '4.22.6-rhodf'
        with self.assertRaisesRegex(ValueError, '必须与主包版本'):
            product_rules.expand(catalogs, ['redhat/odf-operator'], '4.22.22')

    def test_visible_odf_in_5_catalog_does_not_override_declared_platform_limit(self):
        with self.assertRaisesRegex(ValueError, '最高 OpenShift 4.23'):
            product_rules.expand(self.odf_catalog('5.0'), ['redhat/odf-operator'], '5.0.1')

    def test_mtv_uses_its_own_version_and_platform_support(self):
        for platform, version in [('4.22.22', '2.12.10'), ('4.22.22', '5.0.0'), ('5.0.1', '5.0.0')]:
            _, _, requirements = product_rules.expand(CatalogFixture([('mtv-operator', version)]),
                ['redhat/mtv-operator'], platform)
            self.assertEqual(requirements[0]['product'], 'mtv')
        with self.assertRaisesRegex(ValueError, '下载组合'):
            product_rules.expand(CatalogFixture([('mtv-operator', '2.12.10')]),
                                 ['redhat/mtv-operator'], '5.0.1')

    def test_explicit_guest_images_override_the_legacy_rhel_default(self):
        catalogs = CatalogFixture([('kubevirt-hyperconverged', '4.22.16')])
        _, images, _ = product_rules.expand(catalogs, ['redhat/kubevirt-hyperconverged'],
                                           '4.22.22', guest_images=[])
        self.assertEqual(images, [])
        fedora = 'quay.io/containerdisks/fedora@sha256:' + 'a' * 64
        _, images, _ = product_rules.expand(catalogs, ['redhat/kubevirt-hyperconverged'],
                                           '4.22.22', guest_images=[fedora])
        self.assertEqual(images, [fedora])

    def test_node_healthcheck_adds_a_remediation_provider_but_keeps_explicit_alternatives(self):
        c = CatalogFixture([('node-healthcheck-operator', '0.12.1'), ('self-node-remediation', '0.13.1')])
        roots, _, _ = product_rules.expand(c, ['redhat/node-healthcheck-operator'], '4.22.22')
        self.assertIn('redhat/self-node-remediation', roots)
        c = CatalogFixture([('node-healthcheck-operator', '0.12.1'), ('fence-agents-remediation', '0.6.1')])
        roots, _, _ = product_rules.expand(c, ['redhat/node-healthcheck-operator', 'redhat/fence-agents-remediation'], '4.22.22')
        self.assertFalse(any('self-node-remediation' in s for s in roots))

    def test_gpu_adds_nfd_matching_driver_toolkit_and_cuda_workbenches(self):
        c = CatalogFixture([('rhods-operator', '3.5.2'), ('gpu-operator-certified', '26.7.2'), ('nfd', '4.22.0')])
        gpu = next(b for b in c.bundles if b['package'] == 'gpu-operator-certified')
        gpu['relatedImages'] = [{'name': 'driver-image', 'image': 'nvcr.io/nvidia/driver@sha256:' + 'a' * 64}]
        roots, images, requirements = product_rules.expand(c, ['redhat/rhods-operator', 'redhat/gpu-operator-certified'], '4.22.22')
        self.assertIn('redhat/nfd', roots)
        self.assertTrue(any('-cuda-' in i for i in images))
        toolkit = json.loads((Path(product_rules.__file__).resolve().parent.parent / 'config/ocp-4.22.22-gpu-images.json').read_text())
        self.assertTrue(set(toolkit['images']) <= set(images))
        ai = next(r for r in requirements if r['product'] == 'ai')
        self.assertNotIn('GPU', ai['excludedFeatures'])
        self.assertTrue(ai['nvidiaImagesIncluded'])

    def test_gpu_rejects_missing_driver_or_unknown_platform_patch(self):
        c = CatalogFixture([('gpu-operator-certified', '26.7.2'), ('nfd', '4.22.0')])
        with self.assertRaisesRegex(ValueError, '缺少默认 driver-image'):
            product_rules.expand(c, ['redhat/gpu-operator-certified'], '4.22.22')
        with self.assertRaisesRegex(ValueError, '尚未核实目标补丁'):
            product_rules.expand(c, ['redhat/gpu-operator-certified'], '4.22.23')
        with self.assertRaisesRegex(ValueError, '5.0 certified'):
            product_rules.expand(c, ['redhat/gpu-operator-certified'], '5.0.1')


if __name__ == '__main__':
    unittest.main()
