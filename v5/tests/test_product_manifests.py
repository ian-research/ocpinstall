import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'lib'))
import operator_profile
import operators
import product_manifests


class ProductManifestTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.destination = Path(self.temp.name) / 'product manifests'

    def fixture(self, packages, target=None, aliases=None):
        target = target or operator_profile.release()
        aliases = aliases or {}
        catalogs = [{'alias': alias, 'pinned': 'registry.test/catalog@sha256:' + 'a'*64}
                    for alias in sorted({'redhat', *aliases.values()})]
        selected = []
        gvks = {'kubevirt-hyperconverged': ('hco.kubevirt.io', 'HyperConverged'),
                'multicluster-engine': ('multicluster.openshift.io', 'MultiClusterEngine'),
                'advanced-cluster-management': ('operator.open-cluster-management.io', 'MultiClusterHub')}
        for package in packages:
            namespace, scope = product_manifests.PRODUCTS[package]
            properties = [{'type': 'olm.csv.metadata', 'value': {'installModes': [{'type': scope, 'supported': True}]}}]
            if package == 'rhods-operator':
                for group, kind in [('datasciencecluster.opendatahub.io', 'DataScienceCluster'), ('dscinitialization.opendatahub.io', 'DSCInitialization')]:
                    properties += [{'type': 'olm.gvk', 'value': {'group': group, 'kind': kind, 'version': v}} for v in ('v1', 'v2')]
                examples = [
                    {'apiVersion': 'datasciencecluster.opendatahub.io/v2', 'kind': 'DataScienceCluster',
                     'spec': {'components': {'dashboard': {'managementState': 'Managed'},
                         'workbenches': {'managementState': 'Managed'},
                         'kserve': {'managementState': 'Managed', 'nim': {'managementState': 'Managed'}},
                         'futureFeature': {'managementState': 'Managed'}}}},
                    {'apiVersion': 'dscinitialization.opendatahub.io/v2', 'kind': 'DSCInitialization',
                     'spec': {'applicationsNamespace': 'redhat-ods-applications',
                              'trustedCABundle': {'managementState': 'Managed', 'customCABundle': ''}}}]
                properties[0]['value']['annotations'] = {'alm-examples': json.dumps(examples)}
            if package in gvks:
                group, kind = gvks[package]
                properties += [{'type': 'olm.gvk', 'value': {'group': group, 'kind': kind, 'version': v}} for v in ('v1beta1', 'v1')]
            version = target.rsplit('.', 1)[0] + '.0' if package == 'kubevirt-hyperconverged' else ('3.5.2' if package == 'rhods-operator' else '5.0.0')
            bundle = 'rhods-operator.' + version if package == 'rhods-operator' else package + '.v' + version
            selected.append({'catalog': aliases.get(package, 'redhat'), 'package': package, 'version': version,
                'channel': 'stable', 'bundle': bundle, 'properties': properties})
        plan = {'targetVersion': target, 'planHash': 'f'*64, 'catalogs': catalogs,
                'selected': selected, 'additionalImages': [], 'archiveSize': 20}
        resources = [{'kind': 'CatalogSource', 'metadata': {'name': 'offline-' + c['alias'], 'namespace': 'openshift-marketplace'},
                      'spec': {'image': 'mirror.test/project/' + operator_profile.catalog_repository(plan, c['alias']) + ':filtered'}}
                     for c in catalogs if any(p['catalog'] == c['alias'] for p in selected)]
        return plan, resources

    def test_acm_mce_override_uses_actual_offline_source_and_pinned_csv(self):
        plan, resources = self.fixture(['advanced-cluster-management', 'multicluster-engine'])
        product_manifests.render(plan, resources, self.destination)
        hub = json.loads((self.destination / '03-multiclusterhub.json').read_text())
        override = json.loads(hub['metadata']['annotations']['installer.open-cluster-management.io/mce-subscription-spec'])
        self.assertEqual(override['source'], 'offline-redhat')
        self.assertEqual(override['startingCSV'], 'multicluster-engine.v5.0.0')
        self.assertEqual(override['installPlanApproval'], 'Manual')
        self.assertEqual(hub['spec']['availabilityConfig'], 'High')

    def test_suffix_aliases_point_to_their_own_catalogs(self):
        plan, resources = self.fixture(['advanced-cluster-management', 'multicluster-engine'],
                                       aliases={'multicluster-engine': 'extra-redhat'})
        product_manifests.render(plan, resources, self.destination, 'Basic')
        hub = json.loads((self.destination / '03-multiclusterhub.json').read_text())
        override = json.loads(hub['metadata']['annotations']['installer.open-cluster-management.io/mce-subscription-spec'])
        self.assertEqual(override['source'], 'offline-extra-redhat')
        self.assertEqual(hub['spec']['availabilityConfig'], 'Basic')

    def test_hyperconverged_uses_declared_stable_api(self):
        plan, resources = self.fixture(['kubevirt-hyperconverged'])
        product_manifests.render(plan, resources, self.destination)
        hco = json.loads((self.destination / '02-hyperconverged.json').read_text())
        self.assertEqual(hco['apiVersion'], 'hco.kubevirt.io/v1')
        self.assertEqual(hco['spec'], {'workloadSources': {'enableCommonBootImageImport': False}})
        subscriptions = json.loads((self.destination / '01-subscriptions.json').read_text())['items']
        group = next(r for r in subscriptions if r['kind'] == 'OperatorGroup')
        self.assertEqual(group['spec']['targetNamespaces'], ['openshift-cnv'])

    def test_beta_api_uses_supported_boot_source_field_without_ignored_feature_gate(self):
        plan, resources = self.fixture(['kubevirt-hyperconverged'])
        plan['selected'][0]['properties'] = [p for p in plan['selected'][0]['properties']
                                            if not (p['type'] == 'olm.gvk' and p['value']['version'] == 'v1')]
        product_manifests.render(plan, resources, self.destination)
        hco = json.loads((self.destination/'02-hyperconverged.json').read_text())
        self.assertEqual(hco['apiVersion'], 'hco.kubevirt.io/v1beta1')
        self.assertEqual(hco['spec'], {'enableCommonBootImageImport': False})

    def test_unknown_hco_api_cannot_silently_leave_online_boot_import_enabled(self):
        plan, resources = self.fixture(['kubevirt-hyperconverged'])
        for p in plan['selected'][0]['properties']:
            if p['type'] == 'olm.gvk':
                p['value']['version'] = 'v2'
        with self.assertRaisesRegex(ValueError, '引导源字段'):
            product_manifests.render(plan, resources, self.destination)
        self.assertFalse(self.destination.exists())

    def test_ai_subscription_requires_declared_all_namespace_scope(self):
        plan, resources = self.fixture(['rhods-operator'], target='4.22.22')
        product_manifests.render(plan, resources, self.destination)
        subscriptions = json.loads((self.destination / '01-subscriptions.json').read_text())['items']
        group = next(r for r in subscriptions if r['kind'] == 'OperatorGroup')
        self.assertEqual(group['spec'], {})
        component = json.loads((self.destination / '02-ai-cpu-workbenches.json').read_text())
        self.assertEqual(component['apiVersion'], 'datasciencecluster.opendatahub.io/v2')
        states = component['spec']['components']
        self.assertEqual({name for name, value in states.items() if value['managementState'] == 'Managed'}, {'dashboard', 'workbenches'})
        self.assertEqual(states['kserve']['nim']['managementState'], 'Removed')
        self.assertEqual(states['futureFeature']['managementState'], 'Removed')
        reference = json.loads((self.destination / 'reference/ai-initialization.json').read_text())
        self.assertEqual(reference['apiVersion'], 'dscinitialization.opendatahub.io/v2')
        top_level = [json.loads(path.read_text()) for path in self.destination.glob('*.json')]
        self.assertFalse(any(item.get('kind') == 'DSCInitialization' for item in top_level))
        original = json.loads(plan['selected'][0]['properties'][0]['value']['annotations']['alm-examples'])
        self.assertEqual(original[0]['spec']['components']['kserve']['nim']['managementState'], 'Managed')
        self.assertIn('不要 apply 初始化参考文件', (self.destination / 'README.md').read_text())

    def test_ai_cannot_generate_platform5_or_unknown_version_components(self):
        for target, version in [('5.0.1', '3.5.2'), ('4.22.22', '3.6.0')]:
            with self.subTest(target=target, version=version):
                plan, resources = self.fixture(['rhods-operator'], target=target)
                plan['selected'][0]['version'] = version
                with self.assertRaisesRegex(ValueError, 'AI 组件清单'):
                    product_manifests.render(plan, resources, self.destination)
                self.assertFalse(self.destination.exists())

    def test_ai_missing_vendor_example_or_api_match_never_writes_partial_subscriptions(self):
        for raw in ('', '{}', '[]'):
            with self.subTest(raw=raw):
                plan, resources = self.fixture(['rhods-operator'], target='4.22.22')
                plan['selected'][0]['properties'][0]['value']['annotations']['alm-examples'] = raw
                with self.assertRaises(ValueError):
                    product_manifests.render(plan, resources, self.destination)
                self.assertFalse(self.destination.exists())

    def test_unsupported_scope_fails_before_writing_templates(self):
        plan, resources = self.fixture(['kubevirt-hyperconverged'])
        plan['selected'][0]['properties'][0]['value']['installModes'][0]['supported'] = False
        with self.assertRaisesRegex(ValueError, '作用域'):
            product_manifests.render(plan, resources, self.destination)
        self.assertFalse(self.destination.exists())

    def test_lvms_subscription_never_selects_or_initializes_storage_devices(self):
        plan, resources = self.fixture(['lvms-operator'])
        product_manifests.render(plan, resources, self.destination)
        subscriptions = json.loads((self.destination / '01-subscriptions.json').read_text())['items']
        group = next(r for r in subscriptions if r['kind'] == 'OperatorGroup')
        subscription = next(r for r in subscriptions if r['kind'] == 'Subscription')
        self.assertEqual(group['metadata']['namespace'], 'openshift-lvm-storage')
        self.assertEqual(group['spec']['targetNamespaces'], ['openshift-lvm-storage'])
        self.assertEqual(subscription['spec']['source'], 'offline-redhat')
        self.assertEqual(subscription['spec']['startingCSV'], plan['selected'][0]['bundle'])
        self.assertEqual(subscription['spec']['installPlanApproval'], 'Manual')
        self.assertEqual({p.name for p in self.destination.glob('*.json')}, {'01-subscriptions.json'})
        self.assertIn('不会自动创建 LVMCluster', (self.destination / 'README.md').read_text())

    def test_ai_storage_stage_can_install_provider_before_ai_subscription(self):
        plan, resources = self.fixture(['rhods-operator', 'lvms-operator'], target='4.22.22')
        product_manifests.render(plan, resources, self.destination)
        storage = json.loads((self.destination / '00-lvms-subscriptions.json').read_text())['items']
        self.assertEqual({i['kind'] for i in storage}, {'Namespace', 'OperatorGroup', 'Subscription'})
        self.assertEqual([i['spec']['name'] for i in storage if i['kind'] == 'Subscription'], ['lvms-operator'])
        self.assertTrue(all(i['metadata'].get('namespace', i['metadata']['name']) == 'openshift-lvm-storage' for i in storage))
        all_items = json.loads((self.destination / '01-subscriptions.json').read_text())['items']
        self.assertEqual({i['spec']['name'] for i in all_items if i['kind'] == 'Subscription'}, {'rhods-operator', 'lvms-operator'})
        instructions = (self.destination / 'README.md').read_text()
        self.assertLess(instructions.index('00-lvms-subscriptions.json'), instructions.index('1. 审阅并应用'))

    def test_missing_mce_is_never_hidden_by_template_generation(self):
        plan, resources = self.fixture(['advanced-cluster-management'])
        with self.assertRaisesRegex(ValueError, '缺少运行时依赖 MCE'):
            product_manifests.render(plan, resources, self.destination)


if __name__ == '__main__':
    unittest.main()
