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
        subscriptions = json.loads((self.destination / '01-subscriptions.json').read_text())['items']
        group = next(r for r in subscriptions if r['kind'] == 'OperatorGroup')
        self.assertEqual(group['spec']['targetNamespaces'], ['openshift-cnv'])

    def test_ai_subscription_requires_declared_all_namespace_scope(self):
        plan, resources = self.fixture(['rhods-operator'], target='4.22.22')
        product_manifests.render(plan, resources, self.destination)
        subscriptions = json.loads((self.destination / '01-subscriptions.json').read_text())['items']
        group = next(r for r in subscriptions if r['kind'] == 'OperatorGroup')
        self.assertEqual(group['spec'], {})
        self.assertEqual(list(self.destination.glob('02-*')), [])

    def test_unsupported_scope_fails_before_writing_templates(self):
        plan, resources = self.fixture(['kubevirt-hyperconverged'])
        plan['selected'][0]['properties'][0]['value']['installModes'][0]['supported'] = False
        with self.assertRaisesRegex(ValueError, '作用域'):
            product_manifests.render(plan, resources, self.destination)
        self.assertFalse(self.destination.exists())

    def test_missing_mce_is_never_hidden_by_template_generation(self):
        plan, resources = self.fixture(['advanced-cluster-management'])
        with self.assertRaisesRegex(ValueError, '缺少运行时依赖 MCE'):
            product_manifests.render(plan, resources, self.destination)


if __name__ == '__main__':
    unittest.main()
