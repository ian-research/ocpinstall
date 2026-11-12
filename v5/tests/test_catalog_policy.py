import json
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'lib'))
import catalog_policy


class CatalogPolicyTests(unittest.TestCase):
    served = {'spec': {'versions': [{'name': 'v1', 'served': True}]}}

    def item(self, name, image, mode='Available'):
        return {'metadata': {'name': name, 'resourceVersion': '12'},
                'spec': {'availabilityMode': mode, 'source': {'image': {'ref': image}}}}

    def test_only_genuine_default_online_catalogs_are_disabled(self):
        items = [self.item('openshift-redhat-operators', 'registry.redhat.io/redhat/redhat-operator-index:v5.0'),
                 self.item('openshift-certified-operators', 'mirror.internal/private:catalog'),
                 self.item('my-offline-catalog', 'registry.redhat.io/redhat/redhat-operator-index:v5.0')]
        with patch.object(catalog_policy, 'run', side_effect=[{}, self.served, {'items': items}, {}]) as run:
            result = catalog_policy.disable_default_sources({})
        self.assertEqual(result['disabledClusterCatalogs'], ['openshift-redhat-operators'])
        command = run.call_args.args[0]
        payload = json.loads(command[command.index('-p')+1])
        self.assertEqual(payload, {'metadata': {'resourceVersion': '12'}, 'spec': {'availabilityMode': 'Unavailable'}})
        self.assertEqual(command[2], 'openshift-redhat-operators')

    def test_disabled_defaults_are_not_patched_again(self):
        item = self.item('openshift-community-operators', 'registry.redhat.io/redhat/community-operator-index@sha256:' + 'a'*64, 'Unavailable')
        with patch.object(catalog_policy, 'run', side_effect=[{}, self.served, {'items': [item]}]) as run:
            result = catalog_policy.disable_default_sources({})
        self.assertEqual(run.call_count, 3)
        self.assertEqual(result['disabledClusterCatalogs'], ['openshift-community-operators'])

    def test_classic_only_clusters_do_not_query_an_unserved_api(self):
        for definition in (None, {'spec': {'versions': [{'name': 'v1', 'served': False}]}}):
            with patch.object(catalog_policy, 'run', side_effect=[{}, definition]) as run:
                result = catalog_policy.disable_default_sources({})
            self.assertEqual(run.call_count, 2)
            self.assertTrue(result['classicDefaultsDisabled'])
            self.assertEqual(result['disabledClusterCatalogs'], [])

    def test_failed_policy_update_never_reports_success(self):
        with patch.object(catalog_policy, 'run', side_effect=subprocess.CalledProcessError(1, ['oc'])):
            with self.assertRaises(subprocess.CalledProcessError):
                catalog_policy.disable_default_sources({})
