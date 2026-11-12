import copy
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'lib'))
import cluster_health


def item(name, **states):
    return {'metadata': {'name': name}, 'status': {
        'conditions': [{'type': key, 'status': value} for key, value in states.items()]}}


class ClusterHealthTests(unittest.TestCase):
    def setUp(self):
        self.nodes = [item('master1', Ready='True')]
        self.pools = [item('master', Updated='True', Updating='False', Degraded='False')]
        self.operators = [item('etcd', Available='True', Progressing='False', Degraded='False')]
        self.deployment = {'metadata': {'name': 'operator', 'generation': 5},
                           'spec': {'replicas': 1}, 'status': {'observedGeneration': 5,
                           'updatedReplicas': 1, 'readyReplicas': 1, 'availableReplicas': 1}}

    def inspect(self):
        return patch.object(cluster_health, 'read', side_effect=[self.nodes, self.pools, self.operators]
                            + [[copy.deepcopy(self.deployment)] for _ in cluster_health.CORE_OPERATOR_NAMESPACES])

    def test_healthy_runtime_passes_using_read_only_queries(self):
        with self.inspect() as read:
            cluster_health.require_ready({'KUBECONFIG': '/private/admin'})
        self.assertEqual(read.call_count, 7)

    def test_stale_healthy_operator_conditions_do_not_hide_crashed_controller(self):
        self.deployment['status']['readyReplicas'] = 0
        self.deployment['status']['availableReplicas'] = 0
        with self.inspect(), self.assertRaisesRegex(ValueError, 'openshift-etcd-operator/operator'):
            cluster_health.require_ready({})

    def test_stale_deployment_status_and_disabled_controllers_are_rejected(self):
        for change in ('generation', 'replicas'):
            with self.subTest(change=change):
                saved = copy.deepcopy(self.deployment)
                if change == 'generation':
                    self.deployment['metadata']['generation'] += 1
                else:
                    self.deployment['spec']['replicas'] = 0
                with self.inspect(), self.assertRaises(ValueError):
                    cluster_health.require_ready({})
                self.deployment = saved

    def test_node_rollout_cordon_and_pressure_are_rejected(self):
        for change in ('updating', 'cordon', 'pressure', 'unknown'):
            with self.subTest(change=change):
                self.setUp()
                if change == 'updating':
                    self.pools[0] = item('master', Updated='False', Updating='True', Degraded='False')
                elif change == 'cordon':
                    self.nodes[0]['spec'] = {'unschedulable': True}
                elif change == 'pressure':
                    self.nodes[0] = item('master1', Ready='True', MemoryPressure='True')
                else:
                    self.nodes[0] = item('master1', Ready='Unknown')
                with self.inspect(), self.assertRaisesRegex(ValueError, 'machineconfigpool:master|node:master1'):
                    cluster_health.require_ready({})

    def test_missing_or_unhealthy_core_status_is_rejected(self):
        self.operators = [item('etcd', Available='True', Degraded='True')]
        with self.inspect(), self.assertRaisesRegex(ValueError, 'clusteroperator:etcd'):
            cluster_health.require_ready({})
        self.nodes, self.pools, self.operators = [], [], []
        with patch.object(cluster_health, 'read', return_value=[]), self.assertRaisesRegex(ValueError, 'empty'):
            cluster_health.require_ready({})

    def test_failed_health_query_fails_closed(self):
        with patch.object(cluster_health, 'read', side_effect=subprocess.TimeoutExpired(['oc'], 45)), \
             self.assertRaises(subprocess.TimeoutExpired):
            cluster_health.require_ready({})


if __name__ == '__main__':
    unittest.main()
