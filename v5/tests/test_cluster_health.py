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
        self.nodes[0]['metadata']['labels'] = {'node-role.kubernetes.io/master': ''}
        self.nodes[0]['metadata']['annotations'] = {
            'machineconfiguration.openshift.io/state': 'Done',
            'machineconfiguration.openshift.io/currentConfig': 'rendered-current',
            'machineconfiguration.openshift.io/desiredConfig': 'rendered-current'}
        self.pools = [item('master', Updated='True', Updating='False', Degraded='False')]
        self.operators = [item('etcd', Available='True', Progressing='False', Degraded='False')]
        self.deployment = {'metadata': {'name': 'operator', 'generation': 5},
                           'spec': {'replicas': 1}, 'status': {'observedGeneration': 5,
                           'updatedReplicas': 1, 'readyReplicas': 1, 'availableReplicas': 1}}
        pod = item('static-master1', Ready='True')
        pod['metadata']['annotations'] = {'kubernetes.io/config.source': 'file',
                                           'kubernetes.io/config.mirror': 'fixture-mirror'}
        pod['spec'] = {'nodeName': 'master1', 'containers': [{'name': 'controller'}]}
        pod['status'].update(phase='Running', containerStatuses=[{
            'name': 'controller', 'ready': True, 'state': {'running': {}}}])
        self.static_pods = {namespace: [copy.deepcopy(pod)] for namespace in cluster_health.STATIC_POD_NAMESPACES}

    def inspect(self):
        return patch.object(cluster_health, 'read', side_effect=[self.nodes, self.pools, self.operators]
                            + [[copy.deepcopy(self.deployment)] for _ in cluster_health.CORE_OPERATOR_NAMESPACES]
                            + [copy.deepcopy(self.static_pods[namespace]) for namespace in cluster_health.STATIC_POD_NAMESPACES])

    def test_healthy_runtime_passes_using_read_only_queries(self):
        with self.inspect() as read:
            cluster_health.require_ready({'KUBECONFIG': '/private/admin'})
        self.assertEqual(read.call_count, 11)

    def test_stale_healthy_co_and_operator_cannot_hide_running_static_pod_crash(self):
        for failure in ('crashloop', 'unready', 'missing-status', 'deleting'):
            with self.subTest(failure=failure):
                self.setUp()
                pod = self.static_pods['openshift-kube-controller-manager'][0]
                if failure == 'crashloop':
                    pod['status']['containerStatuses'][0]['state'] = {'waiting': {'reason': 'CrashLoopBackOff'}}
                elif failure == 'unready':
                    pod['status']['containerStatuses'][0]['ready'] = False
                elif failure == 'missing-status':
                    pod['status']['containerStatuses'] = []
                else:
                    pod['metadata']['deletionTimestamp'] = '2026-11-13T00:00:00Z'
                with self.inspect(), self.assertRaisesRegex(ValueError, 'openshift-kube-controller-manager/static-master1'):
                    cluster_health.require_ready({})

    def test_each_control_node_requires_a_static_pod_in_each_core_namespace(self):
        second = copy.deepcopy(self.nodes[0])
        second['metadata']['name'] = 'master2'
        second['metadata']['labels'] = {'node-role.kubernetes.io/control-plane': ''}
        self.nodes.append(second)
        with self.inspect(), self.assertRaisesRegex(ValueError, 'master2:static-pod:missing'):
            cluster_health.require_ready({})

    def test_workers_do_not_require_control_plane_static_pods(self):
        worker = copy.deepcopy(self.nodes[0])
        worker['metadata']['name'] = 'worker1'
        worker['metadata']['labels'] = {'node-role.kubernetes.io/worker': ''}
        self.nodes.append(worker)
        with self.inspect():
            cluster_health.require_ready({})

    def test_healthy_installer_pod_cannot_substitute_for_missing_static_mirror(self):
        self.static_pods['openshift-etcd'][0]['metadata']['annotations'] = {}
        with self.inspect(), self.assertRaisesRegex(ValueError, 'openshift-etcd/master1:static-pod:missing'):
            cluster_health.require_ready({})

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
                    self.nodes[0]['status']['conditions'].append({'type': 'MemoryPressure', 'status': 'True'})
                else:
                    self.nodes[0]['status']['conditions'][0]['status'] = 'Unknown'
                with self.inspect(), self.assertRaisesRegex(ValueError, 'machineconfigpool:master|node:master1'):
                    cluster_health.require_ready({})

    def test_missing_or_unhealthy_core_status_is_rejected(self):
        self.operators = [item('etcd', Available='True', Degraded='True')]
        with self.inspect(), self.assertRaisesRegex(ValueError, 'clusteroperator:etcd'):
            cluster_health.require_ready({})
        self.nodes, self.pools, self.operators = [], [], []
        with patch.object(cluster_health, 'read', return_value=[]), self.assertRaisesRegex(ValueError, 'empty'):
            cluster_health.require_ready({})

    def test_node_configuration_mismatch_blocks_even_if_status_flags_are_stale(self):
        for key, value in [('desiredConfig', 'rendered-next'), ('state', 'Working'), ('currentConfig', '')]:
            with self.subTest(key=key):
                self.setUp()
                self.nodes[0]['metadata']['annotations']['machineconfiguration.openshift.io/' + key] = value
                with self.inspect(), self.assertRaisesRegex(ValueError, 'node:master1'):
                    cluster_health.require_ready({})

    def test_failed_health_query_fails_closed(self):
        with patch.object(cluster_health, 'read', side_effect=subprocess.TimeoutExpired(['oc'], 45)), \
             self.assertRaises(subprocess.TimeoutExpired):
            cluster_health.require_ready({})


if __name__ == '__main__':
    unittest.main()
