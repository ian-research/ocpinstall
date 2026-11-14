#!/usr/bin/env python3
"""Read-only gates before post-configuration or installing new mirror rules."""
import json
import os
import subprocess
import sys


CORE_OPERATOR_NAMESPACES = (
    'openshift-etcd-operator', 'openshift-kube-apiserver-operator',
    'openshift-kube-controller-manager-operator', 'openshift-kube-scheduler-operator',
)
STATIC_POD_NAMESPACES = (
    'openshift-etcd', 'openshift-kube-apiserver',
    'openshift-kube-controller-manager', 'openshift-kube-scheduler',
)


def read(resource, env, namespace=None):
    command = ['oc', '--request-timeout=30s', 'get', resource, '-o', 'json']
    if namespace:
        command += ['-n', namespace]
    result = subprocess.run(command, env=env, check=True, capture_output=True,
                            text=True, timeout=45)
    return json.loads(result.stdout)['items']


def conditions(item):
    return {c['type']: c['status'] for c in item.get('status', {}).get('conditions', [])}


def static_pod_failures(pods, control_nodes, namespace):
    mirrors = {}
    for pod in pods:
        annotations = pod['metadata'].get('annotations', {})
        if (annotations.get('kubernetes.io/config.source') == 'file'
                and annotations.get('kubernetes.io/config.mirror')):
            mirrors.setdefault(pod.get('spec', {}).get('nodeName'), []).append(pod)
    failures = []
    for node in sorted(control_nodes):
        candidates = mirrors.get(node, [])
        if len(candidates) != 1:
            failures.append(namespace + '/' + node + ':static-pod:missing-or-duplicate')
            continue
        pod = candidates[0]
        status = pod.get('status', {})
        expected = {c['name'] for c in pod.get('spec', {}).get('containers', [])}
        actual = {c['name']: c for c in status.get('containerStatuses', [])}
        if (pod['metadata'].get('deletionTimestamp') or status.get('phase') != 'Running'
                or conditions(pod).get('Ready') != 'True' or not expected
                or actual.keys() != expected
                or any(not c.get('ready') or 'running' not in c.get('state', {})
                       for c in actual.values())):
            failures.append(namespace + '/' + pod['metadata']['name'])
    return failures


def require_ready(env):
    # ClusterVersion/ClusterOperator conditions can remain stale when their
    # controllers crash. Check actual core Deployment availability as well.
    failures = []
    nodes = read('nodes', env)
    if not nodes:
        failures.append('nodes:empty')
    control_nodes = {item['metadata']['name'] for item in nodes
                     if any(role in item['metadata'].get('labels', {}) for role in
                            ('node-role.kubernetes.io/master', 'node-role.kubernetes.io/control-plane'))}
    if not control_nodes:
        failures.append('control-plane:nodes:empty')
    for item in nodes:
        state = conditions(item)
        config = item['metadata'].get('annotations', {})
        prefix = 'machineconfiguration.openshift.io/'
        if (state.get('Ready') != 'True' or item.get('spec', {}).get('unschedulable')
                or config.get(prefix + 'state') != 'Done'
                or not config.get(prefix + 'currentConfig')
                or config.get(prefix + 'currentConfig') != config.get(prefix + 'desiredConfig')
                or any(state.get(key) == 'True' for key in ('MemoryPressure', 'DiskPressure', 'PIDPressure'))):
            failures.append('node:' + item['metadata']['name'])
    pools = read('machineconfigpools', env)
    if not pools:
        failures.append('machineconfigpools:empty')
    for item in pools:
        state = conditions(item)
        if not all(state.get(key) == value for key, value in (
                ('Updated', 'True'), ('Updating', 'False'), ('Degraded', 'False'))):
            failures.append('machineconfigpool:' + item['metadata']['name'])
    operators = read('clusteroperators', env)
    if not operators:
        failures.append('clusteroperators:empty')
    for item in operators:
        state = conditions(item)
        if not all(state.get(key) == value for key, value in (
                ('Available', 'True'), ('Progressing', 'False'), ('Degraded', 'False'))):
            failures.append('clusteroperator:' + item['metadata']['name'])
    for namespace in CORE_OPERATOR_NAMESPACES:
        deployments = read('deployments', env, namespace)
        if not deployments:
            failures.append(namespace + ':deployments:empty')
        for item in deployments:
            status = item.get('status', {})
            replicas = item.get('spec', {}).get('replicas', 1)
            if (replicas < 1 or status.get('observedGeneration', 0) < item['metadata']['generation']
                    or any(status.get(key, 0) != replicas for key in
                           ('updatedReplicas', 'readyReplicas', 'availableReplicas'))):
                failures.append(namespace + '/' + item['metadata']['name'])
    # A healthy operator Deployment does not establish that the static control
    # plane it manages is running. CO conditions can lag these container failures.
    for namespace in STATIC_POD_NAMESPACES:
        failures.extend(static_pod_failures(read('pods', env, namespace), control_nodes, namespace))
    if failures:
        raise ValueError('集群尚未稳定，未修改集群。请先恢复管理组件、等待节点和 MCP 更新完成：'
                         + ', '.join(failures))


if __name__ == '__main__':
    try:
        require_ready(dict(os.environ))
    except (ValueError, KeyError, OSError, subprocess.SubprocessError) as error:
        print(f'错误: {error}', file=sys.stderr)
        sys.exit(1)
