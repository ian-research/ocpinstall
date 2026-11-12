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


def read(resource, env, namespace=None):
    command = ['oc', '--request-timeout=30s', 'get', resource, '-o', 'json']
    if namespace:
        command += ['-n', namespace]
    result = subprocess.run(command, env=env, check=True, capture_output=True,
                            text=True, timeout=45)
    return json.loads(result.stdout)['items']


def conditions(item):
    return {c['type']: c['status'] for c in item.get('status', {}).get('conditions', [])}


def require_ready(env):
    # ClusterVersion/ClusterOperator conditions can remain stale when their
    # controllers crash. Check actual core Deployment availability as well.
    failures = []
    nodes = read('nodes', env)
    if not nodes:
        failures.append('nodes:empty')
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
    if failures:
        raise ValueError('集群尚未稳定，未修改集群。请先恢复管理组件、等待节点和 MCP 更新完成：'
                         + ', '.join(failures))


if __name__ == '__main__':
    try:
        require_ready(dict(os.environ))
    except (ValueError, KeyError, OSError, subprocess.SubprocessError) as error:
        print(f'错误: {error}', file=sys.stderr)
        sys.exit(1)
