#!/usr/bin/env python3
"""Disable built-in online catalogs while preserving custom offline sources."""
import json
import os
import subprocess

DEFAULT_CATALOGS = {
    'openshift-redhat-operators': 'registry.redhat.io/redhat/redhat-operator-index',
    'openshift-certified-operators': 'registry.redhat.io/redhat/certified-operator-index',
    'openshift-community-operators': 'registry.redhat.io/redhat/community-operator-index',
    'openshift-redhat-marketplace': 'registry.redhat.io/redhat/redhat-marketplace-index',
}


def run(arguments, env):
    output = subprocess.run(['oc', *arguments], env=env, capture_output=True, text=True, check=True).stdout.strip()
    return json.loads(output) if output else None


def repository(reference):
    value = reference.split('@', 1)[0]
    return value.rsplit(':', 1)[0] if ':' in value.rsplit('/', 1)[-1] else value


def disable_default_sources(env=None):
    env = dict(os.environ) if env is None else env
    run(['patch', 'OperatorHub', 'cluster', '--type', 'merge', '-p',
         '{"spec":{"disableAllDefaultSources":true}}', '-o', 'json'], env)
    report = {'classicDefaultsDisabled': True, 'disabledClusterCatalogs': []}
    definition = run(['get', 'crd', 'clustercatalogs.olm.operatorframework.io',
                      '--ignore-not-found', '-o', 'json'], env)
    if not definition or not any(v['name'] == 'v1' and v.get('served') is True for v in definition['spec']['versions']):
        return report
    for item in run(['get', 'clustercatalogs.olm.operatorframework.io', '-o', 'json'], env)['items']:
        name = item['metadata']['name']
        source = item.get('spec', {}).get('source', {}).get('image', {}).get('ref', '')
        # A user may have repointed a built-in name to a private mirror.
        if name not in DEFAULT_CATALOGS or repository(source) != DEFAULT_CATALOGS[name]:
            continue
        if item['spec'].get('availabilityMode', 'Available') != 'Unavailable':
            patch = {'spec': {'availabilityMode': 'Unavailable'},
                     'metadata': {'resourceVersion': item['metadata']['resourceVersion']}}
            run(['patch', 'clustercatalog', name, '--type', 'merge', '-p', json.dumps(patch), '-o', 'json'], env)
        report['disabledClusterCatalogs'].append(name)
    report['disabledClusterCatalogs'].sort()
    return report


if __name__ == '__main__':
    try:
        print(json.dumps(disable_default_sources(), ensure_ascii=False))
    except (ValueError, OSError, KeyError, subprocess.CalledProcessError) as error:
        raise SystemExit('离线目录策略配置失败: ' + str(error))
