#!/usr/bin/env python3
"""Merge the explicitly supplied registry CA into OpenShift component trust."""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import time


def certificates(content):
    content = '\n'.join(line for line in content.splitlines() if not line.lstrip().startswith('#'))
    pattern = r'-----BEGIN CERTIFICATE-----([A-Za-z0-9+/=\s]+)-----END CERTIFICATE-----'
    matches = list(re.finditer(pattern, content))
    if not matches or re.sub(pattern, '', content).strip():
        raise ValueError('CA 文件必须只包含 PEM 证书，不能包含私钥或其他内容')
    result = {}
    for match in matches:
        encoded = re.sub(r'\s', '', match[1])
        raw = base64.b64decode(encoded, validate=True)
        pem = '-----BEGIN CERTIFICATE-----\n' + '\n'.join(encoded[i:i+64] for i in range(0, len(encoded), 64)) + '\n-----END CERTIFICATE-----\n'
        subprocess.run(['openssl', 'x509', '-noout'], input=pem, text=True,
                       capture_output=True, check=True)
        result[hashlib.sha256(raw).hexdigest()] = pem
    return result


def oc(arguments, env, payload=None, structured=True):
    output = subprocess.run(['oc', *arguments], env=env,
        input=json.dumps(payload) if payload is not None else None,
        text=True, capture_output=True, check=True).stdout.strip()
    return (json.loads(output) if output else None) if structured else output


def ensure(ca_file, env=None, dry_run=False):
    incoming = certificates(Path(ca_file).read_text())
    env = dict(os.environ) if env is None else env
    proxy = oc(['get', 'proxy', 'cluster', '-o', 'json'], env)
    previous_name = proxy.get('spec', {}).get('trustedCA', {}).get('name', '')
    name = previous_name or 'ocpinstall-registry-ca'
    existing = oc(['get', 'configmap', name, '-n', 'openshift-config',
                   '--ignore-not-found', '-o', 'json'], env)
    if previous_name and existing is None:
        raise ValueError('Proxy 引用的现有 CA ConfigMap 不存在，请先修复该引用')
    old = (existing or {}).get('data', {}).get('ca-bundle.crt', '')
    merged = certificates(old) if old.strip() else {}
    previous_count = len(merged)
    merged.update(incoming)
    content = ''.join(merged.values())
    changed = content != old
    if not dry_run:
        if existing is None:
            oc(['create', '-f', '-', '-o', 'json'], env, {
                'apiVersion': 'v1', 'kind': 'ConfigMap',
                'metadata': {'name': name, 'namespace': 'openshift-config'},
                'data': {'ca-bundle.crt': content}})
        elif changed:
            patch = {'data': {'ca-bundle.crt': content}}
            if existing.get('metadata', {}).get('resourceVersion'):
                patch['metadata'] = {'resourceVersion': existing['metadata']['resourceVersion']}
            oc(['patch', 'configmap', name, '-n', 'openshift-config', '--type', 'merge',
                '-p', json.dumps(patch), '-o', 'json'], env)
        if previous_name != name:
            patch = {'spec': {'trustedCA': {'name': name}}}
            if proxy.get('metadata', {}).get('resourceVersion'):
                patch['metadata'] = {'resourceVersion': proxy['metadata']['resourceVersion']}
            oc(['patch', 'proxy', 'cluster', '--type', 'merge', '-p',
                json.dumps(patch), '-o', 'json'], env)
    return {'dryRun': dry_run, 'configMap': name, 'previousCertificateCount': previous_count,
            'certificateCount': len(merged), 'incomingCertificateFingerprints': sorted(incoming),
            'bundleChanged': changed, 'proxyReferenceChanged': previous_name != name}


def reload_components(receipt, env, timeout=300):
    if receipt['dryRun'] or not (receipt['bundleChanged'] or receipt['proxyReferenceChanged']):
        return []
    components = []
    for namespace, name in (('openshift-catalogd', 'catalogd-controller-manager'),
                            ('openshift-operator-controller', 'operator-controller-controller-manager')):
        deployment = oc(['get', 'deployment', name, '-n', namespace, '--ignore-not-found', '-o', 'json'], env)
        if deployment is None:
            continue
        maps = set()
        for volume in deployment['spec']['template']['spec'].get('volumes', []):
            candidates = [volume] + volume.get('projected', {}).get('sources', [])
            for item in candidates:
                config = item.get('configMap', {})
                if any(i.get('key') == 'ca-bundle.crt' for i in config.get('items', [])):
                    maps.add(config['name'])
        if not maps:
            raise ValueError(namespace + ' 未找到受信 CA 挂载；请核对组件配置后继续')
        components.append((namespace, name, maps))
    required = set(receipt['incomingCertificateFingerprints'])
    deadline = time.monotonic() + timeout
    while components:
        injected = True
        for namespace, _, maps in components:
            for name in maps:
                config = oc(['get', 'configmap', name, '-n', namespace, '--ignore-not-found', '-o', 'json'], env)
                content = (config or {}).get('data', {}).get('ca-bundle.crt', '')
                if not content.strip() or not required <= certificates(content).keys():
                    injected = False
        if injected:
            break
        if time.monotonic() >= deadline:
            raise ValueError('等待仓库 CA 注入目录服务超时；未重启组件')
        time.sleep(5)
    restarted = []
    for namespace, name, _ in components:
        # These consumers cache CA pools. Refresh only after the mounted bundle
        # contains the requested certificate, so existing clusters recover too.
        oc(['rollout', 'restart', 'deployment/' + name, '-n', namespace], env, structured=False)
        oc(['rollout', 'status', 'deployment/' + name, '-n', namespace, '--timeout=180s'], env, structured=False)
        restarted.append(namespace + '/' + name)
    return restarted


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--ca-file', required=True)
    parser.add_argument('--kubeconfig', default=os.environ.get('KUBECONFIG'))
    parser.add_argument('--dry-run', action='store_true', help='读取并检查合并计划，不写入集群')
    args = parser.parse_args()
    if not args.kubeconfig:
        raise ValueError('请提供 --kubeconfig 或 KUBECONFIG')
    env = dict(os.environ, KUBECONFIG=str(Path(args.kubeconfig).expanduser().resolve()))
    receipt = ensure(args.ca_file, env, args.dry_run)
    receipt['reloadedComponents'] = reload_components(receipt, env)
    print(json.dumps(receipt, ensure_ascii=False))


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, KeyError, subprocess.CalledProcessError) as error:
        raise SystemExit('CA 信任配置失败: ' + str(error))
