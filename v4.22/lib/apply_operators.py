#!/usr/bin/env python3
"""Apply verified Operator mirror rules to a ready cluster of the matching minor."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys

from operator_profile import release
from operator_resources import prepare
from operators import load_plan
from registry_trust import ensure as ensure_registry_trust, reload_components
from catalog_policy import disable_default_sources


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bundle', required=True)
    parser.add_argument('--kubeconfig', default=os.environ.get('KUBECONFIG'))
    parser.add_argument('--dry-run', action='store_true', help='服务端预检查，不写入集群')
    parser.add_argument('--registry-ca', default=os.environ.get('REGISTRY_CA'), help='明确提供的本地镜像仓库 CA 文件；保留并合并已有 CA')
    args = parser.parse_args()
    if not args.kubeconfig:
        raise ValueError('请提供 --kubeconfig 或 KUBECONFIG；不要把其内容粘贴到终端')
    env = dict(os.environ, KUBECONFIG=str(Path(args.kubeconfig).expanduser().resolve()))
    bundle = Path(args.bundle).expanduser().resolve()
    plan = load_plan(bundle)
    cluster = json.loads(subprocess.run(['oc', 'get', 'clusterversion', 'version', '-o', 'json'],
                                        env=env, check=True, text=True, capture_output=True).stdout)
    actual = cluster['status']['desired']['version']
    minor = release().rsplit('.', 1)[0]
    if actual.rsplit('.', 1)[0] != minor or plan['targetVersion'].rsplit('.', 1)[0] != minor:
        raise ValueError(f'当前集群 {actual} 与本脚本 {minor} 不匹配；未应用任何资源')
    conditions = {c['type']: c['status'] for c in cluster['status'].get('conditions', [])}
    if conditions.get('Available') != 'True' or conditions.get('Progressing') != 'False' or conditions.get('Failing') != 'False':
        raise ValueError('集群尚未安装完成或存在故障；未应用任何资源')
    output = bundle / 'operator-resources.json'
    prepare(bundle, output, os.environ.get('ACM_AVAILABILITY', 'High'))
    if args.registry_ca:
        receipt = ensure_registry_trust(args.registry_ca, env, args.dry_run)
        reload_components(receipt, env)
    command = ['oc', 'apply', '-f', str(output)]
    if args.dry_run:
        command.append('--dry-run=server')
    else:
        disable_default_sources(env)
    subprocess.run(command, env=env, check=True)
    print('预检查完成' if args.dry_run else '已应用离线目录及镜像规则；请等待 MCP 更新和 CatalogSource READY，再安装 Operator')


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, KeyError, subprocess.CalledProcessError) as error:
        print(f'错误: {error}', file=sys.stderr)
        sys.exit(1)
