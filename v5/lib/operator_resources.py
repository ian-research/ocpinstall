#!/usr/bin/env python3
"""Give separate Operator bundles independent resource names without changing specs."""
import hashlib
import json
from pathlib import Path
import sys
import os

import offline
from operator_resolver import read_documents
from operators import load_plan
from operator_oci import verify_catalogs
from operator_profile import resource_prefix
from operator_archive import verify_record
import product_manifests


def prepare(bundle, output, availability='High'):
    bundle = bundle.resolve()
    offline.verify(bundle)
    if 'operators-plan.json' not in json.loads((bundle / 'checksums.json').read_text()):
        raise ValueError('Operator 计划未包含在离线包校验清单中')
    plan = load_plan(bundle)
    verify_catalogs(bundle, plan, require_manifest=True)
    verify_record(bundle, plan)
    folder = bundle / 'images/working-dir/cluster-resources'
    if not folder.is_dir():
        raise ValueError('缺少导入端 oc-mirror 生成的集群资源')
    allowed = {'ImageDigestMirrorSet', 'ImageTagMirrorSet', 'CatalogSource', 'ClusterCatalog'}
    records = {}
    for document in read_documents(folder):
        items = document.get('items', []) if document.get('kind') == 'List' else [document]
        for item in items:
            if item.get('kind') not in allowed:
                raise ValueError('Operator-only 导入出现意外资源类型: ' + str(item.get('kind')))
            metadata = item['metadata']
            key = (item['kind'], metadata.get('namespace', ''), metadata['name'])
            if key in records and records[key] != item:
                raise ValueError('导入资源包含同名但内容不同的条目')
            records[key] = item
    if not any(key[0] == 'CatalogSource' for key in records):
        raise ValueError('导入未生成可供后置脚本使用的 CatalogSource')
    result = []
    for key, item in sorted(records.items()):
        cloned = json.loads(json.dumps(item))
        identity = hashlib.sha256(json.dumps(key).encode()).hexdigest()[:10]
        # Red Hat permits metadata changes; spec mappings and image fields stay exact.
        cloned['metadata']['name'] = f'{resource_prefix(plan["targetVersion"])}-{plan["planHash"][:12]}-{identity}'
        cloned['metadata'].setdefault('labels', {})['ocpinstall.ian-research/operator-plan'] = plan['planHash'][:12]
        result.append(cloned)
    offline.save_json(output, {'apiVersion': 'v1', 'kind': 'List', 'items': result})
    product_manifests.render(plan, result, output.parent / 'product-manifests', availability)
    print('已生成独立命名的 Operator 资源：' + str(output))


if __name__ == '__main__':
    try:
        prepare(Path(sys.argv[1]), Path(sys.argv[2]), os.environ.get('ACM_AVAILABILITY', 'High'))
    except (ValueError, OSError, KeyError) as error:
        print(f'错误: {error}', file=sys.stderr)
        sys.exit(1)
