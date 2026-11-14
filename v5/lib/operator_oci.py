"""Stage portable OCI catalogs so an Operator import never needs source registries."""
import json
import hashlib
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

import offline


def layout_files(layout):
    layout = layout.resolve()
    if json.loads((layout / 'oci-layout').read_text()).get('imageLayoutVersion') != '1.0.0':
        raise ValueError('不支持的 OCI layout 版本')
    files = {}
    for path in layout.rglob('*'):
        if path.is_symlink():
            raise ValueError('OCI layout 不允许链接')
        if not path.is_file():
            continue
        name = str(path.relative_to(layout))
        if name not in ('oci-layout', 'index.json') and not re.fullmatch(r'blobs/sha256/[a-f0-9]{64}', name):
            raise ValueError('OCI layout 包含非镜像文件，拒绝复制: ' + name)
        files[name] = offline.digest(path)
        if name.startswith('blobs/') and files[name] != path.name:
            raise ValueError('OCI blob SHA256 不匹配: ' + name)
    index = json.loads((layout / 'index.json').read_text())
    if len(index.get('manifests', [])) != 1:
        raise ValueError('OCI catalog 必须有一个明确的根描述符')
    visited = set()
    def visit(descriptor, manifest=False, depth=0):
        digest = descriptor.get('digest', '')
        if depth > 16 or not re.fullmatch(r'sha256:[a-f0-9]{64}', digest):
            raise ValueError('OCI descriptor 无效或过深')
        name = 'blobs/sha256/' + digest.split(':')[1]
        if name not in files:
            raise ValueError('OCI descriptor 引用缺失的 blob: ' + digest)
        path = layout / name
        if path.stat().st_size != descriptor['size']:
            raise ValueError('OCI descriptor 大小不匹配')
        if not manifest or digest in visited:
            return
        visited.add(digest)
        if path.stat().st_size > 16 * 1024 * 1024:
            raise ValueError('OCI manifest 过大')
        data = json.loads(path.read_text())
        if 'manifests' in data:
            for child in data['manifests']:
                visit(child, True, depth + 1)
        elif 'layers' in data and 'config' in data:
            visit(data['config'])
            for child in data['layers']:
                visit(child)
        else:
            raise ValueError('OCI manifest 内容无效')
    visit(index['manifests'][0], True)
    return index['manifests'][0]['digest'], files


def config_for_oci(config, record):
    result = json.loads(json.dumps(config))
    for operator in result['mirror']['operators']:
        source = next((c for c in record['catalogs'] if c['pinned'] == operator['catalog'] and
                       operator.get('targetCatalog') in {f'{prefix}-{c["alias"]}-{record["planHash"][:12]}'
                                                        for prefix in ('ocp5', 'ocp422')}), None)
        if not source:
            raise ValueError('OCI catalog 记录与导出配置不匹配')
        operator['catalog'] = f'oci://catalogs/{source["alias"]}@{source["ociDigest"]}'
    return result


def verify_catalogs(bundle, plan, require_manifest=False):
    record = json.loads((bundle / 'operator-catalogs.json').read_text())
    if record.get('schema') != 'ocpinstall/operator-catalogs/v1' or record.get('planHash') != plan['planHash']:
        raise ValueError('OCI catalog 来源与依赖计划不匹配')
    used = {item['catalog'] for item in plan['selected']}
    if {c['alias'] for c in record['catalogs']} != used or len(record['catalogs']) != len(used):
        raise ValueError('OCI catalog 清单缺失或重复')
    expected = {'operator-catalogs.json', 'imagesetconfiguration-oci.json', 'operators-plan.json', 'imagesetconfiguration.json'}
    for item in record['catalogs']:
        if not re.fullmatch(r'[a-z0-9][a-z0-9-]{0,30}', item['alias']):
            raise ValueError('OCI catalog 别名无效')
        source = next(c for c in plan['catalogs'] if c['alias'] == item['alias'])
        if item['pinned'] != source['pinned']:
            raise ValueError('OCI catalog 源镜像不匹配')
        digest, files = layout_files(bundle / 'catalogs' / item['alias'])
        if digest != item['ociDigest'] or files != item['files']:
            raise ValueError('OCI catalog 文件已改变')
        expected.update(f'catalogs/{item["alias"]}/{name}' for name in files)
    original = json.loads((bundle / 'imagesetconfiguration.json').read_text())
    config = bundle / 'imagesetconfiguration-oci.json'
    if json.loads(config.read_text()) != config_for_oci(original, record):
        raise ValueError('OCI 配置与原始镜像计划不一致')
    if require_manifest:
        recorded = json.loads((bundle / 'checksums.json').read_text())
        if not expected <= set(recorded):
            raise ValueError('OCI catalog 文件未全部列入离线包校验清单')
    return config, [bundle / name for name in sorted(expected)]


def stage_catalogs(args, bundle, cache, plan):
    if (bundle / 'operator-catalogs.json').is_file():
        return verify_catalogs(bundle, plan)
    if (bundle / 'checksums.json').exists():
        raise ValueError('旧离线包没有本地 OCI catalog，请在新目录重新导出，不能原地改写已完成的包')
    auth = offline.auth_file(args, bundle)
    supplied = dict(item.split('=', 1) for item in args.catalog_oci)
    used = {item['catalog'] for item in plan['selected']}
    if set(supplied) - used:
        raise ValueError('--catalog-oci 包含计划之外的别名')
    record = {'schema': 'ocpinstall/operator-catalogs/v1', 'planHash': plan['planHash'], 'catalogs': []}
    for source in plan['catalogs']:
        alias = source['alias']
        if alias not in used:
            continue
        destination = bundle / 'catalogs' / alias
        if alias in supplied:
            layout = Path(supplied[alias]).expanduser().resolve()
            digest, files = layout_files(layout)
        else:
            if not shutil.which('skopeo'):
                raise ValueError('准备本地 OCI catalog 需要 skopeo')
            layout = cache / 'oci-catalogs' / hashlib.sha256(source['pinned'].encode()).hexdigest()
            if not (layout / 'index.json').is_file():
                layout.parent.mkdir(parents=True, exist_ok=True)
                print('准备可转移的本地 OCI catalog: ' + alias, flush=True)
                with tempfile.TemporaryDirectory(prefix='oci-download-', dir=layout.parent) as temporary:
                    fresh = Path(temporary) / 'layout'
                    # OCI layouts cannot store the registry's legacy detached signatures.
                    # This matches oc-mirror's own OCI conversion; source policy and TLS remain configured.
                    subprocess.run(['skopeo', 'copy', '--remove-signatures', '--override-os', 'linux', '--override-arch', 'amd64',
                                    '--authfile', str(auth), 'docker://' + source['pinned'], 'oci:' + str(fresh) + ':catalog'], check=True)
                    layout_files(fresh)
                    fresh.rename(layout)
            digest, files = layout_files(layout)
        destination.parent.mkdir(parents=True, exist_ok=True)
        if destination.exists():
            existing_digest, existing_files = layout_files(destination)
            if (existing_digest, existing_files) != (digest, files):
                raise ValueError(f'目标 OCI catalog 与缓存不同，请审阅 {destination}，不要覆盖旧离线包')
        else:
            with tempfile.TemporaryDirectory(prefix='oci-stage-', dir=destination.parent) as temporary:
                staged = Path(temporary) / 'layout'
                shutil.copytree(layout, staged)
                staged.rename(destination)
        record['catalogs'].append({'alias': alias, 'pinned': source['pinned'], 'ociDigest': digest, 'files': files})
    offline.save_json(bundle / 'operator-catalogs.json', record)
    original = json.loads((bundle / 'imagesetconfiguration.json').read_text())
    offline.save_json(bundle / 'imagesetconfiguration-oci.json', config_for_oci(original, record))
    return verify_catalogs(bundle, plan)
