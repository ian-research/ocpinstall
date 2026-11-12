"""Check archived registry tags and image descriptor closure before delivery."""
import hashlib
import json
from pathlib import Path
import re
import tarfile

import offline


class RegistryArchives:
    def __init__(self, archives):
        self.tags, self.blobs = {}, {}
        self.archives = archives
        for archive in archives:
            with tarfile.open(archive, 'r:*') as tar:
                for member in tar:
                    if not member.isfile():
                        continue
                    name = member.name.removeprefix('./')
                    tag = re.search(r'(?:^|/)docker/registry/v2/repositories/(.+)/_manifests/tags/([^/]+)/current/link$', name)
                    blob = re.search(r'(?:^|/)docker/registry/v2/blobs/sha256/[a-f0-9]{2}/([a-f0-9]{64})/data$', name)
                    if tag:
                        if member.size > 200:
                            raise ValueError('归档中的 registry tag link 过大')
                        value = tar.extractfile(member).read().decode().strip()
                        if not re.fullmatch(r'sha256:[a-f0-9]{64}', value):
                            raise ValueError('归档中的 registry tag 摘要无效')
                        key = (tag[1], tag[2])
                        if key in self.tags and self.tags[key] != value:
                            raise ValueError('多份归档包含冲突的 registry tag')
                        self.tags[key] = value
                    if blob:
                        self.blobs[blob[1]] = (archive, member.name, member.size)

    def read_manifest(self, digest):
        location = self.blobs.get(digest.removeprefix('sha256:'))
        if not location:
            raise ValueError('归档缺少镜像 manifest blob: ' + digest)
        archive, name, size = location
        if size > 16 * 1024 * 1024:
            raise ValueError('归档中的镜像 manifest 过大')
        with tarfile.open(archive, 'r:*') as tar:
            content = tar.extractfile(name).read()
        if 'sha256:' + hashlib.sha256(content).hexdigest() != digest:
            raise ValueError('归档中的镜像 manifest SHA256 不匹配')
        return json.loads(content)

    def closure(self, digest, visited=None, depth=0):
        visited = set() if visited is None else visited
        if digest in visited:
            return
        if depth > 16 or not re.fullmatch(r'sha256:[a-f0-9]{64}', digest):
            raise ValueError('镜像 manifest 引用无效或过深')
        visited.add(digest)
        data = self.read_manifest(digest)
        if 'manifests' in data:
            for descriptor in data['manifests']:
                self.check_blob(descriptor)
                self.closure(descriptor['digest'], visited, depth + 1)
        elif 'config' in data and 'layers' in data:
            for descriptor in [data['config'], *data['layers']]:
                self.check_blob(descriptor)
        else:
            raise ValueError('归档中的镜像 manifest 格式无效')

    def check_blob(self, descriptor):
        digest = descriptor.get('digest', '')
        if not re.fullmatch(r'sha256:[a-f0-9]{64}', digest):
            raise ValueError('镜像仅支持 SHA256 descriptor')
        location = self.blobs.get(digest.split(':')[1])
        if not location or location[2] != descriptor['size']:
            raise ValueError('归档缺少镜像 layer/config 或大小不符: ' + digest)

    def check_tag(self, repository, tag, expected=None):
        digest = self.tags.get((repository, tag))
        if digest is None or (expected and digest != expected):
            raise ValueError(f'归档缺少正确的目录/镜像标签 {repository}:{tag}；不能交付增量或不完整镜像包')
        self.closure(digest)
        return digest


def image_refs(plan):
    result = set(plan.get('additionalImages', []))
    for selected in plan['selected']:
        if not selected.get('image'):
            raise ValueError('依赖计划缺少 bundle image')
        result.add(selected['image'])
        result.update(item['image'] for item in selected.get('relatedImages', []))
    return sorted(result)


def image_tag(reference):
    _, _, path = reference.partition('/')
    if not path:
        raise ValueError('镜像引用缺少 registry')
    expected = None
    if '@' in path:
        path, expected = path.rsplit('@', 1)
        if not re.fullmatch(r'sha256:[a-f0-9]{64}', expected):
            raise ValueError('镜像 digest 无效')
        path = path.rsplit(':', 1)[0] if ':' in path.rsplit('/', 1)[-1] else path
        tag = expected.replace(':', '-', 1)
    elif ':' in path.rsplit('/', 1)[-1]:
        path, tag = path.rsplit(':', 1)
    else:
        tag = 'latest'
    return path, tag, expected


def build_record(bundle, archives, plan):
    index = RegistryArchives(archives)
    records = []
    for reference in image_refs(plan):
        repository, tag, expected = image_tag(reference)
        digest = index.check_tag(repository, tag, expected)
        records.append({'kind': 'image', 'reference': reference, 'repository': repository, 'tag': tag, 'digest': digest})
    config = json.loads((bundle / 'imagesetconfiguration.json').read_text())
    oci = json.loads((bundle / 'operator-catalogs.json').read_text())
    for catalog in config['mirror']['operators']:
        source = next(c for c in oci['catalogs'] if c['pinned'] == catalog['catalog'] and
                      catalog['targetCatalog'].endswith('-' + c['alias'] + '-' + plan['planHash'][:12]))
        folder = (bundle / 'images/working-dir/operator-catalogs' / source['alias'] /
                  source['ociDigest'].split(':')[1] / 'filtered-catalogs')
        candidates = []
        for path in folder.glob('*/digest'):
            tag = path.parent.name
            digest = 'sha256:' + path.read_text().strip()
            if index.tags.get((catalog['targetCatalog'], tag)) == digest:
                candidates.append((tag, digest))
        if len(candidates) != 1:
            raise ValueError('归档未包含唯一正确的过滤 catalog 标签: ' + catalog['targetCatalog'])
        tag, digest = candidates[0]
        index.check_tag(catalog['targetCatalog'], tag, digest)
        records.append({'kind': 'catalog', 'alias': source['alias'], 'repository': catalog['targetCatalog'], 'tag': tag, 'digest': digest})
    output = bundle / 'operator-archive.json'
    offline.save_json(output, {'schema': 'ocpinstall/operator-archive/v1', 'planHash': plan['planHash'], 'records': records})
    return [output]


def verify_record(bundle, plan):
    manifest = json.loads((bundle / 'checksums.json').read_text())
    if 'operator-archive.json' not in manifest:
        raise ValueError('缺少可独立搬迁的归档闭包记录，请重新导出')
    record = json.loads((bundle / 'operator-archive.json').read_text())
    if record.get('schema') != 'ocpinstall/operator-archive/v1' or record.get('planHash') != plan['planHash']:
        raise ValueError('归档闭包记录与依赖计划不匹配')
    if {r.get('reference') for r in record['records'] if r.get('kind') == 'image'} != set(image_refs(plan)):
        raise ValueError('归档闭包记录没有覆盖全部 bundle/related/附加镜像')
    if {r.get('alias') for r in record['records'] if r.get('kind') == 'catalog'} != {i['catalog'] for i in plan['selected']}:
        raise ValueError('归档闭包记录没有覆盖全部过滤 catalog')
    index = RegistryArchives(sorted((bundle / 'images').glob('*.tar')))
    for item in record['records']:
        index.check_tag(item['repository'], item['tag'], item['digest'])
