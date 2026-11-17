"""Select and pin VM container disks separately from Operator operands."""
import hashlib
import json
from pathlib import Path
import re
import subprocess

PRESETS = {
    'rhel9': 'registry.redhat.io/rhel9/rhel-guest-image:latest',
    'rhel10': 'registry.redhat.io/rhel10/rhel-guest-image:latest',
    'fedora': 'quay.io/containerdisks/fedora:latest',
    'centos-stream9': 'quay.io/containerdisks/centos-stream:9',
    'centos-stream10': 'quay.io/containerdisks/centos-stream:10',
}
NAME = re.compile(r'[a-z0-9][a-z0-9-]{0,39}')
REFERENCE = re.compile(r'[a-z0-9.-]+(?::[0-9]+)?/[a-z0-9._/-]+(?::[A-Za-z0-9_.-]+|@sha256:[a-f0-9]{64})')


def add_arguments(parser):
    parser.add_argument('--guest-image', action='append', default=[],
                        metavar='PRESET', help='可重复：' + ', '.join(PRESETS) + '；none 表示不准备系统镜像')
    parser.add_argument('--guest-image-ref', action='append', default=[], metavar='NAME=IMAGE',
                        help='自定义或覆盖系统镜像及 tag/digest；必须是 containerDisk OCI 镜像，不是 ISO/QCOW2 文件')


def repository(reference):
    if not isinstance(reference, str) or not REFERENCE.fullmatch(reference):
        raise ValueError('系统镜像需要完整 registry/repository:tag 或 @sha256:digest')
    base = reference.split('@', 1)[0]
    base = base.rsplit(':', 1)[0] if ':' in base.rsplit('/', 1)[-1] else base
    if any(part in ('.', '..', '') for part in base.split('/', 1)[1].split('/')):
        raise ValueError('系统镜像仓库路径无效')
    return base


def inputs(args, virtualization=False, interactive=False, prompt=None):
    aliases = list(getattr(args, 'guest_image', []))
    custom = list(getattr(args, 'guest_image_ref', []))
    explicit = bool(aliases or custom)
    if interactive and virtualization and not explicit:
        print('虚拟机系统镜像（与 Operator 一起下载；公共引导源自动导入仍关闭）：')
        names = list(PRESETS)
        for number, name in enumerate(names, 1):
            print(f'  {number}. {name}: {PRESETS[name]}')
        print('  0. 不准备系统镜像')
        choices = prompt('选择序号，多个用逗号分隔', '1').split(',')
        if choices == ['0']:
            aliases = ['none']
        else:
            if any(not c.strip().isdigit() or not 1 <= int(c.strip()) <= len(names) for c in choices):
                raise ValueError('系统镜像序号无效；0 不能与其他选项混用')
            for choice in choices:
                name = names[int(choice.strip()) - 1]
                source = PRESETS[name]
                tag = prompt(name + ' 的 tag 或 sha256:digest', source.rsplit(':', 1)[1])
                custom.append(name + '=' + repository(source) + ('@' if tag.startswith('sha256:') else ':') + tag)
    elif not explicit and virtualization:
        aliases = ['rhel9']
    if 'none' in aliases:
        if aliases != ['none'] or custom:
            raise ValueError('--guest-image none 不能与其他系统镜像选择混用')
        return []
    result = {}
    for name in aliases:
        if name not in PRESETS:
            raise ValueError('未知系统镜像预置: ' + name)
        result[name] = PRESETS[name]
    seen = set()
    for item in custom:
        name, separator, source = item.partition('=')
        if not separator or not NAME.fullmatch(name) or name == 'none' or name in seen:
            raise ValueError('自定义系统镜像必须为不重复的 NAME=IMAGE')
        repository(source)
        seen.add(name)
        result[name] = source
    return [{'name': name, 'source': source} for name, source in sorted(result.items())]


def fetch(reference, auth, config=False):
    command = ['skopeo', 'inspect', '--authfile', str(auth), '--override-os', 'linux',
               '--override-arch', 'amd64', '--config' if config else '--raw', 'docker://' + reference]
    try:
        return subprocess.run(command, check=True, capture_output=True, timeout=120).stdout
    except subprocess.TimeoutExpired as error:
        raise ValueError('读取系统镜像元数据超时，可在网络恢复后重试') from error


def pin(specifications, auth):
    result = []
    for item in specifications:
        source = item['source']
        base = repository(source)
        reference = source
        expected = source.rsplit('@', 1)[1] if '@' in source else None
        for _ in range(4):
            raw = fetch(reference, auth)
            digest = 'sha256:' + hashlib.sha256(raw).hexdigest()
            if expected and digest != expected:
                raise ValueError('系统镜像 manifest 摘要不一致: ' + item['name'])
            manifest = json.loads(raw)
            if not isinstance(manifest, dict):
                raise ValueError('系统镜像 manifest 必须为对象')
            if 'manifests' not in manifest:
                break
            if not isinstance(manifest['manifests'], list) or any(not isinstance(m, dict) for m in manifest['manifests']):
                raise ValueError('系统镜像 index 格式无效')
            candidates = [m for m in manifest['manifests'] if isinstance(m.get('platform'), dict)
                          and m['platform'].get('os') == 'linux' and m['platform'].get('architecture') == 'amd64']
            if len(candidates) != 1:
                raise ValueError('系统镜像没有唯一 linux/amd64 manifest: ' + item['name'])
            expected = candidates[0].get('digest', '')
            if not re.fullmatch(r'sha256:[a-f0-9]{64}', expected):
                raise ValueError('系统镜像 descriptor 摘要无效')
            reference = base + '@' + expected
        else:
            raise ValueError('系统镜像 manifest 嵌套过深')
        if not isinstance(manifest.get('config'), dict) or not manifest.get('layers'):
            raise ValueError('系统镜像 manifest 缺少 config/layers')
        pinned = base + '@' + digest
        config = json.loads(fetch(pinned, auth, config=True))
        if not isinstance(config, dict) or config.get('os') != 'linux' or config.get('architecture') != 'amd64':
            raise ValueError('系统镜像必须为 linux/amd64: ' + item['name'])
        if not isinstance(manifest['layers'], list) or any(not isinstance(layer, dict)
                or not isinstance(layer.get('size'), int) or layer['size'] < 0 for layer in manifest['layers']):
            raise ValueError('系统镜像 layer 大小无效')
        result.append({**item, 'image': pinned, 'architecture': 'amd64',
                       'type': 'containerDisk', 'compressedBytes': sum(layer['size'] for layer in manifest['layers'])})
    return result


def validate_saved_options(args, plan):
    if getattr(args, 'guest_image', []) or getattr(args, 'guest_image_ref', []):
        actual = inputs(args, virtualization=any('/kubevirt-hyperconverged' in s for s in plan['roots']))
        if actual != plan.get('guestImageInputs'):
            raise ValueError('系统镜像选择与已有计划不同，请使用新离线包目录')
    option = getattr(args, 'odf_local_storage', None)
    if option is not None and option != plan.get('downloadOptions', {}).get('odfLocalStorage'):
        raise ValueError('ODF 本地存储选择与已有计划不同，请使用新离线包目录')
    option = getattr(args, 'ai_nvidia', None)
    if option is not None and option != plan.get('downloadOptions', {}).get('aiNvidia', False):
        raise ValueError('AI GPU 选择与已有计划不同，请使用新离线包目录')


def local_sources(plan, resource_folder, destination):
    from operator_resolver import read_documents
    mappings = []
    for document in read_documents(Path(resource_folder)):
        for item in document.get('items', []) if document.get('kind') == 'List' else [document]:
            if item.get('kind') not in ('ImageDigestMirrorSet', 'ImageTagMirrorSet'):
                continue
            for key in ('imageDigestMirrors', 'imageTagMirrors'):
                for mapping in item.get('spec', {}).get(key, []):
                    if not isinstance(mapping.get('source'), str) or not isinstance(mapping.get('mirrors'), list):
                        raise ValueError('导入端镜像映射格式无效')
                    mappings.append(mapping)
    result = []
    for guest in plan.get('guestImages', []):
        source = repository(guest['image'])
        matches = [m for m in mappings if source == m['source'] or source.startswith(m['source'] + '/')]
        if not matches:
            raise ValueError('未找到系统镜像的实际导入映射: ' + guest['name'])
        scoped = []
        for match in matches:
            for mirror in match['mirrors']:
                if not isinstance(mirror, str):
                    raise ValueError('镜像 mirror 不是字符串')
                target = mirror.rstrip('/') + source[len(match['source']):]
                if target.startswith(destination.rstrip('/') + '/'):
                    scoped.append((len(match['source']), target))
        if not scoped:
            raise ValueError('系统镜像映射超出本次导入目标或为空')
        length = max(size for size, _ in scoped)
        targets = {target + '@' + guest['image'].rsplit('@', 1)[1] for size, target in scoped if size == length}
        result.append({**guest, 'localImages': sorted(targets)})
    return {'schema': 'ocpinstall/guest-images-local/v1', 'planHash': plan['planHash'],
            'images': result, 'clusterResourcesApplied': False}
