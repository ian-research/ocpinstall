#!/usr/bin/env python3
"""交互式 Operator 离线包：目录选择 → 依赖解析 → 下载 → 校验 → 导入。"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

import offline
from operator_resolver import Catalogs, Resolver
from operator_semantics import Semantics
from operator_oci import stage_catalogs, verify_catalogs
import operator_profile
import operator_archive
import fcntl
import product_rules

DEFAULT_CATALOG = 'registry.redhat.io/redhat/redhat-operator-index:v' + operator_profile.release().rsplit('.', 1)[0]
NAME = re.compile(r'[a-z0-9][a-z0-9-]{0,30}')
IMAGE = re.compile(r'[A-Za-z0-9.-]+(?::[0-9]+)?/[A-Za-z0-9_./:@+-]+')


def prompt(label, default=None):
    value = input(label + (f' [{default}]' if default is not None else '') + ': ').strip()
    if not value and default is None:
        raise ValueError(label + '不能为空')
    return value or default


def run_json(command):
    result = subprocess.run(command, text=True, capture_output=True, check=True)
    return json.loads(result.stdout)


def cached_catalog(alias, image, auth, cache):
    if not NAME.fullmatch(alias) or not IMAGE.fullmatch(image):
        raise ValueError('catalog 应为 别名=完整镜像地址，别名使用小写字母、数字和短横线')
    if not shutil.which('skopeo'):
        raise ValueError('读取远端目录需要 skopeo，以及 podman 或 docker')
    command = ['skopeo', 'inspect', '--authfile', str(auth), '--override-os', 'linux', '--override-arch', 'amd64', 'docker://' + image]
    info = run_json(command)
    reference = image.split('@')[0]
    if ':' in reference.rsplit('/', 1)[-1]:
        reference = reference.rsplit(':', 1)[0]
    pinned = reference + '@' + info['Digest']
    if not re.fullmatch(r'.+@sha256:[a-f0-9]{64}', pinned):
        raise ValueError('目录未返回有效 SHA256 digest')
    folder = cache / 'catalogs' / info['Digest'].split(':')[1]
    metadata = folder / 'configs'
    if not (folder / 'complete.json').is_file():
        runtime = shutil.which('podman') or shutil.which('docker')
        if not runtime:
            raise ValueError('需要 podman 或 docker 提取 FBC 目录元数据')
        folder.mkdir(parents=True, exist_ok=True)
        if metadata.exists():
            raise ValueError(f'发现未完成的元数据缓存，请选择新 --cache-dir 或审阅后移走 {folder}')
        # Credential copies exist only in a private temporary directory, outside the bundle.
        with tempfile.TemporaryDirectory(prefix='catalog-auth-', dir=cache) as temporary:
            private = Path(temporary) / 'config.json'
            private.write_text(json.dumps({'auths': json.loads(auth.read_text())['auths']}))
            private.chmod(0o600)
            is_podman = Path(runtime).name == 'podman'
            base = [runtime] if is_podman else [runtime, '--config', temporary]
            pull = base + ['pull', '--platform', 'linux/amd64']
            if is_podman:
                pull += ['--authfile', str(private)]
            subprocess.run(pull + [pinned], check=True)
            label = run_json(base + ['image', 'inspect', pinned])[0]['Config']['Labels'].get('operators.operatorframework.io.index.configs.v1')
            if not label or not re.fullmatch(r'/[A-Za-z0-9_./-]+', label) or '..' in Path(label).parts:
                raise ValueError('只支持带有 configs.v1 标签的 FBC 目录；请将旧 SQLite 目录转换为 FBC')
            container = subprocess.run(base + ['create', '--entrypoint', '/bin/true', pinned], check=True, capture_output=True, text=True).stdout.strip()
            if not re.fullmatch(r'[a-f0-9]{12,64}', container):
                raise ValueError('容器运行时返回了无效容器 ID')
            try:
                subprocess.run(base + ['cp', container + ':' + label, str(metadata)], check=True)
            finally:
                subprocess.run(base + ['rm', container], check=True, stdout=subprocess.DEVNULL)
        files = {str(p.relative_to(metadata)): offline.digest(p) for p in metadata.rglob('*') if p.is_file() and not p.is_symlink()}
        offline.save_json(folder / 'complete.json', {'pinned': pinned, 'files': files})
    record = json.loads((folder / 'complete.json').read_text())
    if record['pinned'] != pinned:
        raise ValueError('目录缓存来源不匹配')
    actual = {str(p.relative_to(metadata)): offline.digest(p) for p in metadata.rglob('*') if p.is_file() and not p.is_symlink()}
    if record['files'] != actual:
        raise ValueError('目录元数据缓存校验失败；请使用新缓存目录')
    return {'alias': alias, 'source': image, 'pinned': pinned, 'metadata': str(metadata)}


def image_config(plan):
    operators = []
    for source in plan['catalogs']:
        packages = []
        for item in plan['selected']:
            if item['catalog'] == source['alias']:
                packages.append({'name': item['package'], 'defaultChannel': item['channel'],
                                 'channels': [{'name': item['channel'], 'minVersion': item['version'], 'maxVersion': item['version']}]})
        if packages:
            repository = operator_profile.catalog_repository(plan, source['alias'])
            tag = 'snapshot'
            # Some oc-mirror rebuilds replace the first occurrence of the tag.
            # Keep it out of the repository name so the replacement stays in the tag.
            while tag in repository:
                tag = 'x' + tag
            operators.append({'catalog': source['pinned'], 'targetCatalog': repository,
                              'targetTag': tag, 'packages': packages})
    mirror = {'operators': operators}
    if plan['additionalImages']:
        mirror['additionalImages'] = [{'name': image} for image in plan['additionalImages']]
    return {'apiVersion': 'mirror.openshift.io/v2alpha1', 'kind': 'ImageSetConfiguration',
            'archiveSize': plan['archiveSize'], 'mirror': mirror}


def fingerprint(plan):
    return hashlib.sha256(json.dumps({k: v for k, v in plan.items() if k != 'planHash'}, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def save_plan(bundle, plan):
    bundle.mkdir(parents=True, exist_ok=True)
    for path, data in ((bundle / 'operators-plan.json', plan), (bundle / 'imagesetconfiguration.json', image_config(plan))):
        if path.exists() and json.loads(path.read_text()) != data:
            raise ValueError('目标目录已有不同计划，请选择新的下载目录，避免覆盖旧离线包')
    offline.save_json(bundle / 'operators-plan.json', plan)
    offline.save_json(bundle / 'imagesetconfiguration.json', image_config(plan))


def load_plan(bundle):
    plan = json.loads((bundle / 'operators-plan.json').read_text())
    if plan.get('schema') != 'ocpinstall/operators/v1' or plan.get('planHash') != fingerprint(plan):
        raise ValueError('Operator 计划格式或指纹错误')
    if not operator_profile.validate_target(plan['targetVersion']):
        raise ValueError('离线包属于不同的 OpenShift 版本，请使用对应目录中的脚本')
    if json.loads((bundle / 'imagesetconfiguration.json').read_text()) != image_config(plan):
        raise ValueError('镜像配置与依赖计划不一致，禁止直接修改配置绕过依赖检查')
    return plan


def show_plan(plan):
    print('\n下载计划（平台镜像不重复下载）：')
    for item in plan['selected']:
        reason = '手动选择' if item['requested'] else '自动补齐依赖'
        print(f'  {item["catalog"]}/{item["package"]}:{item["channel"]} = {item["version"]}  [{reason}]')
        for requirement in item['dependencies']:
            print('    依赖 ' + json.dumps(requirement['constraint'], ensure_ascii=False) +
                  ' → ' + (', '.join(requirement['selectedProviders']) or '已声明的目标集群 API / 否定约束'))
    print(f'共 {len(plan["selected"])} 个 Operator；计划指纹 {plan["planHash"][:12]}')
    for product in plan.get('productRequirements', []):
        print('组件范围：' + product['product'] + ' ' + product['version'] + ' — ' + product['scope'])
        for requirement in product['prerequisites']:
            print('  前提：' + requirement)
    print(f'附加运行镜像：{len(plan["additionalImages"])} 个')
    print('自动解析范围为目录声明的依赖和 relatedImages；厂商未声明的外部服务、授权和运行时镜像需补充。')


def interactive_selections(catalogs):
    selections = []
    while True:
        term = prompt('搜索 Operator（名称片段；* 显示全部；done 结束选择）', 'done' if selections else '*')
        if term == 'done':
            if not selections:
                raise ValueError('至少选择一个 Operator')
            return selections
        matches = sorted((a, p) for a, p in catalogs.packages if term == '*' or term.lower() in p.lower())
        for index, (alias, package) in enumerate(matches, 1):
            print(f'  {index}. {alias}/{package}  默认 channel: {catalogs.packages[(alias, package)]["defaultChannel"]}')
        if not matches:
            print('没有匹配项'); continue
        choice = prompt('选择序号，或输入 s 重新搜索', 's')
        if choice == 's':
            continue
        try:
            number = int(choice)
            if not 1 <= number <= len(matches):
                raise ValueError()
        except ValueError:
            print('无效序号，请重新选择'); continue
        alias, package = matches[number - 1]
        available = sorted(c for a, p, c in catalogs.channels if (a, p) == (alias, package))
        print('可选 channel: ' + ', '.join(available))
        channel = prompt('channel', catalogs.packages[(alias, package)]['defaultChannel'])
        if channel not in available:
            print('channel 不在目录中，请重新选择'); continue
        versions = [b['version'] for b in catalogs.bundles if b['alias'] == alias and b['package'] == package and channel in b['channels']]
        print('可选版本: ' + ', '.join(versions))
        version = prompt('版本（head 表示所选 channel 最新节点）', 'head')
        spec = f'{alias}/{package}:{channel}' + ('' if version == 'head' else '=' + version)
        try:
            catalogs.root(spec)
        except ValueError as error:
            print(str(error)); continue
        if spec not in selections:
            selections.append(spec)


def prepare(args, bundle, cache, interactive):
    metadata = dict(item.split('=', 1) for item in args.catalog_metadata)
    choices = args.catalog
    if not choices:
        choices = [prompt('catalog 别名=镜像（可用逗号添加多个目录）', 'redhat=' + DEFAULT_CATALOG)] if interactive else ['redhat=' + DEFAULT_CATALOG]
        choices = [item.strip() for choice in choices for item in choice.split(',')]
    sources = []
    if set(metadata) - {item.split('=', 1)[0] for item in choices}:
        raise ValueError('--catalog-metadata 别名必须出现在 --catalog 中')
    auth = None
    for choice in choices:
        alias, image = choice.split('=', 1)
        if not NAME.fullmatch(alias) or not IMAGE.fullmatch(image) or any(s['alias'] == alias for s in sources):
            raise ValueError('目录别名/镜像无效或别名重复')
        if alias in metadata:
            if not re.fullmatch(r'.+@sha256:[a-f0-9]{64}', image):
                raise ValueError('本地元数据必须同时指定经核实的 digest 目录镜像')
            sources.append({'alias': alias, 'source': image, 'pinned': image, 'metadata': str(Path(metadata[alias]).expanduser().resolve())})
        else:
            if auth is None:
                if not args.authfile and interactive:
                    args.authfile = prompt('pull secret / registry auth JSON 路径')
                auth = offline.auth_file(args, bundle)
            sources.append(cached_catalog(alias, image, auth, cache))
    semantic = Semantics(cache / 'tools', args.go)
    try:
        catalogs = Catalogs(sources, semantic, args.target_version)
        print(f'已读取 {len(catalogs.packages)} 个包、{len(catalogs.bundles)} 个 bundle；排除 {len(catalogs.incompatible)} 个声明不支持目标版本的 bundle')
        selections = args.select or (interactive_selections(catalogs) if interactive else [])
        if not selections:
            raise ValueError('非交互模式请通过 --select 指定至少一个 Operator')
        requested = list(selections)
        selections, runtime_images, requirements = product_rules.expand(catalogs, selections, args.target_version)
        roots = [catalogs.root(s) for s in selections]
        provided = json.loads(Path(args.provided_apis).expanduser().read_text()) if args.provided_apis else []
        resolver = Resolver(catalogs, provided, args.max_states)
        selected = resolver.solve(roots)
        if interactive and not args.image:
            extra = prompt('额外运行时镜像（可选，多个用逗号分隔，回车跳过）', '')
            args.image = [image.strip() for image in extra.split(',') if image.strip()]
        requested_images = list(args.image)
        for image in runtime_images:
            if '@sha256:' not in image:
                if auth is None:
                    auth = offline.auth_file(args, bundle)
                data = subprocess.run(['skopeo', 'inspect', '--raw', '--authfile', str(auth), 'docker://' + image],
                                      check=True, capture_output=True).stdout
                image = image.rsplit(':', 1)[0] + '@sha256:' + hashlib.sha256(data).hexdigest()
            args.image.append(image)
        plan = {'schema': 'ocpinstall/operators/v1', 'targetVersion': args.target_version,
                'catalogs': [{k: s[k] for k in ('alias', 'source', 'pinned')} for s in sources],
                'roots': selections, 'selected': resolver.plan(roots, selected), 'providedAPIs': provided,
                'requestedRoots': requested, 'requestedImages': requested_images,
                'productRequirements': requirements,
                'additionalImages': sorted(set(args.image)), 'archiveSize': args.archive_size}
        for image in plan['additionalImages']:
            if not IMAGE.fullmatch(image):
                raise ValueError('附加镜像需要完整 registry 主机名')
        plan['planHash'] = fingerprint(plan)
        save_plan(bundle, plan)
        return plan
    finally:
        semantic.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', nargs='?', choices=['plan', 'export', 'import', 'verify'])
    parser.add_argument('--bundle', help='用户选择的离线包下载/转移目录')
    parser.add_argument('--authfile', help='目录外的 registry auth JSON；不会复制进离线包')
    parser.add_argument('--catalog', action='append', default=[], metavar='ALIAS=IMAGE')
    parser.add_argument('--catalog-metadata', action='append', default=[], metavar='ALIAS=PATH', help='已从指定 digest 提取的 FBC 元数据（显式信任此本地文件）')
    parser.add_argument('--catalog-oci', action='append', default=[], metavar='ALIAS=PATH', help='复用已核实来源的 OCI layout（显式信任其与目录 digest 的对应关系）')
    parser.add_argument('--select', action='append', default=[], metavar='ALIAS/PACKAGE[:CHANNEL][=VERSION]')
    parser.add_argument('--provided-apis', help='目标集群预置 API JSON 数组：group/version/kind；必须在目标离线集群同样存在')
    parser.add_argument('--target-version', default=operator_profile.release())
    parser.add_argument('--image', action='append', default=[], help='额外 operand 镜像；可重复')
    parser.add_argument('--archive-size', type=int, default=20)
    parser.add_argument('--cache-dir', help='独立缓存，默认 下载目录-cache')
    parser.add_argument('--registry', help='导入目标 hostname[:port]/project')
    parser.add_argument('--parallel-images', type=int, choices=range(1, 11), default=4)
    parser.add_argument('--parallel-layers', type=int, choices=range(1, 11), default=5)
    parser.add_argument('--dry-run', action='store_true', help='运行 oc-mirror dry-run，不生成成功标记')
    parser.add_argument('--non-interactive', action='store_true')
    parser.add_argument('--max-states', type=int, default=50000)
    parser.add_argument('--go', help='Go 1.23+ 可执行文件，未安装时自动校验下载固定工具链')
    args = parser.parse_args()
    interactive = not args.non_interactive and sys.stdin.isatty()
    if not args.action:
        if not interactive:
            parser.error('请指定 plan/export/import/verify，或在终端直接运行进入交互菜单')
        print('1. 选择 Operator 并下载离线包\n2. 只生成依赖计划\n3. 导入离线镜像仓库\n4. 校验离线包')
        args.action = {'1': 'export', '2': 'plan', '3': 'import', '4': 'verify'}.get(prompt('操作', '1'))
        if not args.action:
            raise ValueError('无效操作')
    if args.action in ('export', 'import') and sys.platform != 'linux':
        raise ValueError('导出和导入需要 Linux 准备机/Helper；plan 和 verify 可在本机运行')
    if not args.bundle:
        if not interactive:
            parser.error('非交互模式需要 --bundle')
        args.bundle = prompt('离线包保存/读取路径', str(Path.cwd() / (operator_profile.resource_prefix(operator_profile.release()) + '-operators')))
    bundle = Path(args.bundle).expanduser().resolve()
    cache = Path(args.cache_dir or str(bundle) + '-cache').expanduser().resolve()
    if cache == bundle or bundle in cache.parents or cache in bundle.parents:
        raise ValueError('缓存和离线包必须位于互不包含的独立目录')
    args.cache_dir = str(cache)
    bundle.mkdir(parents=True, exist_ok=True)
    with (bundle / '.operators.lock').open('a') as operation_lock:
        try:
            fcntl.flock(operation_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise ValueError('该 Operator 离线包已有任务执行，禁止并发覆盖') from error
        if args.archive_size <= 0 or args.max_states <= 0 or not operator_profile.validate_target(args.target_version):
            raise ValueError('归档大小/搜索上限必须为正数，目标版本必须属于本目录配置的 ' + operator_profile.release().rsplit('.', 1)[0])
        args.version = None  # Operator-only bundle must never pass the platform installer's version check.
        if args.action in ('plan', 'export'):
            cache.mkdir(parents=True, exist_ok=True)
            if (bundle / 'operators-plan.json').is_file():
                plan = load_plan(bundle)
                if args.select and args.select != plan.get('requestedRoots', plan['roots']):
                    raise ValueError('已有不同选择，请使用新离线包目录')
                if args.target_version != plan['targetVersion'] or (args.image and args.image != plan.get('requestedImages', plan['additionalImages'])):
                    raise ValueError('版本或附加镜像与已有计划不同，请使用新离线包目录')
                expected_sources = {s['alias']: (s['source'], s['pinned']) for s in plan['catalogs']}
                if any(item.split('=', 1)[1] not in expected_sources.get(item.split('=', 1)[0], ()) for item in args.catalog):
                    raise ValueError('目录来源与已有计划不同，请使用新离线包目录')
            else:
                plan = prepare(args, bundle, cache, interactive)
            show_plan(plan)
            if args.action == 'plan':
                print(f'计划已保存：{bundle}/operators-plan.json；尚未下载镜像')
                return
            if interactive and prompt('按以上计划开始下载？输入 yes', 'no') != 'yes':
                print('计划已保留，未开始镜像下载'); return
            if not args.authfile and interactive:
                args.authfile = prompt('pull secret / registry auth JSON 路径')
            config, files = stage_catalogs(args, bundle, cache, plan)
            args.cache_dir = str(cache / 'mirror' / plan['planHash'] / ('preview' if args.dry_run else 'export'))
            offline.mirror(args, bundle, True, config, files, cwd=bundle, standalone=True,
                           export_validator=lambda folder, archives: operator_archive.build_record(folder, archives, plan))
        else:
            offline.verify(bundle)
            checksums = json.loads((bundle / 'checksums.json').read_text())
            if 'operators-plan.json' not in checksums:
                raise ValueError('Operator 计划未包含在离线包校验清单中')
            plan = load_plan(bundle)
            config, _ = verify_catalogs(bundle, plan, require_manifest=True)
            operator_archive.verify_record(bundle, plan)
            show_plan(plan)
            if args.action == 'verify':
                return
            if not args.authfile and interactive:
                args.authfile = prompt('目标镜像仓库 auth JSON 路径')
            if not args.registry and interactive:
                args.registry = prompt('导入目标 hostname:port/project')
            args.cache_dir = str(cache / 'mirror' / plan['planHash'] / 'import')
            offline.mirror(args, bundle, False, config, cwd=bundle)
            print('下一步：审阅 images/working-dir/cluster-resources，再按 README 配合 setup-cluster.sh 应用。')


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, KeyError, TypeError, subprocess.CalledProcessError) as error:
        # Do not include captured command output; registry tools might include authentication data.
        print(f'错误: {error}', file=sys.stderr)
        sys.exit(1)
