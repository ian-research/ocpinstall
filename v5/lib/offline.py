#!/usr/bin/env python3
"""Build and transport oc-mirror v2 image sets; never copy registry credentials."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import urllib.request
import fcntl
import tempfile


def fail(message):
    raise ValueError(message)


def digest(path):
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(8 * 1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def save_json(path, data):
    temporary = path.with_suffix(path.suffix + '.tmp')
    temporary.write_text(json.dumps(data, indent=2) + '\n')
    temporary.replace(path)


def make_config(args):
    import operator_profile
    if not operator_profile.validate_target(args.version):
        fail('版本必须属于本脚本配置的 OpenShift minor，且包含 patch')
    minor = args.version.rsplit('.', 1)[0]
    channel = args.channel or f'stable-{minor}'
    if not re.fullmatch(r'(stable|fast|eus)-' + re.escape(minor), channel):
        fail('channel 必须与版本的 minor 一致')
    mirror = {'platform': {'architectures': [args.arch], 'channels': [
        {'name': channel, 'minVersion': args.version, 'maxVersion': args.version}
    ]}}
    packages = []
    for item in args.operator:
        parts = item.split(':')
        if len(parts) > 2 or not all(re.fullmatch(r'[A-Za-z0-9_.-]+', p) for p in parts):
            fail('Operator 格式为 package 或 package:channel')
        package = {'name': parts[0]}
        if len(parts) == 2:
            package['channels'] = [{'name': parts[1]}]
        packages.append(package)
    if args.all_operators and packages:
        fail('--all-operators 和 --operator 不能同时使用')
    if packages or args.all_operators:
        if not args.catalog:
            fail('Operator 必须通过 --catalog 明确指定已核实的目录镜像')
        catalog = {'catalog': args.catalog or f'registry.redhat.io/redhat/redhat-operator-index:v{minor}'}
        if args.all_operators:
            catalog['full'] = True
        else:
            catalog['packages'] = packages
        mirror['operators'] = [catalog]
    if args.image:
        mirror['additionalImages'] = [{'name': image} for image in args.image]
    return {'apiVersion': 'mirror.openshift.io/v2alpha1', 'kind': 'ImageSetConfiguration',
            'archiveSize': args.archive_size, 'mirror': mirror}


def config_for_bundle(args, bundle):
    desired = make_config(args)
    path = bundle / 'imagesetconfiguration.json'
    if path.exists() and json.loads(path.read_text()) != desired:
        fail('目录中已有不同配置；请使用新 --bundle，避免混用版本或覆盖历史镜像集')
    bundle.mkdir(parents=True, exist_ok=True)
    if not path.exists():
        save_json(path, desired)
    return path


def verify(bundle, version=None):
    manifest = bundle / 'checksums.json'
    if not manifest.is_file():
        fail('缺少 checksums.json，请先成功导出镜像包')
    checksums = json.loads(manifest.read_text())
    if not isinstance(checksums, dict) or 'imagesetconfiguration.json' not in checksums:
        fail('无效的校验清单')
    if 'mirror-tool.json' not in checksums:
        fail('缺少 oc-mirror 导出端校验记录')
    archives = set()
    for name, expected in checksums.items():
        path = (bundle / name).resolve()
        if bundle not in path.parents:
            fail('校验清单包含目录外路径')
        if name.startswith('images/') and name.endswith('.tar') and path.is_file():
            print(f'正在校验镜像归档 {name} ({path.stat().st_size / 1024**3:.1f} GiB)', flush=True)
        if not path.is_file() or digest(path) != expected:
            fail(f'文件缺失或 SHA256 校验失败: {name}')
        if name.startswith('images/') and name.endswith('.tar'):
            archives.add(name)
    actual = {str(p.relative_to(bundle)) for p in (bundle / 'images').glob('*.tar')}
    if not archives or archives != actual:
        fail('镜像归档缺失，或存在未记录的归档文件')
    if version:
        config = json.loads((bundle / 'imagesetconfiguration.json').read_text())
        if config['mirror']['platform'].get('architectures') != ['amd64']:
            fail('此安装工具仅支持 amd64 镜像包')
        channels = config['mirror']['platform']['channels']
        if not any(c.get('minVersion') == c.get('maxVersion') == version for c in channels):
            fail(f'镜像包版本与安装版本 {version} 不一致')
    print('镜像包完整性及版本检查通过')


def auth_file(args, bundle):
    if not args.authfile:
        fail('请通过 --authfile 提供 pull secret / 目标仓库凭据文件')
    path = Path(args.authfile).expanduser().resolve()
    if bundle == path or bundle in path.parents:
        fail('凭据必须存放在离线包目录之外，避免转移离线包时泄露')
    data = json.loads(path.read_text())
    if not isinstance(data.get('auths'), dict) or not data['auths']:
        fail('凭据文件必须包含非空 auths 对象')
    return path


def _mirror(args, bundle, exporting, prepared_config=None, manifest_extras=(), cwd=None, standalone=False, export_validator=None):
    if sys.platform != 'linux':
        fail('镜像导出/导入需要 Linux；config 和 verify 可跨平台运行')
    if not shutil.which('oc') or not shutil.which('oc-mirror'):
        fail('请安装 oc 和 oc-mirror v2，或先运行 tools 子命令下载工具')
    auth = auth_file(args, bundle)
    if exporting:
        config = prepared_config or config_for_bundle(args, bundle)
    else:
        verify(bundle, args.version)
        config = prepared_config or bundle / 'imagesetconfiguration.json'
        if not args.registry or not re.fullmatch(r'[A-Za-z0-9.-]+(?::[0-9]+)?(?:/[A-Za-z0-9._-]+)*', args.registry):
            fail('--registry 应为 hostname[:port][/project]，不要包含协议')
    plugin_hash = digest(Path(shutil.which('oc-mirror')).resolve())
    tool_record = bundle / 'mirror-tool.json'
    if tool_record.exists() and json.loads(tool_record.read_text())['sha256'] != plugin_hash:
        fail('oc-mirror 与导出时的二进制不一致，请使用源端同一工具')
    if not exporting and not tool_record.exists():
        fail('缺少导出端 oc-mirror 二进制校验记录')
    subprocess.run(['oc', 'mirror', '--v2', '--help'], check=True, stdout=subprocess.DEVNULL)
    images = bundle / 'images'
    images.mkdir(exist_ok=True)
    # Separate cache from the transferable bundle. Retain it for retries.
    cache = Path(args.cache_dir or str(bundle) + '-cache').resolve()
    cache.mkdir(parents=True, exist_ok=True)
    command = ['oc', 'mirror', '--v2', '-c', str(config), '--authfile', str(auth),
               '--cache-dir', str(cache), '--parallel-images', str(args.parallel_images),
               '--parallel-layers', str(args.parallel_layers), '--retry-times', '3']
    if args.dry_run:
        command.append('--dry-run')
    if exporting and standalone:
        # Standalone delivery must include cached content too, not an incremental delta.
        command += ['--since', '1970-01-01']
    if exporting:
        command.append('file://' + str(images))
    else:
        command += ['--from', 'file://' + str(images), 'docker://' + args.registry]
    # A failed retry must not leave a success manifest from an older export.
    if exporting and not args.dry_run:
        (bundle / 'checksums.json').unlink(missing_ok=True)
    os.umask(0o022)  # oc-mirror documented prerequisite; no credentials written here.
    old_errors = {str(p): (p.stat().st_mtime_ns, p.stat().st_size) for p in images.rglob('*')
                  if p.is_file() and 'logs' in p.parts and 'error' in p.name.lower()}
    # distribution/registry consumes REGISTRY_* as its own configuration.
    # Project post-install settings (e.g. REGISTRY_STORAGE=unchanged/emptydir)
    # must not become an embedded cache registry storage driver.
    mirror_env = {key: value for key, value in os.environ.items() if not key.startswith('REGISTRY_')}
    subprocess.run(command, check=True, cwd=cwd, env=mirror_env)
    if args.dry_run:
        print('预检查完成；尚未生成可交付离线包。请检查 working-dir/dry-run。')
        return
    # v2 may finish while reporting incomplete Operator images in separate logs.
    errors = [p for p in images.rglob('*') if p.is_file() and
              'logs' in p.parts and 'error' in p.name.lower() and p.stat().st_size and
              old_errors.get(str(p)) != (p.stat().st_mtime_ns, p.stat().st_size)]
    if errors:
        fail('oc-mirror 生成错误日志，请检查并重试: ' + ', '.join(map(str, errors)))
    if exporting:
        archives = sorted(images.glob('*.tar'))
        if not archives:
            fail('oc-mirror 未生成 tar 归档，不能标记导出完成')
        validated = export_validator(bundle, archives) if export_validator else []
        save_json(tool_record, {'sha256': plugin_hash})
        files = [config, tool_record] + list(manifest_extras) + validated + archives
        save_json(bundle / 'checksums.json', {str(p.relative_to(bundle)): digest(p) for p in files})
        print(f'导出完成：{bundle}。转移整个目录，保留源端缓存；凭据未复制。')
    else:
        print(f'导入完成；集群资源见 {images}/working-dir/cluster-resources，请审阅后应用。')


def mirror(args, bundle, exporting, prepared_config=None, manifest_extras=(), cwd=None, standalone=False, export_validator=None):
    if sys.platform != 'linux':
        fail('镜像导出/导入需要 Linux；config 和 verify 可跨平台运行')
    # oc-mirror uses a fixed local registry port. Serialize different bundles too.
    lock_path = Path(tempfile.gettempdir()) / f'ocpinstall-oc-mirror-{os.getuid()}.lock'
    descriptor = os.open(lock_path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, 'a') as mirror_lock:
        try:
            fcntl.flock(mirror_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise ValueError('当前用户已有 oc-mirror 任务；请等待完成，避免本地 registry 端口冲突') from error
        return _mirror(args, bundle, exporting, prepared_config, manifest_extras, cwd, standalone, export_validator)


def tools(args, bundle):
    make_config(args)  # validates version before constructing URLs
    destination = bundle / 'tools'
    destination.mkdir(parents=True, exist_ok=True)
    base = f'https://mirror.openshift.com/pub/openshift-v4/x86_64/clients/ocp/{args.version}/'
    files = [f'openshift-client-linux-amd64-rhel9-{args.version}.tar.gz',
             'openshift-install-linux.tar.gz']
    with urllib.request.urlopen(base + 'sha256sum.txt', timeout=60) as response:
        content = response.read().decode()
    expected = {}
    for line in content.splitlines():
        parts = line.split()
        if len(parts) == 2:
            expected[parts[1].lstrip('*')] = parts[0]
    for name in files:
        if name not in expected:
            fail(f'官方校验清单缺少 {name}')
        path = destination / name
        if path.exists() and digest(path) == expected[name]:
            continue
        print(f'下载 {name}', flush=True)
        temporary = path.with_suffix(path.suffix + '.part')
        with urllib.request.urlopen(base + name, timeout=120) as response, temporary.open('wb') as out:
            shutil.copyfileobj(response, out)
        if digest(temporary) != expected[name]:
            fail(f'官方 SHA256 校验失败: {name}')
        temporary.replace(path)
    checksums = {name: expected[name] for name in files}
    if args.oc_mirror_url or args.oc_mirror_archive or args.oc_mirror_sha256:
        if not (bool(args.oc_mirror_url) != bool(args.oc_mirror_archive)) or not args.oc_mirror_sha256:
            fail('选择 --oc-mirror-url 或 --oc-mirror-archive，并提供 --oc-mirror-sha256')
        if (args.oc_mirror_url and not args.oc_mirror_url.startswith('https://')) or not re.fullmatch(r'[a-fA-F0-9]{64}', args.oc_mirror_sha256):
            fail('oc-mirror 下载需 HTTPS URL 和 64 位 SHA256')
        path = destination / 'oc-mirror.tar.gz'
        expected_mirror = args.oc_mirror_sha256.lower()
        if not path.exists() or digest(path) != expected_mirror:
            temporary = path.with_suffix('.part')
            if args.oc_mirror_archive:
                shutil.copyfile(args.oc_mirror_archive, temporary)
            else:
                with urllib.request.urlopen(args.oc_mirror_url, timeout=120) as response, temporary.open('wb') as out:
                    shutil.copyfileobj(response, out)
            if digest(temporary) != expected_mirror:
                fail('oc-mirror SHA256 校验失败')
            temporary.replace(path)
        checksums[path.name] = expected_mirror
        save_json(destination / 'oc-mirror-source.json', {'source': args.oc_mirror_url or args.oc_mirror_archive, 'sha256': expected_mirror})
    else:
        print(f'请另行准备支持 {args.version} 的 oc-mirror v2；未假设它位于平台版本下载目录。')
    save_json(destination / 'checksums.json', checksums)
    print(f'RHEL 9 / x86_64 工具已保存至 {destination}；解压到 PATH 后运行 export。')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['config', 'tools', 'export', 'import', 'verify'])
    parser.add_argument('--version', default=re.search(r'^OCP_RELEASE=(.+)$', (Path(__file__).resolve().parent.parent / 'config/versions.sh').read_text(), re.M)[1])
    parser.add_argument('--bundle', required=True, help='可转移的离线包目录')
    parser.add_argument('--authfile', help='目录外的 registry auth JSON')
    parser.add_argument('--operator', action='append', default=[], metavar='PACKAGE[:CHANNEL]')
    parser.add_argument('--all-operators', action='store_true', help='显式下载完整目录，可能非常大')
    parser.add_argument('--catalog', help='Operator 镜像目录，需明确指定并通过 dry-run 验证')
    parser.add_argument('--oc-mirror-url', help='tools: 独立 oc-mirror HTTPS 下载地址')
    parser.add_argument('--oc-mirror-archive', help='tools: 从官方获取的本地 oc-mirror tar.gz')
    parser.add_argument('--oc-mirror-sha256', help='tools: oc-mirror 官方 SHA256')
    parser.add_argument('--channel')
    parser.add_argument('--arch', choices=['amd64'], default='amd64')
    parser.add_argument('--image', action='append', default=[], help='额外镜像，可重复')
    parser.add_argument('--archive-size', type=int, default=20, help='每个归档目标大小 GiB')
    parser.add_argument('--cache-dir')
    parser.add_argument('--parallel-images', type=int, choices=range(1, 11), default=4)
    parser.add_argument('--parallel-layers', type=int, choices=range(1, 11), default=5)
    parser.add_argument('--registry', help='导入目标 hostname:port/project')
    parser.add_argument('--dry-run', action='store_true')
    args = parser.parse_args()
    if args.archive_size <= 0:
        parser.error('--archive-size 必须大于 0')
    bundle = Path(args.bundle).resolve()
    if args.action == 'config':
        print(config_for_bundle(args, bundle))
    elif args.action == 'verify':
        verify(bundle, args.version)
    elif args.action == 'tools':
        tools(args, bundle)
    else:
        mirror(args, bundle, args.action == 'export', standalone=args.action == 'export')


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, KeyError, subprocess.CalledProcessError) as error:
        print(f'错误: {error}', file=sys.stderr)
        sys.exit(1)
