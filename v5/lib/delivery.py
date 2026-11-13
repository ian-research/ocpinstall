#!/usr/bin/env python3
"""Prepare a portable platform + Operator delivery and connect its three stages."""
import argparse
import contextlib
import fcntl
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tarfile
import urllib.request
import time
import http.client
import tempfile

import offline
import operator_profile

SOURCE = Path(__file__).resolve().parent.parent
KNOWN_HELPER_STATES = ('/opt/ocpinstall', '/opt/ocp5', '/opt/ocp422', '/opt/harbor/harbor/harbor.yml')
PACKAGES = ['glibc-langpack-zh', 'glibc-langpack-en', 'python3', 'python3-pyyaml',
            'policycoreutils-python-utils', 'haproxy', 'bind', 'bind-utils',
            'skopeo', 'httpd-tools', 'openssl', 'python3.11', 'python3-pip',
            'jq', 'wget', 'nfs-utils', 'chrony', 'httpd', 'cockpit', 'firewalld',
            'docker-ce', 'docker-ce-cli', 'containerd.io', 'docker-compose-plugin']


def helper_packages():
    # Language packs require the exact glibc-common EVR. --alldeps resolves
    # forward dependencies, but cannot include installed reverse dependencies.
    result = list(PACKAGES)
    installed = run(['rpm', '-qa', '--qf', '%{NAME}\\n', 'glibc-langpack-*'],
                    capture_output=True, text=True).stdout.splitlines()
    for name in sorted(set(installed)):
        if not re.fullmatch(r'glibc-langpack-[A-Za-z0-9_-]+', name):
            raise ValueError('无法识别准备机上的 glibc 语言包名称')
        if name not in result:
            result.append(name)
    return result


def download_helper_transaction(repos, repository, cache, packages):
    # DNF marks --downloadonly's destination as disposable until the next real
    # transaction. Never register the portable repository as that destination.
    with tempfile.TemporaryDirectory(prefix='helper-rpm-transaction-', dir=cache) as temporary:
        work = Path(temporary)
        downloads = work / 'downloads'
        downloads.mkdir()
        run(['dnf', '--setopt=reposdir=' + str(repos),
             '--setopt=cachedir=' + str(work / 'cache'),
             '--setopt=persistdir=' + str(work / 'persist'),
             'install', '-y', '--downloadonly', '--downloaddir=' + str(downloads), *packages])
        for package in downloads.rglob('*.rpm'):
            if package.is_symlink() or not package.is_file():
                raise ValueError('事务下载目录中的 RPM 文件类型无效')
            target = repository / package.name
            if target.exists() and offline.digest(target) != offline.digest(package):
                raise ValueError('同名 Helper RPM 内容不一致，请使用新交付目录')
            shutil.copy2(package, target)


def preflight_helper_rpms(helper):
    """Test the complete local RPM transaction without installing packages."""
    requirements = json.loads((helper / 'requirements.json').read_text())
    if requirements.get('mode') != 'rpm':
        return
    packages = requirements.get('packages')
    if not isinstance(packages, list) or not packages or any(
            not isinstance(p, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9+_.-]*', p)
            for p in packages):
        raise ValueError('Helper RPM 软件清单无效')
    keys = sorted(p.resolve().as_uri() for p in (helper / 'keys').iterdir() if p.is_file())
    if not keys:
        raise ValueError('Helper RPM 签名 key 缺失')
    payloads = {p.name: offline.digest(p) for p in (helper / 'rpms').glob('*.rpm')}
    if not payloads:
        raise ValueError('Helper 本地源没有 RPM 文件')
    # A private reposdir prevents fallback to RHUI, subscription or Docker.
    with tempfile.TemporaryDirectory(prefix='ocp-helper-rpm-check-') as temporary:
        repo = Path(temporary) / 'helper.repo'
        repo.write_text('[ocpinstall-helper-preflight]\nname=Offline Helper transaction check\n'
                        'baseurl=' + (helper / 'rpms').resolve().as_uri() + '\n'
                        'enabled=1\ngpgcheck=1\ngpgkey=' + ' '.join(keys) + '\n')
        print('预检本地 Helper RPM 完整事务；不会安装软件包。', flush=True)
        run(['dnf', '--setopt=reposdir=' + temporary,
             '--setopt=cachedir=' + str(Path(temporary) / 'cache'),
             '--setopt=persistdir=' + str(Path(temporary) / 'persist'),
             '--setopt=keepcache=1', '--disablerepo=*',
             '--enablerepo=ocpinstall-helper-preflight', '--setopt=tsflags=test',
             'install', '-y', *packages])
    after = {p.name: offline.digest(p) for p in (helper / 'rpms').glob('*.rpm')}
    if after != payloads:
        raise ValueError('RPM 事务预检修改了交付文件，拒绝封包或安装')


def ask(label, default=None):
    answer = input(label + (f' [{default}]' if default is not None else '') + ': ').strip()
    return answer or default


def run(command, **kwargs):
    return subprocess.run([str(c) for c in command], check=True, **kwargs)


def fetch(url, path, expected=None):
    if not url.startswith('https://'):
        raise ValueError('下载仅允许 HTTPS')
    path.parent.mkdir(parents=True, exist_ok=True)
    if expected and path.is_file() and offline.digest(path) == expected:
        return
    temporary = path.with_name(path.name + '.part')
    for attempt in range(3):
        try:
            with urllib.request.urlopen(url, timeout=120) as response, temporary.open('wb') as output:
                shutil.copyfileobj(response, output)
            break
        except (OSError, http.client.IncompleteRead):
            if attempt == 2:
                raise
            time.sleep(attempt + 1)
    if expected and offline.digest(temporary) != expected:
        raise ValueError('下载 SHA256 不匹配: ' + path.name)
    temporary.replace(path)


def safe_path(root, relative):
    root = root.resolve()
    if not isinstance(relative, str) or Path(relative).is_absolute() or '..' in Path(relative).parts:
        raise ValueError('交付清单包含不安全路径')
    result = root / relative
    if any(p.is_symlink() for p in [result, *result.parents] if p != root and root in p.parents) or root not in result.resolve().parents:
        raise ValueError('交付文件不能是链接或位于包目录外')
    return result


@contextlib.contextmanager
def locked(root):
    root.mkdir(parents=True, exist_ok=True)
    with (root / '.delivery.lock').open('a') as stream:
        try:
            fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise ValueError('此离线包已有任务运行；请勿并发操作同一目录') from error
        yield


def prepare_tools(args, root, cache):
    # Transport the exact plugin used for export, including user-provided builds.
    mirror = Path(args.oc_mirror or shutil.which('oc-mirror') or '').expanduser().resolve()
    if not mirror.is_file() or mirror.name != 'oc-mirror':
        raise ValueError('请通过 --oc-mirror 指定官方 oc-mirror 可执行文件')
    previous = root / 'platform/mirror-tool.json'
    if previous.is_file() and json.loads(previous.read_text())['sha256'] != offline.digest(mirror):
        raise ValueError('重试必须使用原 oc-mirror 二进制；更换工具请使用新的交付目录')
    cache.mkdir(parents=True, exist_ok=True)
    archive = cache / 'oc-mirror.tar.gz'
    with tarfile.open(archive, 'w:gz') as output:
        output.add(mirror, arcname='oc-mirror', recursive=False)
    options = argparse.Namespace(version=operator_profile.release(), channel=None, arch='amd64',
        operator=[], all_operators=False, catalog=None, image=[], archive_size=args.archive_size,
        oc_mirror_url=None, oc_mirror_archive=str(archive), oc_mirror_sha256=offline.digest(archive))
    offline.tools(options, root / 'platform')
    tools = root / 'platform/tools'
    expected = json.loads((tools / 'checksums.json').read_text())
    for path in tools.glob('*.tar.gz'):
        if path.name not in expected:
            retired = cache / 'unused-tools'
            retired.mkdir(exist_ok=True)
            shutil.move(path, retired / path.name)
    from artifacts import extract_tools
    binary = cache / 'bin'
    extract_tools(root / 'platform/tools', binary)
    os.environ['PATH'] = str(binary) + os.pathsep + os.environ.get('PATH', '')
    actual = run([binary / 'openshift-install', 'version'], capture_output=True, text=True).stdout
    if not actual.splitlines()[0].endswith(' ' + operator_profile.release()):
        raise ValueError('安装器实际版本与交付版本不一致')


def prepare_boot(root, cache):
    stream = json.loads(run([cache / 'bin/openshift-install', 'coreos', 'print-stream-json'],
                            capture_output=True, text=True).stdout)
    disk = stream['architectures']['x86_64']['artifacts']['metal']['formats']['iso']['disk']
    fetch(disk['location'], root / 'platform/boot/rhcos-live.iso', disk['sha256'])
    offline.save_json(root / 'platform/boot/source.json', disk)


def prepare_helper(args, root, cache):
    helper = root / 'helper'
    helper.mkdir(exist_ok=True)
    complete = helper / 'checksums.json'
    if complete.is_file():
        for name, expected in json.loads(complete.read_text()).items():
            if offline.digest(safe_path(helper, name)) != expected:
                raise ValueError('已准备的 Helper 软件被修改，请使用新目录重新准备')
        if args.harbor_sha256 and offline.digest(helper / 'harbor-offline-installer.tgz') != args.harbor_sha256:
            raise ValueError('已有不同 Harbor 安装包，请使用新交付目录')
        requirements = json.loads((helper / 'requirements.json').read_text())
        if requirements.get('mode') == 'rpm' and not set(PACKAGES) <= set(requirements.get('packages', [])):
            raise ValueError('已有 Helper RPM 清单缺少当前依赖，请使用新交付目录重新准备')
        if requirements.get('mode') == 'rpm' and requirements.get('rpmCollection') != 'isolated-transaction-cache-v1':
            raise ValueError('已有 Helper RPM 早于缓存隔离修复，请使用新交付目录重新准备')
        return
    # RHEL RHUI/entitlement stays on the preparation host; only RPMs and public keys travel.
    if args.helper_mode == 'existing':
        offline.save_json(helper / 'requirements.json', {'mode': 'existing', 'packages': PACKAGES,
            'notice': '目标 Helper 必须事先具备所有软件及可运行的 Docker；此模式不宣称 Helper 完全离线初始化。'})
    else:
        for command in ('dnf', 'createrepo_c'):
            if not shutil.which(command):
                raise ValueError('完整离线准备需要 RHEL 9 上的 dnf download 和 createrepo_c')
        release = dict(line.split('=', 1) for line in Path('/etc/os-release').read_text().splitlines() if '=' in line)
        if release.get('ID', '').strip('"') != 'rhel' or not release.get('VERSION_ID', '').strip('"').startswith('9'):
            raise ValueError('Helper RPM 必须在 RHEL 9 x86_64 上解析；请勿在其他发行版打包')
        if os.uname().machine != 'x86_64':
            raise ValueError('Helper RPM 准备机必须为 x86_64')
        repos = cache / 'repos'
        repos.mkdir(parents=True, exist_ok=True)
        for source in Path('/etc/yum.repos.d').glob('*.repo'):
            shutil.copy2(source, repos / source.name)
        fetch('https://download.docker.com/linux/rhel/docker-ce.repo', repos / 'docker-ce.repo')
        repository = helper / 'rpms'
        repository.mkdir(exist_ok=True)
        packages = helper_packages()
        run(['dnf', '--setopt=reposdir=' + str(repos), 'download', '--resolve', '--alldeps',
             '--destdir', repository, *packages])
        # Also resolve a real transaction against this preparation baseline.
        # Download-only includes installed reverse dependencies that must move
        # with newer libraries; no packages are installed or erased here.
        download_helper_transaction(repos, repository, cache, packages)
        run(['createrepo_c', repository])
        keys = helper / 'keys'
        keys.mkdir(exist_ok=True)
        for source in Path('/etc/pki/rpm-gpg').glob('RPM-GPG-KEY-redhat*'):
            shutil.copyfile(source, keys / source.name)
        if not list(keys.iterdir()):
            raise ValueError('找不到 RHEL 官方 RPM GPG key')
        fetch('https://download.docker.com/linux/rhel/gpg', keys / 'RPM-GPG-KEY-docker')
        # Signature validation is performed again by dnf on the target Helper.
        offline.save_json(helper / 'requirements.json', {'mode': 'rpm', 'packages': packages,
            'rhelVersion': release['VERSION_ID'].strip('"'),
            'rpmCollection': 'isolated-transaction-cache-v1'})
        preflight_helper_rpms(helper)
    if args.harbor_archive:
        source = Path(args.harbor_archive).expanduser().resolve()
        if not args.harbor_sha256 or offline.digest(source) != args.harbor_sha256:
            raise ValueError('本地 Harbor 包必须提供匹配的 --harbor-sha256')
        shutil.copyfile(source, helper / 'harbor-offline-installer.tgz')
    else:
        base = 'https://github.com/goharbor/harbor/releases/download/v2.12.2/'
        manifest = cache / 'harbor-upstream-md5.txt'
        fetch(base + 'md5sum', manifest)
        name = 'harbor-offline-installer-v2.12.2.tgz'
        expected = next((line.split()[0] for line in manifest.read_text().splitlines()
                         if line.split()[-1].lstrip('*') == name), None)
        if not expected or not re.fullmatch(r'[a-f0-9]{32}', expected):
            raise ValueError('Harbor 官方 MD5 清单缺少离线包；可显式提供本地包和 SHA256')
        target = helper / 'harbor-offline-installer.tgz'
        fetch(base + name, target)
        import hashlib
        value = hashlib.md5()
        with target.open('rb') as stream:
            for block in iter(lambda: stream.read(8 * 1024 * 1024), b''):
                value.update(block)
        if value.hexdigest() != expected:
            raise ValueError('Harbor 包与官方发布清单不符')
        offline.save_json(helper / 'harbor-source.json', {'url': base + name,
            'upstreamChecksumType': 'md5', 'upstreamChecksum': expected,
            'sha256': offline.digest(target),
            'note': '来源通过官方 GitHub HTTPS 获取；SHA256 为本地交付校验值，并非上游签名。'})
    offline.save_json(complete, {str(p.relative_to(helper)): offline.digest(p)
        for p in sorted(helper.rglob('*')) if p.is_file() and p != complete})


def snapshot_scripts(root):
    destination = root / 'scripts'
    if destination.is_symlink() or (destination.exists() and not destination.is_dir()):
        raise ValueError('scripts 快照路径必须是本包内的普通目录')
    entrypoints = {'install-cluster.sh', 'setup-cluster.sh', 'prepare-offline.sh',
                   'prepare-operators.sh', 'apply-operators.sh',
                   'README.md', 'DELIVERY.md', 'OPERATORS.md', 'VALIDATION.md'}
    configuration = {'versions.sh', 'ai-3.5.2-cpu-images.json', 'ai-3.5.3-cpu-images.json'}
    candidates = [SOURCE / name for name in entrypoints]
    candidates += [SOURCE / 'config' / name for name in configuration]
    candidates += list((SOURCE / 'lib').glob('*.py')) + list((SOURCE / 'lib').glob('*.sh'))
    candidates += [SOURCE / 'lib/operator-semantics' / name for name in ('main.go', 'go.mod', 'go.sum')]
    with tempfile.TemporaryDirectory(prefix='.scripts-stage-', dir=root) as temporary:
        fresh = Path(temporary) / 'scripts'
        fresh.mkdir()
        for path in sorted(set(candidates)):
            relative = path.relative_to(SOURCE)
            if not path.is_file() or path.is_symlink() or '__pycache__' in relative.parts:
                continue
            target = fresh / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(path, target)
        # Refresh the tool-owned snapshot so a retry cannot retain retired files.
        if destination.exists():
            shutil.rmtree(destination)
        fresh.replace(destination)
    for name, action in (('install.sh', 'install'), ('configure.sh', 'configure'), ('verify.sh', 'verify')):
        path = root / name
        path.write_text('#!/usr/bin/env bash\nset -Eeuo pipefail\n'
            'ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)\n'
            f'exec python3 "$ROOT/scripts/lib/delivery.py" {action} --bundle "$ROOT" "$@"\n')
        path.chmod(0o755)


def verify(root):
    root = root.resolve()
    record = json.loads((root / 'delivery.json').read_text())
    if record.get('schema') != 'ocpinstall/delivery/v1' or record.get('version') != operator_profile.release():
        raise ValueError('交付包格式或版本与脚本不一致')
    if not record.get('files'):
        raise ValueError('交付包清单为空')
    if record.get('arch') != 'amd64' or record.get('helperMode') not in ('rpm', 'existing'):
        raise ValueError('交付包架构或 Helper 模式无效')
    required = {'install.sh', 'configure.sh', 'verify.sh', 'delivery-plan.json',
        'scripts/install-cluster.sh', 'scripts/setup-cluster.sh', 'scripts/lib/delivery.py',
        'scripts/config/versions.sh', 'helper/requirements.json',
        'helper/harbor-offline-installer.tgz', 'platform/checksums.json',
        'platform/tools/checksums.json', 'platform/boot/rhcos-live.iso'}
    if record.get('operators'):
        required.add('operators/checksums.json')
    if not required <= record['files'].keys():
        raise ValueError('交付清单缺少必要的安装、配置或启动文件')
    # Child verification hashes the large image archives. Authenticate each child
    # manifest first and require exact agreement, rather than hashing every tar
    # once here and then again in offline.verify().
    covered = set()
    for child in ('platform', 'operators') if record['operators'] else ('platform',):
        name = child + '/checksums.json'
        path = safe_path(root, name)
        if not path.is_file() or offline.digest(path) != record['files'][name]:
            raise ValueError('子包校验清单缺失或 SHA256 不匹配: ' + name)
        covered.add(name)
        for relative, expected in json.loads(path.read_text()).items():
            combined = child + '/' + relative
            safe_path(root, combined)
            if record['files'].get(combined) != expected:
                raise ValueError('交付与子包校验清单不一致: ' + combined)
            covered.add(combined)
    for name, expected in record['files'].items():
        path = safe_path(root, name)
        if not path.is_file() or (name not in covered and offline.digest(path) != expected):
            raise ValueError('交付文件缺失或 SHA256 不匹配: ' + name)
    requirements = json.loads((root / 'helper/requirements.json').read_text())
    if requirements['mode'] != record['helperMode']:
        raise ValueError('Helper 软件与交付模式不一致')
    offline.verify(root / 'platform', record['version'])
    if record['operators']:
        import operators
        import operator_archive
        import operator_oci
        offline.verify(root / 'operators')
        plan = operators.load_plan(root / 'operators')
        if plan['targetVersion'] != record['version']:
            raise ValueError('平台和 Operator 目标版本不同')
        operator_oci.verify_catalogs(root / 'operators', plan, require_manifest=True)
        operator_archive.verify_record(root / 'operators', plan)
    return record


def seal(root, operators_enabled):
    files = []
    recorded = {}
    for folder in ('platform', 'operators') if operators_enabled else ('platform',):
        child = root / folder
        checksums = json.loads((child / 'checksums.json').read_text())
        recorded.update({child / name: value for name, value in checksums.items()})
        files += [child / name for name in checksums] + [child / 'checksums.json']
    for folder in ('scripts', 'helper', 'platform/tools', 'platform/boot'):
        files += [p for p in (root / folder).rglob('*') if p.is_file() and not p.is_symlink()]
    files += [root / name for name in ('install.sh', 'configure.sh', 'verify.sh', 'delivery-plan.json')]
    offline.save_json(root / 'delivery.json', {'schema': 'ocpinstall/delivery/v1',
        'version': operator_profile.release(), 'arch': 'amd64', 'operators': operators_enabled,
        'helperMode': json.loads((root / 'helper/requirements.json').read_text())['mode'],
        'files': {str(p.relative_to(root)): recorded[p] if p in recorded else offline.digest(p)
                  for p in sorted(set(files))}})
    try:
        verify(root)
    except Exception:
        (root / 'delivery.json').unlink(missing_ok=True)
        raise


def export(args, root, cache):
    if sys.platform != 'linux':
        raise ValueError('完整离线包必须在 Linux x86_64 准备机生成')
    if cache == root or root in cache.parents or cache in root.parents:
        raise ValueError('缓存和交付包必须位于互不包含的目录')
    auth = offline.auth_file(args, root)
    intent = {'version': operator_profile.release(), 'helperMode': args.helper_mode,
              'operators': not args.platform_only, 'select': args.select, 'catalog': args.catalog,
              'image': args.image, 'archiveSize': args.archive_size}
    path = root / 'delivery-plan.json'
    if not path.exists() and any(p.name not in ('.delivery.lock', 'delivery-state.json') for p in root.iterdir()):
        raise ValueError('首次准备请选择空目录，避免将既有文件或凭据混入交付包')
    if path.exists() and json.loads(path.read_text()) != intent:
        raise ValueError('已有不同交付计划；请使用新目录，避免覆盖历史离线包')
    offline.save_json(path, intent)
    (root / 'delivery.json').unlink(missing_ok=True)
    def stage(name):
        offline.save_json(root / 'delivery-state.json', {'stage': name, 'version': operator_profile.release()})
    stage('tools')
    prepare_tools(args, root, cache)
    operator_command = ['bash', SOURCE / 'prepare-operators.sh', '--bundle', root / 'operators',
        '--authfile', auth, '--cache-dir', cache / 'operators', '--archive-size', args.archive_size]
    for option in args.catalog:
        operator_command += ['--catalog', option]
    for option in args.select:
        operator_command += ['--select', option]
    if not args.platform_only:
        stage('operator-plan')
        command = operator_command[:2] + ['plan'] + operator_command[2:]
        if args.select:
            command += ['--non-interactive']
        run(command)
    if sys.stdin.isatty() and ask('计划已确认。开始下载平台、启动镜像、Helper 和 Operator？输入 yes', 'no') != 'yes':
        stage('cancelled-before-download')
        print('计划已保留；尚未生成可安装的完整离线包。')
        return
    stage('rhcos-boot')
    prepare_boot(root, cache)
    stage('helper-software')
    prepare_helper(args, root, cache)
    stage('platform-images')
    command = ['bash', SOURCE / 'prepare-offline.sh', 'export', '--bundle', root / 'platform',
        '--authfile', auth, '--cache-dir', cache / 'platform', '--archive-size', args.archive_size]
    for image in args.image:
        command += ['--image', image]
    if (root / 'platform/checksums.json').is_file():
        offline.verify(root / 'platform', operator_profile.release())
        print('已校验并复用完成的平台镜像包')
    else:
        run(command)
    if not args.platform_only:
        stage('operator-images')
        command = operator_command[:2] + ['export'] + operator_command[2:] + ['--non-interactive']
        if (root / 'operators/checksums.json').is_file():
            run(['bash', SOURCE / 'prepare-operators.sh', 'verify', '--non-interactive',
                 '--bundle', root / 'operators'])
        else:
            run(command)
        if not (root / 'operators/checksums.json').is_file():
            raise ValueError('Operator 下载未完成；交付包尚不能用于安装')
    snapshot_scripts(root)
    stage('verifying-delivery')
    seal(root, not args.platform_only)
    stage('complete')
    print('完整交付包已校验。复制整个目录后依次运行：\n'
          f'  bash "{root}/verify.sh"\n  bash "{root}/install.sh"\n'
          f'  bash "{root}/configure.sh"\n配置阶段会先等待节点安装完成。')


def preflight_helper_state(state):
    # Keep the native installer's guard; detect conflicts before hashing large archives.
    for name in KNOWN_HELPER_STATES:
        known = Path(name)
        if known != state and known.exists():
            raise ValueError(f'发现其他版本或路径的 Helper 状态：{known}。请使用独立 Helper；尚未校验大归档或修改系统。')


def execute(args, root):
    root = root.resolve()
    if args.action == 'install':
        prefix = operator_profile.resource_prefix(operator_profile.release())
        preflight_helper_state(Path(getattr(args, 'state_root', None) or '/opt/' + prefix).expanduser().resolve())
    record = verify(root)  # All validation precedes host or cluster changes.
    prefix = operator_profile.resource_prefix(record['version'])
    state = Path(args.state_root or '/opt/' + prefix).expanduser().resolve()
    if state == root or root in state.parents or state in root.parents:
        raise ValueError('集群私有状态与交付包必须位于互不包含的目录，避免转移时泄露凭据')
    env = dict(os.environ, BUNDLE_DIR=str(root / 'platform'), STATE_ROOT=str(state),
        HARBOR_ARCHIVE=str(root / 'helper/harbor-offline-installer.tgz'),
        HELPER_REPO_DIR=str(root / 'helper/rpms'), HELPER_KEYS_DIR=str(root / 'helper/keys'),
        RHCOS_ISO=str(root / 'platform/boot/rhcos-live.iso'))
    if args.action == 'install':
        requirements = json.loads((root / 'helper/requirements.json').read_text())
        if record['helperMode'] == 'rpm':
            actual = dict(line.split('=', 1) for line in Path('/etc/os-release').read_text().splitlines() if '=' in line)
            if actual.get('ID', '').strip('"') != 'rhel' or actual.get('VERSION_ID', '').strip('"') != requirements['rhelVersion']:
                raise ValueError('Helper 的 RHEL 版本必须与 RPM 准备机一致；请为目标版本重新准备')
            preflight_helper_rpms(root / 'helper')
        run(['bash', root / 'scripts/install-cluster.sh', '--repo-mode',
             'bundle' if record['helperMode'] == 'rpm' else 'existing', *args.script_args], env=env)
        return
    handoff = json.loads((state / 'handoff.json').read_text())
    if handoff['version'] != record['version']:
        raise ValueError('安装状态与离线包版本不同')
    binary = state / 'bin'
    env['PATH'] = str(binary) + os.pathsep + env.get('PATH', '')
    env['KUBECONFIG'] = args.kubeconfig or env.get('KUBECONFIG', str(state / 'install/auth/kubeconfig'))
    run([binary / 'openshift-install', 'wait-for', 'bootstrap-complete', '--dir=' + str(state / 'install')], env=env)
    run(['bash', root / 'scripts/install-cluster.sh', '--remove-bootstrap', *args.script_args], env=env)
    run([binary / 'openshift-install', 'wait-for', 'install-complete', '--dir=' + str(state / 'install')], env=env)
    for key in ('OCP_DOMAIN', 'NFS_SERVER', 'NFS_SC_DIR'):
        env[key] = handoff[key]
    auth = args.authfile or '/root/.docker/config.json'
    platform_resources = root / 'platform/images/working-dir/cluster-resources'
    if not platform_resources.is_dir() or not any(platform_resources.glob('*')):
        # A package can be moved between installation and configuration without
        # carrying the old import working-dir. Rebuild resources from its archives.
        run(['bash', root / 'scripts/prepare-offline.sh', 'import', '--bundle', root / 'platform',
             '--registry', handoff['registry'], '--authfile', auth, '--version', record['version'],
             '--cache-dir', state / 'platform-import-cache'], env=env)
    if record['operators']:
        run(['bash', root / 'scripts/prepare-operators.sh', 'import', '--non-interactive',
             '--bundle', root / 'operators', '--registry', handoff['registry'], '--authfile', auth,
             '--cache-dir', state / 'operator-import-cache'], env=env)
        env['OPERATOR_BUNDLE_DIR'] = str(root / 'operators')
    run(['bash', root / 'scripts/setup-cluster.sh', *args.script_args], env=env)


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', nargs='?', choices=('export', 'verify', 'install', 'configure'), default='export')
    parser.add_argument('--bundle')
    parser.add_argument('--cache-dir')
    parser.add_argument('--authfile')
    parser.add_argument('--oc-mirror', help='已取得的官方 oc-mirror 可执行文件路径')
    parser.add_argument('--helper-mode', choices=('rpm', 'existing'), default='rpm')
    parser.add_argument('--harbor-archive')
    parser.add_argument('--harbor-sha256')
    parser.add_argument('--platform-only', action='store_true')
    parser.add_argument('--catalog', action='append', default=[])
    parser.add_argument('--select', action='append', default=[])
    parser.add_argument('--image', action='append', default=[])
    parser.add_argument('--archive-size', type=int, default=20)
    parser.add_argument('--state-root')
    parser.add_argument('--kubeconfig')
    args, args.script_args = parser.parse_known_args()
    if args.platform_only and (args.select or args.catalog):
        parser.error('--platform-only 不能同时选择 Operator 或 catalog')
    if any(value.startswith('--repo-mode') for value in args.script_args):
        parser.error('交付包按记录的 Helper 模式选择软件源，不允许通过 --repo-mode 覆盖')
    if args.script_args and args.action not in ('install', 'configure'):
        parser.error('未知参数: ' + ' '.join(args.script_args))
    if not args.bundle and sys.stdin.isatty():
        args.bundle = ask('完整离线包保存/读取目录', str(Path.cwd() / (operator_profile.resource_prefix(operator_profile.release()) + '-delivery')))
    if not args.bundle or args.archive_size <= 0:
        parser.error('需要 --bundle 和大于零的 --archive-size')
    if args.action == 'export' and sys.stdin.isatty():
        args.authfile = args.authfile or ask('pull secret 路径（不会复制到交付包）')
        args.oc_mirror = args.oc_mirror or ask('官方 oc-mirror 可执行文件路径', shutil.which('oc-mirror'))
        args.harbor_archive = args.harbor_archive or ask('已有 Harbor 离线安装包路径（留空从官方获取）')
        if args.harbor_archive:
            args.harbor_sha256 = args.harbor_sha256 or ask('Harbor 包的 SHA256')
    root = Path(args.bundle).expanduser().resolve()
    with locked(root):
        if args.action == 'export':
            try:
                export(args, root, Path(args.cache_dir or str(root) + '-cache').expanduser().resolve())
            except Exception as error:
                if not (root / 'delivery.json').exists():
                    status = root / 'delivery-state.json'
                    previous = json.loads(status.read_text()).get('stage') if status.is_file() else 'input-validation'
                    offline.save_json(status, {'stage': 'failed', 'failedAt': previous,
                        'version': operator_profile.release(), 'errorType': type(error).__name__})
                raise
        elif args.action == 'verify':
            verify(root)
            print('完整交付包校验通过')
        else:
            execute(args, root)


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, KeyError, subprocess.CalledProcessError) as error:
        print(f'错误: {error}', file=sys.stderr)
        sys.exit(1)
