#!/usr/bin/env python3
"""Build v5 installation artifacts without executing an installation."""
import base64
import hashlib
import json
import ipaddress
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import sys
import tarfile
import tempfile


def write_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + '\n')
    path.chmod(0o600)


def load_yaml(path):
    import yaml
    return list(yaml.safe_load_all(Path(path).read_text()))


def mirror_sources(directory, required, prefix):
    found = {}
    for path in sorted(Path(directory).glob('*')):
        if path.suffix not in ('.yaml', '.yml', '.json'):
            continue
        for document in load_yaml(path):
            if not isinstance(document, dict):
                continue
            documents = document.get('items', []) if document.get('kind') == 'List' else [document]
            for item in documents:
                if item.get('kind') != 'ImageDigestMirrorSet':
                    continue
                for entry in item.get('spec', {}).get('imageDigestMirrors', []):
                    source = entry['source']
                    mirrors = entry.get('mirrors', [])
                    if source in required:
                        valid = [m for m in mirrors if m.startswith(prefix + '/')]
                        if not valid:
                            raise ValueError(f'{source} 未映射到目标仓库 {prefix}')
                        found[source] = list(dict.fromkeys(found.get(source, []) + valid))
    missing = set(required) - found.keys()
    if missing:
        raise ValueError('oc-mirror 未生成所需的离线映射: ' + ', '.join(sorted(missing)))
    return [{'source': source, 'mirrors': found[source]} for source in required]


def install_config(resources, destination):
    domain = os.environ['OCP_DOMAIN']
    name, base = domain.split('.', 1)
    registry = os.environ['LOCAL_REGISTRY']
    secret = json.loads(Path(os.environ['CLUSTER_PULL_SECRET']).read_text())
    if not secret.get('auths', {}).get(registry, {}).get('auth'):
        raise ValueError(f'集群 pull secret 缺少 {registry} 的内联 auth；不要使用 credential helper')
    helper = ipaddress.IPv4Address(os.environ['HELPER_IP_ADDRESS'])
    machine = ipaddress.IPv4Network(os.environ.get('MACHINE_CIDR', f'{helper}/24'), strict=False)
    pods = ipaddress.IPv4Network('10.128.0.0/14')
    services = ipaddress.IPv4Network('172.30.0.0/16')
    if helper not in machine or machine.overlaps(pods) or machine.overlaps(services):
        raise ValueError('machineNetwork 必须包含 Helper，且不能与 Pod/Service 网络重叠')
    config = {
        'apiVersion': 'v1', 'baseDomain': base, 'metadata': {'name': name},
        'compute': [{'name': 'worker', 'hyperthreading': 'Enabled', 'replicas': 0}],
        'controlPlane': {'name': 'master', 'hyperthreading': 'Enabled', 'replicas': 3},
        'networking': {'networkType': 'OVNKubernetes', 'machineNetwork': [{'cidr': str(machine)}],
                       'clusterNetwork': [{'cidr': str(pods), 'hostPrefix': 23}],
                       'serviceNetwork': [str(services)]},
        'platform': {'none': {}}, 'fips': False, 'pullSecret': json.dumps(secret),
        'sshKey': Path(os.environ['SSH_KEY'] + '.pub').read_text().strip(),
        'additionalTrustBundle': (Path(os.environ['CERT_DIR']) / 'ca.crt').read_text(),
        'imageDigestSources': mirror_sources(resources, [os.environ['RELEASE_SOURCE'],
            os.environ['COMPONENT_SOURCE']], registry + '/' + os.environ['LOCAL_REPOSITORY'])
    }
    write_json(destination, config)  # JSON is also valid YAML; avoids interpolation of secrets.


def chrony_config(server):
    if not re.fullmatch(r'[A-Za-z0-9.-]+', server):
        raise ValueError('无效 NTP 服务器名称')
    return (f'server {server} iburst prefer\ndriftfile /var/lib/chrony/drift\n'
            'makestep 1.0 3\nrtcsync\nlogdir /var/log/chrony\n')


def helper_chrony_config(server, cidr, helper, mode='upstream'):
    network = ipaddress.IPv4Network(cidr)
    address = ipaddress.IPv4Address(helper)
    if address not in network:
        raise ValueError('NFS_CIDR 必须包含 Helper；该网段也用于限制 NTP 客户端')
    if mode == 'local':
        if server:
            raise ValueError('NTP_MODE=local 时不要设置 NTP_SERVER，避免误认为已同步上游')
        source = 'local stratum 10\n'
    elif mode == 'upstream':
        if not server or not re.fullmatch(r'[A-Za-z0-9.-]+', server):
            raise ValueError('请设置可访问的内部 NTP_SERVER，或显式设置 NTP_MODE=local')
        try:
            resolved = {ipaddress.ip_address(item[4][0]) for item in
                        socket.getaddrinfo(server, 123, socket.AF_INET, socket.SOCK_DGRAM)}
        except socket.gaierror as error:
            raise ValueError('NTP_SERVER 无法解析；请先修复 DNS 或使用上游 IPv4') from error
        if any(ip == address or ip.is_loopback or ip.is_unspecified for ip in resolved):
            raise ValueError('NTP_SERVER 指向 Helper 自身；请使用真实上游或显式设置 NTP_MODE=local')
        source = f'server {server} iburst\n'
    else:
        raise ValueError('NTP_MODE 必须为 upstream 或 local')
    return ('driftfile /var/lib/chrony/drift\nmakestep 1.0 3\nrtcsync\n'
            'logdir /var/log/chrony\n' + source + f'allow {network}\n')


def helper_chrony(server, cidr, helper, mode='upstream'):
    print(helper_chrony_config(server, cidr, helper, mode), end='')


def ignition_file(path, content):
    return {'path': path, 'mode': 420, 'overwrite': True,
            'contents': {'source': 'data:text/plain;charset=utf-8;base64,' +
                         base64.b64encode(content.encode()).decode()}}


def prepare_manifests(directory):
    directory = Path(directory)
    scheduler = directory / 'manifests/cluster-scheduler-02-config.yml'
    documents = load_yaml(scheduler)
    if len(documents) != 1 or documents[0].get('kind') != 'Scheduler':
        raise ValueError('找不到安装器生成的 Scheduler 配置')
    document = documents[0]
    document.setdefault('spec', {})['mastersSchedulable'] = True
    write_json(scheduler, document)
    chrony = chrony_config('helper.' + os.environ['OCP_DOMAIN'])
    write_json(directory / 'openshift/99-master-chrony.yaml', {
        'apiVersion': 'machineconfiguration.openshift.io/v1', 'kind': 'MachineConfig',
        'metadata': {'name': '99-master-chrony',
                     'labels': {'machineconfiguration.openshift.io/role': 'master'}},
        'spec': {'config': {'ignition': {'version': '3.5.0'},
                           'storage': {'files': [ignition_file('/etc/chrony.conf', chrony)]}}}
    })


def bootstrap_ntp(directory):
    path = Path(directory) / 'bootstrap.ign'
    document = json.loads(path.read_text())
    if not document.get('ignition', {}).get('version', '').startswith('3.'):
        raise ValueError('Bootstrap Ignition 版本不受支持')
    files = document.setdefault('storage', {}).setdefault('files', [])
    files[:] = [item for item in files if item.get('path') != '/etc/chrony.conf']
    files.append(ignition_file('/etc/chrony.conf', chrony_config('helper.' + os.environ['OCP_DOMAIN'])))
    write_json(path, document)


def commands(directory, published, hostname, output):
    lines = ['# 在对应节点的 RHCOS Live ISO 中执行，替换 /dev/REPLACE_WITH_TARGET_DISK。',
             '# 网络配置正确后运行；必须在生成 Ignition 后 12 小时内开始安装。']
    for role in ('bootstrap', 'master'):
        source = Path(directory) / (role + '.ign')
        target = Path(published) / source.name
        expected = hashlib.sha512(source.read_bytes()).hexdigest()
        if hashlib.sha512(target.read_bytes()).hexdigest() != expected:
            raise ValueError(f'HTTP 发布副本与源文件不一致: {role}')
        lines += [f'# {role}', f'sudo coreos-installer install /dev/REPLACE_WITH_TARGET_DISK '
                  f'--ignition-url=http://{hostname}:9088/ocp5/ignition/{role}.ign '
                  f'--ignition-hash=sha512-{expected} --offline --copy-network']
    Path(output).write_text('\n'.join(lines) + '\n')
    Path(output).chmod(0o600)


def sha256(path):
    result = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(8 * 1024 * 1024), b''):
            result.update(block)
    return result.hexdigest()


def extract_tools(directory, destination):
    directory, destination = Path(directory), Path(destination)
    checksums = json.loads((directory / 'checksums.json').read_text())
    needed = {'oc', 'kubectl', 'openshift-install', 'oc-mirror'}
    files = sorted(directory.glob('*.tar.gz'))
    found = {}
    kubectl_link_archive = None
    # Only write named tools; preserve the official kubectl hardlink to oc.
    for archive in files:
        if archive.name not in checksums:
            raise ValueError(f'工具归档没有校验记录: {archive.name}')
        if sha256(archive) != checksums[archive.name]:
            raise ValueError(f'工具校验失败: {archive.name}')
        with tarfile.open(archive, 'r:gz') as stream:
            for member in stream.getmembers():
                name = Path(member.name).name
                if name not in needed:
                    continue
                if name in found or '..' in Path(member.name).parts or Path(member.name).is_absolute():
                    raise ValueError('工具包有重复二进制、不安全的路径或文件类型')
                if not member.isfile():
                    if (name == 'kubectl' and member.islnk()
                            and Path(member.name) == Path('kubectl')
                            and Path(member.linkname) == Path('oc')):
                        kubectl_link_archive = archive
                    else:
                        raise ValueError('工具包有不支持的链接或文件类型')
                found[name] = (archive, member.name)
    if set(found) != needed:
        raise ValueError('工具包缺少: ' + ', '.join(sorted(needed - found.keys())))
    if kubectl_link_archive is not None and found['oc'][0] != kubectl_link_archive:
        raise ValueError('kubectl 硬链接必须指向同一归档内的 oc')
    destination.mkdir(parents=True, exist_ok=True)
    for name, (archive, member) in found.items():
        if name == 'kubectl' and kubectl_link_archive is not None:
            continue
        # Atomic replacement also avoids following an existing output symlink.
        with tempfile.NamedTemporaryFile(dir=destination, delete=False) as out:
            temporary = Path(out.name)
            try:
                with tarfile.open(archive, 'r:gz') as stream, stream.extractfile(member) as source:
                    shutil.copyfileobj(source, out)
                out.flush()
                temporary.chmod(0o755)
                temporary.replace(destination / name)
            finally:
                temporary.unlink(missing_ok=True)
    if kubectl_link_archive is not None:
        alias = destination / 'kubectl'
        alias.unlink(missing_ok=True)
        os.link(destination / 'oc', alias)


def remove_bootstrap(path):
    path = Path(path)
    original = path.read_text()
    lines = [line for line in original.splitlines() if not re.match(r'\s*server\s+bootstrap\s', line)]
    if len(lines) == len(original.splitlines()):
        print('HAProxy 已无 bootstrap 后端')
        return
    with tempfile.NamedTemporaryFile('w', dir=path.parent, delete=False) as temporary:
        temporary.write('\n'.join(lines) + '\n')
        candidate = Path(temporary.name)
    try:
        subprocess.run(['haproxy', '-c', '-f', str(candidate)], check=True)
        backup = path.with_suffix('.cfg.ocp5-bootstrap.bak')
        if not backup.exists():
            shutil.copy2(path, backup)
        candidate.chmod(path.stat().st_mode & 0o777)
        candidate.replace(path)
    finally:
        candidate.unlink(missing_ok=True)


if __name__ == '__main__':
    actions = {'install-config': install_config, 'prepare-manifests': prepare_manifests,
               'bootstrap-ntp': bootstrap_ntp, 'helper-chrony': helper_chrony, 'commands': commands,
               'extract-tools': extract_tools, 'remove-bootstrap': remove_bootstrap}
    try:
        actions[sys.argv[1]](*sys.argv[2:])
    except (ValueError, OSError, KeyError, IndexError, subprocess.CalledProcessError) as error:
        print(f'错误: {error}', file=sys.stderr)
        sys.exit(1)
