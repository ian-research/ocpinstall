#!/usr/bin/env python3
"""Small shared Helper profile for RHEL 9 and RHEL 10 x86_64.

The delivery engine and install-cluster.sh both use this module so the RPM
manifest and the installed package list cannot silently diverge.  RHEL 9 keeps
the frozen known-good package set; RHEL 10 replaces the optional python3.11
package with the distribution default python3.

This module deliberately does not change any dnf command line.  RHEL 10 does
not imply DNF5: the actual AMI's ``dnf --version`` and the local transaction
must decide whether the existing DNF4-style flags work.  No RHEL 10 native
oc/oc-mirror archive is claimed or fabricated here.
"""
import argparse
from dataclasses import dataclass
import json
import os
from pathlib import Path
import re
import sys

RHEL9 = '9'
RHEL10 = '10'
SUPPORTED_MAJORS = (RHEL9, RHEL10)
SUPPORTED_ARCH = 'x86_64'
PYTHON311 = 'python3.11'

# RHEL 9 package roots retained from the tested installation flow.
_LEGACY_MANIFEST = [
    'glibc-langpack-zh', 'glibc-langpack-en', 'python3', 'python3-pyyaml',
    'policycoreutils-python-utils', 'haproxy', 'bind', 'bind-utils',
    'skopeo', 'httpd-tools', 'openssl', 'python3.11', 'python3-pip',
    'jq', 'wget', 'nfs-utils', 'chrony', 'httpd', 'cockpit', 'firewalld',
    'docker-ce', 'docker-ce-cli', 'containerd.io', 'docker-compose-plugin',
]

# Frozen RHEL 9 package list installed by install_dependencies().  Docker RPMs
# are installed by the same function as a separate local transaction.
_LEGACY_INSTALL = [
    'python3-pyyaml', 'policycoreutils-python-utils', 'haproxy', 'bind',
    'bind-utils', 'skopeo', 'httpd-tools', 'openssl', 'python3.11',
    'python3-pip', 'jq', 'wget', 'nfs-utils', 'chrony', 'httpd', 'cockpit',
]


@dataclass(frozen=True)
class Profile:
    id: str
    major: str
    version: str
    arch: str
    name: str


def parse_os_release(path='/etc/os-release'):
    """Read os-release without sourcing it or executing any content."""
    values = {}
    for line in Path(path).read_text().splitlines():
        line = line.strip()
        if not line or line.startswith('#') or '=' not in line:
            continue
        key, value = line.split('=', 1)
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        values[key.strip()] = value
    return values


def profile_from(values, machine=None):
    """Validate ID/major/arch and return the closed profile."""
    identifier = values.get('ID', '')
    version = values.get('VERSION_ID', '')
    arch = machine or os.uname().machine
    if identifier != 'rhel':
        raise ValueError('Helper 必须运行 RHEL；当前 ID=%s' % (identifier or '未知'))
    if arch != SUPPORTED_ARCH:
        raise ValueError('Helper 必须为 x86_64；当前架构=%s' % arch)
    if not re.fullmatch(r'(9|10)(\.[0-9]+)*', version):
        raise ValueError('Helper 必须为 RHEL 9 或 RHEL 10；当前 VERSION_ID=%s'
                         % (version or '未知'))
    major = version.split('.', 1)[0]
    return Profile('rhel', major, version, arch, 'rhel' + major)


def detect_host(os_release='/etc/os-release', machine=None):
    return profile_from(parse_os_release(os_release), machine)


def profile_for(major, version=None):
    if str(major) not in SUPPORTED_MAJORS:
        raise ValueError('不支持的 Helper 主版本: %s' % major)
    return Profile('rhel', str(major), version or str(major), SUPPORTED_ARCH,
                   'rhel' + str(major))


def manifest_packages(profile):
    """RPM download roots recorded in helper/requirements.json."""
    packages = list(_LEGACY_MANIFEST)
    if profile.major == RHEL10:
        packages = [p for p in packages if p != PYTHON311]
    return packages


def install_packages(profile):
    """Packages installed by install_dependencies() before the Docker step."""
    packages = ['python3' if profile.major == RHEL10 and p == PYTHON311 else p
                for p in _LEGACY_INSTALL]
    seen = set()
    return [p for p in packages if not (p in seen or seen.add(p))]


def requirements(profile, packages):
    """Requirements record with the legacy field plus small optional profile fields."""
    return {
        'mode': 'rpm',
        'packages': list(packages),
        'rhelVersion': profile.version,
        'osMajor': profile.major,
        'osVersion': profile.version,
        'arch': profile.arch,
        'profile': profile.name,
    }


def validate_cached(requirements, actual):
    """Reject an old RPM slice before hashing or reusing it.

    Legacy 9 requirements have no osMajor/osVersion/profile fields.  They remain
    usable only when their exact rhelVersion equals the current prep host and the
    current RHEL 9 manifest is still covered.  A RHEL 9 slice is rejected on a
    RHEL 10 prep host even when the package-name subset happens to match.
    """
    if requirements.get('mode') != 'rpm':
        return
    packages = requirements.get('packages')
    if not isinstance(packages, list) or not packages or any(
            not isinstance(p, str) for p in packages):
        raise ValueError('已有 Helper RPM 软件清单无效')
    recorded_version = str(requirements.get('osVersion')
                           or requirements.get('rhelVersion') or '')
    recorded_major = str(requirements.get('osMajor')
                         or recorded_version.split('.', 1)[0])
    if requirements.get('rhelVersion') != recorded_version:
        raise ValueError('已有 Helper RPM 的 OS 版本记录不一致')
    if recorded_major != recorded_version.split('.', 1)[0]:
        raise ValueError('已有 Helper RPM 的 OS 主版本记录不一致')
    if not recorded_version:
        raise ValueError('已有 Helper RPM 缺少 OS 版本记录，请使用新目录重新准备')
    if recorded_major != actual.major:
        raise ValueError('已有 Helper RPM 为 RHEL %s，当前准备机为 RHEL %s；'
                         '请使用新目录重新准备' % (recorded_major, actual.major))
    if recorded_version != actual.version:
        raise ValueError('已有 Helper RPM 为 RHEL %s，当前准备机为 RHEL %s；'
                         '精确版本不一致，请使用新目录重新准备'
                         % (recorded_version, actual.version))
    recorded_arch = requirements.get('arch')
    if recorded_arch and recorded_arch != actual.arch:
        raise ValueError('已有 Helper RPM 架构为 %s，当前准备机为 %s'
                         % (recorded_arch, actual.arch))
    recorded_profile = requirements.get('profile')
    if recorded_profile and recorded_profile != actual.name:
        raise ValueError('已有 Helper RPM 配置为 %s，当前准备机为 %s'
                         % (recorded_profile, actual.name))
    missing = sorted(set(manifest_packages(actual)) - set(packages))
    if missing:
        raise ValueError('已有 Helper RPM 清单缺少当前依赖，请使用新目录重新准备: '
                         + ', '.join(missing))


def audit_rpms(directory, profile):
    """Fail closed if a RHEL 10 slice contains an explicitly foreign el9/el8 RPM.

    RHEL 9 behavior is intentionally unchanged.  The check is a conservative
    filename guard, not a claim that an unlabelled RPM is RHEL 10 native.
    """
    if profile.major != RHEL10:
        return
    foreign = []
    for path in sorted(Path(directory).glob('*.rpm')):
        match = re.search(r'\.el([0-9]+)', path.name)
        if match and match.group(1) != RHEL10:
            foreign.append(path.name)
    if foreign:
        raise ValueError('RHEL 10 Helper RPM 包含非 el10 软件包: '
                         + ', '.join(foreign[:8]))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('detect', 'manifest-packages', 'install-packages'))
    parser.add_argument('--os-release', default='/etc/os-release')
    parser.add_argument('--machine')
    parser.add_argument('--major', choices=SUPPORTED_MAJORS)
    args = parser.parse_args(argv)
    try:
        profile = profile_for(args.major) if args.major else detect_host(
            args.os_release, args.machine)
    except (ValueError, OSError) as error:
        print('错误: %s' % error, file=sys.stderr)
        return 2
    if args.action == 'detect':
        print(json.dumps({'id': profile.id, 'major': profile.major,
                          'version': profile.version, 'arch': profile.arch,
                          'profile': profile.name}, ensure_ascii=False,
                         sort_keys=True))
    else:
        packages = (manifest_packages(profile) if args.action == 'manifest-packages'
                    else install_packages(profile))
        print('\n'.join(packages), end='')
    return 0


if __name__ == '__main__':
    sys.exit(main())
