"""Version-specific defaults live next to each independently deployable script."""
from pathlib import Path
import re


def release():
    config = Path(__file__).resolve().parent.parent / 'config/versions.sh'
    return re.search(r'^OCP_RELEASE=(.+)$', config.read_text(), re.M)[1]


def resource_prefix(version):
    if re.fullmatch(r'4\.22\.\d+', version):
        return 'ocp422'
    if re.fullmatch(r'5\.\d+\.\d+', version):
        return 'ocp5'
    raise ValueError('Operator 离线脚本仅支持 4.22 或 5.x 的完整版本')


def validate_target(version):
    return bool(re.fullmatch(re.escape(release().rsplit('.', 1)[0]) + r'\.\d+', version))
