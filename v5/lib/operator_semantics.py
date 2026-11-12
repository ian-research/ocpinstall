"""Pinned Go helper for OLM's blang/semver ranges and CEL properties environment."""
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import tarfile
import tempfile
import urllib.request

GO_VERSION = '1.27.4'
GO_SHA = {
    'linux-amd64': '7226736c2339719cda28fbf3a54d71aa63bcefe376e98cef00034268dab24840',
    'linux-arm64': '3392582988a273a87ab5043ee1b2c9c17a2c3c00580bf9326c47a2e0aaaeac92',
    'darwin-amd64': '2b799377704ef12db39bd254995d5c348c9cc8d86562ca817724390e56c38f43',
    'darwin-arm64': '91a44a2b8a716600ad94a4f143e156116620db8828086a6e3602291be9bd0bb4',
}


def bootstrap_go(cache):
    cache = cache.resolve()
    target = platform.system().lower() + '-' + {'x86_64': 'amd64', 'aarch64': 'arm64'}.get(platform.machine(), platform.machine())
    if target not in GO_SHA:
        raise ValueError('自动工具链仅支持 Linux/macOS amd64/arm64；请设置 GO 指向 Go 1.23+')
    destination = cache / ('go' + GO_VERSION + '-' + target)
    binary = destination / 'go/bin/go'
    if binary.is_file():
        return str(binary)
    cache.mkdir(parents=True, exist_ok=True)
    print('首次解析依赖：下载并校验官方 Go 工具链（只用于联网准备端）', flush=True)
    with tempfile.TemporaryDirectory(prefix='go-download-', dir=cache) as temporary:
        folder = Path(temporary)
        archive = folder / 'go.tar.gz'
        url = f'https://go.dev/dl/go{GO_VERSION}.{target}.tar.gz'
        with urllib.request.urlopen(url, timeout=120) as response, archive.open('wb') as stream:
            shutil.copyfileobj(response, stream)
        if hashlib.sha256(archive.read_bytes()).hexdigest() != GO_SHA[target]:
            raise ValueError('Go 官方工具链 SHA256 不匹配')
        extracted = folder / 'unpacked'
        extracted.mkdir()
        with tarfile.open(archive) as tar:
            for member in tar.getmembers():
                path = (extracted / member.name).resolve()
                if extracted not in path.parents or not (member.isfile() or member.isdir()):
                    raise ValueError('Go 归档包含不安全路径或链接')
            tar.extractall(extracted)
        extracted.rename(destination)
    return str(binary)


class Semantics:
    def __init__(self, cache, go=None):
        source = Path(__file__).resolve().parent / 'operator-semantics'
        identity = hashlib.sha256(b''.join(p.read_bytes() for p in sorted(source.glob('*')) if p.is_file())).hexdigest()[:20]
        cache = Path(cache).resolve()
        build = cache / ('semantics-' + identity)
        self.binary = build / 'operator-semantics'
        if not self.binary.is_file():
            tool = go or os.environ.get('GO') or shutil.which('go') or bootstrap_go(cache)
            build.mkdir(parents=True, exist_ok=True)
            for path in source.iterdir():
                if path.is_file():
                    shutil.copyfile(path, build / path.name)
            env = dict(os.environ, GOCACHE=str(cache / 'go-build'), GOMODCACHE=str(cache / 'go-mod'),
                       GOTOOLCHAIN='local', CGO_ENABLED='0')
            subprocess.run([tool, 'build', '-mod=readonly', '-trimpath', '-o', str(self.binary), '.'], cwd=build, env=env, check=True)
        self.process = subprocess.Popen([str(self.binary)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
        self.cache = {}

    def call(self, **request):
        key = json.dumps(request, sort_keys=True)
        if key not in self.cache:
            self.process.stdin.write(json.dumps(request) + '\n')
            self.process.stdin.flush()
            line = self.process.stdout.readline()
            if not line:
                raise ValueError('Operator 依赖语义工具提前退出')
            response = json.loads(line)
            if 'error' in response:
                raise ValueError('依赖表达式无效: ' + response['error'])
            self.cache[key] = response['result']
        return self.cache[key]

    def close(self):
        self.process.stdin.close()
        self.process.wait(timeout=10)
        self.process.stdout.close()
