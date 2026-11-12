import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('v5offline_tools', Path(__file__).resolve().parents[1] / 'lib/offline.py')
o = importlib.util.module_from_spec(spec)
spec.loader.exec_module(o)
from test_offline import args


class ToolTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.plugin = self.root / 'download.tar.gz'
        self.plugin.write_bytes(b'plugin archive')
        self.options = args(oc_mirror_url=None, oc_mirror_archive=str(self.plugin),
                            oc_mirror_sha256=o.digest(self.plugin))
        self.client = 'openshift-client-linux-amd64-rhel9-5.0.1.tar.gz'
        self.installer = 'openshift-install-linux.tar.gz'
        self.calls = []

    def urlopen(self, url, **kw):
        self.calls.append(url)
        if url.endswith('sha256sum.txt'):
            text = '\n'.join(f'{hashlib.sha256(b"archive").hexdigest()}  {name}'
                             for name in (self.client, self.installer))
            return io.BytesIO(text.encode())
        return io.BytesIO(b'archive')

    def test_separate_plugin_source_and_standard_installer(self):
        bundle = self.root / 'bundle'
        with patch.object(o.urllib.request, 'urlopen', side_effect=self.urlopen):
            o.tools(self.options, bundle)
        self.assertTrue(any(url.endswith(self.installer) for url in self.calls))
        self.assertFalse(any(url.endswith('oc-mirror.rhel9.tar.gz') for url in self.calls))
        manifest = json.loads((bundle / 'tools/checksums.json').read_text())
        self.assertEqual(manifest['oc-mirror.tar.gz'], o.digest(self.plugin))

    def test_wrong_plugin_checksum_never_publishes_success(self):
        self.options.oc_mirror_sha256 = '0' * 64
        bundle = self.root / 'bundle'
        with patch.object(o.urllib.request, 'urlopen', side_effect=self.urlopen):
            with self.assertRaises(ValueError):
                o.tools(self.options, bundle)
        self.assertFalse((bundle / 'tools/checksums.json').exists())

    def test_operator_catalog_must_be_explicit(self):
        with self.assertRaises(ValueError):
            o.make_config(args(operator=['foo'], catalog=None))

    def test_v4_not_accepted_by_v5_entrypoint(self):
        with self.assertRaises(ValueError):
            o.make_config(args(version='4.22.18'))
