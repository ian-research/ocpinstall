import json
import hashlib
import os
from pathlib import Path
import shutil
import sys
import tempfile
import tarfile
import io
import unittest
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'lib'))
from operator_resolver import Catalogs, Resolver, read_documents
from operator_semantics import Semantics
import operators
import operator_resources
import offline
import operator_oci
import operator_profile
import operator_archive


def make_layout(layout):
    (layout / 'blobs/sha256').mkdir(parents=True)
    def blob(data, media):
        digest = hashlib.sha256(data).hexdigest()
        (layout / 'blobs/sha256' / digest).write_bytes(data)
        return {'mediaType': media, 'digest': 'sha256:' + digest, 'size': len(data)}
    config = blob(b'{}', 'application/vnd.oci.image.config.v1+json')
    layer = blob(b'catalog-layer-fixture', 'application/vnd.oci.image.layer.v1.tar+gzip')
    manifest = blob(json.dumps({'schemaVersion': 2, 'config': config, 'layers': [layer]}).encode(), 'application/vnd.oci.image.manifest.v1+json')
    (layout / 'index.json').write_text(json.dumps({'schemaVersion': 2, 'manifests': [manifest]}))
    (layout / 'oci-layout').write_text('{"imageLayoutVersion":"1.0.0"}')
    return operator_oci.layout_files(layout)


def package(name, versions=('1.0.0',), dependencies=None, extra=None):
    result = [{'schema': 'olm.package', 'name': name, 'defaultChannel': 'stable'}]
    entries = []
    previous = None
    for version in versions:
        bundle = name + '.v' + version
        entry = {'name': bundle}
        if previous:
            entry['replaces'] = previous
        entries.append(entry)
        previous = bundle
        props = [{'type': 'olm.package', 'value': {'packageName': name, 'version': version}}]
        props += (dependencies or {}).get(version, [])
        props += (extra or {}).get(version, [])
        result.append({'schema': 'olm.bundle', 'name': bundle, 'package': name,
                       'image': f'registry.example.com/{name}@sha256:' + 'a' * 64, 'properties': props})
    result.append({'schema': 'olm.channel', 'package': name, 'name': 'stable', 'entries': entries})
    return result


def pkg(name, version='*'):
    return {'type': 'olm.package.required', 'value': {'packageName': name, 'versionRange': version}}


def api(group='example.com', kind='Widget'):
    return {'group': group, 'version': 'v1', 'kind': kind}


@unittest.skipUnless(os.environ.get('GO') or shutil.which('go'), '安装 Go 或设置 GO 后运行依赖解析测试；CI 必须运行')
class OperatorResolverTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cache = Path(tempfile.gettempdir()) / 'ocpinstall-operator-tests'
        cls.semantic = Semantics(cls.cache, os.environ.get('GO'))

    @classmethod
    def tearDownClass(cls):
        cls.semantic.close()

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def catalog(self, data):
        sources = []
        for alias, docs in data.items():
            path = self.root / (alias + '.json')
            path.write_text('\n'.join(json.dumps(d) for d in docs))
            sources.append({'alias': alias, 'pinned': 'registry.example.com/' + alias + '@sha256:' + 'b' * 64, 'metadata': str(path)})
        return Catalogs(sources, self.semantic)

    def solve(self, data, selections=('a/root',), provided=()):
        catalog = self.catalog(data)
        roots = [catalog.root(s) for s in selections]
        resolver = Resolver(catalog, provided)
        selected = resolver.solve(roots)
        return resolver.plan(roots, selected)

    def test_cross_catalog_recursive_package_dependency(self):
        data = {'a': package('root', dependencies={'1.0.0': [pkg('middle', '>=1.0.0 <2.0.0')]}),
                'b': package('middle', dependencies={'1.0.0': [pkg('leaf')]}) + package('leaf')}
        self.assertEqual({p['package'] for p in self.solve(data)}, {'root', 'middle', 'leaf'})

    def test_gvk_and_package_share_one_provider(self):
        deps = [{'type': 'olm.gvk.required', 'value': api()}, pkg('provider')]
        data = {'a': package('root', dependencies={'1.0.0': deps}) +
                package('provider', extra={'1.0.0': [{'type': 'olm.gvk', 'value': api()}]})}
        self.assertEqual(len(self.solve(data)), 2)

    def test_cycle_is_satisfied_without_infinite_recursion(self):
        data = {'a': package('root', dependencies={'1.0.0': [pkg('other')]}) +
                package('other', dependencies={'1.0.0': [pkg('root')]})}
        self.assertEqual(len(self.solve(data)), 2)

    def test_backtracks_to_compatible_dependency_version(self):
        data = {'a': package('root', dependencies={'1.0.0': [pkg('provider'), pkg('leaf', '<2.0.0')]}) +
                package('provider', ('1.0.0', '2.0.0'), dependencies={'1.0.0': [pkg('leaf', '<2.0.0')], '2.0.0': [pkg('leaf', '>=2.0.0')]}) +
                package('leaf', ('1.0.0', '2.0.0'))}
        versions = {p['package']: p['version'] for p in self.solve(data)}
        self.assertEqual(versions['provider'], '1.0.0')
        self.assertEqual(versions['leaf'], '1.0.0')

    def test_missing_dependency_fails_closed(self):
        with self.assertRaisesRegex(ValueError, '不存在可行组合'):
            self.solve({'a': package('root', dependencies={'1.0.0': [pkg('missing')]})})

    def test_root_pins_conflict(self):
        data = {'a': package('root', dependencies={'1.0.0': [pkg('provider', '<2.0.0')]}) + package('provider', ('1.0.0', '2.0.0'))}
        with self.assertRaises(ValueError):
            self.solve(data, ('a/root', 'a/provider=2.0.0'))

    def test_duplicate_api_owners_rejected(self):
        data = {'a': package('root', dependencies={'1.0.0': [pkg('one'), pkg('two')]}) +
                package('one', extra={'1.0.0': [{'type': 'olm.gvk', 'value': api()}]}) +
                package('two', extra={'1.0.0': [{'type': 'olm.gvk', 'value': api()}]})}
        with self.assertRaises(ValueError):
            self.solve(data)

    def test_explicit_target_baseline_api(self):
        data = {'a': package('root', dependencies={'1.0.0': [{'type': 'olm.gvk.required', 'value': api()}]})}
        self.assertEqual(len(self.solve(data, provided=[api()])), 1)

    def test_compound_any_all_not(self):
        constraint = {'all': {'constraints': [
            {'any': {'constraints': [{'package': {'packageName': 'missing'}}, {'package': {'packageName': 'provider'}}]}},
            {'not': {'constraints': [{'package': {'packageName': 'banned'}}]}}]}}
        data = {'a': package('root', dependencies={'1.0.0': [{'type': 'olm.constraint', 'value': constraint}]}) + package('provider') + package('banned')}
        self.assertEqual({p['package'] for p in self.solve(data)}, {'root', 'provider'})
        with self.assertRaises(ValueError):
            self.solve(data, ('a/root', 'a/banned'))

    def test_not_all_uses_de_morgan(self):
        constraint = {'not': {'constraints': [{'all': {'constraints': [
            {'package': {'packageName': 'one'}}, {'package': {'packageName': 'two'}}]}}]}}
        data = {'a': package('root', dependencies={'1.0.0': [{'type': 'olm.constraint', 'value': constraint}]}) + package('one') + package('two')}
        self.assertEqual(len(self.solve(data, ('a/root', 'a/one'))), 2)
        with self.assertRaises(ValueError):
            self.solve(data, ('a/root', 'a/one', 'a/two'))

    def test_cel_matches_properties_and_olm_semver_function(self):
        rule = 'properties.exists(p, p.type == "olm.package" && p.value.packageName == "provider" && semver_compare(p.value.version, "1.0.0") >= 0)'
        data = {'a': package('root', dependencies={'1.0.0': [{'type': 'olm.constraint', 'value': {'cel': {'rule': rule}}}]}) + package('provider')}
        self.assertEqual(len(self.solve(data)), 2)

    def test_invalid_cel_is_not_ignored(self):
        data = {'a': package('root', dependencies={'1.0.0': [{'type': 'olm.constraint', 'value': {'cel': {'rule': 'unknown == 1'}}}]})}
        with self.assertRaisesRegex(ValueError, '依赖表达式无效'):
            self.solve(data)

    def test_blang_range_prerelease_and_or(self):
        match = self.semantic.call(op='range', range='>=1.0.0 <2.0.0 || =3.0.0-beta.1', versions=['1.5.0', '2.0.0', '3.0.0-beta.1'])
        self.assertEqual(match, [True, False, True])

    def test_equal_build_metadata_cannot_be_precisely_filtered(self):
        data = {'a': package('root', ('1.0.0+one', '1.0.0+two'))}
        with self.assertRaisesRegex(ValueError, '语义版本相同'):
            self.solve(data, ('a/root=1.0.0+two',))

    def test_declared_old_maximum_is_rejected(self):
        data = {'a': package('root', extra={'1.0.0': [{'type': 'olm.maxOpenShiftVersion', 'value': '4.21'}]})}
        with self.assertRaises(ValueError):
            self.solve(data)

    def test_historical_numeric_maximum_does_not_block_other_packages(self):
        data = {'a': package('root') + package('old', extra={'1.0.0': [{'type': 'olm.maxOpenShiftVersion', 'value': 4.8}]})}
        self.assertEqual(len(self.solve(data)), 1)

    def test_search_limit_is_distinct_from_unsatisfiable(self):
        catalog = self.catalog({'a': package('root', dependencies={'1.0.0': [pkg('provider')]}) + package('provider')})
        with self.assertRaisesRegex(ValueError, '超过上限'):
            Resolver(catalog, max_states=1).solve([catalog.root('a/root')])

    def test_legacy_dependencies(self):
        data = package('root') + package('provider')
        next(d for d in data if d.get('name') == 'root.v1.0.0')['dependencies'] = [{'type': 'olm.package', 'value': {'packageName': 'provider', 'version': '>=1.0.0'}}]
        self.assertEqual(len(self.solve({'a': data})), 2)


class OperatorBundleTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.bundle = Path(self.temporary.name) / 'bundle with spaces'
        self.plan = {'schema': 'ocpinstall/operators/v1', 'targetVersion': operator_profile.release(), 'catalogs': [{'alias': 'redhat', 'source': 'test', 'pinned': 'registry.test/catalog@sha256:' + 'a'*64}],
                     'selected': [{'catalog': 'redhat', 'package': 'test', 'version': '1.0.0', 'channel': 'stable'}],
                     'roots': ['redhat/test'], 'providedAPIs': [], 'additionalImages': [], 'archiveSize': 20}
        self.plan['planHash'] = operators.fingerprint(self.plan)

    def test_operator_config_excludes_platform_and_pins_versions(self):
        config = operators.image_config(self.plan)
        self.assertNotIn('platform', config['mirror'])
        package_config = config['mirror']['operators'][0]['packages'][0]
        self.assertEqual(package_config['defaultChannel'], 'stable')
        self.assertEqual(package_config['channels'][0]['minVersion'], package_config['channels'][0]['maxVersion'])

    def test_catalog_tag_never_occurs_in_repository_name(self):
        for alias in ('redhat', 'snapshot', 'xsnapshot', 'xxsnapshot'):
            self.plan['catalogs'][0]['alias'] = alias
            self.plan['selected'][0]['catalog'] = alias
            catalog = operators.image_config(self.plan)['mirror']['operators'][0]
            self.assertNotIn(catalog['targetTag'], catalog['targetCatalog'])

    def test_plan_integrity_and_different_plan_rejected(self):
        operators.save_plan(self.bundle, self.plan)
        self.assertEqual(operators.load_plan(self.bundle), self.plan)
        self.plan['additionalImages'] = ['registry.test/extra:1']
        with self.assertRaises(ValueError):
            operators.save_plan(self.bundle, self.plan)
        (self.bundle / 'operators-plan.json').write_text(json.dumps(self.plan))
        with self.assertRaises(ValueError):
            operators.load_plan(self.bundle)

    def test_config_edit_cannot_bypass_dependency_selection(self):
        operators.save_plan(self.bundle, self.plan)
        (self.bundle / 'imagesetconfiguration.json').write_text('{}')
        with self.assertRaises(ValueError):
            operators.load_plan(self.bundle)

    def test_version_profiles_do_not_accept_each_others_bundles(self):
        self.plan['targetVersion'] = '4.22.22' if operator_profile.release().startswith('5.') else '5.0.1'
        self.plan['planHash'] = operators.fingerprint(self.plan)
        operators.save_plan(self.bundle, self.plan)
        with self.assertRaisesRegex(ValueError, '不同的 OpenShift 版本'):
            operators.load_plan(self.bundle)

    def test_metadata_symlink_rejected(self):
        path = Path(self.temporary.name) / 'link.json'
        path.symlink_to('/etc/passwd')
        with self.assertRaises(ValueError):
            list(read_documents(path))

    def resource_fixture(self, docs):
        layout = self.bundle / 'catalogs/redhat'
        digest, hashes = make_layout(layout)
        self.plan['selected'][0]['image'] = 'registry.test/test-bundle@' + digest
        self.plan['planHash'] = operators.fingerprint(self.plan)
        operators.save_plan(self.bundle, self.plan)
        folder = self.bundle / 'images/working-dir/cluster-resources'
        folder.mkdir(parents=True)
        (folder / 'resources.json').write_text(json.dumps({'kind': 'List', 'items': docs}))
        archive = self.bundle / 'images/mirror_000001.tar'
        catalog = operators.image_config(self.plan)['mirror']['operators'][0]
        filtered = self.bundle / 'images/working-dir/operator-catalogs/redhat' / digest.split(':')[1] / 'filtered-catalogs/filteredtag/digest'
        filtered.parent.mkdir(parents=True)
        filtered.write_text(digest.split(':')[1])
        with tarfile.open(archive, 'w') as tar:
            def add(name, data):
                item = tarfile.TarInfo(name)
                item.size = len(data)
                tar.addfile(item, io.BytesIO(data))
            for blob in (layout / 'blobs/sha256').iterdir():
                add('docker/registry/v2/blobs/sha256/' + blob.name[:2] + '/' + blob.name + '/data', blob.read_bytes())
            for repo, tag in [('test-bundle', digest.replace(':', '-')), (catalog['targetCatalog'], 'filteredtag')]:
                add(f'docker/registry/v2/repositories/{repo}/_manifests/tags/{tag}/current/link', digest.encode())
        record = self.bundle / 'mirror-tool.json'
        record.write_text('{}')
        files = [self.bundle / 'operators-plan.json', self.bundle / 'imagesetconfiguration.json', record, archive]
        catalog_record = {'schema': 'ocpinstall/operator-catalogs/v1', 'planHash': self.plan['planHash'],
                          'catalogs': [{'alias': 'redhat', 'pinned': self.plan['catalogs'][0]['pinned'], 'ociDigest': digest, 'files': hashes}]}
        offline.save_json(self.bundle / 'operator-catalogs.json', catalog_record)
        offline.save_json(self.bundle / 'imagesetconfiguration-oci.json', operator_oci.config_for_oci(operators.image_config(self.plan), catalog_record))
        files += [self.bundle / 'operator-catalogs.json', self.bundle / 'imagesetconfiguration-oci.json']
        files += [layout / name for name in hashes]
        files += operator_archive.build_record(self.bundle, [archive], self.plan)
        offline.save_json(self.bundle / 'checksums.json', {str(p.relative_to(self.bundle)): offline.digest(p) for p in files})
        return self.bundle / 'operator-resources.json'

    def test_resource_names_are_independent_without_spec_changes(self):
        docs = [{'apiVersion': 'config.openshift.io/v1', 'kind': 'ImageDigestMirrorSet',
                 'metadata': {'name': 'idms-operator-0'},
                 'spec': {'imageDigestMirrors': [{'source': 'registry.test/source', 'mirrors': ['helper.test/local']}] }},
                {'apiVersion': 'operators.coreos.com/v1alpha1', 'kind': 'CatalogSource',
                 'metadata': {'name': 'cs-test', 'namespace': 'openshift-marketplace'},
                 'spec': {'image': 'helper.test/catalog:tag', 'sourceType': 'grpc'}}]
        output = self.resource_fixture(docs)
        operator_resources.prepare(self.bundle, output)
        result = json.loads(output.read_text())['items']
        for source in docs:
            generated = next(d for d in result if d['kind'] == source['kind'])
            self.assertEqual(source['spec'], generated['spec'])
            self.assertNotEqual(source['metadata']['name'], generated['metadata']['name'])
        operator_resources.prepare(self.bundle, output)
        self.assertEqual(json.loads(output.read_text())['items'], result)

    def test_operator_resources_reject_unexpected_cluster_changes(self):
        docs = [{'apiVersion': 'v1', 'kind': 'Secret', 'metadata': {'name': 'unexpected'}}]
        output = self.resource_fixture(docs)
        with self.assertRaisesRegex(ValueError, '意外资源类型'):
            operator_resources.prepare(self.bundle, output)

    def test_oci_layout_digest_tampering_rejected(self):
        layout = Path(self.temporary.name) / 'oci'
        make_layout(layout)
        next((layout / 'blobs/sha256').iterdir()).write_bytes(b'tampered')
        with self.assertRaisesRegex(ValueError, 'SHA256'):
            operator_oci.layout_files(layout)

    def test_oci_layout_never_copies_auth_or_unrelated_files(self):
        layout = Path(self.temporary.name) / 'oci'
        make_layout(layout)
        (layout / 'auth.json').write_text('{"auths":{}}')
        with self.assertRaisesRegex(ValueError, '非镜像文件'):
            operator_oci.layout_files(layout)

    def test_oci_is_portable_and_not_bound_to_download_path(self):
        layout = Path(self.temporary.name) / 'oci'
        make_layout(layout)
        auth = Path(self.temporary.name) / 'auth.json'
        auth.write_text('{"auths":{"registry.test":{"auth":"test"}}}')
        args = SimpleNamespace(catalog_oci=['redhat=' + str(layout)], authfile=str(auth))
        operators.save_plan(self.bundle, self.plan)
        config, files = operator_oci.stage_catalogs(args, self.bundle, Path(self.temporary.name) / 'cache', self.plan)
        reference = json.loads(config.read_text())['mirror']['operators'][0]['catalog']
        self.assertTrue(reference.startswith('oci://catalogs/redhat@sha256:'))
        self.assertNotIn(str(self.bundle), reference)
        self.assertIn(self.bundle / 'operator-catalogs.json', files)
        moved = Path(self.temporary.name) / 'new offline path'
        shutil.copytree(self.bundle, moved)
        operator_oci.verify_catalogs(moved, self.plan)

    def test_missing_catalog_manifest_entry_rejected(self):
        output = self.resource_fixture([{'kind': 'CatalogSource', 'metadata': {'name': 'test'}, 'spec': {'image': 'test'}}])
        manifest = json.loads((self.bundle / 'checksums.json').read_text())
        del manifest['operator-catalogs.json']
        offline.save_json(self.bundle / 'checksums.json', manifest)
        with self.assertRaisesRegex(ValueError, '未全部列入'):
            operator_resources.prepare(self.bundle, output)

    def altered_archive(self, omit):
        source = self.bundle / 'images/mirror_000001.tar'
        output = self.bundle / 'altered.tar'
        with tarfile.open(source) as original, tarfile.open(output, 'w') as changed:
            for member in original:
                if not omit(member.name):
                    changed.addfile(member, original.extractfile(member))
        return output

    def test_missing_filtered_catalog_prevents_success_record(self):
        self.resource_fixture([])
        catalog = operators.image_config(self.plan)['mirror']['operators'][0]['targetCatalog']
        archive = self.altered_archive(lambda name: '/repositories/' + catalog + '/' in name)
        with self.assertRaisesRegex(ValueError, '过滤 catalog'):
            operator_archive.build_record(self.bundle, [archive], self.plan)

    def test_missing_image_layer_prevents_delivery(self):
        self.resource_fixture([])
        root_digest = self.plan['selected'][0]['image'].split('@')[1]
        manifest = json.loads((self.bundle / 'catalogs/redhat/blobs/sha256' / root_digest.split(':')[1]).read_text())
        layer = manifest['layers'][0]['digest'].split(':')[1]
        archive = self.altered_archive(lambda name: '/' + layer + '/data' in name)
        with self.assertRaisesRegex(ValueError, 'layer/config'):
            operator_archive.build_record(self.bundle, [archive], self.plan)

    def test_archive_record_must_cover_every_bundle(self):
        self.resource_fixture([])
        path = self.bundle / 'operator-archive.json'
        record = json.loads(path.read_text())
        record['records'] = [r for r in record['records'] if r['kind'] != 'image']
        offline.save_json(path, record)
        with self.assertRaisesRegex(ValueError, '覆盖全部 bundle'):
            operator_archive.verify_record(self.bundle, self.plan)


if __name__ == '__main__':
    unittest.main()
