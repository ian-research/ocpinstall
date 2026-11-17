import hashlib
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'lib'))
import guest_images
import operators


def options(**values):
    return SimpleNamespace(**dict({'guest_image': [], 'guest_image_ref': [],
                                   'odf_local_storage': None}, **values))


def encoded(value):
    return json.dumps(value).encode()


class GuestImageTests(unittest.TestCase):
    def test_virtualization_keeps_only_rhel9_as_the_default(self):
        self.assertEqual(guest_images.inputs(options(), True),
                         [{'name': 'rhel9', 'source': guest_images.PRESETS['rhel9']}])
        self.assertEqual(guest_images.inputs(options()), [])

    def test_explicit_systems_do_not_add_unrequested_defaults(self):
        result = guest_images.inputs(options(guest_image=['fedora', 'centos-stream10']), True)
        self.assertEqual({item['name'] for item in result}, {'fedora', 'centos-stream10'})
        self.assertEqual(guest_images.inputs(options(guest_image=['none']), True), [])

    def test_custom_reference_can_override_a_preset_version(self):
        result = guest_images.inputs(options(guest_image=['fedora'],
            guest_image_ref=['fedora=quay.io/containerdisks/fedora:44']), True)
        self.assertEqual(result, [{'name': 'fedora', 'source': 'quay.io/containerdisks/fedora:44'}])

    def test_none_unknown_and_duplicate_choices_fail_before_network_io(self):
        for args in [options(guest_image=['none', 'fedora']), options(guest_image=['unknown']),
                     options(guest_image=['none'], guest_image_ref=['custom=example.test/os:1']),
                     options(guest_image_ref=['disk=example.test/os:1', 'disk=example.test/os:2'])]:
            with self.subTest(args=args), self.assertRaises(ValueError):
                guest_images.inputs(args, True)

    def test_raw_files_and_urls_are_not_container_disk_references(self):
        for source in ['/tmp/rhel.iso', 'https://example.test/os.qcow2', 'example.test/../os:1',
                       'example.test/os', 'example.test/os@sha256:wrong', 'example.test/..:9']:
            with self.subTest(source=source), self.assertRaises(ValueError):
                guest_images.repository(source)
        self.assertEqual(guest_images.repository('registry.test:8443/ns/os:9'), 'registry.test:8443/ns/os')

    def test_interactive_multiple_systems_accept_custom_tags(self):
        with patch('builtins.print'):
            answers = iter(['3,4', '44', '9'])
            result = guest_images.inputs(options(), True, True, lambda label, default=None: next(answers))
        self.assertEqual(result, [{'name': 'centos-stream9', 'source': 'quay.io/containerdisks/centos-stream:9'},
                                  {'name': 'fedora', 'source': 'quay.io/containerdisks/fedora:44'}])

    def transport(self, architecture='amd64', tampered=False):
        leaf = encoded({'schemaVersion': 2, 'config': {'digest': 'sha256:' + 'a' * 64},
                        'layers': [{'size': 123, 'digest': 'sha256:' + 'b' * 64}]})
        digest = 'sha256:' + hashlib.sha256(leaf).hexdigest()
        source = 'registry.test/guests/os:latest'
        index = encoded({'schemaVersion': 2, 'manifests': [
            {'digest': 'sha256:' + 'c' * 64, 'platform': {'os': 'linux', 'architecture': 'arm64'}},
            {'digest': digest, 'platform': {'os': 'linux', 'architecture': 'amd64'}}]})
        def fetch(reference, auth, config=False):
            if config:
                self.assertEqual(reference, 'registry.test/guests/os@' + digest)
                return encoded({'os': 'linux', 'architecture': architecture})
            if reference == source:
                return index
            self.assertEqual(reference, 'registry.test/guests/os@' + digest)
            return leaf + b' ' if tampered else leaf
        return source, digest, fetch

    def test_multiarch_image_is_pinned_to_the_actual_amd64_leaf(self):
        source, digest, fetch = self.transport()
        with patch.object(guest_images, 'fetch', side_effect=fetch):
            result = guest_images.pin([{'name': 'example', 'source': source}], '/private/auth.json')
        self.assertEqual(result[0]['image'], 'registry.test/guests/os@' + digest)
        self.assertEqual(result[0]['compressedBytes'], 123)

    def test_wrong_architecture_or_modified_manifest_is_rejected(self):
        for parameters in [{'architecture': 'arm64'}, {'tampered': True}]:
            source, _, fetch = self.transport(**parameters)
            with self.subTest(parameters=parameters), patch.object(guest_images, 'fetch', side_effect=fetch):
                with self.assertRaises(ValueError):
                    guest_images.pin([{'name': 'example', 'source': source}], '/private/auth.json')

    def test_missing_amd64_manifest_does_not_silently_use_another_architecture(self):
        raw = encoded({'manifests': [{'digest': 'sha256:' + 'a' * 64,
                                     'platform': {'os': 'linux', 'architecture': 'arm64'}}]})
        with patch.object(guest_images, 'fetch', return_value=raw), self.assertRaisesRegex(ValueError, 'amd64'):
            guest_images.pin([{'name': 'example', 'source': 'registry.test/os:latest'}], '/private/auth.json')

    def test_registry_failure_never_saves_an_empty_successful_guest_list(self):
        with patch.object(guest_images, 'fetch', side_effect=OSError('registry unavailable')):
            with self.assertRaises(OSError):
                guest_images.pin([{'name': 'rhel9', 'source': guest_images.PRESETS['rhel9']}], '/private/auth.json')

    def test_changed_selection_requires_a_new_bundle_but_old_defaults_can_resume(self):
        plan = {'roots': ['redhat/kubevirt-hyperconverged']}
        guest_images.validate_saved_options(options(), plan)
        guest_images.validate_saved_options(options(ai_nvidia=False), plan)
        with self.assertRaisesRegex(ValueError, '新离线包'):
            guest_images.validate_saved_options(options(guest_image=['fedora']), plan)
        plan['guestImageInputs'] = guest_images.inputs(options(guest_image=['fedora']))
        guest_images.validate_saved_options(options(guest_image=['fedora']), plan)

    def test_local_import_mapping_uses_the_most_specific_namespace_prefix(self):
        digest = 'sha256:' + 'a' * 64
        plan = {'planHash': 'fixture', 'guestImages': [
            {'name': 'rhel9', 'image': 'registry.test/rhel9/guest@' + digest}]}
        with tempfile.TemporaryDirectory(prefix='guest sources ') as directory:
            folder = Path(directory)
            (folder / 'idms.json').write_text(json.dumps({'kind': 'ImageDigestMirrorSet', 'spec': {
                'imageDigestMirrors': [
                    {'source': 'registry.test', 'mirrors': ['wrong.test/destination']},
                    {'source': 'registry.test/rhel9', 'mirrors': ['harbor.test:8443/offline/rhel9']}]}}))
            actual = guest_images.local_sources(plan, folder, 'harbor.test:8443/offline')
        self.assertEqual(actual['images'][0]['localImages'], ['harbor.test:8443/offline/rhel9/guest@' + digest])
        self.assertFalse(actual['clusterResourcesApplied'])

    def test_reimport_uses_current_project_without_reporting_old_destination(self):
        digest = 'sha256:' + 'b' * 64
        plan = {'planHash': 'fixture', 'guestImages': [
            {'name': 'fedora', 'image': 'quay.io/containerdisks/fedora@' + digest}]}
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)
            (folder / 'rules.json').write_text(json.dumps({'kind': 'List', 'items': [
                {'kind': 'ImageDigestMirrorSet', 'spec': {'imageDigestMirrors': [
                    {'source': 'quay.io/containerdisks/fedora', 'mirrors': ['old.test/prior/fedora']},
                    {'source': 'quay.io/containerdisks', 'mirrors': ['new.test/current/containerdisks']}]}}]}))
            actual = guest_images.local_sources(plan, folder, 'new.test/current')
        self.assertEqual(actual['images'][0]['localImages'], ['new.test/current/containerdisks/fedora@' + digest])

    def test_missing_or_outside_destination_mappings_fail(self):
        plan = {'planHash': 'fixture', 'guestImages': [
            {'name': 'fedora', 'image': 'quay.io/containerdisks/fedora@sha256:' + 'a' * 64}]}
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)
            with self.assertRaisesRegex(ValueError, '未找到'):
                guest_images.local_sources(plan, folder, 'harbor.test/offline')
            (folder / 'itms.json').write_text(json.dumps({'kind': 'ImageTagMirrorSet', 'spec': {
                'imageTagMirrors': [{'source': 'quay.io/containerdisks',
                                     'mirrors': ['harbor.test/offline-other']} ]}}))
            with self.assertRaisesRegex(ValueError, '超出'):
                guest_images.local_sources(plan, folder, 'harbor.test/offline')

    def test_import_preview_keeps_previous_report_and_failed_real_import_removes_it(self):
        with tempfile.TemporaryDirectory() as directory:
            bundle = Path(directory) / 'bundle'
            bundle.mkdir()
            (bundle / 'checksums.json').write_text('{"operators-plan.json":"fixture"}')
            report = bundle / 'guest-images-local.json'
            report.write_text('previous successful destination')
            plan = {'guestImages': [{'name': 'rhel9'}], 'planHash': 'fixture'}
            command = ['operators.py', 'import', '--non-interactive', '--bundle', str(bundle),
                       '--registry', 'harbor.test/project', '--authfile', '/private/auth.json']
            with patch.object(operators.sys, 'platform', 'linux'), \
                 patch.object(operators.offline, 'verify'), patch.object(operators, 'load_plan', return_value=plan), \
                 patch.object(operators, 'verify_catalogs', return_value=({}, None)), \
                 patch.object(operators.operator_archive, 'verify_record'), patch.object(operators, 'show_plan'), \
                 patch.object(operators.offline, 'mirror') as mirror, \
                 patch.object(guest_images, 'local_sources') as sources:
                with patch.object(operators.sys, 'argv', command + ['--dry-run']):
                    operators.main()
                sources.assert_not_called()
                self.assertEqual(report.read_text(), 'previous successful destination')
                mirror.side_effect = ValueError('destination unavailable')
                with patch.object(operators.sys, 'argv', command):
                    with self.assertRaisesRegex(ValueError, 'destination unavailable'):
                        operators.main()
                self.assertFalse(report.exists())
                sources.assert_not_called()


if __name__ == '__main__':
    unittest.main()
