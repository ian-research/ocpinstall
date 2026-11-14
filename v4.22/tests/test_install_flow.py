from pathlib import Path
import os
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


def function(name):
    text = (ROOT / 'install-cluster.sh').read_text()
    start = text.index(name + '() {')
    return text[start:text.index('\n}', start) + 2]


class InstallFlowTests(unittest.TestCase):
    def test_setup_bounds_api_requests_without_shortening_rollout_watch(self):
        text = (ROOT / 'setup-cluster.sh').read_text()
        start = text.index('oc() {')
        wrapper = text[start:text.index('\n}', start) + 2]
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / 'oc'
            binary.write_text('#!/bin/sh\nprintf "%s\\n" "$@"\nexit "${FIXTURE_OC_EXIT:-0}"\n')
            binary.chmod(0o700)
            env = dict(os.environ, PATH=directory + os.pathsep + os.environ['PATH'])
            for arguments, expected in [('get nodes', '30s'), ('rollout status deployment/example --timeout=180s', '0')]:
                result = subprocess.run(['bash', '-c', wrapper + '\noc ' + arguments],
                                        env=env, check=True, capture_output=True, text=True)
                self.assertEqual(result.stdout.splitlines()[0], '--request-timeout=' + expected)
                if expected == '0':
                    self.assertIn('--timeout=180s', result.stdout)
            failed = subprocess.run(['bash', '-c', wrapper + '\noc get nodes'],
                                    env=dict(env, FIXTURE_OC_EXIT='1'), capture_output=True, text=True)
            self.assertEqual(failed.returncode, 1)

    def test_invalid_second_operator_bundle_cannot_change_cluster_policy(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            mirror = root / 'mirror/working-dir/cluster-resources'
            mirror.mkdir(parents=True)
            marker = root / 'mutated'
            code = (ROOT / 'setup-cluster.sh').read_text()
            start = code.index('configure_operators() {')
            code = code[start:code.index('\n}', start)+2]
            script = ('set -euo pipefail\ndie() { exit 1; }\n'
                      'python3() { [[ $1 != */operator_resources.py ]]; }\n'
                      'oc() { touch "$MARKER"; }\n' + code + '\nconfigure_operators\n')
            env = dict(os.environ, MIRROR_DIR=str(root / 'mirror'), BUNDLE_DIR=str(root / 'platform'),
                       OPERATOR_BUNDLE_DIR=str(root / 'broken-operators'), SCRIPT_DIR=str(ROOT), MARKER=str(marker))
            result = subprocess.run(['bash', '-c', script], env=env, text=True, capture_output=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(marker.exists())

    def test_harbor_retry_preserves_existing_password_configuration(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory)
            harbor = state / 'harbor/harbor'
            harbor.mkdir(parents=True)
            config = harbor / 'harbor.yml'
            config.write_text('harbor_admin_password: fixture-original\n')
            installer = harbor / 'install.sh'
            installer.write_text('#!/bin/sh\ntouch "$TEST_STAMP"\n')
            installer.chmod(0o700)
            script = ('set -euo pipefail\nlog() { :; }\n'
                      'die() { echo "$*" >&2; exit 1; }\nsudo() { "$@"; }\n'
                      'tar() { echo "unexpected overwrite" >&2; exit 1; }\n'
                      + function('install_harbor') + '\ninstall_harbor\n')
            env = dict(os.environ, STATE_ROOT=str(state), CERT_DIR=str(state / 'cert'),
                       OCP_DOMAIN='lab.test', HARBOR_PASSWORD='fixture-new-value', TEST_STAMP=str(state / 'installed'))
            rejected = subprocess.run(['bash', '-c', script], env=env, text=True, capture_output=True)
            self.assertNotEqual(rejected.returncode, 0)
            self.assertFalse((state / 'installed').exists())
            (state / 'helper-plan.json').write_text('{}')
            subprocess.run(['bash', '-c', script], env=env, check=True)
            self.assertTrue((state / 'installed').exists())
            self.assertEqual(config.read_text(), 'harbor_admin_password: fixture-original\n')

    def test_platform_import_cache_stays_outside_delivery(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            config = base / 'bundle/platform/imagesetconfiguration.json'
            config.parent.mkdir(parents=True)
            config.write_text('{}')
            output = base / 'command.txt'
            script = ('set -euo pipefail\nlog() { :; }\n'
                      'bash() { printf "%s\\n" "$@" > "$OUTPUT"; }\n'
                      + function('upload_ocp_image') + '\nupload_ocp_image\n')
            env = dict(os.environ, SCRIPT_DIR=str(ROOT), IMAGESET_CONFIG=str(config),
                       BUNDLE_DIR=str(config.parent), STATE_ROOT=str(base / 'private-state'),
                       OUTPUT=str(output), LOCAL_REGISTRY='mirror.example.com',
                       LOCAL_REPOSITORY='openshift', OCP_RELEASE='test')
            subprocess.run(['bash', '-c', script], env=env, check=True)
            command = output.read_text().splitlines()
            self.assertEqual(command[command.index('--cache-dir') + 1], str(base / 'private-state/platform-import-cache'))

    def test_unsynchronized_upstream_stops_installation(self):
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / 'chrony.conf'
            script = ('set -euo pipefail\nlog() { :; }\nbackup_file() { :; }\n'
                      'systemctl() { :; }\npython3() { echo "server 192.168.1.1 iburst"; }\n'
                      'chronyc() { [[ $1 != waitsync ]]; }\n'
                      'die() { echo "$*" >&2; exit 1; }\n'
                      'SCRIPT_DIR=/unused\nNTP_SERVER=192.168.1.1\nNTP_MODE=upstream\n'
                      'NFS_CIDR=192.168.1.0/24\nHELPER_IP_ADDRESS=192.168.1.10\n'
                      + function('configure_chrony').replace('/etc/chrony.conf', str(config))
                      + '\nconfigure_chrony\necho UNEXPECTED_SUCCESS\n')
            result = subprocess.run(['bash', '-c', script], text=True, capture_output=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('上游 NTP 未同步', result.stderr)
            self.assertNotIn('UNEXPECTED_SUCCESS', result.stdout)

    def test_existing_repos_skip_iso_and_repo_mutations(self):
        script = ('set -euo pipefail\nYUM_REPO_MODE=existing\n'
                  'log() { :; }\n'
                  'dnf() { [[ $* == "-q makecache" ]]; }\n'
                  'mount() { echo "unexpected ISO mount" >&2; exit 1; }\n'
                  'mkdir() { echo "unexpected repo mutation" >&2; exit 1; }\n'
                  + function('configure_local_yum') + '\nconfigure_local_yum\n')
        subprocess.run(['bash', '-c', script], check=True)

    def test_ntp_manifest_present_when_ignition_is_created(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory)
            (state / 'install-config.yaml').write_text('{}')
            script = r'''
set -euo pipefail
STATE_ROOT=$1
SCRIPT_DIR=$2
INSTALL_DIR=$STATE_ROOT/install
HTTP_ROOT=$STATE_ROOT/http
HELPER_HOSTNAME=helper.lab.example.com
export OCP_DOMAIN=lab.example.com
log() { :; }
restorecon() { :; }
die() { echo "$*" >&2; exit 1; }
openshift-install() {
    if [[ $2 == manifests ]]; then
        mkdir -p "$INSTALL_DIR/manifests" "$INSTALL_DIR/openshift"
        cat > "$INSTALL_DIR/manifests/cluster-scheduler-02-config.yml" <<'EOF'
kind: Scheduler
spec:
  mastersSchedulable: false
EOF
    elif [[ $2 == ignition-configs ]]; then
        [[ -f "$INSTALL_DIR/openshift/99-master-chrony.yaml" ]]
        grep -q '"mastersSchedulable": true' "$INSTALL_DIR/manifests/cluster-scheduler-02-config.yml"
        for node in bootstrap master worker; do
            echo '{"ignition":{"version":"3.5.0"}}' > "$INSTALL_DIR/$node.ign"
        done
        mkdir -p "$INSTALL_DIR/auth"
        echo private > "$INSTALL_DIR/auth/kubeconfig"
        echo password > "$INSTALL_DIR/auth/kubeadmin-password"
    else
        exit 1
    fi
}
'''
            script += '\n' + function('create_manifest_config') + '\ncreate_manifest_config\n'
            subprocess.run(['bash', '-c', script, 'test', str(state), str(ROOT)], check=True)
            self.assertTrue((state / 'node-install-commands.txt').exists())
            self.assertFalse((state / 'http/auth').exists())
            self.assertIn('/etc/chrony.conf', (state / 'http/ignition/bootstrap.ign').read_text())
            self.assertEqual((state / 'install/auth/kubeconfig').stat().st_mode & 0o777, 0o600)

    def test_readyz_probe_and_three_node_ingress(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'haproxy.cfg'
            code = function('configure_haproxy').replace('/etc/haproxy/haproxy.cfg', str(output))
            script = ('set -euo pipefail\nlog() { :; }\nbackup_file() { :; }\n'
                      'getenforce() { echo Disabled; }\nhaproxy() { :; }\nsystemctl() { :; }\n'
                      'BOOTSTRAP_IP=192.168.1.20\nMASTER_IPS=(192.168.1.21 192.168.1.22 192.168.1.23)\n'
                      + code + '\nconfigure_haproxy\n')
            subprocess.run(['bash', '-c', script], check=True)
            text = output.read_text()
            self.assertIn('httpchk GET /readyz', text)
            self.assertIn('inter 5s fall 3 rise 2', text)
            for ip in ('192.168.1.21', '192.168.1.22', '192.168.1.23'):
                self.assertIn(ip + ':443', text)
                self.assertIn(ip + ':80', text)


if __name__ == '__main__':
    unittest.main()
