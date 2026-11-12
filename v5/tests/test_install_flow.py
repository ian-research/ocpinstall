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
