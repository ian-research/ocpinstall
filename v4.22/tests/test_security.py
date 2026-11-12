from pathlib import Path
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[1]


def install_function(name):
    text = (ROOT / 'install-cluster.sh').read_text()
    start = text.index(name + '() {')
    return text[start:text.index('\n}', start) + 2]


class SecurityTests(unittest.TestCase):
    def test_skip_firewalld_is_explicit_and_validated(self):
        program = 'source "$1"; parse_security_options "${@:2}"; echo "$SKIP_FIREWALLD $RELAXED_SECURITY"'
        for args, expected in (([], 'false false'), (['--skip-firewalld'], 'true false')):
            result = subprocess.run(['bash', '-c', program, 'test', str(ROOT / 'lib/common.sh'), *args],
                                    capture_output=True, text=True, check=True)
            self.assertEqual(result.stdout.strip(), expected)
        result = subprocess.run(['bash', '-c', 'source "$1"; SKIP_FIREWALLD=invalid; parse_security_options',
                                 'test', str(ROOT / 'lib/common.sh')], capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)

    def test_skip_firewalld_preserves_selinux_configuration(self):
        program = r'''
set -euo pipefail
RELAXED_SECURITY=false
SKIP_FIREWALLD=true
getenforce() { echo Enforcing; }
semanage() { echo 'http_port_t tcp 9088'; }
setsebool() { echo "SELINUX $*"; }
systemctl() { echo 'unexpected firewalld operation' >&2; exit 99; }
firewall-cmd() { echo 'unexpected firewall rules' >&2; exit 99; }
'''
        result = subprocess.run(['bash', '-c', program + install_function('configure_host_security')
                                 + '\nconfigure_host_security\n'], capture_output=True, text=True, check=True)
        self.assertIn('SELINUX -P haproxy_connect_any 1', result.stdout)
        self.assertIn('SELINUX -P nfs_export_all_rw 1', result.stdout)

    def test_default_still_enables_firewalld(self):
        program = ('set -euo pipefail\nRELAXED_SECURITY=false\nSKIP_FIREWALLD=false\n'
                   'getenforce() { echo Disabled; }\n'
                   'systemctl() { echo "SYSTEMCTL $*"; }\n'
                   'firewall-cmd() { echo "FIREWALL $*"; }\n')
        result = subprocess.run(['bash', '-c', program + install_function('configure_host_security')
                                 + '\nconfigure_host_security\n'], capture_output=True, text=True, check=True)
        self.assertIn('SYSTEMCTL enable --now firewalld', result.stdout)
        self.assertIn('FIREWALL --permanent --add-port=6443/tcp', result.stdout)
        self.assertIn('FIREWALL --reload', result.stdout)

    def test_dependency_install_omits_firewalld_only_when_requested(self):
        for skip in ('true', 'false'):
            program = ('set -euo pipefail\nlog() { :; }\n'
                       f'SKIP_FIREWALLD={skip}\n'
                       'dnf_install() { printf "%s\\n" "$@"; exit 0; }\n')
            result = subprocess.run(['bash', '-c', program + install_function('install_dependencies')
                                     + '\ninstall_dependencies\n'], capture_output=True, text=True, check=True)
            self.assertEqual('firewalld' in result.stdout.splitlines(), skip == 'false')
            self.assertIn('policycoreutils-python-utils', result.stdout.splitlines())

    def test_scc_only_in_selected_namespace(self):
        text = (ROOT / 'setup-cluster.sh').read_text()
        start = text.index('configure_relaxed_scc() {')
        function = text[start:text.index('\n}', start) + 2]
        for enabled in ('true', 'false'):
            program = ('set -euo pipefail\noc() { echo "$*"; }\n'
                       f'RELAXED_SECURITY={enabled}\nSECURITY_NAMESPACE=lab5\n'
                       + function + '\nconfigure_relaxed_scc\n')
            output = subprocess.run(['bash', '-c', program], capture_output=True, text=True, check=True).stdout
            if enabled == 'false':
                self.assertEqual(output, '')
            else:
                for scc in ('anyuid', 'hostmount-anyuid', 'privileged'):
                    self.assertIn(f'add-scc-to-user {scc} -z default -n lab5', output)
