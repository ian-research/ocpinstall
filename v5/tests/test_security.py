from pathlib import Path
import os
import subprocess
import unittest
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def install_function(name):
    text = (ROOT / 'install-cluster.sh').read_text()
    start = text.index(name + '() {')
    return text[start:text.index('\n}', start) + 2]


class SecurityTests(unittest.TestCase):
    def test_harbor_credentials_use_stdin_and_existing_project_is_reusable(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            program = ('set -euo pipefail\nlog() { :; }\n'
                       'die() { echo "$*" >&2; exit 1; }\n'
                       'curl() { printf "%s\\n" "$@" > "$ARGUMENTS"; cat > "$INPUT"; printf "%s" "$HTTP_STATUS"; }\n'
                       + install_function('create_harbor_project') + '\ncreate_harbor_project\n')
            env = dict(os.environ, CERT_DIR=str(root), LOCAL_REGISTRY='mirror.lab.test:8443',
                       LOCAL_REPOSITORY='openshift', HARBOR_PASSWORD='fixture-password',
                       ARGUMENTS=str(root/'arguments'), INPUT=str(root/'input'))
            for status in ('201', '409', '401'):
                result = subprocess.run(['bash', '-c', program], env=dict(env, HTTP_STATUS=status),
                                        text=True, capture_output=True)
                self.assertEqual(result.returncode == 0, status != '401')
            arguments = (root/'arguments').read_text()
            self.assertNotIn('fixture-password', arguments)
            self.assertIn('user = "admin:fixture-password"', (root/'input').read_text())
            self.assertIn('--max-time', arguments)

    def test_harbor_transport_failure_cannot_be_reported_as_success(self):
        program = ('set -euo pipefail\nlog() { :; }\ndie() { exit 1; }\n'
                   'curl() { cat >/dev/null; return 28; }\n'
                   + install_function('create_harbor_project') + '\ncreate_harbor_project\necho FALSE_SUCCESS\n')
        env = dict(os.environ, CERT_DIR='/unused', LOCAL_REGISTRY='mirror.lab.test:8443',
                   LOCAL_REPOSITORY='openshift', HARBOR_PASSWORD='fixture-password')
        result = subprocess.run(['bash', '-c', program], env=env, text=True, capture_output=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn('FALSE_SUCCESS', result.stdout)

    def test_existing_admin_or_identity_assets_block_before_account_changes(self):
        text = (ROOT/'setup-cluster.sh').read_text()
        start = text.index('validate_admin_creation() {')
        check = text[start:text.index('\n}', start)+2]
        for scenario in ('user', 'secret', 'provider', 'api-failure', 'new'):
            with self.subTest(scenario=scenario), tempfile.TemporaryDirectory() as temporary:
                marker = Path(temporary)/'changed'
                program = r'''
set -euo pipefail
die() { echo "$*" >&2; exit 1; }
CREATE_ADMIN=true
oc() {
    [[ $1 == get ]] || { touch "$MARKER"; return 99; }
    case "$2" in
        user) [[ $SCENARIO != api-failure ]] || return 1
              if [[ $SCENARIO == user ]]; then echo user/admin; fi ;;
        secret) if [[ $SCENARIO == secret ]]; then echo secret/existing; fi ;;
        oauth) echo '{}' ;;
        *) return 99 ;;
    esac
}
jq() { cat >/dev/null; if [[ $SCENARIO == provider ]]; then echo 1; else echo 0; fi; }
'''
                result = subprocess.run(['bash', '-c', program+check+'\nvalidate_admin_creation\n'],
                                        env=dict(os.environ, SCENARIO=scenario, MARKER=str(marker)),
                                        text=True, capture_output=True)
                self.assertEqual(result.returncode == 0, scenario == 'new')
                self.assertFalse(marker.exists())

    def test_account_secret_creation_conflict_cannot_overwrite_or_grant_access(self):
        text = (ROOT/'setup-cluster.sh').read_text()
        start = text.index('create_users() {')
        function = text[start:text.index('\n}', start)+2]
        with tempfile.TemporaryDirectory() as temporary:
            marker = Path(temporary)/'changed'
            program = r'''
set -euo pipefail
CREATE_ADMIN=true
validate_admin_creation() { :; }
die() { exit 1; }
mktemp() { echo "$TEST_TEMP/hashed-password"; }
htpasswd() { cat >/dev/null; }
oc() {
    if [[ $1 == create && $2 == secret ]]; then return 1; fi
    touch "$MARKER"
    return 0
}
'''
            result = subprocess.run(['bash', '-c', program+function+'\ncreate_users\n'],
                                    input='fixture-long-password\n', text=True, capture_output=True,
                                    env=dict(os.environ, TEST_TEMP=temporary, MARKER=str(marker)))
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(marker.exists())

    def test_other_version_state_blocks_before_host_changes(self):
        with tempfile.TemporaryDirectory() as temporary:
            own, foreign = Path(temporary) / 'own', Path(temporary) / 'other-version'
            foreign.mkdir()
            program = 'source "$1"; shift; guard_helper_state "$@"; echo WOULD_CHANGE_HOST'
            result = subprocess.run(['bash', '-c', program, 'test', str(ROOT / 'lib/common.sh'), str(own), str(foreign)],
                                    text=True, capture_output=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertNotIn('WOULD_CHANGE_HOST', result.stdout)

    def test_current_version_state_reaches_its_existing_install_guard(self):
        with tempfile.TemporaryDirectory() as temporary:
            own = Path(temporary) / 'own'
            own.mkdir()
            program = 'source "$1"; shift; guard_helper_state "$@"'
            result = subprocess.run(['bash', '-c', program, 'test', str(ROOT / 'lib/common.sh'), str(own), str(own)],
                                    text=True, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr)

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
