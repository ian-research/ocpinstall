#!/usr/bin/env bash
# Shared validation. Sourcing this file does not change the host.
die() { printf '错误: %s\n' "$*" >&2; exit 1; }

validate_ip() {
    local ip=${1:-} octet
    local -a octets
    [[ $ip =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || return 1
    IFS=. read -r -a octets <<< "$ip"
    for octet in "${octets[@]}"; do
        ((10#$octet <= 255)) || return 1
    done
}

validate_domain() {
    local label
    local -a labels
    [[ ${#1} -le 253 && $1 == *.* && $1 != *. ]] || return 1
    IFS=. read -r -a labels <<< "$1"
    for label in "${labels[@]}"; do
        [[ ${#label} -le 63 && $label =~ ^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?$ ]] || return 1
    done
}

require_host() {
    [[ ${BASH_VERSINFO[0]} -ge 4 ]] || die '需要 Bash 4 或更新版本'
    [[ $(id -u) == 0 ]] || die '请使用 root 运行'
    [[ -r /etc/os-release ]] || die '需要 RHEL 9'
    local ID VERSION_ID
    source /etc/os-release
    [[ $ID == rhel && ( $VERSION_ID == 9 || $VERSION_ID == 9.* ) ]] || die '当前仅支持 RHEL 9'
}

backup_file() {
    [[ ! -f $1 || -f $1.ocp422.bak ]] || cp -p -- "$1" "$1.ocp422.bak"
}

guard_helper_state() {
    local current=${1%/} known
    shift
    for known in "$@"; do
        if [[ $known != "$current" && -e $known ]]; then
            die "发现其他版本或路径的 Helper 状态：${known}。请使用独立 Helper；未修改系统。"
        fi
    done
}

parse_security_options() {
    RELAXED_SECURITY=${RELAXED_SECURITY:-false}
    SECURITY_NAMESPACE=${SECURITY_NAMESPACE:-default}
    YUM_REPO_MODE=${YUM_REPO_MODE:-iso}
    SKIP_FIREWALLD=${SKIP_FIREWALLD:-false}
    while (($#)); do
        case "$1" in
            --relaxed-security) RELAXED_SECURITY=true; shift ;;
            --skip-firewalld) SKIP_FIREWALLD=true; shift ;;
            --repo-mode)
                [[ $# -ge 2 ]] || die '--repo-mode 缺少 bundle、existing 或 iso'
                YUM_REPO_MODE=$2; shift 2 ;;
            --security-namespace)
                [[ $# -ge 2 ]] || die '--security-namespace 缺少命名空间'
                SECURITY_NAMESPACE=$2; shift 2 ;;
            --help|-h)
                printf '用法: bash %s [--relaxed-security] [--security-namespace NAME]\n' "${0##*/}"
                echo '默认保留主机安全策略；--relaxed-security 将 SELinux 设为 permissive 并关闭 firewalld。'
                echo '授时：NTP_SERVER 指定真实内部上游；无上游时显式设置 NTP_MODE=local 并省略 NTP_SERVER。'
                echo 'install-cluster.sh 另支持 --remove-bootstrap（先等待 bootstrap-complete）。'
                echo '--repo-mode bundle 使用完整交付包内的 RPM；existing 使用现有 YUM/RHUI；iso（默认）使用 RHEL DVD。'
                echo '--skip-firewalld 跳过 firewalld 安装、启停和规则管理；用于由外部规则管理防火墙的环境。'
                echo 'setup-cluster.sh 同时给指定命名空间（默认 default）的 default ServiceAccount 授予宽松 SCC。'
                exit 0 ;;
            *) die "未知参数: $1" ;;
        esac
    done
    [[ $RELAXED_SECURITY == true || $RELAXED_SECURITY == false ]] || die 'RELAXED_SECURITY 必须是 true 或 false'
    [[ $YUM_REPO_MODE == iso || $YUM_REPO_MODE == existing || $YUM_REPO_MODE == bundle ]] || die 'YUM_REPO_MODE 必须是 bundle、iso 或 existing'
    [[ $SKIP_FIREWALLD == true || $SKIP_FIREWALLD == false ]] || die 'SKIP_FIREWALLD 必须是 true 或 false'
    [[ ${#SECURITY_NAMESPACE} -le 63 && $SECURITY_NAMESPACE =~ ^[a-z0-9]([a-z0-9-]*[a-z0-9])?$ ]] || die '命名空间格式无效'
}

dnf_install() {
    if [[ ${YUM_REPO_MODE:-iso} == bundle ]]; then
        dnf --disablerepo='*' --enablerepo=ocp-delivery install -y "$@"
    else
        dnf install -y "$@"
    fi
}

relax_host_security() {
    [[ $RELAXED_SECURITY == true ]] || return 0
    echo '宽松安全模式：Helper SELinux permissive。'
    backup_file /etc/selinux/config
    if [[ $(getenforce) == Enforcing ]]; then setenforce 0; fi
    sed -i 's/^SELINUX=.*/SELINUX=permissive/' /etc/selinux/config
    if [[ ${SKIP_FIREWALLD:-false} != true ]] && systemctl list-unit-files firewalld.service --no-legend | grep -q '^firewalld.service'; then
        echo '停止并禁用 firewalld。'
        systemctl disable --now firewalld
    fi
}
