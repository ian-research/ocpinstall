#!/bin/bash
set -Eeuo pipefail
umask 077
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$SCRIPT_DIR/lib/common.sh"
source "$SCRIPT_DIR/config/versions.sh"
if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
    if [[ ${1:-} == --remove-bootstrap ]]; then
        REMOVE_BOOTSTRAP=true; shift
    fi
    parse_security_options "$@"
    require_host
fi
trap 'printf "错误: 第 %s 行执行失败，请检查输出后重试。\n" "$LINENO" >&2' ERR

#
# Author: Jun Sun
# Email: junsun@redhat.com
# Organization: Red Hat
# Created Time: 2025-05-05 17:30:00 UTC
# Description: Install OpenShift 4.22.22 three node Cluster in airgap environment

# debug
#set -x

# 默认值
DEFAULT_OCP_DOMAIN="poc.ocprhtest.com"
HARBOR_USER="admin"
CERT_DIR="$STATE_ROOT/harbor/cert"
HARBOR_PORT="8443"
HARBOR_DATA_DIR="$STATE_ROOT/harbor/data"
HELPER_IP_ADDRESS=${HELPER_IP_ADDRESS:-}


SSH_KEY="$STATE_ROOT/ssh/id_ed25519"
NFS_SC_DIR="/mnt/ocp422-nfs"
NTP_SERVER=${NTP_SERVER:-}
NTP_MODE=${NTP_MODE:-upstream}
NFS_CIDR=${NFS_CIDR:-}
LOG_FILE="/var/log/openshift422-install-local.log"
export PATH="$BIN_DIR:$PATH"

# 颜色和样式定义
COLOR_RESET='\033[0m'
COLOR_RED='\033[0;31m'
COLOR_GREEN='\033[0;32m'
COLOR_YELLOW='\033[0;33m'
COLOR_CYAN='\033[0;36m'
STYLE_BOLD='\033[1m'

# 文件路径定义
declare -A REQUIRED_FILES=(
  ["镜像配置"]="$IMAGESET_CONFIG"
  ["Harbor安装包"]="$HARBOR_ARCHIVE"
  ["oc-mirror包"]="$TOOLS_DIR/oc-mirror.tar.gz"
  ["openshift-client包"]="$TOOLS_DIR/$CLIENT_ARCHIVE"
  ["openshift-install包"]="$TOOLS_DIR/$INSTALLER_ARCHIVE"
)
if [[ ${YUM_REPO_MODE:-iso} == bundle ]]; then
    REQUIRED_FILES["Helper RPM 元数据"]="$HELPER_REPO_DIR/repodata/repomd.xml"
elif ! command -v docker >/dev/null; then
    REQUIRED_FILES["docker-ce安装包"]="$DOCKER_ARCHIVE"
fi

# 检查文件是否存在
check_files() {
  local missing_count=0
  local total_count=0

  echo -e "\n${COLOR_YELLOW}${STYLE_BOLD}正在检查必需文件...${COLOR_RESET}"

  for desc in "${!REQUIRED_FILES[@]}"; do
    ((total_count+=1))
    if [[ -f "${REQUIRED_FILES[$desc]}" ]]; then
      printf "  ${COLOR_GREEN}✓${COLOR_RESET} %-20s ${COLOR_CYAN}%s${COLOR_RESET}\n" "$desc" "${REQUIRED_FILES[$desc]}"
    else
      printf "  ${COLOR_RED}✗${COLOR_RESET} %-20s ${COLOR_RED}%s (文件缺失)${COLOR_RESET}\n" "$desc" "${REQUIRED_FILES[$desc]}"
      ((missing_count+=1))
    fi
  done

  echo -e "\n${COLOR_YELLOW}检查结果：${COLOR_RESET}"
  echo -e "  已找到文件: ${COLOR_GREEN}$((total_count - missing_count))/${total_count}${COLOR_RESET}"

  if [[ $missing_count -gt 0 ]]; then
    echo -e "\n${COLOR_RED}${STYLE_BOLD}错误：缺少 $missing_count 个必需文件${COLOR_RESET}"
    echo -e "请确保所有文件已存放到正确路径后再继续操作\n"
    return 1
  else
    echo -e "\n${COLOR_GREEN}${STYLE_BOLD}所有必需文件已就绪${COLOR_RESET}\n"
    return 0
  fi
}

hint() {
  echo -e "${COLOR_YELLOW}${STYLE_BOLD}请确保已将以下软件包存放到本地目录：${COLOR_RESET}"

  # 计算最大描述长度用于对齐
  local max_len=0
  for desc in "${!REQUIRED_FILES[@]}"; do
    if (( ${#desc} > max_len )); then max_len=${#desc}; fi
  done

  # 格式化输出文件列表
  for desc in "${!REQUIRED_FILES[@]}"; do
    printf "  ${COLOR_CYAN}%-${max_len}s${COLOR_RESET}  %s\n" "$desc" "${REQUIRED_FILES[$desc]}"
  done

  echo -e "\n${COLOR_YELLOW}提示：${COLOR_RESET}"
  echo -e "  - 请确保所有文件路径正确且可访问"
  echo -e "  - 文件大小应与官方发布一致"
  echo -e "  - 可使用 ${COLOR_GREEN}ls -lh <文件路径>${COLOR_RESET} 验证文件"

  # 自动执行文件检查
  check_files || exit 1
}

# 日志函数
log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a "$LOG_FILE"
}

# 检查用户是否是 root 权限
check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        log "错误: 请使用 root 权限运行此脚本！"
        exit 1
    fi
}

# 配置本地yum源
configure_local_yum() {
    if [[ ${YUM_REPO_MODE:-iso} == bundle ]]; then
        [[ -r $HELPER_REPO_DIR/repodata/repomd.xml && -d $HELPER_KEYS_DIR ]] || die '离线 RPM 仓库或签名 key 缺失'
        local key key_urls='' repo_url
        for key in "$HELPER_KEYS_DIR"/*; do
            [[ -f $key ]] || continue
            rpm --import "$key"
            key_urls+=" $(python3 -c 'import pathlib,sys; print(pathlib.Path(sys.argv[1]).resolve().as_uri())' "$key")"
        done
        [[ -n $key_urls ]] || die '离线 RPM 仓库没有签名 key'
        backup_file /etc/yum.repos.d/ocp-delivery.repo
        repo_url=$(python3 -c 'import pathlib,sys; print(pathlib.Path(sys.argv[1]).resolve().as_uri())' "$HELPER_REPO_DIR")
        cat > /etc/yum.repos.d/ocp-delivery.repo <<EOF
[ocp-delivery]
name=OpenShift delivery Helper RPMs
baseurl=$repo_url
enabled=0
gpgcheck=1
gpgkey=$key_urls
EOF
        dnf --disablerepo='*' --enablerepo=ocp-delivery -q makecache
        return
    fi
    if [[ ${YUM_REPO_MODE:-iso} == existing ]]; then
        log "使用现有 YUM/RHUI 源，跳过 ISO 挂载和 repo 文件变更。"
        dnf -q makecache
        return 0
    fi
    log "配置本地 YUM 源..."
    local MNT_DIR="/mnt/iso"
    local REPO_DIR="/etc/yum.repos.d"
    local BAK_DIR="$REPO_DIR/bak"
    local LOCAL_REPO="$REPO_DIR/ocp422-local.repo"

    # 检查是否已经挂载

    # 检查 /dev/sr0 是否存在
    if [ ! -e "/dev/sr0" ]; then
        log "错误: /dev/sr0 不存在，请插入光盘！"
        exit 1
    fi

    # 挂载光盘
    mkdir -p "$MNT_DIR"
    if ! mountpoint -q "$MNT_DIR"; then mount /dev/sr0 "$MNT_DIR"; fi
    [[ ! -f $LOCAL_REPO ]] || return 0

    # 备份原有 repo 文件
    mkdir -p "$BAK_DIR"
    for repo in "$REPO_DIR"/*.repo; do
        [[ -f $repo ]] || continue
        cp -pn "$repo" "$BAK_DIR/"
        mv "$repo" "$repo.disabled"
    done

    # 创建本地 repo 文件
    cat << EOF > "$LOCAL_REPO"
[baseos]
name=baseos
baseurl=file://$MNT_DIR/BaseOS
gpgcheck=0
enabled=1

[appstream]
name=appstream
baseurl=file://$MNT_DIR/AppStream
gpgcheck=0
enabled=1
EOF

    # 清理并生成缓存
    yum clean all
    yum makecache
    log "本地 YUM 源配置完成！"
}


# 添加中文支持
add_chinese_support() {
    log "添加中文支持..."
    dnf_install glibc-langpack-zh python3
}

# 默认配置实际需要的 SELinux 端口标签和防火墙规则。
configure_host_security() {
    if [[ $RELAXED_SECURITY == true ]]; then
        relax_host_security
        return
    fi
    echo "默认安全模式：保留 SELinux 状态，配置必要端口标签和布尔值。"
    if [[ $(getenforce) != Disabled ]]; then
        if semanage port -l | awk '$1 == "http_port_t" {print}' | grep -qw 9088; then
            :
        else
            semanage port -a -t http_port_t -p tcp 9088
        fi
        setsebool -P haproxy_connect_any 1
        setsebool -P nfs_export_all_rw 1
    fi
    if [[ $SKIP_FIREWALLD == true ]]; then
        echo '按选项跳过 firewalld；请由现有主机/网络规则允许集群所需通信。'
        return
    fi
    systemctl enable --now firewalld
    local service port
    for service in dns ntp http https nfs rpc-bind mountd; do
        firewall-cmd --permanent --add-service="$service"
    done
    for port in 6443 22623 9088 8443; do
        firewall-cmd --permanent --add-port="$port/tcp"
    done
    firewall-cmd --reload
}

# 配置本机信息
add_host_info() {
    log "配置本机信息..."
    read -p "请输入 OCP_DOMAIN (默认: $DEFAULT_OCP_DOMAIN): " OCP_DOMAIN
    OCP_DOMAIN=${OCP_DOMAIN:-$DEFAULT_OCP_DOMAIN}
    validate_domain "$OCP_DOMAIN" || die "域名格式无效"

    #read -p "请输入 Harbor 管理员用户名 (默认: $DEFAULT_HARBOR_USER): " HARBOR_USER
    #HARBOR_USER=${HARBOR_USER:-$DEFAULT_HARBOR_USER}

    read -r -s -p "请输入 Harbor 管理员密码（至少12位）: " HARBOR_PASSWORD
    [[ ${#HARBOR_PASSWORD} -ge 12 && $HARBOR_PASSWORD =~ ^[a-zA-Z0-9_!@%+=.-]+$ ]] || die "Harbor 密码至少 12 位，仅使用字母、数字及 _!@%+=.-"
    echo

    LOCAL_REGISTRY="helper.$OCP_DOMAIN:$HARBOR_PORT"
    HELPER_HOSTNAME="helper.$OCP_DOMAIN"
    if [[ -z $HELPER_IP_ADDRESS ]]; then
        read -r -p "请输入 Helper IPv4 地址: " HELPER_IP_ADDRESS
    fi
    validate_ip "$HELPER_IP_ADDRESS" || die "Helper IP 无效"
    REVERSE_DNS=$(echo "$HELPER_IP_ADDRESS" | awk -F. '{print $3"."$2"."$1".in-addr.arpa"}')

    if [[ -z "$HELPER_IP_ADDRESS" ]]; then
        log "错误: 无法获取本机 IPv4 地址，请检查网络配置。"
        exit 1
    fi


}

# 收集节点信息
collect_ips() {
  echo -e "\n${COLOR_GREEN}=== 节点IP配置 ===${COLOR_RESET}"

  # 输入bootstrap节点IP
  while true; do
    read -p "请输入bootstrap节点IP: " BOOTSTRAP_IP
    if validate_ip "$BOOTSTRAP_IP"; then
      break
    fi
  done

  # 输入master节点IP
  MASTER_IPS=()
  echo -e "\n请输入3个master节点IP:"
  for i in {1..3}; do
    while true; do
      read -p "  master节点$i IP: " ip
      if validate_ip "$ip"; then
        MASTER_IPS+=("$ip")
        break
      fi
    done
  done

  local node prefix=${HELPER_IP_ADDRESS%.*}
  local seen=" $HELPER_IP_ADDRESS "
  for node in "$BOOTSTRAP_IP" "${MASTER_IPS[@]}"; do
      [[ ${node%.*} == "$prefix" ]] || die "当前 DNS 模板要求所有节点与 Helper 在同一 /24 网段"
      [[ $seen != *" $node "* ]] || die "节点 IP 重复: $node"
      seen+="$node "
  done

  # 输入worker节点IP
  #WORKER_IPS=()
  #echo -e "\n请输入worker节点IP(至少1个，直接回车结束输入):"
  #i=1
  #while true; do
  #  read -p "  worker节点$i IP: " ip
  #
  #  if [ -z "$ip" ]; then
  #    if [ ${#WORKER_IPS[@]} -eq 0 ]; then
  #      echo -e "${COLOR_RED}错误: 至少需要1个worker节点${COLOR_RESET}"
  #      continue
  #    else
  #      break
  #    fi
  #  fi
  #
  #  if validate_ip "$ip"; then
  #    WORKER_IPS+=("$ip")
  #    ((i++))
  #  fi
  #done
}

# 显示配置摘要
show_summary() {
  echo -e "\n${COLOR_YELLOW}${STYLE_BOLD}=== 配置摘要 ===${COLOR_RESET}"
  echo "宽松安全模式: $RELAXED_SECURITY"
  echo "跳过 firewalld: $SKIP_FIREWALLD"
  echo -e "OCP所使用的域名: ${COLOR_CYAN}$OCP_DOMAIN${COLOR_RESET}"
  echo "Harbor 管理员密码: [已隐藏]"
  echo -e "本地镜像仓库: ${COLOR_CYAN}$LOCAL_REGISTRY${COLOR_RESET}"
  echo -e "Bootstrap节点IP: ${COLOR_CYAN}$BOOTSTRAP_IP${COLOR_RESET}"

  echo -e "Master节点IP:"
  for ip in "${MASTER_IPS[@]}"; do
    echo -e "  - ${COLOR_CYAN}$ip${COLOR_RESET}"
  done

  #echo -e "Worker节点IP:"
  #for ip in "${WORKER_IPS[@]}"; do
  #  echo -e "  - ${COLOR_CYAN}$ip${COLOR_RESET}"
  #done
}

# 用户确认
confirm_config() {
  while true; do
    echo -e "\n${COLOR_YELLOW}${STYLE_BOLD}=== 请确认以上配置 ===${COLOR_RESET}"
    read -p "$(echo -e "${COLOR_YELLOW}是否确认配置正确? (y/n): ${COLOR_RESET}")" confirm
    case $confirm in
      y|Y)
        echo -e "${COLOR_GREEN}${STYLE_BOLD}配置已确认，继续安装...${COLOR_RESET}"
        return 0
        ;;
      n|N)
        echo -e "${COLOR_RED}${STYLE_BOLD}安装已取消${COLOR_RESET}"
        exit 0
        ;;
      *)
        echo -e "${COLOR_RED}请输入 y 或 n${COLOR_RESET}"
        ;;
    esac
  done
}

# 安装依赖
install_dependencies() {
    log "安装依赖..."
    local -a packages=(python3-pyyaml policycoreutils-python-utils haproxy bind bind-utils skopeo httpd-tools openssl python3.11 python3-pip jq wget nfs-utils chrony httpd cockpit)
    if [[ $SKIP_FIREWALLD != true ]]; then packages+=(firewalld); fi
    dnf_install "${packages[@]}"
    if [[ ${YUM_REPO_MODE:-iso} == bundle ]]; then
        dnf_install docker-ce docker-ce-cli containerd.io docker-compose-plugin
    elif ! command -v docker >/dev/null; then
        mkdir -p "$STATE_ROOT/docker-rpms"
        # Trusted local administrator-provided legacy RPM archive.
        tar -zxf "$DOCKER_ARCHIVE" -C "$STATE_ROOT/docker-rpms" --strip-components=1
        local -a rpms=("$STATE_ROOT/docker-rpms/"*.rpm)
        [[ -f ${rpms[0]} ]] || die 'Docker 包中没有 RPM'
        dnf_install "${rpms[@]}"
    fi

    # 启动docker
    sudo systemctl enable docker --now
}

# 配置NFS
configure_nfs() {
    log "配置 NFS 共享..."
    [[ -n $NFS_CIDR ]] || die "请设置 NFS_CIDR，明确允许访问 NFS 的网段"
    sudo mkdir -p "$NFS_SC_DIR" /etc/exports.d
    sudo chmod 777 $NFS_SC_DIR
    local squash=root_squash
    [[ $RELAXED_SECURITY != true ]] || squash=no_root_squash
    echo "$NFS_SC_DIR $NFS_CIDR(rw,sync,$squash,no_subtree_check,no_wdelay)" | sudo tee /etc/exports.d/ocp422.exports
    if [[ $(getenforce) != Disabled ]]; then restorecon -RF "$NFS_SC_DIR"; fi
    sudo systemctl restart nfs-server rpcbind
    sudo systemctl enable  nfs-server rpcbind nfs-mountd
}

# 配置chrony
configure_chrony() {
    log "配置 chrony..."
    local content
    content=$(python3 "$SCRIPT_DIR/lib/artifacts.py" helper-chrony "$NTP_SERVER" "$NFS_CIDR" "$HELPER_IP_ADDRESS" "$NTP_MODE")
    backup_file /etc/chrony.conf
    printf '%s\n' "$content" > /etc/chrony.conf
    systemctl enable chronyd
    systemctl restart chronyd
    chronyc -a makestep
    if [[ $NTP_MODE == upstream ]]; then
        chronyc waitsync 30 1 0 2 || die '上游 NTP 未同步，停止安装；修复授时后再继续'
    else
        log '本地授时模式：节点以 Helper 时钟为准，未验证 UTC 准确性；请确认 Helper 时间正确。'
    fi
}

# 配置bind
configure_bind() {
    log "配置 DNS bind 服务..."
    NAMED_CONF="/etc/named.conf"
    backup_file "$NAMED_CONF"

    cat << EOF > "$NAMED_CONF"
options {
    listen-on port 53 { any; };
    listen-on-v6 port 53 { any; };
    directory       "/var/named";
    dump-file       "/var/named/data/cache_dump.db";
    statistics-file "/var/named/data/named_stats.txt";
    memstatistics-file "/var/named/data/named_mem_stats.txt";
    secroots-file   "/var/named/data/named.secroots";
    recursing-file  "/var/named/data/named.recursing";
    allow-query     { any; };
};

zone "$(echo $OCP_DOMAIN | cut -d '.' -f 2-)" IN {
    type master;
    file "$(echo $OCP_DOMAIN | cut -d '.' -f 2-).zone";
};

zone "$(echo $REVERSE_DNS)" IN {
    type master;
    file "$(echo $REVERSE_DNS).zone";
};

include "/etc/named.rfc1912.zones";
include "/etc/named.root.key";
EOF

    ZONE_FILE="/var/named/$(echo $OCP_DOMAIN | cut -d '.' -f 2-).zone"
    cat << EOF > "$ZONE_FILE"
\$TTL 86400
@   IN  SOA     ns1.$(echo $OCP_DOMAIN | cut -d '.' -f 2-). root.$(echo $OCP_DOMAIN | cut -d '.' -f 2-). (
                2024020401  ; Serial
                3600        ; Refresh
                1800        ; Retry
                604800      ; Expire
                86400       ; Minimum TTL
)
@       IN  NS      ns1.$(echo $OCP_DOMAIN | cut -d '.' -f 2-).
ns1     IN  A       $HELPER_IP_ADDRESS
harbor.$OCP_DOMAIN.    IN  A  $HELPER_IP_ADDRESS
helper.$OCP_DOMAIN.    IN  A  $HELPER_IP_ADDRESS
;
api.$OCP_DOMAIN.    IN  A  $HELPER_IP_ADDRESS
api-int.$OCP_DOMAIN.  IN  A  $HELPER_IP_ADDRESS
;
*.apps.$OCP_DOMAIN.  IN  A  $HELPER_IP_ADDRESS
;
bootstrap.$OCP_DOMAIN.  IN  A  $BOOTSTRAP_IP
EOF

    # 添加master节点记录
    for i in "${!MASTER_IPS[@]}"; do
        echo "master$((i+1)).$OCP_DOMAIN.  IN  A  ${MASTER_IPS[$i]}" >> "$ZONE_FILE"
    done

    # 添加worker节点记录
    #for i in "${!WORKER_IPS[@]}"; do
    #    echo "worker$((i+1)).$OCP_DOMAIN.  IN  A  ${WORKER_IPS[$i]}" >> "$ZONE_FILE"
    #done

    REVERSE_ZONE_FILE="/var/named/$(echo $REVERSE_DNS).zone"
    cat << EOF > "$REVERSE_ZONE_FILE"
\$TTL 86400
@   IN  SOA     ns1.$(echo $OCP_DOMAIN | cut -d '.' -f 2-). root.$(echo $OCP_DOMAIN | cut -d '.' -f 2-). (
                2024020401  ; Serial
                3600        ; Refresh
                1800        ; Retry
                604800      ; Expire
                86400       ; Minimum TTL
)
@       IN  NS      ns1.$(echo $OCP_DOMAIN | cut -d '.' -f 2-).
$(echo $HELPER_IP_ADDRESS | awk -F. '{print $4}')  IN  PTR  api.$OCP_DOMAIN.
$(echo $HELPER_IP_ADDRESS | awk -F. '{print $4}')  IN  PTR  api-int.$OCP_DOMAIN.
$(echo $HELPER_IP_ADDRESS | awk -F. '{print $4}')  IN  PTR  helper.$OCP_DOMAIN.
$(echo $HELPER_IP_ADDRESS | awk -F. '{print $4}')  IN  PTR  harbor.$OCP_DOMAIN.
EOF

    # 添加bootstrap反向记录
    echo "$(echo $BOOTSTRAP_IP | awk -F. '{print $4}').$(echo $REVERSE_DNS).  IN  PTR  bootstrap.$OCP_DOMAIN." >> "$REVERSE_ZONE_FILE"

    # 添加master反向记录
    for i in "${!MASTER_IPS[@]}"; do
        echo "$(echo ${MASTER_IPS[$i]} | awk -F. '{print $4}').$(echo $REVERSE_DNS).  IN  PTR  master$((i+1)).$OCP_DOMAIN." >> "$REVERSE_ZONE_FILE"
    done

    # 添加worker反向记录
    #for i in "${!WORKER_IPS[@]}"; do
    #    echo "$(echo ${WORKER_IPS[$i]} | awk -F. '{print $4}').$(echo $REVERSE_DNS).  IN  PTR  worker$((i+1)).$OCP_DOMAIN." >> "$REVERSE_ZONE_FILE"
    #done

    chmod 644 "$NAMED_CONF"
    chown named:named "$ZONE_FILE" "$REVERSE_ZONE_FILE"
    chmod 640 "$ZONE_FILE" "$REVERSE_ZONE_FILE"
    named-checkconf
    named-checkzone "${OCP_DOMAIN#*.}" "$ZONE_FILE"
    named-checkzone "$REVERSE_DNS" "$REVERSE_ZONE_FILE"
    restorecon -RF "$ZONE_FILE" "$REVERSE_ZONE_FILE" "$NAMED_CONF"
    systemctl restart named
    systemctl enable named
    echo "nameserver $HELPER_IP_ADDRESS" > /etc/resolv.conf
    log "BIND 安装与配置完成！"
}

# 配置haproxy
configure_haproxy() {
    log "配置 HAProxy..."
    HAPROXY_CFG="/etc/haproxy/haproxy.cfg"
    backup_file "$HAPROXY_CFG"

    cat << EOF > "$HAPROXY_CFG"
global
  log         127.0.0.1 local2
  pidfile     /var/run/haproxy.pid
  maxconn     4000
  daemon

defaults
  mode                    http
  log                     global
  option                  dontlognull
  option http-server-close
  option                  redispatch
  retries                 3
  timeout http-request    10s
  timeout queue           1m
  timeout connect         10s
  timeout client          1m
  timeout server          1m
  timeout http-keep-alive 10s
  timeout check           10s
  maxconn                 3000

# Enable HAProxy stats
listen stats
    bind 127.0.0.1:9000
    stats uri /stats
    stats refresh 10000ms

listen api-server-6443
  bind *:6443
  mode tcp
  option httpchk GET /readyz HTTP/1.0
  option log-health-checks
  balance roundrobin
  server bootstrap $BOOTSTRAP_IP:6443 check check-ssl verify none inter 5s fall 3 rise 2 backup
EOF

    # 添加master节点到6443和22623监听
    for i in "${!MASTER_IPS[@]}"; do
        echo "  server master$((i+1)) ${MASTER_IPS[$i]}:6443 check check-ssl verify none inter 5s fall 3 rise 2" >> "$HAPROXY_CFG"
    done

    cat << EOF >> "$HAPROXY_CFG"

listen machine-config-server-22623
  bind *:22623
  mode tcp
  server bootstrap $BOOTSTRAP_IP:22623 check inter 1s backup
EOF

    # 添加master节点到22623监听
    for i in "${!MASTER_IPS[@]}"; do
        echo "  server master$((i+1)) ${MASTER_IPS[$i]}:22623 check inter 1s" >> "$HAPROXY_CFG"
    done

    # 添加master节点到80和443监听
    cat << EOF >> "$HAPROXY_CFG"

listen ingress-router-443
  bind *:443
  mode tcp
  balance source
EOF

    for i in "${!MASTER_IPS[@]}"; do
        echo "  server master$((i+1)) ${MASTER_IPS[$i]}:443 check inter 1s" >> "$HAPROXY_CFG"
    done

    cat << EOF >> "$HAPROXY_CFG"

listen ingress-router-80
  bind *:80
  mode tcp
  balance source
EOF

    for i in "${!MASTER_IPS[@]}"; do
        echo "  server master$((i+1)) ${MASTER_IPS[$i]}:80 check inter 1s" >> "$HAPROXY_CFG"
    done

    if [[ $(getenforce) != Disabled ]]; then setsebool -P haproxy_connect_any 1; fi
    chmod 644 "$HAPROXY_CFG"
    haproxy -c -f "$HAPROXY_CFG"
    systemctl enable haproxy
    systemctl restart haproxy
    log "HAProxy 安装与配置完成！"
}

# 配置httpd
configure_httpd() {
    log "配置 HTTPD..."
    sed -i 's/^Listen 80/Listen 9088/' /etc/httpd/conf/httpd.conf
    # 保留默认目录索引限制。
    httpd -t
    systemctl enable httpd
    systemctl restart httpd
}

# 配置openshift关联命令行
config_oc_cli() {
    mkdir -p "$BIN_DIR"
    chmod 755 "$STATE_ROOT" "$BIN_DIR"
    python3 "$SCRIPT_DIR/lib/artifacts.py" extract-tools "$TOOLS_DIR" "$BIN_DIR"
    local binary
    for binary in oc kubectl oc-mirror openshift-install; do
        [[ -x "$BIN_DIR/$binary" ]] || die "缺少工具 $binary"
    done
    oc mirror --v2 --help >/dev/null
}

setup_certs() {
  # 检查必要变量
  if [ -z "$OCP_DOMAIN" ]; then
    echo "错误：OCP_DOMAIN 变量未设置"
    return 1
  fi

  if [ -z "$CERT_DIR" ]; then
    echo "错误：CERT_DIR 变量未设置"
    return 1
  fi

  log "设置 Harbor HTTPS 证书..."
  local CA_KEY="${CERT_DIR}/ca.key"
  local CA_CRT="${CERT_DIR}/ca.crt"
  local SERVER_KEY="${CERT_DIR}/${OCP_DOMAIN}.key"
  local SERVER_CSR="${CERT_DIR}/${OCP_DOMAIN}.csr"
  local SERVER_CRT="${CERT_DIR}/${OCP_DOMAIN}.crt"
  local SERVER_CERT="${CERT_DIR}/${OCP_DOMAIN}.cert"
  local V3_EXT="${CERT_DIR}/v3.ext"

  sudo mkdir -p "$CERT_DIR"

  # 检测现有证书（使用修正后的变量引用）
  if [[ -f "${SERVER_CERT}" && -f "${SERVER_KEY}" && -f "${SERVER_CRT}" && -f "${CA_CRT}" ]]; then
    echo "  ✓ 检测到现有证书，重新安装 CA 信任"
    cp "$CA_CRT" "/etc/pki/ca-trust/source/anchors/${OCP_DOMAIN}.crt"
    update-ca-trust extract
    return 0
  fi

  log "正在生成CA根密钥和证书..."
  openssl genrsa -out "${CA_KEY}" 4096
  openssl req -x509 -new -nodes -sha512 -days 3650 \
    -subj "/C=CN/ST=Shanghai/L=Shanghai/O=helper/OU=Personal/CN=${OCP_DOMAIN}" \
    -key "${CA_KEY}" \
    -out "${CA_CRT}"

  log "正在生成服务器密钥和签名请求..."
  openssl genrsa -out "${SERVER_KEY}" 4096
  openssl req -sha512 -new \
    -subj "/C=CN/ST=Shanghai/L=Shanghai/O=helper/OU=Personal/CN=${OCP_DOMAIN}" \
    -key "${SERVER_KEY}" \
    -out "${SERVER_CSR}"

  log "创建v3.ext扩展文件..."
  cat > "${V3_EXT}" <<EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1=${OCP_DOMAIN}
DNS.2=helper.${OCP_DOMAIN}
EOF

  log "使用CA证书进行签名..."
  openssl x509 -req -sha512 -days 3650 \
    -extfile "${V3_EXT}" \
    -CA "${CA_CRT}" \
    -CAkey "${CA_KEY}" \
    -CAcreateserial \
    -in "${SERVER_CSR}" \
    -out "${SERVER_CRT}"

  log "转换证书格式..."
  openssl x509 -inform PEM -in "${SERVER_CRT}" -out "${SERVER_CERT}"

  log "  ➤ 更新系统信任证书..."
  sudo cp "${CA_CRT}" "/etc/pki/ca-trust/source/anchors/${OCP_DOMAIN}.crt"
  sudo update-ca-trust extract
}

# 安装配置harbor
install_harbor() {
    log "安装 Harbor..."
    local SERVER_CRT="${CERT_DIR}/${OCP_DOMAIN}.crt"
    local SERVER_CERT="${CERT_DIR}/${OCP_DOMAIN}.cert"
    local SERVER_KEY="${CERT_DIR}/${OCP_DOMAIN}.key"

    # 创建 Harbor 配置目录
    mkdir -p "$STATE_ROOT/harbor"

    # 解压 Harbor 安装包
    tar -xvf "$HARBOR_ARCHIVE" -C "$STATE_ROOT/harbor"

    # 进入 Harbor 目录
    cd "$STATE_ROOT/harbor/harbor" || exit 1

    # 修改配置文件
    cp harbor.yml.tmpl harbor.yml
    sed -i "s/^hostname:.*/hostname: $HELPER_HOSTNAME/" harbor.yml
    sed -i "s/^  password:.*/  password: $HARBOR_PASSWORD/" harbor.yml
    sed -i "s/^harbor_admin_password:.*/harbor_admin_password: $HARBOR_PASSWORD/" harbor.yml
    sed -i "s|^# https:|https:|" harbor.yml
    sed -i -E 's/^([[:space:]]*)port:[[:space:]]*80([[:space:]]*(#.*)?)$/\1port: 8088\2/' harbor.yml
    sed -i -E 's/^([[:space:]]*)port:[[:space:]]*443([[:space:]]*(#.*)?)$/\1port: 8443\2/' harbor.yml
    sed -i "s|certificate: /your/certificate/path|certificate: $SERVER_CRT|g" harbor.yml
    sed -i "s|private_key: /your/private/key/path|private_key: $SERVER_KEY|g" harbor.yml
    sed -i "s|^data_volume:.*|data_volume: $HARBOR_DATA_DIR|" harbor.yml


    # 安装 Harbor
    sudo ./install.sh
}

# 启动harbor
start_harbor() {
  log "使用 docker-compose 启动 Harbor..."
  local SERVER_CERT="${CERT_DIR}/${OCP_DOMAIN}.cert"
  local SERVER_KEY="${CERT_DIR}/${OCP_DOMAIN}.key"
  local CA_CRT="${CERT_DIR}/ca.crt"

  mkdir -p /etc/docker/certs.d/$LOCAL_REGISTRY
  cp -f "$CA_CRT" "/etc/docker/certs.d/$LOCAL_REGISTRY/ca.crt"

  systemctl restart docker

  cd "$STATE_ROOT/harbor/harbor" || exit 1
  docker compose up -d

  echo "等待 Harbor 就绪并登录: $LOCAL_REGISTRY"
  mkdir -p /root/.docker
  local attempt logged_in=false
  for attempt in {1..30}; do
      echo "Harbor 登录检查 $attempt/30"
      if printf '%s\n' "$HARBOR_PASSWORD" | docker login "$LOCAL_REGISTRY" --username "$HARBOR_USER" --password-stdin; then
          logged_in=true
          break
      fi
      sleep 2
  done
  [[ $logged_in == true ]] || die "Harbor 登录失败，请检查服务和凭据"
  log "harbor安装完成已启动"
}

# 创建harbor项目
create_harbor_project() {
  log " 创建Harbor项目 [$LOCAL_REPOSITORY]..."
  local status
  status=$(curl --silent --show-error --cacert "$CERT_DIR/ca.crt" \
    -u "admin:$HARBOR_PASSWORD" -o /dev/null \
    -w '%{http_code}' -H "Content-Type: application/json" \
    -X POST "https://${LOCAL_REGISTRY}/api/v2.0/projects" \
    -d "{\"project_name\":\"$LOCAL_REPOSITORY\",\"metadata\":{\"public\":\"false\"}}")
  [[ $status == 201 || $status == 409 ]] || die "Harbor 项目创建失败，HTTP $status"

}

# 配置OpenShift离线镜像仓库
upload_ocp_image() {
    log "配置 OpenShift 离线镜像仓库..."
    [[ -f $IMAGESET_CONFIG ]] || die "缺少离线下载时使用的 ImageSetConfiguration: $IMAGESET_CONFIG"
    echo "使用镜像配置: ${IMAGESET_CONFIG}；请确保离线包包含 $OCP_RELEASE"
    # 推送镜像到本地仓库
    log "推送镜像到本地镜像仓库..."
    bash "$SCRIPT_DIR/prepare-offline.sh" import --bundle "$BUNDLE_DIR" \
        --cache-dir "$STATE_ROOT/platform-import-cache" \
        --authfile /root/.docker/config.json --registry "$LOCAL_REGISTRY/$LOCAL_REPOSITORY" --version "$OCP_RELEASE"
    log "OpenShift 离线镜像同步完成！"
}

# 配置SSH Key
configure_ssh_key() {
    log "配置 SSH Key..."
    mkdir -p "$(dirname "$SSH_KEY")"
    if [ ! -f "$SSH_KEY" ]; then
        ssh-keygen -t ed25519 -N "" -f "$SSH_KEY"
    fi
}

create_install_config() {
    log "创建 install-config.yaml 文件..."

    # 定义常量
    if [[ -z ${CLUSTER_PULL_SECRET:-} ]]; then
        echo "请在 Harbor 项目 $LOCAL_REPOSITORY 创建仅有 pull 权限的 robot 账号，并保存 registry auth JSON。"
        read -r -p "请输入该凭据 JSON 的绝对路径: " CLUSTER_PULL_SECRET
    fi
    [[ -r $CLUSTER_PULL_SECRET ]] || die "无法读取 CLUSTER_PULL_SECRET"
    chmod 600 "$CLUSTER_PULL_SECRET"
    export OCP_DOMAIN LOCAL_REGISTRY LOCAL_REPOSITORY HELPER_IP_ADDRESS NTP_SERVER NFS_CIDR
    export CLUSTER_PULL_SECRET CERT_DIR SSH_KEY INSTALL_DIR RELEASE_SOURCE COMPONENT_SOURCE
    python3 "$SCRIPT_DIR/lib/artifacts.py" install-config "$MIRROR_DIR/working-dir/cluster-resources" "$STATE_ROOT/install-config.yaml"

}

# 创建manifest,ignition文件
create_manifest_config() {
    # 创建manifest文件
    log "创建manifest文件..."
    [[ ! -e "$INSTALL_DIR" ]] || die "安装目录已存在：${INSTALL_DIR}。请先归档旧安装状态，不要覆盖已有集群资料。"
    mkdir -p "$INSTALL_DIR"
    chmod 700 "$INSTALL_DIR"
    cp -f "$STATE_ROOT/install-config.yaml" "$INSTALL_DIR/install-config.yaml"
    openshift-install create manifests --dir="$INSTALL_DIR" || {
        log "错误: 创建 manifest 文件失败"
        exit 1
    }

    python3 "$SCRIPT_DIR/lib/artifacts.py" prepare-manifests "$INSTALL_DIR"

    # 创建 ignition 配置文件
    log "创建 ignition 配置文件..."
    openshift-install create ignition-configs --dir="$INSTALL_DIR" || {
        log "错误: 创建 ignition 配置文件失败"
        exit 1
    }

    python3 "$SCRIPT_DIR/lib/artifacts.py" bootstrap-ntp "$INSTALL_DIR"

    # 拷贝 ignition 文件到 HTTP 根目录
    log "拷贝 ignition 文件到 HTTP 根目录..."
    mkdir -p "$HTTP_ROOT/ignition"
    chmod 755 "$HTTP_ROOT"
    chmod 755 "$HTTP_ROOT/ignition"
    cp -f "$INSTALL_DIR"/{bootstrap,master,worker}.ign "$HTTP_ROOT/ignition/"
    chmod 644 "$HTTP_ROOT"/ignition/*.ign
    restorecon -RF "$HTTP_ROOT/ignition"
    python3 "$SCRIPT_DIR/lib/artifacts.py" commands "$INSTALL_DIR" "$HTTP_ROOT/ignition" "$HELPER_HOSTNAME" "$STATE_ROOT/node-install-commands.txt"
    log "ignition 文件已拷贝到 $HTTP_ROOT/ignition/ 目录下"

    # 管理凭据仅保留在 root 私有安装目录，禁止通过 HTTP 发布。
    chmod 700 "$INSTALL_DIR" "$INSTALL_DIR/auth"
    chmod 600 "$INSTALL_DIR/auth/"*
    log "install-config 准备完成！"
}

# keepgoing
keepgoing () {
    echo "安装文件已生成。使用匹配安装器的 RHCOS Live ISO 启动节点：${RHCOS_ISO:-请运行 coreos print-stream-json 查询并准备}"
    echo "请在 12 小时内使用 Ignition；在 Live ISO 中先设置网络、DNS 和正确的目标磁盘。"
    cat "$STATE_ROOT/node-install-commands.txt"
    echo "在 Helper 上执行：openshift-install wait-for bootstrap-complete --dir=$INSTALL_DIR"
    echo "完成后运行 bash $SCRIPT_DIR/install-cluster.sh --remove-bootstrap，从两个后端移除 bootstrap。"
    echo "核对 CSR 后审批，最后执行 openshift-install wait-for install-complete --dir=$INSTALL_DIR"
    echo "私有凭据目录：$INSTALL_DIR/auth；安装完成后停止分发 HTTP Ignition。"
}

remove_bootstrap() {
    require_host
    [[ -r "$INSTALL_DIR/metadata.json" ]] || die "找不到 $OCP_RELEASE 安装状态，拒绝修改 HAProxy"
    openshift-install wait-for bootstrap-complete --dir="$INSTALL_DIR"
    python3 "$SCRIPT_DIR/lib/artifacts.py" remove-bootstrap /etc/haproxy/haproxy.cfg
    systemctl reload haproxy
}

# 主函数
main() {
    require_host
    if [[ ${REMOVE_BOOTSTRAP:-false} == true ]]; then remove_bootstrap; return; fi
    check_root
    guard_helper_state "$STATE_ROOT" /opt/ocpinstall /opt/ocp5 /opt/ocp422 /opt/harbor/harbor/harbor.yml
    hint
    [[ -f $IMAGESET_CONFIG ]] || die "请提供 bundle 内的 imagesetconfiguration.json"
    python3 "$SCRIPT_DIR/lib/offline.py" verify --bundle "$(dirname "$IMAGESET_CONFIG")" --version "$OCP_RELEASE"
    [[ -n $NFS_CIDR ]] || die "请设置 NFS_CIDR"
    python3 -c 'import ipaddress,sys; ipaddress.IPv4Network(sys.argv[1])' "$NFS_CIDR"
    [[ ! -e /var/www/html/auth/kubeconfig && ! -e /var/www/html/auth/kubeadmin-password ]] || die "检测到旧版公开凭据，请先移至安全位置并轮换凭据"
    [[ ! -e $INSTALL_DIR ]] || die "安装目录已存在，请先归档: $INSTALL_DIR"
    mkdir -p "$STATE_ROOT"
    config_oc_cli
    [[ $(openshift-install version | head -n 1) == *" $OCP_RELEASE" ]] || die "安装器版本与配置不一致"
    add_host_info
    python3 "$SCRIPT_DIR/lib/artifacts.py" helper-chrony "$NTP_SERVER" "$NFS_CIDR" "$HELPER_IP_ADDRESS" "$NTP_MODE" >/dev/null
    collect_ips
    show_summary
    confirm_config
    backup_file /etc/hosts
    printf "%s %s\n" "$HELPER_IP_ADDRESS" "$HELPER_HOSTNAME" >> /etc/hosts
    backup_file /etc/resolv.conf
    hostnamectl set-hostname "$HELPER_HOSTNAME"
    configure_local_yum
    add_chinese_support
    install_dependencies
    configure_host_security
    configure_nfs
    configure_chrony
    configure_bind
    configure_haproxy
    configure_httpd
    setup_certs
    install_harbor
    start_harbor
    create_harbor_project
    upload_ocp_image
    configure_ssh_key
    create_install_config
    create_manifest_config
    python3 - "$STATE_ROOT/handoff.json" "$OCP_RELEASE" "$OCP_DOMAIN" "$HELPER_HOSTNAME" "$NFS_SC_DIR" "$LOCAL_REGISTRY/$LOCAL_REPOSITORY" <<'PY'
import json, pathlib, sys
path = pathlib.Path(sys.argv[1])
record = dict(zip(('version', 'OCP_DOMAIN', 'NFS_SERVER', 'NFS_SC_DIR', 'registry'), sys.argv[2:]))
temporary = path.with_suffix('.tmp')
temporary.write_text(json.dumps(record, indent=2) + '\n')
temporary.chmod(0o600)
temporary.replace(path)
PY
    keepgoing
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then main "$@"; fi
