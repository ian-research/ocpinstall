#!/bin/bash
#
# Author: Jun Sun
# Email: junsun@redhat.com
# Organization: Red Hat
# Created Time: 2025-05-05 17:30:00 UTC
# Description: Install OpenShift 4.18.10 three node Cluster in airgap environment

# debug
#set -x

# 默认值
DEFAULT_OCP_DOMAIN="poc.ocprhtest.com"
DEFAULT_LOCAL_REGISTRY="helper.poc.ocprhtest.com:8443"
HARBOR_USER="admin"
DEFAULT_HARBOR_PASSWORD="RedHat123!"
OCP_RELEASE="4.18.10"
CERT_DIR="/opt/harbor/cert"
HARBOR_PORT="8443"
HARBOR_DATA_DIR="/opt/harbor/data"
HELPER_IP_ADDRESS=$(hostname -I | awk '{print $1}')
PRIVATE_IP_HEAD="$(hostname -I| awk -F. '{print $1"."$2"."$3}')"
PRIVATE_IP_END="$(hostname -I| awk -F. '{print $4}')"
DNS_SERVER="$HELPER_IP_ADDRESS"
LOCAL_REPOSITORY="openshift41810"
PRODUCT_REPO="openshift-release-dev"
RELEASE_NAME="ocp-release"
ARCHITECTURE="x86_64"
HTTP_ROOT="/var/www/html"
OCP_EXT_DIR="/opt/"
DEST_CA_DIR="/etc/pki/ca-trust/source/anchors/"
SSH_KEY="/root/.ssh/helpersshkey"
GRUB_CFG_PATH="/opt/grub"
NFS_SC_DIR="/mnt/nfs"
INSTALL_DIR="/opt/ocpinstall"
LOG_FILE="/var/log/openshift-install-local.log"

# 颜色和样式定义
COLOR_RESET='\033[0m'
COLOR_RED='\033[0;31m'
COLOR_GREEN='\033[0;32m'
COLOR_YELLOW='\033[0;33m'
COLOR_BLUE='\033[0;34m'
COLOR_CYAN='\033[0;36m'
STYLE_BOLD='\033[1m'
STYLE_UNDERLINE='\033[4m'

# 验证IP信息
validate_ip() {
  local ip=$1
  if [[ ! $ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
    echo -e "${COLOR_RED}错误: IP地址格式无效${COLOR_RESET}" >&2
    return 1
  fi
  return 0
}

# 文件路径定义
declare -A REQUIRED_FILES=(
  ["离线镜像包"]="/opt/mirror_000001.tar"
  ["Harbor安装包"]="/opt/harbor-offline-installer-v2.12.2.tgz"
  ["oc-mirror包"]="/opt/oc-mirror.rhel9.tar.gz"
  ["openshift-client包"]="/opt/openshift-client-linux-4.18.10.tar.gz"
  ["openshift-install包"]="/opt/openshift-install-linux-4.18.10.tar.gz"
  ["docker-ce安装包"]="/opt/docker-ce.tar.gz"
)

# 检查文件是否存在
check_files() {
  local missing_count=0
  local total_count=0

  echo -e "\n${COLOR_YELLOW}${STYLE_BOLD}正在检查必需文件...${COLOR_RESET}"

  for desc in "${!REQUIRED_FILES[@]}"; do
    ((total_count++))
    if [[ -f "${REQUIRED_FILES[$desc]}" ]]; then
      printf "  ${COLOR_GREEN}✓${COLOR_RESET} %-20s ${COLOR_CYAN}%s${COLOR_RESET}\n" "$desc" "${REQUIRED_FILES[$desc]}"
    else
      printf "  ${COLOR_RED}✗${COLOR_RESET} %-20s ${COLOR_RED}%s (文件缺失)${COLOR_RESET}\n" "$desc" "${REQUIRED_FILES[$desc]}"
      ((missing_count++))
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
    (( ${#desc} > max_len )) && max_len=${#desc}
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
    log "配置本地 YUM 源..."
    local MNT_DIR="/mnt/iso"
    local REPO_DIR="/etc/yum.repos.d"
    local BAK_DIR="$REPO_DIR/bak"
    local LOCAL_REPO="$REPO_DIR/local.repo"

    # 检查是否已经挂载
    if mount | grep -q "$MNT_DIR"; then
        log "本地 YUM 源已挂载，跳过配置。"
        return 0
    fi

    # 检查是否已经配置了本地 YUM 源
    if [ -f "$LOCAL_REPO" ]; then
        log "本地 YUM 源已配置，跳过配置。"
        return 0
    fi

    # 检查 /dev/sr0 是否存在
    if [ ! -e "/dev/sr0" ]; then
        log "错误: /dev/sr0 不存在，请插入光盘！"
        exit 1
    fi

    # 挂载光盘
    mkdir -p "$MNT_DIR"
    mount /dev/sr0 "$MNT_DIR" || { log "错误: 挂载失败，请检查 /dev/sr0 是否可用！"; exit 1; }

    # 备份原有 repo 文件
    mkdir -p "$BAK_DIR"
    mv "$REPO_DIR"/*.repo "$BAK_DIR"/ 2>/dev/null

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
    sudo dnf install -y glibc-langpack-zh python39 > /dev/null 2>&1
}

# 设置 SELinux 为 permissive 模式
set_selinux_permissive() {
    log "设置 SELinux 为 permissive 模式..."
    sudo setenforce 0
    sudo sed -i 's/^SELINUX=enforcing/SELINUX=permissive/' /etc/selinux/config
}

# 关闭防火墙服务
disable_firewalld() {
    log "关闭防火墙服务..."
    sudo systemctl stop firewalld
    sudo systemctl disable firewalld
}

# 配置本机信息
add_host_info() {
    log "配置本机信息..."
    read -p "请输入 OCP_DOMAIN (默认: $DEFAULT_OCP_DOMAIN): " OCP_DOMAIN
    OCP_DOMAIN=${OCP_DOMAIN:-$DEFAULT_OCP_DOMAIN}

    #read -p "请输入 Harbor 管理员用户名 (默认: $DEFAULT_HARBOR_USER): " HARBOR_USER
    #HARBOR_USER=${HARBOR_USER:-$DEFAULT_HARBOR_USER}

    read -s -p "请输入 Harbor 管理员密码 (默认: $DEFAULT_HARBOR_PASSWORD ): " HARBOR_PASSWORD
    HARBOR_PASSWORD=${HARBOR_PASSWORD:-$DEFAULT_HARBOR_PASSWORD}
    echo

    LOCAL_REGISTRY="helper.$OCP_DOMAIN:$HARBOR_PORT"
    HELPER_HOSTNAME="helper.$OCP_DOMAIN"
    REVERSE_DNS=$(hostname -I | awk '{print $1}' | awk -F. '{print $3"."$2"."$1".in-addr.arpa"}')

    if [[ -z "$HELPER_IP_ADDRESS" ]]; then
        log "错误: 无法获取本机 IPv4 地址，请检查网络配置。"
        exit 1
    fi

    if ! grep -qE "^$HELPER_IP_ADDRESS\s+$HELPER_HOSTNAME$" /etc/hosts; then
        echo "$HELPER_IP_ADDRESS $HELPER_HOSTNAME" | sudo tee -a /etc/hosts > /dev/null
    fi

    echo "nameserver $HELPER_IP_ADDRESS" | sudo tee /etc/resolv.conf > /dev/null
    hostnamectl set-hostname helper.$OCP_DOMAIN
}

# 收集节点信息
collect_ips() {
  echo -e "\n${GREEN}=== 节点IP配置 ===${NC}"

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
  echo -e "OCP所使用的域名: ${COLOR_CYAN}$OCP_DOMAIN${COLOR_RESET}"
  echo -e "Harbor管理员密码: ${COLOR_CYAN}$HARBOR_PASSWORD${COLOR_RESET}"
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
    sudo dnf install -y haproxy bind bind-utils skopeo httpd-tools openssl python3.11 python3-pip jq wget nfs-utils  chrony httpd cockpit > /dev/null 2>&1
    sudo dnf groupinstall "Server with GUI" -y
    systemctl enable --now cockpit.socket
    systemctl enable gdm
    mkdir -p /opt/docker-ce
    tar -zxvf /opt/docker-ce.tar.gz -C /opt/
    cd /opt/docker-ce || exit 1
    sudo dnf localinstall  -y  containerd.io-1.7.27-3.1.el9.x86_64.rpm docker-ce-28.0.4-1.el9.x86_64.rpm docker-ce-rootless-extras-28.0.4-1.el9.x86_64.rpm docker-buildx-plugin-0.22.0-1.el9.x86_64.rpm docker-ce-cli-28.0.4-1.el9.x86_64.rpm docker-compose-plugin-2.34.0-1.el9.x86_64.rpm

    # 启动docker
    sudo systemctl enable docker --now
}

# 配置NFS
configure_nfs() {
    log "配置 NFS 共享..."
    NFS_CIDR=$(hostname -I | awk '{print $1}' | awk -F. '{print $1"."$2".0.0/16"}')
    sudo mkdir -p $NFS_SC_DIR
    sudo chmod 777 $NFS_SC_DIR
    echo "$NFS_SC_DIR $NFS_CIDR(rw,sync,no_root_squash,no_subtree_check,no_wdelay)" | sudo tee /etc/exports
    sudo systemctl restart nfs-server rpcbind
    sudo systemctl enable  nfs-server rpcbind nfs-mountd
}

# 配置chrony
configure_chrony() {
    log "配置 chrony..."
    cat <<EOF > /etc/chrony.conf
# 默认配置
driftfile /var/lib/chrony/drift
makestep 1.0 3
rtcsync
logdir /var/log/chrony

# 使用 ntp.tencent.com 作为主要同步源
server $HELPER_IP_ADDRESS iburst
server ntp.tencent.com iburst
server time1.tencentyun.com iburst

# 备用时间服务器（国内公共 NTP 服务）
server ntp.aliyun.com iburst
server time.windows.com iburst
server cn.pool.ntp.org iburst
EOF
    systemctl enable chronyd
    systemctl restart chronyd
    chronyc -a makestep
}

# 配置bind
configure_bind() {
    log "配置 DNS bind 服务..."
    NAMED_CONF="/etc/named.conf"
    cp "$NAMED_CONF" "$NAMED_CONF.bak"

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
$(echo $HELPER_IP_ADDRESS | awk -F. '{print $4}').  IN  PTR  api.$OCP_DOMAIN.
$(echo $HELPER_IP_ADDRESS | awk -F. '{print $4}').  IN  PTR  api-int.$OCP_DOMAIN.
$(echo $HELPER_IP_ADDRESS | awk -F. '{print $4}').  IN  PTR  helper.$OCP_DOMAIN.
$(echo $HELPER_IP_ADDRESS | awk -F. '{print $4}').  IN  PTR  harbor.$OCP_DOMAIN.
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

    chown named:named "$ZONE_FILE" "$REVERSE_ZONE_FILE"
    chmod 640 "$ZONE_FILE" "$REVERSE_ZONE_FILE"
    systemctl restart named
    systemctl enable named
    echo "nameserver $HELPER_IP_ADDRESS" > /etc/resolv.conf
    log "BIND 安装与配置完成！"
}

# 配置haproxy
configure_haproxy() {
    log "配置 HAProxy..."
    HAPROXY_CFG="/etc/haproxy/haproxy.cfg"
    cp "$HAPROXY_CFG" "$HAPROXY_CFG.bak"

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
    bind :9000
    stats uri /stats
    stats refresh 10000ms

listen api-server-6443
  bind *:6443
  mode tcp
  server bootstrap $BOOTSTRAP_IP:6443 check inter 1s
EOF

    # 添加master节点到6443和22623监听
    for i in "${!MASTER_IPS[@]}"; do
        echo "  server master$((i+1)) ${MASTER_IPS[$i]}:6443 check inter 1s" >> "$HAPROXY_CFG"
    done

    cat << EOF >> "$HAPROXY_CFG"

listen machine-config-server-22623
  bind *:22623
  mode tcp
  server bootstrap $BOOTSTRAP_IP:22623 check inter 1s
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

    setsebool -P haproxy_connect_any 1
    systemctl enable --now haproxy
    log "HAProxy 安装与配置完成！"
}

# 配置httpd
configure_httpd() {
    log "配置 HTTPD..."
    sed -i 's/^Listen 80/Listen 9088/' /etc/httpd/conf/httpd.conf
    sed -i 's/Options -Indexes/Options +Indexes/' /etc/httpd/conf.d/welcome.conf
    systemctl enable httpd --now
}

# 配置openshift关联命令行
config_oc_cli() {
  log "配置 OpenShift CLI..."
  BIN_DIR="/usr/local/bin"
  tar -xvf /opt/openshift-client-linux-4.18.10.tar.gz -C $BIN_DIR
  tar -xvf /opt/openshift-install-linux-4.18.10.tar.gz -C $BIN_DIR
  tar -xvf /opt/oc-mirror.rhel9.tar.gz -C $BIN_DIR

    for BINARY in "oc" "kubectl" "oc-mirror" "openshift-install"; do
        FOUND=$(find "$BIN_DIR" -name "$BINARY" -type f)
        if [ -n "$FOUND" ]; then
            chmod +x "$FOUND"
            cp "$FOUND" "$BIN_DIR"
            echo "已移动并设置可执行权限: $BIN_DIR/$BINARY"
        else
            echo "未找到可执行文件: $BINARY"
        fi
    done
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
  if [[ -f "${SERVER_CERT}" && -f "${SERVER_KEY}" ]]; then
    echo "  ✓ 检测到现有证书，跳过生成"
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
  sudo cp "${SERVER_CERT}" "/etc/pki/ca-trust/source/anchors/${OCP_DOMAIN}.crt"
  sudo update-ca-trust extract
}

# 安装配置harbor
install_harbor() {
    log "安装 Harbor..."
    local SERVER_CRT="${CERT_DIR}/${OCP_DOMAIN}.crt"
    local SERVER_CERT="${CERT_DIR}/${OCP_DOMAIN}.cert"
    local SERVER_KEY="${CERT_DIR}/${OCP_DOMAIN}.key"

    # 创建 Harbor 配置目录
    mkdir -p /opt/harbor

    # 解压 Harbor 安装包
    tar -xvf /opt/harbor-offline-installer-v2.12.2.tgz -C /opt/harbor

    # 进入 Harbor 目录
    cd /opt/harbor/harbor || exit 1

    # 修改配置文件
    cp harbor.yml.tmpl harbor.yml
    sed -i "s/^hostname:.*/hostname: $HELPER_HOSTNAME/" harbor.yml
    sed -i "s/^  password:.*/  password: $HARBOR_PASSWORD/" harbor.yml
    sed -i "s/^harbor_admin_password:.*/harbor_admin_password: $HARBOR_PASSWORD/" harbor.yml
    sed -i "s|^# https:|https:|" harbor.yml
    sed -i "s/[[:space:]]*port:[[:space:]]*80/  port: 8088/g" harbor.yml
    sed -i "s/[[:space:]]*port:[[:space:]]*443/  port: 8443/g" harbor.yml
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
  cp -f $SERVER_CERT /etc/docker/certs.d/$LOCAL_REGISTRY
  cp -f $SERVER_KEY  /etc/docker/certs.d/$LOCAL_REGISTRY
  cp -f $CA_CRT /etc/docker/certs.d/$LOCAL_REGISTRY

  #修改register.conf
  CONFIG_CONTENT=$(cat <<EOF

[[registry]]
location="registry.redhat.io"
[[registry.mirror]]
location="$LOCAL_REGISTRY"
insecure=true

[[registry]]
location="quay.io"
[[registry.mirror]]
location="$LOCAL_REGISTRY"
insecure=true
EOF
  )
  # 检查文件是否已包含这些配置（避免重复添加）
  if ! grep -q "location = \"$LOCAL_REGISTRY\"" /etc/containers/registries.conf; then
      echo "添加镜像仓库配置到 /etc/containers/registries.conf"
      echo "$CONFIG_CONTENT" | sudo tee -a /etc/containers/registries.conf > /dev/null
      echo "配置已添加成功"
  else
      echo "镜像仓库配置已存在，无需重复添加"
  fi
  systemctl restart docker

  cd "/opt/harbor/harbor" || exit 1
  docker compose up -d

  sleep 5
  # 使用 docker 登录 Quay
  echo "正在登录 Harbor : $LOCAL_REGISTRY..."
  mkdir -p ~/.docker
  echo "$HARBOR_PASSWORD" | docker login "$LOCAL_REGISTRY" --username "$HARBOR_USER" --password-stdin

  # 检查登录是否成功
  if [ $? -eq 0 ]; then
      echo "登录成功！"
  else
      echo "登录失败，请检查用户名、密码或注册表地址。"
      exit 1
  fi
  log "harbor安装完成已启动"
}

# 创建harbor项目
create_harbor_project() {
  log " 创建Harbor项目 [$LOCAL_REPOSITORY]..."
  curl -sk -u admin:$HARBOR_PASSWORD \
    -H "Content-Type: application/json" \
    -X POST "https://${LOCAL_REGISTRY}/api/v2.0/projects" \
    -d '{
          "project_name": "'$LOCAL_REPOSITORY'",
          "metadata": {
            "public": "true"
          }
        }'
}

# 配置OpenShift离线镜像仓库
upload_ocp_image() {
    log "配置 OpenShift 离线镜像仓库..."
    log "创建 imagesetconfiguration.yaml..."
    cat << EOF > /opt/imagesetconfiguration.yaml
kind: ImageSetConfiguration
apiVersion: mirror.openshift.io/v2alpha1
mirror:
  platform:
    channels:
    - name: stable-4.18
      minVersion: 4.18.5
      maxVersion: 4.18.5
  operators:
    - catalog: registry.redhat.io/redhat/redhat-operator-index:v4.18
      packages:
       - name: ansible-automation-platform
       - name: local-storage-operator
       - name: cluster-logging
       - name: kubernetes-nmstate-operator
       - name: elasticsearch-operator
       - name: odf-operator
       - name: metallb-operator
       - name: loki-operator
       - name: redhat-oadp-operator
       - name: node-healthcheck-operator
       - name: mtv-operator
       - name: web-terminal
       - name: kubevirt-hyperconverged
       - name: self-node-remediation
  additionalImages:
   - name: registry.redhat.io/ubi8/ubi:latest
   - name: registry.redhat.io/ubi9/ubi@sha256:20f695d2a91352d4eaa25107535126727b5945bff38ed36a3e59590f495046f0
   - name: quay.io/rh_ee_junsun/test/nfs-subdir-external-provisioner:v4.0.2
   - name: quay.io/minio/minio:latest
   - name: quay.io/rh_ee_junsun/filetranspiler:latest
EOF

    # 推送镜像到本地仓库
    log "推送镜像到本地镜像仓库..."
    mkdir -p /opt/41810
    mv -f /opt/mirror_000001.tar /opt/41810/
    if ! oc mirror -c /opt/imagesetconfiguration.yaml --from file:///opt/41810 docker://$LOCAL_REGISTRY/$LOCAL_REPOSITORY --v2; then
        log "错误: 镜像同步到本地仓库失败，请检查网络或仓库配置。"
        exit 1
    fi
    log "OpenShift 离线镜像同步完成！"
}

# 配置SSH Key
configure_ssh_key() {
    log "配置 SSH Key..."
    if [ ! -f "$SSH_KEY" ]; then
        ssh-keygen -t rsa -b 4096 -N "" -f "$SSH_KEY"
    fi
}

create_install_config() {
    log "创建 install-config.yaml 文件..."

    # 定义常量
    PULL_SECRET=$(jq -c . ~/.docker/config.json )
    # 创建 install-config.yaml 文件
    log "生成 install-config.yaml 文件..."
    SSH_KEY_CONTENT=$(cat "$SSH_KEY".pub )
    cat << EOF > /opt/install-config.yaml
apiVersion: v1
baseDomain: $(echo "$OCP_DOMAIN" | cut -d '.' -f 2-)
compute:
- hyperthreading: Enabled
  name: worker
  replicas: 0
controlPlane:
  hyperthreading: Enabled
  name: master
  replicas: 3
metadata:
  name: $(echo "$OCP_DOMAIN" | cut -d '.' -f 1)
networking:
  clusterNetworks:
  - cidr: 10.128.0.0/14
    hostPrefix: 23
  networkType: OVNKubernetes
  serviceNetwork:
  - 172.30.0.0/16
platform:
  none: {}
fips: false
pullSecret: '$PULL_SECRET'
sshKey: '$SSH_KEY_CONTENT'
additionalTrustBundle: |
$(sed 's/^/   /g' "${CERT_DIR}/ca.crt")
ImageDigestSources:
- mirrors:
  - ${LOCAL_REGISTRY}/${LOCAL_REPOSITORY}/openshift/release-images
  source: quay.io/openshift-release-dev/ocp-release
- mirrors:
  - ${LOCAL_REGISTRY}/${LOCAL_REPOSITORY}/openshift/release
  source: quay.io/openshift-release-dev/ocp-v4.0-art-dev
EOF

}

# 创建manifest,ignition文件
create_manifest_config() {
    # 创建manifest文件
    log "创建manifest文件..."
    rm -rf "$INSTALL_DIR"
    mkdir -p "$INSTALL_DIR"
    cp -f /opt/install-config.yaml "$INSTALL_DIR/install-config.yaml"
    openshift-install create manifests --dir="$INSTALL_DIR" || {
        log "错误: 创建 manifest 文件失败"
        exit 1
    }

    # 修改manifest文件
    #log "修改manifest文件..."
    #sed -i 's/mastersSchedulable: true/mastersSchedulable: false/' "$INSTALL_DIR/manifests/cluster-scheduler-02-config.yml" || {
    #    log "错误: 修改manifest 配置文件失败"
    #    exit 1
    #}

    # 创建 ignition 配置文件
    log "创建 ignition 配置文件..."
    openshift-install create ignition-configs --dir="$INSTALL_DIR" || {
        log "错误: 创建 ignition 配置文件失败"
        exit 1
    }

    # 拷贝 ignition 文件到 HTTP 根目录
    log "拷贝 ignition 文件到 HTTP 根目录..."
    mkdir -p "$HTTP_ROOT/ignition"
    cp -f "$INSTALL_DIR"/{bootstrap,master,worker}.ign "$HTTP_ROOT/ignition/"
    chmod 644 "$HTTP_ROOT"/ignition/*.ign
    log "ignition 文件已拷贝到 $HTTP_ROOT/ignition/ 目录下"

    # 拷贝证书及公钥到 HTTP 根目录
    log "拷贝证书及公钥到 HTTP 根目录..."
    mkdir -p "$HTTP_ROOT/auth"
    cp -f "$INSTALL_DIR/auth/kubeadmin-password" "$HTTP_ROOT/auth/kubeadmin-password"
    cp -f "$INSTALL_DIR/auth/kubeconfig" "$HTTP_ROOT/auth/kubeconfig"
    chmod 644 "$HTTP_ROOT/auth/kubeadmin-password" "$HTTP_ROOT/auth/kubeconfig"

    log "install-config 准备完成！"
}

# keepgoing
keepgoing () {
    echo -e "\n${COLOR_YELLOW}${STYLE_BOLD}=== 安装完成 ===${COLOR_RESET}"
    echo -e "${COLOR_GREEN}${STYLE_BOLD}请按照以下步骤继续：${COLOR_RESET}"
    echo -e "1. 在所有待安装节点使用coreos-live.iso启动"
    echo -e "   iso文件路径: http://$HELPER_HOSTNAME:9088/iso/rhcos-live.x86_64.iso"
    echo -e "2. 在所有待安装节点配置网络确认盘符等信息"
    echo -e "   通过nmcli或nmtui配置IP，DNS，bond以及网桥等信息"
    echo -e "3. 在所有待安装节点执行以下命令安装OpenShift"
    echo -e "   ${COLOR_CYAN}以bootstrap为例(修改为实际安装的盘符)： coreos-installer install /dev/sda -I http://$HELPER_HOSTNAME:9088/ignition/bootstrap.ign --insecure --insecure-ignition --copy-network ${COLOR_RESET}"
    echo -e "   ${COLOR_CYAN}以master为例（修改为实际安装的盘符）： coreos-installer install /dev/nvme0n1 -I http://$HELPER_HOSTNAME:9088/ignition/master.ign --insecure --insecure-ignition --copy-network ${COLOR_RESET}"
    echo -e "4. 等待安装完成并重启节点"
    echo -e "5. approve pending状态的csr（需多次执行）"
    echo -e "   ${COLOR_CYAN}oc get csr${COLOR_RESET}"
    echo -e "   ${COLOR_CYAN}oc adm certificate approve <csr-name>${COLOR_RESET}"
    echo -e "6. 等待所有节点状态变为Ready"
    echo -e "   oc get nodes"
    echo -e "7. 集群密码与配置文件位于：/var/www/html/auth/"
}

# 主函数
main() {
    validate_ip
    check_files
    hint
    log
    check_root
    configure_local_yum
    add_chinese_support
    set_selinux_permissive
    disable_firewalld
    add_host_info
    collect_ips
    show_summary
    confirm_config
    install_dependencies
    configure_nfs
    configure_chrony
    configure_bind
    configure_haproxy
    configure_httpd
    config_oc_cli
    setup_certs
    install_harbor
    start_harbor
    create_harbor_project
    upload_ocp_image
    configure_ssh_key
    create_install_config
    create_manifest_config
    keepgoing
}

main
