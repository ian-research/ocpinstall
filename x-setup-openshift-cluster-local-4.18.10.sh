#!/bin/bash
#
# Author: Jun Sun
# Email: junsun@redhat.com
# Organization: Red Hat
# Created Time: 2025-06-05 17:30:00 UTC
# Description: post-configuration OpenShift 4.18.10 three node Cluster in airgap environment

# debug
#set -x

DEFAULT_NFS_SERVER=$(uname -n)
DEFAULT_NFS_SC_DIR="/mnt/nfs"
DEFAULT_OCP_DOMAIN="poc.ocprhtest.com"


# 颜色和样式定义
COLOR_RESET='\033[0m'
COLOR_RED='\033[0;31m'
COLOR_GREEN='\033[0;32m'
COLOR_YELLOW='\033[0;33m'
COLOR_BLUE='\033[0;34m'
COLOR_CYAN='\033[0;36m'
STYLE_BOLD='\033[1m'
STYLE_UNDERLINE='\033[4m'

# 文件路径定义
declare -A REQUIRED_FILES=(
  ["nfs-subdir-external-provisioner"]="/opt/nfs-subdir-external-provisioner.tar"
  ["butane-amd64"]="/opt/butane-amd64"
 
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

# 配置本机信息
add_host_info() {
    echo "配置本机信息..."
    read -p "请输入 OCP_DOMAIN (默认: $DEFAULT_OCP_DOMAIN): " OCP_DOMAIN
    OCP_DOMAIN=${OCP_DOMAIN:-$DEFAULT_OCP_DOMAIN}

    read -p "请输入 NFS SERVER （默认： helper节点 ）：" NFS_SERVER
    NFS_SERVER=${NFS_SERVER:-$DEFAULT_NFS_SERVER}

    read -p "请输入 NFS SC DIR （默认： /mnt/nfs ）：" NFS_SC_DIR
    NFS_SC_DIR=${NFS_SC_DIR:-$DEFAULT_NFS_SC_DIR}

    LOCAL_REGISTRY="helper.$OCP_DOMAIN:8443"
    QUAY_HOSTNAME="helper.$OCP_DOMAIN"
#    QUAY_IP_ADDRESS=$(hostname -I | awk '{print $1}')
#    REVERSE_DNS=$(hostname -I | awk '{print $1}' | awk -F. '{print $3"."$2"."$1".in-addr.arpa"}')
#    
#    if [[ -z "$QUAY_IP_ADDRESS" ]]; then
#        echo "错误: 无法获取本机 IPv4 地址，请检查网络配置。"
#        exit 1
#    fi
#
#    if ! grep -qE "^$QUAY_IP_ADDRESS\s+$QUAY_HOSTNAME$" /etc/hosts; then
#        echo "$QUAY_IP_ADDRESS $QUAY_HOSTNAME" | sudo tee -a /etc/hosts > /dev/null
#    fi

#    echo "nameserver $DNS_SERVER" | sudo tee /etc/resolv.conf > /dev/null
#    hostnamectl set-hostname helper.$OCP_DOMAIN
}

# 配置OC Env
configure_oc_env() {
    mkdir -p "/root/.kube"
    cp -f "/var/www/html/auth/kubeconfig"  /root/.kube/config
}

nfs_sc() {
    echo "配置NFS SC"
    # 配置参数
    local NFS_SERVER="helper.$OCP_DOMAIN"  # NFS 服务器地址
    local STORAGE_CLASS_NAME="nfs-storage"  # StorageClass 名称
    local NFS_NAMESPACE="nfs-provisioner"   # NFS Provisioner 部署的命名空间

    # 检查是否已登录 OpenShift
    if ! oc whoami &> /dev/null; then
        echo "请先登录 OpenShift 集群。"
        exit 1
    fi

    # 创建命名空间
    echo "🚀 创建命名空间 $NFS_NAMESPACE..."
    oc create namespace "$NFS_NAMESPACE" || echo "命名空间 $NFS_NAMESPACE 已存在。"

    if ! docker  load -i /opt/nfs-subdir-external-provisioner.tar; then
        echo "错误: 加载 nfs-provisioner 镜像失败"
        exit 1
    fi
    docker  tag quay.io/rh_ee_junsun/test/nfs-subdir-external-provisioner:v4.0.2 helper.$OCP_DOMAIN:8443/openshift41810/nfs-subdir-external-provisioner:v4.0.2
    docker  push helper.$OCP_DOMAIN:8443/openshift41810/nfs-subdir-external-provisioner:v4.0.2

    # 部署 NFS Provisioner
    echo "部署 NFS Provisioner..."
    if oc get deployment nfs-provisioner -n "$NFS_NAMESPACE" &> /dev/null; then
        echo "NFS Provisioner 已存在，跳过部署。"
    else
        cat <<EOF | oc apply -f -
apiVersion: apps/v1
kind: Deployment
metadata:
  name: nfs-provisioner
  namespace: $NFS_NAMESPACE
spec:
  replicas: 1
  selector:
    matchLabels:
      app: nfs-provisioner
  template:
    metadata:
      labels:
        app: nfs-provisioner
    spec:
      serviceAccountName: nfs-provisioner
      containers:
        - name: nfs-provisioner
          image: helper.$OCP_DOMAIN:8443/openshift41810/nfs-subdir-external-provisioner:v4.0.2
          volumeMounts:
            - name: nfs-client-root
              mountPath: /persistentvolumes
          env:
            - name: PROVISIONER_NAME
              value: $NFS_SERVER/nfs
            - name: NFS_SERVER
              value: $NFS_SERVER
            - name: NFS_PATH
              value: $NFS_SC_DIR
      volumes:
        - name: nfs-client-root
          nfs:
            server: $NFS_SERVER
            path: $NFS_SC_DIR
EOF
    fi

    # 创建 ServiceAccount 和 RBAC 权限
    echo "🚀 创建 ServiceAccount 和 RBAC 权限..."
    cat <<EOF | oc apply -f -
apiVersion: v1
kind: ServiceAccount
metadata:
  name: nfs-provisioner
  namespace: $NFS_NAMESPACE
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: nfs-provisioner-runner
rules:
  - apiGroups: [""]
    resources: ["nodes"]
    verbs: ["get", "list", "watch"]
  - apiGroups: [""]
    resources: ["persistentvolumes"]
    verbs: ["get", "list", "watch", "create", "delete"]
  - apiGroups: [""]
    resources: ["persistentvolumeclaims"]
    verbs: ["get", "list", "watch", "update"]
  - apiGroups: ["storage.k8s.io"]
    resources: ["storageclasses"]
    verbs: ["get", "list", "watch"]
  - apiGroups: [""]
    resources: ["events"]
    verbs: ["create", "update", "patch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: run-nfs-provisioner
subjects:
  - kind: ServiceAccount
    name: nfs-provisioner
    namespace: $NFS_NAMESPACE
roleRef:
  kind: ClusterRole
  name: nfs-provisioner-runner
  apiGroup: rbac.authorization.k8s.io
---
kind: Role
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  name: leader-locking-nfs-provisioner
  namespace: $NFS_NAMESPACE
rules:
  - apiGroups: [""]
    resources: ["endpoints"]
    verbs: ["get", "list", "watch", "create", "update", "patch"]
---
kind: RoleBinding
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  name: leader-locking-nfs-provisioner
  namespace: $NFS_NAMESPACE
subjects:
  - kind: ServiceAccount
    name: nfs-provisioner
    namespace: $NFS_NAMESPACE
roleRef:
  kind: Role
  name: leader-locking-nfs-provisioner
  apiGroup: rbac.authorization.k8s.io
EOF

    # 创建 StorageClass
    echo "创建 StorageClass..."
    cat <<EOF | oc apply -f -
apiVersion: storage.k8s.io/v1
kind: StorageClass
metadata:
  name: $STORAGE_CLASS_NAME
provisioner: $NFS_SERVER/nfs
parameters:
  archiveOnDelete: "false"
EOF

    # 创建 SCC 并绑定到 ServiceAccount
    oc create role use-scc-hostmount-anyuid --verb=use --resource=scc --resource-name=hostmount-anyuid -n $NFS_NAMESPACE
    oc adm policy add-role-to-user use-scc-hostmount-anyuid -z nfs-provisioner --role-namespace $NFS_NAMESPACE -n $NFS_NAMESPACE

    # 设置默认 StorageClass
    echo "🚀 设置默认 StorageClass..."
    oc patch storageclass $STORAGE_CLASS_NAME -p '{"metadata": {"annotations": {"storageclass.kubernetes.io/is-default-class": "true"}}}'

    # 检查 StorageClass 是否创建成功
    if oc get storageclass $STORAGE_CLASS_NAME &> /dev/null; then
        echo "NFS StorageClass 配置完成！"
        echo "StorageClass 名称: $STORAGE_CLASS_NAME"
    else
        echo "StorageClass 创建失败！"
        exit 1
    fi
}

# 配置image registry
config_image_registry() {
    echo "配置image registry..."
    oc patch configs.imageregistry.operator.openshift.io cluster -p '{"spec":{"managementState": "Managed","storage":{"pvc":{"claim":""}}}}' --type=merge
}

# 创建 OpenShift 中的用户 admin, user01, user02 并配置密码为 RedHat123!
create_users() {
  echo "创建 OpenShift 中的用户 admin, user01, user02 并配置密码为 RedHat123!"
  # 定义用户和密码
  OAUTH_NAME="htpasswd-provider"
  SECRET_NAME="htpasswd-secret"
  USERS=("admin" "user01" "user02")
  PASSWORD="RedHat123!"

  # 创建一个 htpasswd 文件（如果没有的话）
  HTPASSWD_FILE="/tmp/openshift-htpasswd"  # 使用 /tmp 目录以避免权限问题

  # 检查 htpasswd 文件是否存在，如果不存在则创建一个新的
  if [ ! -f "$HTPASSWD_FILE" ]; then
    echo "Creating new htpasswd file..."
    touch "$HTPASSWD_FILE"
  fi

  # 为每个用户添加到 htpasswd 文件中
  for USERNAME in "${USERS[@]}"; do
    echo "Adding user $USERNAME to htpasswd file with password $PASSWORD"
    if ! htpasswd -b "$HTPASSWD_FILE" "$USERNAME" "$PASSWORD"; then
      echo "Failed to add user $USERNAME to htpasswd file!"
      exit 1
    fi
  done

  # 配置 OpenShift 使用 htpasswd 认证
  echo "Configuring OpenShift to use htpasswd for authentication..."
  if ! oc create secret generic $SECRET_NAME --from-file=htpasswd=$HTPASSWD_FILE -n openshift-config; then
    echo "Failed to create Secret!"
    exit 1
  fi

  # 检查 Secret 是否创建成功
  if ! oc get secret $SECRET_NAME -n openshift-config &> /dev/null; then
    echo "Secret 创建失败！"
    exit 1
  fi

  # 配置 OAuth 使用 htpasswd 身份提供者
  echo "配置 OAuth 使用 htpasswd 身份提供者..."
  if oc get oauth cluster &> /dev/null; then
    echo "Updating existing OAuth configuration..."
    oc patch oauth cluster --type=merge -p '{"spec":{"identityProviders":[{"name":"'$OAUTH_NAME'","mappingMethod":"claim","type":"HTPasswd","htpasswd":{"fileData":{"name":"'$SECRET_NAME'"}}}]}}'
  else
    echo "Creating new OAuth configuration..."
    cat <<EOF | oc apply -f -
apiVersion: config.openshift.io/v1
kind: OAuth
metadata:
  name: cluster
spec:
  identityProviders:
  - name: $OAUTH_NAME
    mappingMethod: claim
    type: HTPasswd
    htpasswd:
      fileData:
        name: $SECRET_NAME
EOF
  fi

  # 检查 OAuth 配置是否成功
  if ! oc get oauth cluster -o yaml | grep $OAUTH_NAME &> /dev/null; then
    echo "OAuth 配置失败！"
    exit 1
  fi

  # 给 admin 用户添加超级管理员权限
  echo "Granting admin user cluster-admin privileges..."
  oc adm policy add-cluster-role-to-user cluster-admin "admin"

  # 给 user01 配置项目管理员权限
  echo "Granting user01 project-admin privileges..."
  if oc get project test-project &> /dev/null; then
    oc adm policy add-role-to-user admin "user01" -n test-project
  else
    echo "Project test-project does not exist. Skipping permission assignment for user01."
  fi

  # 给 user02 配置查看权限
  echo "Granting user02 view privileges..."
  oc adm policy add-cluster-role-to-user view "user02"

  # 输出成功消息
  echo "Users admin, user01, and user02 created successfully with appropriate privileges."
}

# 配置全开放SCC
configure_scc() {
    echo "配置全开放 SCC..."
    oc adm policy add-scc-to-user anyuid -z default
    oc adm policy add-scc-to-user hostmount-anyuid -z default
    oc adm policy add-scc-to-user privileged -z default
}

# 配置operators
configure_operators() {
    echo "配置 Operators..."
    oc patch OperatorHub cluster --type json -p '[{"op": "add", "path": "/spec/disableAllDefaultSources", "value": true}]'
    oc apply -f /opt/41810/working-dir/cluster-resources/
}

# 配置chronyc
set_chronyc(){
  # 创建 butane-amd64 编码后的 chrony 配置内容
  chmod +x /opt/butane-amd64
  mv /opt/butane-amd64 /usr/local/bin/butane
  cat > /opt/chrony.bu < EOF 
variant: openshift
version: 4.18.0
metadata:
  name: 99-master-chrony
  labels:
    machineconfiguration.openshift.io/role: master
openshift:
  kernel_arguments:
    - loglevel=7
storage:
  files:
    - path: /etc/chrony.conf
      mode: 0644
      overwrite: true
      contents:
        inline: |
          server helper.${OCP_DOMAIN} iburst prefer
          driftfile /var/lib/chrony/drift
          makestep 1.0 3
          rtcsync
          logdir /var/log/chrony
          leapsectz right/Asia/Shanghai
EOF
  # 使用 butane 编码 chrony 配置文件
  butane /opt/chrony.bu -o /opt/99-master-chrony.yaml

  # apply MachineConfig YAML 文件
  oc apply -f /opt/99-master-chrony.yaml 
}

# 主函数
main() {
    check_files
    add_host_info
    configure_oc_env
    nfs_sc
    config_image_registry
    create_users
    configure_scc
    configure_operators
    set_chronyc
}

main
