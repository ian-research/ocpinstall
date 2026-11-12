#!/bin/bash
set -Eeuo pipefail
umask 077
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$SCRIPT_DIR/lib/common.sh"
source "$SCRIPT_DIR/config/versions.sh"
if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
    parse_security_options "$@"
    require_host
fi
export PATH="$BIN_DIR:$PATH"
trap 'printf "错误: 第 %s 行执行失败，请检查输出后重试。\n" "$LINENO" >&2' ERR

#
# Author: Jun Sun
# Email: junsun@redhat.com
# Organization: Red Hat
# Created Time: 2025-06-05 17:30:00 UTC
# Description: post-configuration OpenShift 4.22.22 three node Cluster in airgap environment

# debug
#set -x

DEFAULT_NFS_SC_DIR="/mnt/ocp422-nfs"
DEFAULT_OCP_DOMAIN="poc.ocprhtest.com"


# 配置本机信息
add_host_info() {
    echo "配置本机信息..."
    if [[ -z ${OCP_DOMAIN:-} ]]; then read -r -p "请输入 OCP_DOMAIN (默认: $DEFAULT_OCP_DOMAIN): " OCP_DOMAIN; fi
    OCP_DOMAIN=${OCP_DOMAIN:-$DEFAULT_OCP_DOMAIN}
    validate_domain "$OCP_DOMAIN" || die "域名无效"

    if [[ -z ${NFS_SERVER:-} ]]; then read -r -p "请输入 NFS SERVER （默认： helper节点 ）：" NFS_SERVER; fi
    NFS_SERVER=${NFS_SERVER:-helper.$OCP_DOMAIN}

    if [[ -z ${NFS_SC_DIR:-} ]]; then read -r -p "请输入 NFS SC DIR （默认： /mnt/nfs ）：" NFS_SC_DIR; fi
    NFS_SC_DIR=${NFS_SC_DIR:-$DEFAULT_NFS_SC_DIR}
    validate_ip "$NFS_SERVER" || validate_domain "$NFS_SERVER" || die "NFS_SERVER 无效"
    [[ $NFS_SC_DIR =~ ^/[a-zA-Z0-9_./-]+$ ]] || die "NFS 路径只能包含字母、数字、下划线、点、短横线和斜线"

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
    export KUBECONFIG=${KUBECONFIG:-$INSTALL_DIR/auth/kubeconfig}
    [[ -r $KUBECONFIG ]] || die "无法读取 KUBECONFIG"
    oc whoami >/dev/null
}

nfs_sc() {
    echo "配置NFS SC"
    # 配置参数
    # 使用用户提供的 NFS_SERVER
    local STORAGE_CLASS_NAME="nfs-storage"  # StorageClass 名称
    local NFS_NAMESPACE="nfs-provisioner"   # NFS Provisioner 部署的命名空间

    # 检查是否已登录 OpenShift
    if ! oc whoami &> /dev/null; then
        echo "请先登录 OpenShift 集群。"
        exit 1
    fi

    # 创建命名空间
    echo "🚀 创建命名空间 $NFS_NAMESPACE..."
    oc create namespace "$NFS_NAMESPACE" --dry-run=client -o yaml | oc apply -f -

    [[ ${NFS_IMAGE:-} == "helper.$OCP_DOMAIN:8443/$LOCAL_REPOSITORY/"* ]] || die "NFS_IMAGE 必须指定本地项目内已镜像的完整镜像地址"
    # 部署 NFS Provisioner
    echo "部署 NFS Provisioner..."
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
          image: $NFS_IMAGE
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
    oc create role use-scc-hostmount-anyuid --verb=use --resource=scc --resource-name=hostmount-anyuid -n "$NFS_NAMESPACE" --dry-run=client -o yaml | oc apply -f -
    oc adm policy add-role-to-user use-scc-hostmount-anyuid -z nfs-provisioner --role-namespace $NFS_NAMESPACE -n $NFS_NAMESPACE

    other_defaults=$(oc get storageclass -o json | jq -r '.items[] | select(.metadata.annotations["storageclass.kubernetes.io/is-default-class"] == "true") | .metadata.name | select(. != "nfs-storage")')
    [[ -z $other_defaults ]] || die "已有其他默认 StorageClass: ${other_defaults}；请先确认默认存储选择"
    # 设置默认 StorageClass
    echo "🚀 设置默认 StorageClass..."
    oc patch storageclass $STORAGE_CLASS_NAME -p '{"metadata": {"annotations": {"storageclass.kubernetes.io/is-default-class": "true"}}}'

    oc rollout status deployment/nfs-provisioner -n "$NFS_NAMESPACE" --timeout=180s

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
    case ${OCP_REGISTRY_STORAGE:-${REGISTRY_STORAGE:-unchanged}} in
        unchanged) echo "未请求修改内部 Registry 存储" ;;
        pvc)
            [[ -n ${REGISTRY_CLAIM:-} ]] || die "REGISTRY_STORAGE=pvc 时必须提供 REGISTRY_CLAIM"
            oc get pvc "$REGISTRY_CLAIM" -n openshift-image-registry >/dev/null
            patch=$(jq -cn --arg claim "$REGISTRY_CLAIM" '{spec:{managementState:"Managed",storage:{pvc:{claim:$claim}}}}')
            oc patch configs.imageregistry.operator.openshift.io cluster --type=merge -p "$patch" ;;
        emptydir)
            oc patch configs.imageregistry.operator.openshift.io cluster --type=merge \
                -p '{"spec":{"managementState":"Managed","replicas":1,"storage":{"emptyDir":{}}}}' ;;
        *) die "REGISTRY_STORAGE 必须是 unchanged、pvc 或 emptydir（实验临时存储）" ;;
    esac
}

# 可选用户初始化，保留已有 OAuth identityProviders。
create_users() {
    [[ ${CREATE_ADMIN:-false} == true ]] || return 0
    local password htpasswd_file providers patch
    read -r -s -p "设置 admin 密码（至少 12 位）: " password
    echo
    [[ ${#password} -ge 12 ]] || die "密码至少 12 位"
    htpasswd_file=$(mktemp)
    printf '%s\n' "$password" | htpasswd -iBc "$htpasswd_file" admin
    unset password
    oc create secret generic ocp422-htpasswd --from-file="htpasswd=$htpasswd_file" \
        -n openshift-config --dry-run=client -o yaml | oc apply -f -
    rm -f "$htpasswd_file"
    providers=$(oc get oauth cluster -o json | jq -c '.spec.identityProviders // []')
    patch=$(jq -cn --argjson providers "$providers" \
      '{spec:{identityProviders:([$providers[] | select(.name != "ocp422-htpasswd")] + [{name:"ocp422-htpasswd",mappingMethod:"claim",type:"HTPasswd",htpasswd:{fileData:{name:"ocp422-htpasswd"}}}])}}')
    oc patch oauth cluster --type=merge -p "$patch"
    oc adm policy add-cluster-role-to-user cluster-admin admin
}

# 显式选择宽松安全模式后，仅作用于指定命名空间的 default SA。
configure_relaxed_scc() {
    [[ $RELAXED_SECURITY == true ]] || return 0
    oc get namespace "$SECURITY_NAMESPACE" >/dev/null
    oc get serviceaccount default -n "$SECURITY_NAMESPACE" >/dev/null
    echo "宽松 SCC: system:serviceaccount:$SECURITY_NAMESPACE:default"
    local scc
    for scc in anyuid hostmount-anyuid privileged; do
        oc adm policy add-scc-to-user "$scc" -z default -n "$SECURITY_NAMESPACE"
    done
}

# 配置operators
configure_operators() {
    echo "配置 Operators..."
    [[ -d "$MIRROR_DIR/working-dir/cluster-resources" ]] || die "缺少 oc-mirror 生成的 cluster-resources"
    local resources="$MIRROR_DIR/working-dir/cluster-resources/"
    if [[ -f "$BUNDLE_DIR/operators-plan.json" ]]; then
        resources="$BUNDLE_DIR/operator-resources.json"
        python3 "$SCRIPT_DIR/lib/operator_resources.py" "$BUNDLE_DIR" "$resources"
    fi
    oc patch OperatorHub cluster --type json -p '[{"op": "add", "path": "/spec/disableAllDefaultSources", "value": true}]'
    oc apply -f "$resources"
    if [[ -n ${OPERATOR_BUNDLE_DIR:-} && $OPERATOR_BUNDLE_DIR != "$BUNDLE_DIR" ]]; then
        resources="$OPERATOR_BUNDLE_DIR/operator-resources.json"
        python3 "$SCRIPT_DIR/lib/operator_resources.py" "$OPERATOR_BUNDLE_DIR" "$resources"
        oc apply -f "$resources"
    fi
}

# NTP 已在安装阶段通过 MachineConfig 和 Bootstrap Ignition 设置。
# 主函数
main() {
    require_host
    add_host_info
    configure_oc_env
    actual_version=$(oc get clusterversion version -o jsonpath='{.status.desired.version}')
    [[ $actual_version == "$OCP_RELEASE" ]] || die "集群版本 $actual_version 与目标 $OCP_RELEASE 不一致"
    oc get clusterversion version -o json | python3 -c '
import json,sys
conditions={c["type"]:c["status"] for c in json.load(sys.stdin)["status"]["conditions"]}
if conditions.get("Available") != "True" or conditions.get("Progressing") != "False" or conditions.get("Failing") != "False":
    sys.exit("集群尚未安装完成或存在故障，拒绝继续配置")'
    if [[ $RELAXED_SECURITY == true ]]; then
        oc get namespace "$SECURITY_NAMESPACE" >/dev/null
        relax_host_security
        configure_relaxed_scc
    fi
    if [[ -n ${NFS_IMAGE:-} ]]; then nfs_sc; else echo "未指定 NFS_IMAGE，跳过 NFS provisioner"; fi
    config_image_registry
    create_users
    if [[ ${APPLY_OPERATORS:-true} == true ]]; then configure_operators; fi
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then main "$@"; fi
