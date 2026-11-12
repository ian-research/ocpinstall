# OpenShift 5 离线三节点安装

**完整离线准备入口：** `bash v5/prepare-operators.sh`，选择“准备完整离线包”。包含 OpenShift 本体、工具、RHCOS、Helper 软件和 Operator；搬迁后依次运行 `verify.sh`、`install.sh`、`configure.sh`。详见 [完整交付流程](DELIVERY.md) 和 [实测范围](VALIDATION.md)。

本目录从项目原有 4.x 脚本派生，目标为 **OpenShift 5.0.1 / amd64**，采用裸金属 UPI、三个 Master、零 Worker。4.x 的入口、配置和说明保持原样。版本固定在 `config/versions.sh`，不会自动跟随 stable 更新。

| 入口 | 用途 |
| --- | --- |
| `prepare-offline.sh` | 下载工具、生成镜像配置、导出/导入离线镜像、校验归档 |
| `install-cluster.sh` | 配置 Helper、Harbor、DNS、HAProxy、HTTP、NFS/NTP，并生成安装资料 |
| `setup-cluster.sh` | 应用离线 Operator 资源、可选 NFS、内部 Registry、管理员和宽松 SCC |
| `apply-operators.sh` | 检查版本与集群状态，仅应用已验证 Operator 包的离线目录/镜像规则；支持服务端预检查 |
| `prepare-operators.sh` | 交互选择 Operator，解析依赖并独立导出/导入离线包，详见 [OPERATORS.md](OPERATORS.md) |

5.x 文件在独立的 `v5/` 目录，但 Helper 会使用相同的系统服务和端口，**请使用独立 RHEL 9 Helper 主机**。安装脚本检测到旧版 `/opt/ocpinstall` 或 `/opt/harbor/harbor/harbor.yml` 时会退出。不能在同一 Helper 上同时运行两套 DNS、HAProxy 和 Harbor，也不是把现有 4.x 集群原地升级到 5.x 的工具。

授时默认使用真正可达的内部上游 `NTP_SERVER`，不能填写 Helper 自己。没有上游的完全隔离环境，可显式设置 `NTP_MODE=local` 并省略 `NTP_SERVER`，以 Helper 时钟统一节点；请先核对 Helper 时间。上游模式未同步会停止安装。完整交付路径与重试方法见 [DELIVERY.md](DELIVERY.md)。

## 1. 可选：分步准备工具和平台镜像

推荐使用本文开头的完整离线准备入口，自动收集平台、工具、RHCOS、Helper RPM 和 Harbor。以下为单独维护平台包的分步方式；不要把分步平台包当作完整交付包。

使用 Linux x86_64，安装 Python 3.9+、Bash。源仓库 pull secret 保存在 bundle 外，权限 `600`，例如 `/root/redhat-pull-secret.json`。

### 工具下载

5.0.1 官方平台目录没有提供旧脚本假设的 `oc-mirror.rhel9.tar.gz`。请从 Red Hat Console 的 OpenShift disconnected installation tools 获取适用于 RHEL 9/x86_64、支持目标平台的 oc-mirror v2，以及来源对应的 SHA256。源端和离线 Helper 必须使用同一个二进制。不要重命名解压后的 `oc-mirror`。

下面命令下载官方 5.0.1 RHEL 9 客户端、标准 Linux 安装器，并收录你单独下载的 oc-mirror：

```bash
bash v5/prepare-offline.sh tools --bundle /data/ocp5-bundle \
  --oc-mirror-archive /data/downloads/oc-mirror.tar.gz \
  --oc-mirror-sha256 REPLACE_WITH_OFFICIAL_64_HEX_SHA256
```

也可用 `--oc-mirror-url https://...` 代替本地归档，同样必须传入 `--oc-mirror-sha256`。只下载平台工具时可省略这两个参数，后续需再次运行并补齐插件。平台归档逐一对照其固定版本目录的官方 SHA256 清单。

将工具解压到联网主机的独立目录，不覆盖已有 4.x 命令：

```bash
mkdir -p /data/ocp5-bin
for archive in /data/ocp5-bundle/tools/*.tar.gz; do
  tar -xzf "$archive" -C /data/ocp5-bin
done
chmod +x /data/ocp5-bin/oc /data/ocp5-bin/kubectl /data/ocp5-bin/oc-mirror /data/ocp5-bin/openshift-install
export PATH=/data/ocp5-bin:$PATH
oc mirror --v2 --help
openshift-install version
```

### 导出平台镜像

```bash
bash v5/prepare-offline.sh export --bundle /data/ocp5-bundle \
  --authfile /root/redhat-pull-secret.json --dry-run

# 检查镜像列表与错误输出后，去掉 --dry-run 正式导出：
bash v5/prepare-offline.sh export --bundle /data/ocp5-bundle \
  --authfile /root/redhat-pull-secret.json
```

默认生成 `stable-5.0`、`minVersion=maxVersion=5.0.1`、`amd64` 的配置。可以先通过 `config` 子命令在本机预览，无需 oc 或网络。

### 同时镜像 Operator / 附加镜像

需要自动补齐 Operator 依赖时，使用独立的 `bash v5/prepare-operators.sh`，见 [交互式 Operator 离线指南](OPERATORS.md)。下列 `prepare-offline.sh --operator` 是手工指定清单的入口，不会自动解析依赖；oc-mirror v2 本身也不自动补齐依赖。

5.x 不会自动猜测 Operator catalog。通过 `--catalog` 明确传入经过核实的目录镜像，再选包与 channel；使用该目录实际存在的版本。下面的目录地址是占位符，必须替换后运行：

```bash
bash v5/prepare-offline.sh export --bundle /data/ocp5-with-operators \
  --authfile /root/redhat-pull-secret.json \
  --catalog 'REPLACE_WITH_VERIFIED_CATALOG_IMAGE' \
  --operator local-storage-operator \
  --operator kubernetes-nmstate-operator \
  --image registry.k8s.io/sig-storage/nfs-subdir-external-provisioner:v4.0.2 \
  --dry-run
```

检查结果后使用相同参数去掉 `--dry-run`。Operator 包和附加镜像的可用性由实际仓库及 dry-run 确认；附加的 NFS provisioner 是社区镜像，未宣称已获 5.0 认证。可用 digest 固定 catalog、附加镜像，以提高重现性。

- `--operator PACKAGE[:CHANNEL]` 可重复；未指定 Operator 版本范围时遵循 oc-mirror 默认筛选行为。
- `--all-operators --catalog IMAGE` 导出完整目录，可能占用大量磁盘。
- `--parallel-images 4 --parallel-layers 5` 调整并发，取值 1–10。
- `--archive-size 20` 设置每个归档的目标 GiB，非单个镜像层大小的硬限制。
- `--cache-dir /data/ocp5-cache` 指定持久缓存；默认位于 bundle 旁的 `<bundle>-cache`。
- 需要扩充选包、换版本时使用新的 bundle，避免混用配置和历史归档。

整个 bundle 包含 `tools/`、`images/*.tar`、配置、插件二进制指纹和成功导出后的 `checksums.json`。请完整转移至 Helper 的 **`/opt/ocp5-bundle/`**，不要只复制第一个 tar；源端缓存保留用于重试和增量操作，凭据不会复制。

只有真实导出成功且未发现非空错误日志时才生成成功清单。dry-run 仍需要访问源仓库，不能作为已下载完成的证明。归档或工具校验失败时脚本退出；本轮新建或更新的非空错误日志会阻止标记成功；历史日志保留用于排查。

## 2. Helper 前提和输入

- 独立、最小化安装的 RHEL 9 x86_64，root、Bash 4+、Python 3 已安装。
- 手动 ISO 软件源模式：RHEL 9 ISO 挂载到 `/dev/sr0`。脚本通过 ISO 的 BaseOS/AppStream 安装依赖，包括 `python3-pyyaml`；请使用包含所需依赖的 RHEL 9 DVD 版本。
- AWS RHEL 9 AMI 可改用 `--repo-mode existing`（或 `YUM_REPO_MODE=existing`），保留并使用现有 RHUI/YUM 源，跳过 DVD 挂载和源文件变更。此模式下 Helper 安装依赖时需要访问软件源。
- Helper、Bootstrap 和三个 Master 的静态 IPv4 地址在同一 `/24` 且互不重复；网络不能与 `10.128.0.0/14` Pod 网络及 `172.30.0.0/16` Service 网络重叠。
- 可访问的内部上游 NTP。脚本配置 Helper 提供 NTP，并在安装阶段向 Master MachineConfig 和 Bootstrap Ignition 写入 Helper 的时间源。Live ISO 阶段也应先确认时间正确。
- 按官方要求准备节点 CPU/内存/磁盘和低延迟存储；Bootstrap/Master 使用目标安装器指定的 RHCOS，不使用 Helper 的 RHEL ISO。
- 为归档、镜像仓库、缓存和解压预留足够空间；容量取决于所选 Operator，不保证固定 200 GB 就够用。

准备以下独立依赖：

| 文件 | 路径与内容 |
| --- | --- |
| 完整 bundle | `/opt/ocp5-bundle/`，含工具 SHA256 清单和镜像归档清单 |
| Harbor | `/opt/harbor-offline-installer-v2.12.2.tgz`，沿用 4.x PoC 的独立依赖版本 |
| Docker RPM 集合 | `/opt/docker-ce.tar.gz`，解压后为 `/opt/docker-ce/` |

Docker 集合沿用原脚本的 RHEL 9 RPM 名称：containerd.io 1.7.27-3.1、Docker CE/CLI/rootless extras 28.0.4-1、Buildx 0.22.0-1、Compose 2.34.0-1，以及目标 RHEL 9 所需依赖。Harbor、Docker 不跟随 OpenShift 版本号，尚需在目标主机验证这组依赖。这段为手动准备方式沿用的依赖说明。完整交付模式会收集并记录实际的 Helper RPM 和 Harbor 版本，使用包内本地软件源，不要求提供 RHEL DVD ISO；RPM 准备机与离线 Helper 必须具有相同的 RHEL 小版本。

默认运行路径：

| 内容 | 5.x 路径 |
| --- | --- |
| 私有工具 | `/opt/ocp5/bin/` |
| 安装状态及管理员凭据 | `/opt/ocp5/install/`、`/opt/ocp5/install/auth/` |
| Harbor 配置/数据/证书 | `/opt/ocp5/harbor/` |
| HTTP Ignition | `/var/www/html/ocp5/ignition/` |
| 节点命令 | `/opt/ocp5/node-install-commands.txt` |
| NFS 导出 | `/mnt/ocp5-nfs`、`/etc/exports.d/ocp5.exports` |
| 安装日志 | `/var/log/openshift5-install-local.log` |

## 3. 执行安装准备

```bash
sudo env HELPER_IP_ADDRESS=192.168.100.10 \
  NTP_SERVER=192.168.100.1 NFS_CIDR=192.168.100.0/24 \
  bash v5/install-cluster.sh
```

AWS RHEL 9 AMI 上使用现成的软件源时，在命令末尾增加 `--repo-mode existing`。实验环境可让这台 EC2 同时承担 Helper 和 KVM 宿主机，将 Helper 地址设置为内部虚拟网桥地址，三个 Master 与临时 Bootstrap 使用同一虚拟网段。宿主机必须确认支持嵌套 KVM。节点仍按目标安装器指定的 RHCOS 安装，不使用 RHEL AMI 充当 Master。

本次 EC2 测试由 AWS 安全组和 libvirt 网络规则控制通信，可再增加 `--skip-firewalld`（或 `SKIP_FIREWALLD=true`），跳过 firewalld 的安装、启停和规则管理。此选项保留 SELinux 配置，不授予宽松 SCC；物理服务器不加该参数时仍采用默认 firewalld 流程。实验网桥也不能指定依赖 firewalld 的 `zone` 属性。仅使用 `--repo-mode existing` 不会跳过防火墙配置。

脚本交互询问集群完整域名（如 `poc.example.com`）、Harbor 管理员密码、Bootstrap 和三个 Master 的地址，确认后配置主机基础服务。Harbor 密码至少 12 位，限字母、数字和 `_!@%+=.-`。检测到已有 `/opt/ocp5/install` 时拒绝覆盖，失败后应检查状态并人工归档，不能直接删除已有集群安装状态。

安装器和 CLI 解压到私有 bin；镜像包版本必须与 5.0.1 一致；导入时还比较源端 oc-mirror 二进制 SHA256。Harbor 项目名默认为 `openshift501`。

官方客户端归档中的 `kubectl` 到 `oc` 硬链接会原样保留，两者以 `755` 权限放入私有 bin。若使用已核验版本且在 RHEL 9 实测可运行的通用安装器包，可通过 `INSTALLER_ARCHIVE=openshift-install-linux.tar.gz` 指定实际包名，并将其真实 SHA256 记入工具清单，避免给通用包改名冒充专用构建。

导入后脚本读取 oc-mirror 生成的 ImageDigestMirrorSet，提取 `ocp-release` 和 **`ocp-v5.0-art-dev`** 的真实镜像映射。缺少映射或映射不属于目标项目时停止，不拼接猜测路径。配置使用 5.0 安装器支持的 `imageDigestSources`、`platform: none`、OVN-Kubernetes 和显式 machineNetwork。

镜像上传完成后，脚本会提示创建 **仅有 pull 权限的 Harbor 项目 robot 账号**，并提供该账号的 registry auth JSON 私有文件路径。也可预先用 `CLUSTER_PULL_SECRET` 指定文件。JSON 必须在 `auths` 中包含 `helper.<集群域名>:8443` 及内联 `auth`；不要将 Harbor admin 推送凭据用于节点拉取。

Master 的 Chrony MachineConfig 在生成 Ignition **之前**加入安装目录，并确认 `mastersSchedulable=true`。本版本直接生成原生 MachineConfig/兼容的 Ignition 3.5 文件，避免依赖未验证的旧 Butane 二进制。

默认保留 SELinux 状态并配置运行所需端口/布尔值，启用 firewalld 并添加 DNS/NTP/HTTP/HTTPS/NFS/RPC 及 6443、22623、9088、8443 端口。HAProxy 为 TCP 转发，API 使用 TLS `/readyz` 检查，5 秒间隔、3 次失败摘除。公网边界和节点间网络要求仍需按官方文档设置；Helper 端口规则不代表完成了全部节点防火墙配置。

## 4. 安装节点和完成引导

1. 在联网主机用 **本次 标准 Linux 安装器**执行 `openshift-install coreos print-stream-json`，下载指定的 RHCOS Live ISO，转移到隔离环境。完整交付模式已自动下载该 ISO；只有手动分步模式需要自行准备。
2. ISO 启动 Bootstrap 和 Master，确认地址、网关、DNS、时间及目标磁盘。
3. 查看 `/opt/ocp5/node-install-commands.txt`。该文件为 Bootstrap/Master 分别生成 `sudo coreos-installer install ... --offline --copy-network --ignition-hash=sha512-...`，必须替换目标磁盘占位符。
4. 安装并重启节点，在 Helper 上使用私有工具和凭据：

```bash
export PATH=/opt/ocp5/bin:$PATH
export KUBECONFIG=/opt/ocp5/install/auth/kubeconfig
openshift-install wait-for bootstrap-complete --dir=/opt/ocp5/install
sudo bash v5/install-cluster.sh --remove-bootstrap
oc get csr
# 按节点身份核对 CSR 后逐个批准
oc adm certificate approve REPLACE_WITH_VERIFIED_CSR_NAME
openshift-install wait-for install-complete --dir=/opt/ocp5/install
oc get nodes
oc get clusteroperators
```

`--remove-bootstrap` 会先等待 Bootstrap 完成，生成候选 HAProxy 配置并验证通过后替换，保留备份，再重载服务。安装资料中的证书有时效，建议生成后 12 小时内开始安装；文件不会自动重建以掩盖过期或失败。

管理员凭据只在私有安装目录。HTTP 临时发布的 Ignition 含敏感信息，应限制安装网络访问，并在安装完成后停止分发。本次默认命令使用 SHA512 校验而不是跳过 Ignition 校验。

## 5. 后置配置

```bash
sudo env KUBECONFIG=/opt/ocp5/install/auth/kubeconfig \
  bash v5/setup-cluster.sh
```

默认先核对集群版本、节点 Ready/可调度、MCP 收敛、ClusterOperator 状态，以及四个核心控制平面 Operator 的实际 Deployment 就绪情况；任何检查失败均停止后续集群变更，再禁用默认在线 Operator 源并应用导入生成的资源。只镜像了平台时不会产生可用的离线 Operator catalog；要使用 Operator 需在导出时选包。可设置 `APPLY_OPERATORS=false` 跳过应用。

NTP 已在安装阶段配置，后置脚本不再重复应用 NTP MachineConfig。

可选 NFS：设置 `NFS_IMAGE` 为本地项目内已镜像的完整镜像地址，从 oc-mirror 实际映射确认地址（不要直接照抄源地址或猜测本地路径），然后运行后置脚本。它会询问 NFS 服务器/目录，部署 provisioner 并等待就绪；已有其他默认 StorageClass 时拒绝直接设第二个默认类。

```bash
sudo env KUBECONFIG=/opt/ocp5/install/auth/kubeconfig \
  NFS_IMAGE='helper.poc.example.com:8443/openshift501/REPLACE_WITH_ACTUAL_MIRROR_PATH:v4.0.2' \
  bash v5/setup-cluster.sh
```

内部 Registry 默认保持现状。需要持久化时先在 `openshift-image-registry` 中创建合适的 PVC，再传入 `REGISTRY_STORAGE=pvc REGISTRY_CLAIM=<名称>`；脚本确认 PVC 存在后设置。`REGISTRY_STORAGE=emptydir` 仅供实验临时存储，Pod 重建可能丢失镜像，不作为持久化方案。

可设置 `CREATE_ADMIN=true` 交互创建实验 admin（至少 12 位密码、cluster-admin）。独立维护 `ocp5-htpasswd`，保留其他 OAuth provider。不要用于接管已有同名用户。


管理员初始化仅用于新账号。已有 `admin` 用户、同名凭据或 OAuth provider 时会停止，避免重置他人账号；后续维护请省略 `CREATE_ADMIN=true`。OAuth 更新使用并发版本检查，失败需先核对已有状态再重试。

## 可选宽松安全模式

```bash
sudo env HELPER_IP_ADDRESS=192.168.100.10 NTP_SERVER=192.168.100.1 \
  NFS_CIDR=192.168.100.0/24 bash v5/install-cluster.sh --relaxed-security

sudo env KUBECONFIG=/opt/ocp5/install/auth/kubeconfig \
  bash v5/setup-cluster.sh --relaxed-security --security-namespace my-lab
```

开启后将 **Helper** SELinux 设置为 permissive 并写入配置，停止且禁用 firewalld；安装阶段 NFS 使用 `no_root_squash`。后置阶段向所选 namespace（默认 `default`，必须已存在）的默认 ServiceAccount 授予 `anyuid`、`hostmount-anyuid`、`privileged` SCC。此功能不禁用 OpenShift 节点 SELinux。

默认关闭，仍保留 NFS provisioner 专用服务账户必要的 SCC。移除开关不会自动撤销已有授权或恢复主机状态。原始配置首次备份为 `.ocp5.bak`；应根据备份和实际使用情况恢复。该 Helper 和 NFS 设计用于隔离 PoC，不具备生产高可用或自动回滚能力。

## 验证与边界

```bash
python3 -m pip install PyYAML==6.0.3
for script in v5/*.sh v5/lib/*.sh v5/config/*.sh; do bash -n "$script"; done
shellcheck --external-sources --severity=warning v5/*.sh v5/lib/*.sh v5/config/*.sh
python3 -m unittest discover -s v5/tests -v
```

测试使用隔离临时目录和模拟命令，覆盖镜像配置/导出导入、工具校验、真实映射解析、安装资料生成、NTP、调度设置、HTTP 副本校验、Bootstrap 后端移除及 SCC 范围。尚未在真实 RHEL 9 和 OpenShift 5.0.1 环境执行完整安装；目录镜像、社区 provisioner、Registry 存储和旧版 Harbor/Docker 依赖仍需实测。

## 参考

- [OpenShift 5.0 裸金属安装文档](https://docs.redhat.com/en/documentation/openshift_container_platform/5.0/html/installing_on_bare_metal/index)，主要依据第 2.3 节离线 UPI 流程。
- [官方 5.0.1 工具目录](https://mirror.openshift.com/pub/openshift-v4/x86_64/clients/ocp/5.0.1/)
- [5.0 安装器配置定义](https://github.com/openshift/installer/blob/release-5.0/pkg/types/installconfig.go)，包含 `imageDigestSources`。
