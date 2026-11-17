# OpenShift 4.22 Operator 离线包

`prepare-operators.sh` 与 4.22 安装、后置配置脚本配套。其 `plan/export/import/verify` 子命令处理 Operator 和所选系统镜像；首层完整交付模式同时准备平台和安装工具，见 [DELIVERY.md](DELIVERY.md)。

## 交互使用

联网准备机需要 Linux、Python 3.9+、PyYAML 6.0.3、skopeo、Podman 或 Docker，以及支持目标版本的 `oc`、`oc-mirror v2`。工具必须放在 PATH。使用 Red Hat pull secret 或包含相关源仓库权限的 registry auth JSON；凭据文件必须在离线包目录之外。

依赖解析使用与 OLM 相同的 blang/semver 版本范围和 CEL properties 环境。联网准备端首次运行会编译小型 Go 工具；没有 Go 时，从官方地址下载固定的 Go 1.27.4 并校验内置 SHA256。模块版本和校验值固定在 `lib/operator-semantics/go.mod`、`go.sum`。可以通过 `--go /path/to/go` 使用已安装的 Go 1.23+。需要允许访问源镜像仓库、go.dev、Go 模块代理和校验服务。**离线导入端不需要 Go、skopeo 或容器运行时**，只需 Python、PyYAML、oc 和相同的 oc-mirror 二进制。

```bash
python3 -m pip install PyYAML==6.0.3
bash v4.22/prepare-operators.sh
```

首层选择 1 会连同 OpenShift 本体准备完整交付包，选择 2 进入仅 Operator 子菜单，选择 3 只准备平台完整包。仅 Operator 子菜单支持下载、只生成计划、导入、校验，依次选择：

1. 离线包的保存路径，可使用包含空格的路径；独立缓存默认为该路径加 `-cache`。
2. catalog 别名及镜像地址，可用逗号添加多个目录。默认 `redhat=registry.redhat.io/redhat/redhat-operator-index:v4.22`；脚本读取并锁定实际 digest，访问失败会停止，不自动换成其他平台目录。
3. 搜索 Operator，选择序号、channel 和版本。默认 `head` 为该 channel 的图终点；可以反复选择多个 Operator。
4. 选中 OCP-V 后多选系统镜像及其 tag/digest；选中 ODF 后选择是否包含 Local Storage Operator。检查自动补齐的依赖和配套包，可补充厂商要求的额外运行时镜像。
5. 确认下载。只生成计划时不会下载 Operator 本体镜像。

源 catalog 必须为带 `operators.operatorframework.io.index.configs.v1` 标签的 File-Based Catalog。脚本只创建临时容器提取元数据，不启动 catalog 内的程序。旧 SQLite catalog 需先用官方 opm 工具转换。

实际导出使用本地 OCI catalog。脚本在准备端下载并校验目录的 OCI layout，将其和镜像归档一起转移；生成的 `imagesetconfiguration-oci.json` 使用固定的相对路径，所以换到另一台离线机器、换保存目录后也能使用。原始 registry digest 配置和来源记录保留，导入不会退回源 catalog。此方式也避开部分官方 oc-mirror 构建在 diskToMirror 阶段重新访问源目录的问题；不需要自行修改官方二进制。

## OCP-V、MTV、ODF 下载组合

优先交付 4.22；5.0 为预览。下表是 2026-11-17 实际官方 FBC 目录的核对结果，channel 后续可能更新，生成的计划会固定当次真实版本和 catalog digest。

| 组件 | OCP 4.22.22 | OCP 5.0.1 预览 |
|---|---|---|
| OCP-V | `kubevirt-hyperconverged:stable`，4.22.16 | 同包/channel，5.0.0 |
| MTV | `mtv-operator:release-v2.12`，2.12.10；也可选经支持矩阵核实的 5.0 | `mtv-operator:release-v5.0`，5.0.0 |
| ODF | `odf-operator:stable-4.22`，4.22.7-rhodf，补全配套组 | 目录可见 4.22 包，但声明最高 OCP 4.23，计划明确拒绝 |
| Local Storage Operator | `local-storage-operator:stable`，4.22.0-202611031655 | 对应 5.0 包可单独选；不能使 ODF 变成兼容 |
| AI | 使用已核实的 4.22 / AI 3.5.2、3.5.3 范围 | 尚无已核实支持组合，见验证记录 |

Operator 自己的版本号不必等于平台版本。平台兼容性依据目录声明和已核实的厂商组合；不会仅因数字不同拒绝 MTV 2.12 / OCP 4.22，也不会忽略明确的 `maxOpenShiftVersion`。

ODF 主包本身没有声明完整包依赖。选择它会显式加入以下 **12 个同完整补丁版本**的包，再解析各自声明的依赖和全部 `relatedImages`：

```text
odf-operator                  odf-dependencies
ocs-operator                  mcg-operator
odf-csi-addons-operator        ocs-client-operator
odf-prometheus-operator        recipe
rook-ceph-operator             cephcsi-operator
odf-external-snapshotter-operator
ocs-tls-profiles
```

本地盘模式默认另带 Local Storage Operator；使用已有动态/外部存储时，交互选择 no 或传 `--no-odf-local-storage`。缺少配套包、补丁不一致或依赖无法满足时停止。此范围准备镜像，不创建 StorageCluster、不选择或初始化磁盘；灾备/多集群组件需另选。

MTV 的目标端需要兼容的 OCP-V，想一起准备请同时选择两个包。VMware 场景所需 VDDK SDK 不由红帽 Operator 包分发；按[官方 VDDK 要求](https://docs.redhat.com/en/documentation/migration_toolkit_for_virtualization/2.12/html/planning_your_migration_to_red_hat_openshift_virtualization/assembly_provider-specific-requirements-for-migration_mtv)自行取得 SDK、构建镜像，在仅 Operator 模式以 `--image registry.example.com/migration/vddk@sha256:...` 加入。源平台权限、网络/存储映射和实际迁移不在下载验证范围。

## AI 的 NVIDIA GPU 准备

4.22 新建 AI 计划默认加入 certified 目录的 NVIDIA GPU Operator 26.7、NFD、匹配 4.22.22 的 DTK 和 CUDA/Python 3.12 工作台镜像。交互会询问 yes/no，命令行使用 `--no-ai-nvidia` 保留仅 CPU 范围；完整交付模式同样接受该参数。已有 CPU 包保持原范围，增加 GPU 需使用新目录。

GPU Operator 的官方 relatedImages 包含驱动和 GPU 运行组件，脚本保持完整；DTK 和额外 CUDA 工作台由已核实清单补入并参与归档完整性校验。仅下载 NFD/GPU 控制器不等于驱动可用。后置配置生成 NFD 订阅和参考 CR、GPU 订阅及 DTK ClusterPolicy 参考，需分阶段审阅执行，再验证真实 GPU 和 AI hardware profile。

5.0 certified 目录目前没有该 NVIDIA 包，AI 支持矩阵也未列出 5.0，不借用 4.22 组合。GPU 型号、节点内核、驱动分支、自定义/vGPU 镜像和许可仍需按场景核对。常用包、Multus 以及 AI/Virtualization 按功能依赖的详细结论见 [DEPENDENCIES.md](DEPENDENCIES.md)。

## 虚拟机系统镜像选择

选中 OCP-V 后，交互菜单支持逗号多选，并逐项询问 tag 或 `sha256:digest`：

| 预置名称 | 默认来源 |
|---|---|
| `rhel9` | `registry.redhat.io/rhel9/rhel-guest-image:latest` |
| `rhel10` | `registry.redhat.io/rhel10/rhel-guest-image:latest` |
| `fedora` | `quay.io/containerdisks/fedora:latest` |
| `centos-stream9` | `quay.io/containerdisks/centos-stream:9` |
| `centos-stream10` | `quay.io/containerdisks/centos-stream:10` |

默认只准备 RHEL 9；显式选择其他系统后以所选列表为准，不额外强塞 RHEL 9。选择 0 或 `--guest-image none` 则不准备系统镜像。RHEL 需要有效的源仓库授权；Fedora/CentOS 来源为社区 containerDisk，能下载不表示属于红帽来宾系统支持范围。

可重复传 `--guest-image PRESET`，或用 `--guest-image-ref NAME=REGISTRY/REPO:TAG` 指定自有 containerDisk、覆盖同名预置的 tag/digest。两种选项都支持完整交付模式。示例：

```bash
bash v4.22/prepare-operators.sh plan --non-interactive \
  --bundle '/data/ocp422 systems' --authfile /secure/pull-secret.json \
  --select redhat/kubevirt-hyperconverged:stable \
  --select redhat/mtv-operator:release-v2.12 \
  --select redhat/odf-operator:stable-4.22 \
  --guest-image rhel9 --guest-image fedora \
  --guest-image centos-stream9 --guest-image centos-stream10

# 自己指定 Fedora 版本（须确实存在），也可以使用 @sha256:digest
# --guest-image-ref fedora=quay.io/containerdisks/fedora:YOUR_TAG
```

仅计划阶段会读取系统镜像 manifest/config，选择唯一 linux/amd64 manifest 并固定其摘要，不下载系统磁盘层。无法读取、缺少 amd64、摘要或架构不符时停止。下载后这些系统镜像与 Operator 一起进入归档；成功标记要求相关 manifest、config、全部 layer 都存在且摘要正确。重试固定已保存的选择和 digest，修改系统列表/ODF 本地盘选项请使用新包目录。

完整复制离线包后，可以更改顶层目录和目标 Harbor 项目。导入依据原生 oc-mirror 生成的实际 IDMS/ITMS 输出 `guest-images-local.json`，列出每种系统的本地完整 digest 地址；不依赖原下载绝对路径，也不猜测仓库映射。应用镜像规则并等待 MCP 收敛后，可用报告里的本地地址创建 containerDisk VM，或作为 DataVolume 的 registry 数据源（`docker://本地地址`）导入持久卷，再关联 DataSource/模板。

**镜像归档、引导源注册和虚拟机模板是不同阶段。** 默认公共引导源自动导入仍关闭；本轮不自动创建 DataVolume/DataSource 或恢复公共轮询。系统镜像已下载不代表 Console 中所有系统模板立即可用。ISO、QCOW2、RAW 文件不能直接传给 OCI 镜像参数；QCOW2/RAW 可按[红帽 containerDisk 制作说明](https://docs.redhat.com/en/documentation/openshift_container_platform/4.22/html-single/virtualization/index)制作 OCI 镜像后用 `--guest-image-ref` 加入，ISO 另行携带并通过 CDI/Console 上传。持久化导入还需要可用的 StorageClass 和容量，见[虚拟机存储文档](https://docs.redhat.com/en/documentation/openshift_container_platform/4.22/html/virtualization/storage)。

此次核对覆盖真实目录解析、下载配置、源镜像元数据和镜像层 HEAD 可达性；未重新执行这些组合的全量 oc-mirror 导出/导入，也未安装 MTV/ODF 或验证新增系统 VM。具体证据见 [VALIDATION.md](VALIDATION.md)。

## 依赖处理

红帽明确说明：**oc-mirror v2 不会推断 GVK 或 bundle 依赖**。本脚本先解析目录声明的 `olm.package.required`、`olm.gvk.required`、传统 `dependencies` 和 `olm.constraint`，支持 `all`、`any`、`not`、CEL 及其 `semver_compare`。它递归解析跨目录依赖，检查版本约束、单包单版本和重复 API 提供者，在版本冲突时回溯寻找可行组合。

输出使用包/channel 的精确 minVersion=maxVersion，设置过滤后 defaultChannel，并将目录锁定到 digest。存在多个图终点、无法唯一筛选的同语义版本 bundle、缺失依赖、未知依赖类型、冲突或搜索超限时，脚本停止；oc-mirror dry-run 仍是实际过滤与镜像可达性的必要检查。

计划是**新安装**的可行依赖组合，不是已有 Subscription 的升级路径规划。未选择的旧 bundle 不会自动加入。计划排除声明不支持目标 OpenShift 版本的条目；这不等于替代厂商的支持矩阵或订阅授权检查。

如果依赖 API 已由目标集群提供而不应再装一个 Operator，可显式传入 `--provided-apis /path/baseline-apis.json`，格式如下。只有目标离线集群也确实具备这些 API 时才能使用这份计划；不要把另一个集群上额外安装的 Operator 当成通用平台基线。

```json
[
  {"group": "monitoring.coreos.com", "version": "v1", "kind": "ServiceMonitor"}
]
```

自动解析以 catalog 中声明的依赖及 relatedImages 为边界。厂商未声明的依赖、额外 operand 镜像、外部数据库、存储、证书和许可证无法从目录可靠推断。请结合 Operator 文档补选包或 `--image`，并在离线环境实际创建 CR 验证运行时功能。

## 非交互、预检查与断点重试

```bash
bash v4.22/prepare-operators.sh plan --non-interactive \
  --bundle '/data/ocp422 operators' \
  --authfile /secure/pull-secret.json \
  --catalog redhat=registry.redhat.io/redhat/redhat-operator-index:v4.22 \
  --select redhat/web-terminal

bash v4.22/prepare-operators.sh export --non-interactive --dry-run \
  --bundle '/data/ocp422 operators' --authfile /secure/pull-secret.json

# 检查 images/working-dir/dry-run 和计划，再实际下载。
bash v4.22/prepare-operators.sh export --non-interactive \
  --bundle '/data/ocp422 operators' --authfile /secure/pull-secret.json

bash v4.22/prepare-operators.sh verify --bundle '/data/ocp422 operators'
```

`--select ALIAS/PACKAGE[:CHANNEL][=VERSION]` 可重复。`--catalog` 可重复，以解析来自其他目录的依赖。`--image REGISTRY/REPO:TAG` 可重复补充镜像，推荐 digest。`--archive-size` 设置单个归档 GiB；`--cache-dir` 自选独立缓存路径。

再次 export 会使用已保存的计划，保留缓存以重试。切换目录、版本或 Operator 组合请使用新的离线包路径。不要直接修改生成的 imagesetconfiguration；脚本会核对它与依赖计划的一致性。失败不会留下成功标记；dry-run 也不会生成成功标记。本轮新建或更新的非空 mirroring error 日志会阻止标记完成；历史日志保留供排查，不会让已修复的重试永久失败。

为高级测试提供 `--catalog-metadata ALIAS=/path/to/extracted-fbc`，此时 `--catalog ALIAS=IMAGE@sha256:...` 必须固定 digest。这表示调用者明确保证本地元数据来自该镜像；一般使用不需要此参数。

同样可用 `--catalog-oci ALIAS=/path/to/verified-oci-layout` 复用已从该 digest 获取的 OCI 目录，减少重复下载。它表示调用者明确保证本地 OCI layout 的来源，脚本会逐个验证 blob 摘要及完整引用，拒绝链接、凭据文件或缺失的 blob。一般使用由脚本自行从已锁定源镜像准备。

## 转移、导入和后置配置

成功导出的目录包含 `operators-plan.json`、原始 `imagesetconfiguration.json`、本地 `imagesetconfiguration-oci.json`、`operator-catalogs.json`、`catalogs/`、`mirror-tool.json`、`checksums.json`、`operator-archive.json` 和 `images/*.tar`。计划逐项记录根包、自动依赖、约束、满足它的 bundle、镜像及版本。校验清单包含计划、OCI 目录和归档；将整个目录转移到离线端，凭据与源缓存留在准备端。不要只拷贝 tar，也不要将旧 registry catalog 包原地改成 OCI 包。准备充足磁盘空间，容量随所选包变化，完整 catalog layout 也占用空间。

```bash
bash v4.22/prepare-operators.sh import --non-interactive \
  --bundle '/data/ocp422 operators' \
  --authfile /secure/harbor-auth.json \
  --registry helper.poc.example.com:8443/openshift42222
```

使用与导出端 SHA256 相同的 oc-mirror 二进制。目标 Harbor 项目、仓库证书信任以及集群 pull secret 权限应已配置；导入不自动给集群扩大仓库权限。每个计划使用独立的目标 catalog 名称和标签，避免覆盖之前已导入的过滤目录。

导入后审阅 `images/working-dir/cluster-resources`，再在匹配的 RHEL 9/10 x86_64 Helper 上运行：

```bash
sudo env BUNDLE_DIR='/data/ocp422 operators' \
  KUBECONFIG=/opt/ocp422/install/auth/kubeconfig \
  REGISTRY_STORAGE=unchanged CREATE_ADMIN=false \
  bash v4.22/setup-cluster.sh
```

EC2 测试环境按已采用的方式增加 `--skip-firewalld`。后置脚本先校验离线包，为每份 Operator 计划派生独立的资源名称，再应用 oc-mirror 生成的 IDMS/ITMS 和 CatalogSource，并禁用默认在线目录；这样多份独立离线包不会覆盖同名的镜像规则。只修改 metadata，保留官方要求不变的 image、映射等 spec 字段。原始导入资源保留，派生结果为 `operator-resources.json`。存储与管理员配置保持现状。资源变更可能触发 MachineConfigPool 滚动更新，应等待 MCP 更新完成、CatalogSource `READY` 后再安装 Operator。

在 Console 中选择离线 catalog 与计划中的 channel/version；首次建议手动审批 InstallPlan，确认计划包含依赖包且镜像来自本地仓库。相关 CRD、RBAC、OperatorGroup 作用域和厂商支持要求仍由目标集群 OLM 检查。仅完成下载或导入不等于已完成 Operator 的运行验证。

## 官方依据

- [Red Hat：oc-mirror v2、过滤与依赖限制](https://docs.redhat.com/en/documentation/openshift_container_platform/4.22/html/disconnected_environments/about-installing-oc-mirror-v2)
- [OLM：Dependency Resolution](https://olm.operatorframework.io/docs/concepts/olm-architecture/dependency-resolution/)
- [OLM：File-Based Catalogs](https://olm.operatorframework.io/docs/reference/file-based-catalogs/)
- [OpenShift oc-mirror 源码](https://github.com/openshift/oc-mirror)
- [OLM CEL 环境实现](https://github.com/operator-framework/api/blob/master/pkg/constraints/cel.go)
- [oc-mirror：diskToMirror 访问源 catalog 的上游修复](https://github.com/openshift/oc-mirror/commit/4cfbc254b92f34b456f44ca3540e36d09f79fffa)

Operator 与平台版本分别核实；5.x 预览组合和限制见独立的 [5.x 说明](../v5/OPERATORS.md)。


需要同时准备 OpenShift 本体和安装工具时，首层菜单选择完整交付模式，见 [DELIVERY.md](DELIVERY.md)。原有 `export/import/verify` 命令仍表示仅操作 Operator 包。

## 在已有集群单独应用离线目录

镜像成功导入后，可仅应用本包的镜像规则与 CatalogSource：

```bash
bash v4.22/apply-operators.sh --bundle "/offline/operator bundle" \
  --kubeconfig /secure/kubeconfig --dry-run
# 检查通过后去掉 --dry-run 正式应用
```

使用内部 CA 的目标仓库时，增加 `--registry-ca /secure/harbor-ca.crt`；正式应用前会保留并合并现有集群 CA，预检查只读取合并计划。

入口先检查集群版本和安装完成状态，再验证离线包；失败时不修改 OperatorHub。`--dry-run` 使用服务端验证，不关闭默认目录。正式执行会关闭 Classic 默认联网目录，并将仍指向官方在线源的默认 OLM v1 ClusterCatalog 设为 Unavailable；同名但已改成本地镜像的目录会保留。复杂组件生成的 `product-manifests/` 需按其中 README 分阶段应用；小型 ACM 验证可显式设置 `ACM_AVAILABILITY=Basic`。

AI 的 CPU Workbenches 范围用于限定配置和功能验收，不会删改官方 CSV 的 `relatedImages`。因此包中仍保留 Operator 声明的其他功能镜像，不能按少数 Workbench 镜像估算整个离线包容量；镜像归档、独立缓存和目标仓库需要分别预留空间。

新版默认目录的处理依据：[红帽 OLM v1 目录管理说明](https://docs.redhat.com/en/documentation/openshift_container_platform/4.22/html-single/extensions/index)。

### Virtualization 的离线引导源

基础包默认包含固定摘要的 RHEL 9 guest container disk，也可按上文改选/多选系统镜像。产品清单保持关闭公共引导源自动导入；导入后使用本地地址，按需注册 DataSource/模板。持久化模板还需要对应存储，下载完成不代表所有系统模板均已可用。

HCO `v1` 使用 `spec.workloadSources.enableCommonBootImageImport`；`v1beta1` 使用 `spec.enableCommonBootImageImport`。旧的 `spec.featureGates.enableCommonBootImageImport` 已被忽略，不能据此判定已经关闭。5.0 的两种实际 CRD 已核对；4.22 的 beta 字段依据[红帽引导源文档](https://docs.redhat.com/en/documentation/openshift_container_platform/4.22/html/virtualization/storage)。创建 HCO 后再次等待 MCP 收敛，并按 Available/Progressing/Degraded 条件和实际 Deployment 验证；不要求未在 CRD 中定义的 `status.phase`。

应用入口还会逐个检查控制平面节点的四类静态 Pod 及其主容器，避免 Operator Deployment 和旧汇总状态显示健康时继续修改集群。工作节点不要求具备控制平面静态 Pod；API 读取失败仍会停止。

### AI 的托管网关镜像

AI 3.5.2/3.5.3 的 Dashboard 和 Workbenches 还依赖平台托管 Gateway 的 `istio-pilot-rhel9`、`istio-proxyv2-rhel9`。这两个镜像没有出现在 AI CSV 的 `relatedImages` 中。生成器从 `config/ocp-4.22.22-gateway-images.json` 自动补齐固定摘要，并在计划中记录来源；当前只核实 4.22.22，其他平台补丁版本须先增加经过核实的清单。

4.22.22 / AI 3.5.2 的实际验收使用原完整包加这两个镜像的独立可搬迁补充包，完成全新缓存和阻断外网导入后，Dashboard、CPU 工作台及停止/启动后的持久文件读取通过。新版完整计划自动包含它们，但本轮没有重新导出和重装整个新版大包；详见 [验收记录](VALIDATION.md)。
