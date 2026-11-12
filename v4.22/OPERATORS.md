# OpenShift 5 Operator 离线包

`prepare-operators.sh` 与 5.x 安装、后置配置脚本配套。它只准备 Operator 及其相关镜像，不重新下载平台镜像，也不修改原 4.x 脚本。

## 交互使用

联网准备机需要 Linux、Python 3.9+、PyYAML 6.0.3、skopeo、Podman 或 Docker，以及支持目标版本的 `oc`、`oc-mirror v2`。工具必须放在 PATH。使用 Red Hat pull secret 或包含相关源仓库权限的 registry auth JSON；凭据文件必须在离线包目录之外。

依赖解析使用与 OLM 相同的 blang/semver 版本范围和 CEL properties 环境。联网准备端首次运行会编译小型 Go 工具；没有 Go 时，从官方地址下载固定的 Go 1.27.4 并校验内置 SHA256。模块版本和校验值固定在 `lib/operator-semantics/go.mod`、`go.sum`。可以通过 `--go /path/to/go` 使用已安装的 Go 1.23+。需要允许访问源镜像仓库、go.dev、Go 模块代理和校验服务。**离线导入端不需要 Go、skopeo 或容器运行时**，只需 Python、oc 和相同的 oc-mirror 二进制。

```bash
python3 -m pip install PyYAML==6.0.3
bash v4.22/prepare-operators.sh
```

首层选择 1 会连同 OpenShift 本体准备完整交付包，选择 2 进入仅 Operator 子菜单，选择 3 只准备平台完整包。仅 Operator 子菜单支持下载、只生成计划、导入、校验，依次选择：

1. 离线包的保存路径，可使用包含空格的路径；独立缓存默认为该路径加 `-cache`。
2. catalog 别名及镜像地址，可用逗号添加多个目录。默认 `redhat=registry.redhat.io/redhat/redhat-operator-index:v5.0`；脚本读取并锁定实际 digest，访问失败会停止，不自动换成 4.x 目录。
3. 搜索 Operator，选择序号、channel 和版本。默认 `head` 为该 channel 的图终点；可以反复选择多个 Operator。
4. 检查自动补齐的依赖、版本约束、提供依赖的包，可补充厂商要求的额外运行时镜像。
5. 确认下载。只生成计划时不会下载 Operator 本体镜像。

源 catalog 必须为带 `operators.operatorframework.io.index.configs.v1` 标签的 File-Based Catalog。脚本只创建临时容器提取元数据，不启动 catalog 内的程序。旧 SQLite catalog 需先用官方 opm 工具转换。

实际导出使用本地 OCI catalog。脚本在准备端下载并校验目录的 OCI layout，将其和镜像归档一起转移；生成的 `imagesetconfiguration-oci.json` 使用固定的相对路径，所以换到另一台离线机器、换保存目录后也能使用。原始 registry digest 配置和来源记录保留，导入不会退回源 catalog。此方式也避开部分官方 oc-mirror 构建在 diskToMirror 阶段重新访问源目录的问题；不需要自行修改官方二进制。

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
  --catalog redhat=registry.redhat.io/redhat/redhat-operator-index:v5.0 \
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

成功导出的目录包含 `operators-plan.json`、原始 `imagesetconfiguration.json`、本地 `imagesetconfiguration-oci.json`、`operator-catalogs.json`、`catalogs/`、`mirror-tool.json`、`checksums.json` 、`operator-archive.json` 、`operator-archive.json` 和 `images/*.tar`。计划逐项记录根包、自动依赖、约束、满足它的 bundle、镜像及版本。校验清单包含计划、OCI 目录和归档；将整个目录转移到离线端，凭据与源缓存留在准备端。不要只拷贝 tar，也不要将旧 registry catalog 包原地改成 OCI 包。准备充足磁盘空间，容量随所选包变化，完整 catalog layout 也占用空间。

```bash
bash v4.22/prepare-operators.sh import --non-interactive \
  --bundle '/data/ocp422 operators' \
  --authfile /secure/harbor-auth.json \
  --registry helper.poc.example.com:8443/openshift501
```

使用与导出端 SHA256 相同的 oc-mirror 二进制。目标 Harbor 项目、仓库证书信任以及集群 pull secret 权限应已配置；导入不自动给集群扩大仓库权限。每个计划使用独立的目标 catalog 名称和标签，避免覆盖之前已导入的过滤目录。

导入后审阅 `images/working-dir/cluster-resources`，再在 RHEL 9 Helper 上运行：

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

上述 4.22 文档用于核对 oc-mirror v2 行为；5.x 的目录、平台和 Operator 版本分别核实，不能因为平台升级就把 Operator 自己的版本号也改成 5.0。


需要同时准备 OpenShift 本体和安装工具时，首层菜单选择完整交付模式，见 [DELIVERY.md](DELIVERY.md)。原有 `export/import/verify` 命令仍表示仅操作 Operator 包。


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

基础包包含固定摘要的 RHEL 9 guest container disk；产品清单关闭系统默认引导镜像自动导入，避免 Fedora/CentOS 的公共镜像轮询在隔离环境持续失败。这不影响手动创建使用本地已镜像 container disk 的 VM。其他系统需在准备阶段补充镜像，并把自定义引导源指向实际本地镜像，持久化模板还需要对应存储。不会把所有系统模板宣称为已可用。

HCO `v1` 使用 `spec.workloadSources.enableCommonBootImageImport`；`v1beta1` 使用 `spec.enableCommonBootImageImport`。旧的 `spec.featureGates.enableCommonBootImageImport` 已被忽略，不能据此判定已经关闭。5.0 的两种实际 CRD 已核对；4.22 的 beta 字段依据[红帽引导源文档](https://docs.redhat.com/en/documentation/openshift_container_platform/4.22/html/virtualization/storage)。创建 HCO 后再次等待 MCP 收敛，并按 Available/Progressing/Degraded 条件和实际 Deployment 验证；不要求未在 CRD 中定义的 `status.phase`。
