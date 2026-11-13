# 完整离线准备 → 安装 → 配置

本入口把 **OpenShift 5.0.1 / amd64 本体、匹配的 oc/kubectl/安装器、导出端同一 oc-mirror、RHCOS Live ISO、Helper RPM/Harbor，以及可选 Operator** 放到同一交付目录。平台镜像与 Operator 镜像仍独立保存，避免不同目录的生成资源相互覆盖。旧版根目录脚本不受影响。

```text
交付目录/
  platform/       平台镜像、工具、RHCOS 启动 ISO
  operators/      所选 Operator、依赖、过滤目录、镜像归档
  helper/         RHEL 9 / Docker RPM、签名 key、Harbor 离线包
  scripts/        本版本安装、配置及准备脚本的快照
  delivery.json   相对路径和 SHA256 清单
  install.sh      初始化 Helper、导入平台、生成安装资料
  configure.sh    等待安装完成、导入 Operator、执行安装后配置
  verify.sh       搬迁后校验整包
```

## 联网准备机

完整 `rpm` 模式使用 **RHEL 9 x86_64**，目标 Helper 的 RHEL 版本须与准备机相同。准备机必须已启用有权访问的 RHEL 软件源，并具备 Python 3.9+、PyYAML、Bash 4+、skopeo、`dnf download`（dnf-plugins-core）及 createrepo_c。需要足够磁盘同时保存缓存、镜像归档和目录镜像；复杂 Operator 组合可能达到数百 GB。源 pull secret 放在交付目录外。

从红帽获取官方 oc-mirror v2 并解压为名为 `oc-mirror` 的可执行文件。完整入口会把此二进制打包到工具目录，确保源端与离线端一致。它不会另行下载一个不同版本的插件。

直接运行：

```bash
bash v5/prepare-operators.sh
```

首层菜单选择“准备完整离线包”，填写保存目录、pull secret 和 oc-mirror 路径；随后搜索 Operator，选择包、channel/version，可重复添加。依赖解析后展示计划，确认后下载。只准备平台、不选 Operator 时，可在首层菜单选择“仅准备平台完整包”，或使用 `--platform-only`。

可复用的命令行示例：

```bash
bash v5/prepare-operators.sh delivery export \
  --bundle '/data/ocp5 delivery' \
  --cache-dir /data/ocp5-delivery-cache \
  --authfile /secure/redhat-pull-secret.json \
  --oc-mirror /data/bin/oc-mirror \
  --helper-mode rpm \
  --select redhat/web-terminal
```

`--select`、`--catalog ALIAS=IMAGE` 可重复；不指定 `--select` 时终端会进入选包交互。`--image` 可重复补充平台或运行负载需要的镜像。工具和 ISO 根据固定版本官方元数据的 SHA256 下载校验。Harbor 默认从官方 GitHub 固定的 v2.12.2 发布地址下载，核对该发布提供的 MD5，再记录交付用 SHA256；该 SHA256 不是上游数字签名。已有可信 Harbor 包时可加：

```bash
  --harbor-archive /data/harbor-offline-installer-v2.12.2.tgz \
  --harbor-sha256 实际核实的64位SHA256
```

RHEL/Docker 软件及其依赖通过 `dnf download --resolve --alldeps` 收集，生成本地软件源。目标安装时只启用该离线源，保留 RPM 签名检查。订阅配置、RHUI 私钥及源仓库登录信息留在准备机的缓存或原位置，不装入交付包。

AWS 测试可明确选择 `--helper-mode existing`：使用目标机已有的 YUM/RHUI 和 Docker，不收集 Helper RPM。**此模式只保证 OpenShift/Operator 镜像离线，不代表 Helper 初始化完全离线。**物理隔离环境使用默认 `rpm` 模式，或继续使用独立安装入口的 RHEL DVD 模式。

## 搬迁和安装

可以改变目录和磁盘挂载位置，也支持目录名包含空格。保留完整目录结构；不要只复制一个 tar。缓存留在源端，凭据另行安全提供。

```bash
bash '/offline/new location/verify.sh'
sudo env NTP_SERVER=192.168.100.254 NFS_CIDR=192.168.100.0/24 \
  bash '/offline/new location/install.sh'
```

`NTP_SERVER` 必须是真正可用的内部上游，不能填写 Helper 自身；默认会等待同步，失败即停止。完全隔离、没有上游时，可显式使用 `NTP_MODE=local` 且不设置 `NTP_SERVER`，按 RHEL chrony 的 `local stratum 10` 模式统一节点时间；该模式以 Helper 时钟为准，需要先确认其时间正确。参见 [RHEL 9 隔离网络授时说明](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/configuring_basic_system_settings/configuring-time-synchronization_configuring-basic-system-settings)。

`install.sh` 按包内记录自动选择软件源；沿用安装脚本的域名、IP 和仓库密码交互。RHCOS ISO 位于 `platform/boot/rhcos-live.iso`。脚本生成 Ignition 与各节点的磁盘安装命令后，需要按命令启动和安装实体服务器/虚拟机；裸金属 UPI 的开机、磁盘选择和 CSR 核对不会自动跳过。

集群私有状态默认 `/opt/ocp5`。需要自选时给安装与配置两个入口传入相同的 `--state-root /绝对路径`，状态目录不能在交付包内。安装目录已经存在时拒绝覆盖，以免破坏现有集群。初装在生成 Ignition 前失败时，可按相同拓扑重试：`helper-plan.json` 固定版本、域名和节点地址；已有 Harbor 复用原配置和数据，不改写管理员或数据库密码，需输入原管理员密码。上游 NTP 故障可以更换时间源。安装目录产生后仍拒绝覆盖。初装失败后查看阶段输出；不要删除现有安装状态强行重跑，也不要复用已过期的 Ignition。

## 衔接安装后配置

节点启动后执行：

```bash
sudo env OCP_REGISTRY_STORAGE=unchanged CREATE_ADMIN=false \
  bash '/offline/new location/configure.sh'
```

配置入口读取本机 `handoff.json` 中的版本、域名和仓库信息，依次：

1. 校验整包及版本。
2. 等待 bootstrap 完成，移除 HAProxy 的 bootstrap 后端。
3. 等待 `install-complete`；节点/CSR 未准备好时停止在安装阶段。
4. 缺少搬迁前生成的平台镜像规则时，先从本包平台归档重新导入并生成规则；再使用本地 Harbor 凭据导入 Operator 包（默认 `/root/.docker/config.json`，也可 `--authfile /secure/harbor-auth.json`）。
5. 运行配置脚本，应用平台镜像规则和独立命名的离线 Operator 目录。

新安装明确设置 `additionalTrustBundlePolicy: Always`。配置阶段将 Helper 的公开 Harbor CA 合并进集群组件信任，保留已有 CA 和代理地址配置；单独配置其他 Helper 时可用 `REGISTRY_CA=/secure/harbor-ca.crt` 指定。CA 发生变化时，先验证其已注入目录服务，再刷新 OLM v1 的证书缓存；重复执行且 CA 未变时不重启组件。这样目录服务与节点使用相同的本地仓库信任。参数依据见 [官方安装器的信任策略说明](https://github.com/openshift/installer/blob/main/docs/user/customization.md)。

集群未达到 Available、仍在 Progressing 或 Failing 时，配置脚本拒绝修改集群。内部 Registry 默认保持现状；需要持久存储、动态 StorageClass、身份认证或额外操作数镜像时，应按所选组件的要求准备。等待 MCP 更新、CatalogSource READY 后再安装计划中的 Operator。配置离线目录不等于自动创建所有 Operator 的 Subscription 或业务 CR。

AWS 明确由外部规则管理防火墙时可在安装和配置命令末尾增加 `--skip-firewalld`。默认仍保留 SELinux 和主机安全策略；`--relaxed-security` 沿用独立脚本的显式开关，配置阶段的 SCC 仅作用于指定命名空间。

## 重试和交付边界

- 同一交付目录/Operator 目录禁止并发执行。缓存与交付目录不得互相包含。
- 固定版本和选包计划；切换版本、Helper 模式或选包组合请使用新目录。
- 脚本快照只收录指定入口、公共代码及版本配置，不收录代码目录中临时放置的 pull secret、额外 JSON 或私人笔记；重试会刷新旧快照。
- 下载临时文件通过校验才替换正式文件；成功收集的 Helper 资产按清单复用。
- 平台和 Operator 采用独立、完整导出；Operator 归档额外校验 bundle、relatedImages、过滤目录标签及镜像层是否齐全。
- 首次输入错误（例如凭据路径填错）可修正后使用原目录重试；自动失败记录不会把空目录误判为混有其他文件。
- 失败重试移除旧成功标记。仅下载完成并通过整包校验才生成 `delivery.json`；阶段见 `delivery-state.json`，该状态文件不能代替校验。
- 全新 Helper 的安装仍需独立 RHEL 主机、正确网络/DNS/NTP、足够资源和可用的集群 pull-only 仓库账户。不会把联网源 pull secret 自动当作集群凭据。

实测范围及仍待验收的复杂组件见 [VALIDATION.md](VALIDATION.md)；Operator 依赖规则与额外镜像要求见 [OPERATORS.md](OPERATORS.md)。

## 产品清单的交接

选中 Virtualization、ACM/MCE 或 AI 时，安装后配置还会在 Operator 包的 `product-manifests/` 中生成安装阶段清单：

- `01-subscriptions.json`：按目录声明的安装作用域生成 Namespace、OperatorGroup 和固定版本 Subscription，首次采用手动审批。
- `02-hyperconverged.json`、`02-multiclusterengine.json`：使用该 bundle 实际声明的稳定 API，等待 CSV Succeeded 后应用。
- `03-multiclusterhub.json`：MCE 订阅源指向本次实际离线 CatalogSource，包含计划中的 channel/CSV。

应用 HyperConverged 后还可能触发额外的节点配置更新；应再次等待 MCP Updated、所有节点恢复可调度及产品 Available，再启动虚拟机或判断容量不足。本次 5.0 实测出现了这一过程。

ACM/MCE 清单默认 High；小型验证可在配置前设置 `ACM_AVAILABILITY=Basic`。先等待 MCP 和目录就绪，审阅并应用订阅、批准计划内 CSV，再按目录内 README 应用业务 CR。它们不会混入自动应用的镜像规则文件。AI 目前生成 Operator 订阅；DSCI/DSC、默认动态存储、IDP 和 CPU Workbench 的整体验收仍需在 4.22 上完成。

## 节点容量也属于交付前提

本次 5.0.1 三节点基础平台在每节点 4 CPU/16 GiB 上安装成功；随后部署 Virtualization、MCE 与 ACM 时，Virtualization 自动触发额外的 MachineConfigPool 更新，节点轮流暂时不可调度，其间出现 CPU/内存请求不足。容量结论需等 MCP 更新完成、全部节点恢复可调度后再判断；不能把滚动更新时的等待直接认定为稳态容量不足。基础平台规格也不代表复杂组件的容量保证。

准备和安装前，应按厂商要求叠加平台、控制组件及实际工作负载的资源预算，另确认存储、硬件虚拟化和网络。Operator CSV 达到 Succeeded 后还需等待业务 CR 健康，并完成实际工作负载验收；查看 `oc get pods -A` 的 Pending 原因及节点的 Allocated resources。不要通过删减官方资源请求或启用虚拟化模拟来绕过验收。

默认离线目录策略同时覆盖 Classic 和 OLM v1：关闭 Classic 默认源，并将仍指向官方在线仓库的默认 ClusterCatalog 设置为 Unavailable。已有自定义目录及同名但已改成本地镜像的目录保持原配置；已关闭的 OLM v1 默认目录不重复变更。

升级脚本后，请在联网准备机使用新版仓库入口重新执行相同计划的 `delivery export`，保留缓存并重新封包；成功后转移新的整包。不要直接替换已封包的 `scripts/`，这样会破坏 SHA256 清单。切换选包计划、平台版本或 oc-mirror 二进制时使用新目录。

本文中的 `v5/...` 命令以 Git 仓库根目录为工作目录。完整包的离线端直接使用包根目录三个入口；需要单独运行包内脚本时，把版本目录前缀替换为 `scripts/`。仅 Operator 模式须一并转移对应版本的脚本目录和匹配工具，或复用已有完整安装包中的脚本；无需保持原下载路径。

## 集群尚未稳定时

配置入口和独立 Operator 应用入口会在写入集群前检查节点、MCP、ClusterOperator、四个核心控制平面 Operator Deployment，以及每个控制平面节点上的 etcd、API Server、Controller Manager、Scheduler 静态 Pod。静态 Pod 必须存在且唯一、未处于删除中，所有主容器均 Running 且 Ready；普通安装任务或 guard Pod 不能代替静态 Pod。仅看 ClusterVersion Available 或节点 Ready 不足以继续安装：控制器退出时，旧状态可能仍显示正常；节点在更新期间也可能 Ready 但不可调度。检查有超时，失败会列出阻塞资源，不自动重复写入。

先确认故障原因、恢复管理组件并等节点更新完成，再重新运行同一入口。Virtualization 安装后可能触发额外的节点配置更新，应待该轮 MCP 收敛后再检查实际容量和组件功能。脚本不会降低控制平面维护保护规则、强制驱逐 Pod 或重启节点来掩盖阻塞；宽松安全开关也不包含这些操作。

### Virtualization 的离线引导源

基础包包含固定摘要的 RHEL 9 guest container disk；产品清单关闭系统默认引导镜像自动导入，避免 Fedora/CentOS 的公共镜像轮询在隔离环境持续失败。这不影响手动创建使用本地已镜像 container disk 的 VM。其他系统需在准备阶段补充镜像，并把自定义引导源指向实际本地镜像，持久化模板还需要对应存储。不会把所有系统模板宣称为已可用。

HCO `v1` 使用 `spec.workloadSources.enableCommonBootImageImport`；`v1beta1` 使用 `spec.enableCommonBootImageImport`。旧的 `spec.featureGates.enableCommonBootImageImport` 已被忽略，不能据此判定已经关闭。5.0 的两种实际 CRD 已核对；4.22 的 beta 字段依据[红帽引导源文档](https://docs.redhat.com/en/documentation/openshift_container_platform/4.22/html/virtualization/storage)。创建 HCO 后再次等待 MCP 收敛，并按 Available/Progressing/Degraded 条件和实际 Deployment 验证；不要求未在 CRD 中定义的 `status.phase`。

CA 合并、目录策略和集群版本检查的 API 访问设置超时，失败停止而不生成成功结果。CA 组件刷新仅在实际 rollout 成功后记录完成摘要；如果证书写入后中断，修复 API 连通性后重试会继续未完成的刷新，不把证书相同误判为配置已全部完成。

后置配置中普通 `oc` 请求也设置 30 秒请求超时，API 无响应时返回失败；NFS provisioner 的部署等待保留独立的 180 秒期限。请求超时不表示服务端一定没有接受写入，重试前应先核对实际资源；管理员初始化遇到已创建的凭据仍会停止，不重置账号。
