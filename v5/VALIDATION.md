# 验证范围与交付状态

更新：2026-11-13。固定目标 5.0.1 / amd64。以下逐项区分实际执行、代码检查和仍待验收；不以下载/导入成功代替组件功能验收。

| 范围 | 结果 |
|---|---|
| 三节点 5.0.1，KVM/裸金属 UPI 流程 | 已在 Ohio 单台 EC2 的三台 RHCOS 虚拟机完成安装；3 Ready、ClusterVersion 完成、34 ClusterOperator 健康 |
| 离线平台安装 | 已使用本地 Harbor 安装；节点外网出口阻断，仅放行本地镜像仓库 |
| 安装后基础功能 | Deployment/Route、扩缩容、重启、DNS、非 root 容器、静态 NFS PVC、RBAC、内部 Registry 已验证 |
| Operator 可搬迁导出/导入 | Web Terminal 1.17.2 + DevWorkspace 1.0.0，10 个镜像；全新缓存、不同含空格路径、只转移校验清单内文件、外网阻断的导入通过 |
| Operator 实际使用 | 两个 CSV 均 Succeeded；创建 DevWorkspace 达到 Running，并成功执行标记命令 |
| 完整 delivery 打包 | 完整组合导出与换路径整包校验已通过，收集 359 个 Helper RPM；新路径下从平台归档重建规则、阻断外网导入、安装后配置通过，MCP 收敛，原有工作空间仍 Running |
| 本地回归 | 两版分别 141 项 Python 检查通过；Bash 语法与 ShellCheck warning 级别检查通过 |
| 全新隔离 Helper 初始化 | RHEL 9.6 虚拟机完成 359 RPM 本地 GPG 安装、默认 SELinux/firewalld、Docker/Harbor、平台离线导入及 Ignition/handoff 生成；未启动第二套集群节点，物理服务器尚待单独验收 |
| 授时与缓存针对性回归 | 在隔离 Helper 完成 30 项实测：拒绝 NTP 自引用、上游不可达时失败、显式本地 stratum 10 回应真实 NTP 查询、缓存位于包外；安全策略保持开启 |
| 本地仓库的组件证书信任 | AWS 实测完成 CA 注入后刷新目录服务、三份 ClusterCatalog Serving；重复执行不修改 CA、不重启组件。合并已有用户 CA、保留代理字段及并发保护另有回归检查。官方 4.22.22/5.0.1 安装器均确认支持 Always 策略 |
| 默认在线目录策略 | 真实代码将三个官方在线默认 ClusterCatalog 设为 Unavailable，三份自定义离线目录的 spec 和 Serving 状态保持正常；重复运行不再变更已关闭的目录 |
| Virtualization / ACM | 5.0 的 Virtualization 和 ACM/MCE 均已完成独立归档、换路径校验和阻断外网导入；本次 3×4 CPU/16 GiB 在 Virtualization 触发的 MCP 更新期间出现调度等待，需待更新及工作负载验收完成后判断稳态容量；4.22 对应组件尚未完成实机验收 |
| OpenShift AI | 当前官方支持矩阵列出 4.22，未列出 5.0；5.x 准备脚本明确拒绝该组合 |

## 复杂组件的范围

目录中的 `relatedImages` 和 OLM 依赖只覆盖声明的镜像/API，不能自动证明所有业务功能都可用。`operators-plan.json` 的 `productRequirements` 记录额外前提。

- **Virtualization**：5.0 平台使用 Virtualization 5.0；4.22 使用 Virtualization 4.22，禁止直接借用 5.0 默认 channel。HCO 关联镜像包含其控制组件，另补充并锁定 RHEL 9 guest container disk。基础虚拟机之外，桥接网络、SR-IOV、负载均衡、持久化/迁移能力需要对应网络和存储组件。
- **ACM 5.0**：补选 MCE 5.0，不能依赖空的 OLM catalog dependency。创建 MultiClusterHub 时要把 `installer.open-cluster-management.io/mce-subscription-spec` 的 `source` 指向实际离线 CatalogSource。基础 Hub 验收不等于备份、Submariner、GitOps 或多托管集群场景验收。
- **AI 3.5.2/3.5.3 / 4.22**：目前规则范围是 Dashboard 和 CPU Workbenches，额外收录红帽固定提交中的 CPU/Python 3.12 Workbench 镜像。需要默认动态 StorageClass、真实 IDP 用户以及至少两个 8 CPU/32 GiB 可调度节点。GPU、KServe、训练、llm-d、RAG 不包含在此基础范围；应按功能另选 cert-manager、Kueue、JobSet、Connectivity Link、LWS 等，并准备对象存储、模型数据及其他运行镜像。

按现有组合进行准备时，规则会拒绝不在当前核实范围内的版本，不静默借用其他平台 catalog。

## 当前复杂组件测试的恢复记录

Virtualization 触发的 MCP 更新中，三个控制平面 Operator 异常，缺失的 guard Pod 使维护保护规则阻止下一节点更新。dsh 曾临时将三个 guard PDB 的 `minAvailable` 从 2 降为 1；该验收任务已停止，三个值均已要求恢复并核对为 2。此临时操作未写入脚本，也不能作为可重复安装的解决方案。当前节点更新和复杂组件功能尚待重新验收，不能沿用早先安装完成时的健康快照宣称通过。

两版配置与应用入口新增实际管理组件和节点/MCP 检查，防止 ClusterVersion 的旧健康状态掩盖控制器异常。遇到此类故障应先恢复组件及维护保护，再继续安装，不通过强制驱逐、关闭 SELinux 或降低 PDB 来绕过问题。

## 实测中的工具问题

所提供的官方 oc-mirror 构建在从 registry catalog 的归档导入时仍访问源 catalog。上游已有修复，但当时官方发布包早于该修复。当前流程先准备本地 OCI catalog，导出与导入均使用包内相对路径；该路径已完成阻断外网的实测。

另一个已修复问题是过滤 catalog 的 targetTag 与仓库名包含相同文本时，现有工具可能替换错误位置。生成器保证 tag 不出现在 repository 名称中；导出后额外检查归档中的正确过滤目录标签及全部镜像 descriptor/layer，缺失时不生成成功清单。独立交付使用完整导出，避免把仅含增量的归档误当成可搬迁全量包。

新 Helper 实测还发现上游 NTP 自引用，当前代码拒绝该配置并提供显式 `NTP_MODE=local`；默认上游模式等待同步，失败停止。平台导入缓存移至私有状态目录；首次输入失败可使用原目录重试。生成 Ignition 前的重试固定 Helper 拓扑，并复用已有 Harbor 配置和数据。

官方 `openshift-install-rhel9-amd64.tar.gz` 中的二进制为 `openshift-install-fips`；当前非 FIPS 安装改用官方标准 `openshift-install-linux.tar.gz`，不会把 FIPS 文件直接改名。

## 依据

- [红帽 Operator 生命周期及平台支持版本](https://access.redhat.com/support/policy/updates/openshift_operators)
- [OpenShift AI 当前支持矩阵](https://access.redhat.com/articles/rhoai-supported-configs)
- [AI 3.5.3 离线运行镜像清单，固定提交](https://github.com/red-hat-data-services/rhoai-disconnected-install-helper/blob/9d5a7fcde1061de090ddc0b2c3b58086698ef4b1/rhoai-3.5.3-imagesetconfig.yaml)
- [oc-mirror v2 文档](https://docs.redhat.com/en/documentation/openshift_container_platform/4.22/html/disconnected_environments/about-installing-oc-mirror-v2)
- [oc-mirror 离线 catalog 导入修复](https://github.com/openshift/oc-mirror/commit/4cfbc254b92f34b456f44ca3540e36d09f79fffa)

已去除凭据的 AWS 实测数据：[offline evidence](tests/evidence/aws-offline-2026-11-13.json)。该记录对应 5.0.1，不能替代 4.22 的整套集群验收。
