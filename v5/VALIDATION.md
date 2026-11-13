# 验证范围与交付状态

更新：2026-11-13。固定目标 5.0.1 / amd64。以下逐项区分实际执行、代码检查和仍待验收；不以下载/导入成功代替组件功能验收。

**本轮整体验收未通过，PR 保持草稿。** 平台安装及基础离线模式下的 RHEL 9 VM 两轮真实启停验证已通过；后续正常重启、资源调整和独立健康复核已完成。ACM/MCE 初始化、Hub/Policy 及 4.22 上的 AI 功能仍待验收。最新状态见下方“追加预算后的恢复复核”；较早的故障快照按原时间保留。

| 范围 | 结果 |
|---|---|
| 三节点 5.0.1，KVM/裸金属 UPI 流程 | 已在 Ohio 单台 EC2 的三台 RHCOS 虚拟机完成安装；3 Ready、ClusterVersion 完成、34 ClusterOperator 健康 |
| 离线平台安装 | 已使用本地 Harbor 安装；节点外网出口阻断，仅放行本地镜像仓库 |
| 安装后基础功能 | Deployment/Route、扩缩容、重启、DNS、非 root 容器、静态 NFS PVC、RBAC、内部 Registry 已验证 |
| Operator 可搬迁导出/导入 | Web Terminal 1.17.2 + DevWorkspace 1.0.0，10 个镜像；全新缓存、不同含空格路径、只转移校验清单内文件、外网阻断的导入通过 |
| Operator 实际使用 | 两个 CSV 均 Succeeded；创建 DevWorkspace 达到 Running，并成功执行标记命令 |
| 完整 delivery 打包 | 完整组合导出与换路径整包校验已通过，收集 359 个 Helper RPM；新路径下从平台归档重建规则、阻断外网导入、安装后配置通过，MCP 收敛，原有工作空间仍 Running |
| 本地回归 | 两版分别 157 项 Python 检查通过；Bash 语法与 ShellCheck warning 级别检查通过 |
| 全新隔离 Helper 初始化 | RHEL 9.6 虚拟机完成 359 RPM 本地 GPG 安装、默认 SELinux/firewalld、Docker/Harbor、平台离线导入及 Ignition/handoff 生成；未启动第二套集群节点，物理服务器尚待单独验收 |
| 授时与缓存针对性回归 | 在隔离 Helper 完成 30 项实测：拒绝 NTP 自引用、上游不可达时失败、显式本地 stratum 10 回应真实 NTP 查询、缓存位于包外；安全策略保持开启 |
| 本地仓库的组件证书信任 | AWS 实测完成 CA 注入后刷新目录服务、三份 ClusterCatalog Serving；重复执行不修改 CA、不重启组件。合并已有用户 CA、保留代理字段及并发保护另有回归检查。官方 4.22.22/5.0.1 安装器均确认支持 Always 策略 |
| 默认在线目录策略 | 真实代码将三个官方在线默认 ClusterCatalog 设为 Unavailable，三份自定义离线目录的 spec 和 Serving 状态保持正常；重复运行不再变更已关闭的目录 |
| Virtualization | 完整独立归档、换路径、阻断外网导入通过；基础离线模式下真实 RHEL 9.9 VM 连续两轮启动、Ready/Guest Agent 与来宾系统信息检查、正常停止通过；结束后 VM Halted，无 VMI/launcher，原 CPU/内存和镜像摘要保持不变。持久化、迁移和所有系统模板不在本次验收范围 |
| ACM/MCE | 完整独立归档、换路径、阻断外网导入通过；基础 Hub 与策略未执行；MCE 初始化未通过，测试实例的正常卸载已恢复并独立确认完成，功能仍需重新验收，不能以 CSV Succeeded 代替 |
| Virtualization 离线引导源策略 | 基础清单关闭未准备的公共引导镜像自动导入；v1/v1beta1 严格服务端预演通过，运行中的策略切换已完成。新模式的两轮真实 VM 验证通过，公共 DataImportCron 与引导源导入任务保持为空 |
| OpenShift AI | 当前官方支持矩阵列出 4.22，未列出 5.0；5.x 准备脚本明确拒绝该组合 |


引导源字段检查记录见 `tests/evidence/boot-policy-server-2026-11-13.json`；4.22 catalog 声明两种 HCO API，不代表在 4.22 上做过运行验收。

CA 刷新完成标记及 API 超时另有故障回归：证书写入后刷新中断时，重试会继续未完成组件，已完成组件不重复刷新。实际 5.0 已只读验证新标记通过服务端校验，未为此重启组件；运行刷新仍以此前记录的实测为准。

Harbor 项目请求另经本机真实 HTTPS/curl 测试：模拟 503 后重试得到已有项目的 409，认证和私有项目内容检查通过。该测试不代表重装了一套 Harbor。管理员冲突、API 失败及创建凭据时的竞争失败已加入回归；没有在测试集群重置管理员密码。

## 复杂组件的范围

目录中的 `relatedImages` 和 OLM 依赖只覆盖声明的镜像/API，不能自动证明所有业务功能都可用。`operators-plan.json` 的 `productRequirements` 记录额外前提。

- **Virtualization**：5.0 平台使用 Virtualization 5.0；4.22 使用 Virtualization 4.22，禁止直接借用 5.0 默认 channel。HCO 关联镜像包含其控制组件，另补充并锁定 RHEL 9 guest container disk。基础虚拟机之外，桥接网络、SR-IOV、负载均衡、持久化/迁移能力需要对应网络和存储组件。
- **ACM 5.0**：补选 MCE 5.0，不能依赖空的 OLM catalog dependency。创建 MultiClusterHub 时要把 `installer.open-cluster-management.io/mce-subscription-spec` 的 `source` 指向实际离线 CatalogSource。基础 Hub 验收不等于备份、Submariner、GitOps 或多托管集群场景验收。
- **AI 3.5.2/3.5.3 / 4.22**：目前规则范围是 Dashboard 和 CPU Workbenches，额外收录红帽固定提交中的 CPU/Python 3.12 Workbench 镜像。需要默认动态 StorageClass、真实 IDP 用户以及至少两个 8 CPU/32 GiB 可调度节点。GPU、KServe、训练、llm-d、RAG 不包含在此基础范围；应按功能另选 cert-manager、Kueue、JobSet、Connectivity Link、LWS 等，并准备对象存储、模型数据及其他运行镜像。

按现有组合进行准备时，规则会拒绝不在当前核实范围内的版本，不静默借用其他平台 catalog。

## 节点更新恢复的阶段性记录

Virtualization 触发的 MCP 更新中，三个控制平面 Operator 异常，缺失的 guard Pod 使维护保护规则阻止下一节点更新。dsh 曾临时将三个 guard PDB 的 `minAvailable` 从 2 降为 1；该验收任务已停止，三个值均已要求恢复并核对为 2。此临时操作未写入脚本，也不能作为可重复安装的解决方案。20:59 UTC 的阶段性复核确认 MCP 3/3 完成、三个节点 Ready 且可调度、三个 PDB 均为 2 且各有三个健康 guard、四个核心管理组件就绪。随后单 VM 验证通过；ACM/MCE 联调期间再次出现控制器与 API 异常，当前结果见下一节。

两版配置与应用入口新增实际管理组件和节点/MCP 检查，防止 ClusterVersion 的旧健康状态掩盖控制器异常；节点 MachineConfig 必须为 Done 且当前配置与目标配置相同。新检查已通过真实 5.0 集群只读验证，源码摘要随实测数据保存。遇到此类故障应先恢复组件及维护保护，再继续安装，不通过强制驱逐、关闭 SELinux 或降低 PDB 来绕过问题。

## 追加预算后的恢复复核

截至 2026-11-13，恢复复验仍在进行，尚未完成全部产品验收。

- AWS 已于 02:20 UTC 接受现有磁盘吞吐从 125 提高至 500 MiB/s 的调整，仍处于后台优化阶段；容量 1 TiB、3000 IOPS、EC2 和三台节点规格均未变。后续实际吞吐超过原上限，仍出现过短时积压；这些数据不能证明所有故障只由存储引起。
- 02:28 UTC，使用当前交付生成器应用 RHEL 9 基础离线策略，HCO 代数从 2 到 3，关闭公共引导镜像自动导入；其他 spec 和注解保持不变。随后默认 DataImportCron 列表为空，HCO 已观察到代数 3 并恢复健康。新模式的两轮 VM 启停请求均因所有节点缺少足够内存请求余量而未能调度，未取得新的来宾启动证明；两轮均正常停止并确认 VMI/launcher 清理完成。已获授权将两台测试节点从 4 CPU/16 GiB 调整至 8 CPU/32 GiB，正在逐台维护，尚未据此标为完成。
- 03:39 UTC 独立复核确认测试 MCE、ClusterManager 和 Hub 命名空间均不存在，正常清理已完成；ACM Hub/Policy 功能尚未执行。清理恢复见下一段。
- 曾出现 CO 和核心 Operator Deployment 显示健康、实际 KCM 容器却在退出的情况。两版门禁现已增加每个控制平面节点的四类静态 Pod 和全部主容器检查，拒绝缺失、重复、删除中、未就绪或非 Running 容器。回归覆盖陈旧健康状态、缺失主节点静态 Pod、误用安装任务及工作节点范围；[真实只读快照](tests/evidence/static-pod-gate-live-2026-11-13.json)中 12 个静态 Pod 均就绪，新旧门禁在同一份响应上均通过。该快照证明健康状态可以通过新检查，不能代替持续稳定性或复杂组件验收。
- 首次扩容维护因 API 请求超时中止。后续按批准的恢复流程完成正常关机、资源调整和启动；独立复核确认控制平面、节点配置池、平台 Operator、Virtualization 与工作空间组件健康，维护保护规则保持原值。详细维护诊断保存在私有测试记录中。
- 基础离线模式随后完成两轮 RHEL 9.9 VM 实际启动、来宾系统与 Guest Agent 检查及正常停止。两轮使用原有 CPU/内存和固定镜像摘要；结束后确认 VM Halted、VMI 和 launcher 已清理，VM 其余 spec 不变，完整健康门禁再次通过。本地 Harbor 可达、外部镜像源仍被阻断。该结果仅覆盖基础 VM，ACM/MCE 与 AI 的产品功能仍需继续验收。

MCE 5.0.0 在本次失败后的卸载中，先撤销部分 API，随后控制器无法映射 `ManagedCluster`，另有两个系统 ManagedClusterSet 的角色清理等待原控制器处理。03:25–03:28 使用与实际 registration-operator 镜像匹配的官方源码提交 `ec745b6c194ce437e7e82baa3f1225af53f16924` 恢复五个缺失 API，转换证书采用仍保留的官方 webhook 公共 CA。为防止定义立刻再次被回收，短暂暂停已经在卸载的 ClusterManager 控制器，并设置自动恢复保护；系统集合由原控制器正常清理后，立即恢复原来的三个副本，再由正常卸载流程完成删除。没有修改 finalizer、控制平面 PDB 或供应商二进制。[精简证据](tests/evidence/mce-normal-cleanup-2026-11-13.json)保留了副本变更与独立复核结果。该恢复仅针对本次测试实例，不属于三个脚本的默认安装步骤，也不能代替 MCE/ACM 功能验收。

后置配置普通 `oc` 请求的 30 秒超时另经真实 RHEL 9/5.0 客户端验证：连接本机延迟服务约 30.06 秒后非零退出，同一包装函数读取集群 `/readyz` 成功；见 [请求超时实测](tests/evidence/setup-api-timeout-2026-11-13.json)。上述 5.0 记录不代表 4.22 集群实机验收。

## 本轮复杂组件联调结论

截至 2026-11-12 22:21 UTC（北京时间 11 月 13 日 06:21），本轮功能验收状态为 **blocked**。

- Virtualization 已实际启动 RHEL 9.9 VM，取得来宾系统信息后正常停止；初次固定到 master1 的放置因请求内存不足而改为有余量的 master3，节点规格保持不变。该记录不包含持久化、迁移或所有系统模板的验收。
- MCE 初始化出现组件重启、API 超时和 leader election 失败；未继续创建 ACM Hub 或策略。已核对资源归属并正常请求删除本次 MCE，以及其自动创建的 `local-cluster` 注册。22:09 UTC 仍可读到卸载 finalizer；22:21 的部分 API 读取失败，**不能确认清理或完整健康恢复已经完成**。未移除 finalizer、未强制删除命名空间、未降低副本或维护保护。
- 最新快照中 HCO operator 为 0/1、webhook 为 1/1；DWO 和部分核心管理组件状态读取失败，不能标为健康。较早工作空间仍 Running 且实际执行标记命令成功；公网临时 Console 首页在 22:19 UTC 返回 200，仅证明匿名页面可达。
- 新基础离线引导源策略已通过严格服务端预检查；本轮因 HCO/webhook 健康前提不满足，未应用到运行集群，也未在该策略下重跑 VM。
- 共享存储出现过 97% 忙碌度和约 42 ms 平均读写等待。短时采样与 CPU requests 不能单独确定瓶颈；本轮没有调整 EC2/虚拟机规格、磁盘性能、外网隔离或既定结束时间。

去除私密内容的记录：[最终联调状态](tests/evidence/product-acceptance-final-2026-11-13.json)、[单 VM](tests/evidence/virtualization-basic-2026-11-13.json)、[性能采样](tests/evidence/runtime-pressure-2026-11-13.json)。后续应在明确功能范围、性能条件和预算窗口后重新验收 ACM/MCE；4.22 整机和 AI 验收仍待完成。

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
