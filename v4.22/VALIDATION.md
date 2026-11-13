# 验证范围与交付状态

更新：2026-11-13。本目录固定目标 4.22.22 / amd64。共享引擎在 5.0.1 的实测仅说明同类流程可行，不能当作 4.22 已完成实机安装。以下逐项区分实际执行、代码检查和仍待验收；不以下载/导入成功代替组件功能验收。

| 范围 | 结果 |
|---|---|
| 官方 4.22.22 工具 | 已真实下载并验证客户端、标准安装器、kubectl 硬链接和执行权限；[记录](tests/evidence/tools-2026-11-13.json) |
| 4.22 Operator 包离线导入 | 使用真实 4.22 目录及工具完成 Web Terminal/DevWorkspace 的换路径、全新缓存、阻断外网导入；在 5.0 上错误版本应用被阻止，未写入 4.22 资源；[记录](tests/evidence/operators-2026-11-13.json) |
| 三节点 4.22.22 | 尚未完成实机验收；独立版本脚本与平台配置已提供 |
| 共享流程在 5.0.1 的离线平台安装 | 已使用本地 Harbor 安装；不能据此认定 4.22 已验收 |
| 共享流程在 5.0.1 的安装后基础功能 | Deployment/Route、扩缩容、重启、DNS、非 root 容器、静态 NFS PVC、RBAC、内部 Registry 已验证 |
| 共享引擎在 5.0.1 的 Operator 可搬迁导出/导入 | Web Terminal 1.17.2 + DevWorkspace 1.0.0，10 个镜像；全新缓存、不同含空格路径、只转移校验清单内文件、外网阻断的导入通过 |
| 5.0.1 的 Operator 实际使用 | 两个 CSV 均 Succeeded；创建 DevWorkspace 达到 Running，并成功执行标记命令 |
| 共享引擎在 5.0.1 的完整 delivery 打包 | 完整组合导出与换路径整包校验已通过，收集 359 个 Helper RPM；新路径下从平台归档重建规则、阻断外网导入、安装后配置通过，MCP 收敛，原有工作空间仍 Running |
| 本地回归 | 两版分别 157 项 Python 检查通过；Bash 语法与 ShellCheck warning 级别检查通过 |
| 共享 Helper 初始化流程在 5.0.1 | RHEL 9.6 虚拟机完成 359 RPM 本地 GPG 安装、默认 SELinux/firewalld、Docker/Harbor、平台离线导入及 Ignition/handoff 生成；未启动第二套集群节点，物理服务器尚待单独验收 |
| 共享授时/缓存函数在 5.0.1 的回归 | 在隔离 Helper 完成 30 项实测：拒绝 NTP 自引用、上游不可达时失败、显式本地 stratum 10 回应真实 NTP 查询、缓存位于包外；安全策略保持开启 |
| 共享组件信任函数在 5.0.1 的回归 | AWS 实测完成 CA 注入后刷新目录服务、三份 ClusterCatalog Serving；重复执行不修改 CA、不重启组件。合并已有用户 CA、保留代理字段及并发保护另有回归检查。官方 4.22.22/5.0.1 安装器均确认支持 Always 策略 |
| 共享目录策略在 5.0.1 的回归 | 真实代码将三个官方在线默认 ClusterCatalog 设为 Unavailable，三份自定义离线目录的 spec 和 Serving 状态保持正常；重复运行不再变更已关闭的目录 |
| Virtualization / ACM | 5.0 的 Virtualization 和 ACM/MCE 均已完成独立归档、换路径校验和阻断外网导入；本次 3×4 CPU/16 GiB 在 Virtualization 触发的 MCP 更新期间出现调度等待，MCP 已收敛，仍需待工作负载验收完成后判断稳态容量；4.22 对应组件尚未完成实机验收 |
| OpenShift AI | 当前官方支持矩阵列出 4.22，未列出 5.0；5.x 准备脚本明确拒绝该组合 |

## 复杂组件的范围

目录中的 `relatedImages` 和 OLM 依赖只覆盖声明的镜像/API，不能自动证明所有业务功能都可用。`operators-plan.json` 的 `productRequirements` 记录额外前提。

- **Virtualization**：5.0 平台使用 Virtualization 5.0；4.22 使用 Virtualization 4.22，禁止直接借用 5.0 默认 channel。HCO 关联镜像包含其控制组件，另补充并锁定 RHEL 9 guest container disk。基础虚拟机之外，桥接网络、SR-IOV、负载均衡、持久化/迁移能力需要对应网络和存储组件。
- **ACM 5.0**：补选 MCE 5.0，不能依赖空的 OLM catalog dependency。创建 MultiClusterHub 时要把 `installer.open-cluster-management.io/mce-subscription-spec` 的 `source` 指向实际离线 CatalogSource。基础 Hub 验收不等于备份、Submariner、GitOps 或多托管集群场景验收。
- **AI 3.5.2/3.5.3 / 4.22**：目前规则范围是 Dashboard 和 CPU Workbenches，额外收录红帽固定提交中的 CPU/Python 3.12 Workbench 镜像。需要默认动态 StorageClass、真实 IDP 用户以及至少两个 8 CPU/32 GiB 可调度节点。GPU、KServe、训练、llm-d、RAG 不包含在此基础范围；应按功能另选 cert-manager、Kueue、JobSet、Connectivity Link、LWS 等，并准备对象存储、模型数据及其他运行镜像。

AI 3.5.2 的只读容量审计包含 145 个镜像引用；完整多架构引用中去重压缩层约 294 GiB（不含归档、缓存和 Harbor 的额外空间）。该数字是元数据审计，未下载镜像或在 4.22 上安装 AI；当前单台测试机空间不足以按保留余量的方案完成全量导入，需另行安排资源与测试窗口。

按现有组合进行准备时，规则会拒绝不在当前核实范围内的版本，不静默借用其他平台 catalog。

## 实测中的工具问题

所提供的官方 oc-mirror 构建在从 registry catalog 的归档导入时仍访问源 catalog。上游已有修复，但当时官方发布包早于该修复。当前流程先准备本地 OCI catalog，导出与导入均使用包内相对路径；该路径已完成阻断外网的实测。

另一个已修复问题是过滤 catalog 的 targetTag 与仓库名包含相同文本时，现有工具可能替换错误位置。生成器保证 tag 不出现在 repository 名称中；导出后额外检查归档中的正确过滤目录标签及全部镜像 descriptor/layer，缺失时不生成成功清单。独立交付使用完整导出，避免把仅含增量的归档误当成可搬迁全量包。

新 Helper 实测还发现上游 NTP 自引用，当前代码拒绝该配置并提供显式 `NTP_MODE=local`；默认上游模式等待同步，失败停止。平台导入缓存移至私有状态目录；首次输入失败可使用原目录重试。生成 Ignition 前的重试固定 Helper 拓扑，并复用已有 Harbor 配置和数据。

官方 `openshift-install-rhel9-amd64.tar.gz` 中的二进制为 `openshift-install-fips`；当前非 FIPS 安装改用官方标准 `openshift-install-linux.tar.gz`，不会把 FIPS 文件直接改名。


引导源字段检查记录见 `tests/evidence/boot-policy-schema-2026-11-13.json`；4.22 catalog 声明两种 HCO API，不代表在 4.22 上做过运行验收。

CA 刷新完成标记及 API 超时另有故障回归：证书写入后刷新中断时，重试会继续未完成组件，已完成组件不重复刷新。实际 5.0 已只读验证新标记通过服务端校验，未为此重启组件；运行刷新仍以此前记录的实测为准。

Harbor 项目请求另经本机真实 HTTPS/curl 测试：模拟 503 后重试得到已有项目的 409，认证和私有项目内容检查通过。该测试不代表重装了一套 Harbor。管理员冲突、API 失败及创建凭据时的竞争失败已加入回归；没有在测试集群重置管理员密码。

## 依据

- [红帽 Operator 生命周期及平台支持版本](https://access.redhat.com/support/policy/updates/openshift_operators)
- [OpenShift AI 当前支持矩阵](https://access.redhat.com/articles/rhoai-supported-configs)
- [AI 3.5.3 离线运行镜像清单，固定提交](https://github.com/red-hat-data-services/rhoai-disconnected-install-helper/blob/9d5a7fcde1061de090ddc0b2c3b58086698ef4b1/rhoai-3.5.3-imagesetconfig.yaml)
- [oc-mirror v2 文档](https://docs.redhat.com/en/documentation/openshift_container_platform/4.22/html/disconnected_environments/about-installing-oc-mirror-v2)
- [oc-mirror 离线 catalog 导入修复](https://github.com/openshift/oc-mirror/commit/4cfbc254b92f34b456f44ca3540e36d09f79fffa)

## 本轮 5.0 联调的补充限制

共享流程在 5.0 上的单个 RHEL 9.9 VM 已实际运行并正常停止；新基础离线模式的复验因节点资源不足未能调度，首次扩容维护因 API 超时中止，节点容量未改变，环境健康仍需恢复。ACM/MCE 初始化未通过，Hub/策略未执行；2026-11-13 03:39 UTC 已独立确认失败测试实例正常清理完成，功能仍需重新验收。该结果不作为 4.22 整机或 AI 的运行验收。最新记录见 [5.0 验证范围](../v5/VALIDATION.md)。

后置配置的普通 `oc` 请求已补上 30 秒请求超时，部署等待仍使用独立的 180 秒期限；回归验证超时参数和错误退出传递。相同包装函数已在 RHEL 9 上使用官方 5.0 客户端连接本机延迟服务，约 30.06 秒超时；这不是 4.22 集群实机验收。

两版健康门禁已补充控制平面静态 Pod 和全部主容器检查，回归覆盖汇总状态陈旧但容器异常、主节点缺少静态 Pod、安装任务混淆及工作节点范围。新实现已在实际 5.0 集群的 12 个健康静态 Pod 上通过只读核验；4.22 运行验收仍待完成。
