# AI、Virtualization 与常用 Operator 的离线范围

核对日期：2026-11-17。优先目标为 **OCP 4.22.22 / x86_64**；5.0.1 仅作预览。这里区分厂商必需项、按功能选配项和当前脚本的验证边界。镜像清单以实际固定 catalog/bundle 的 `operators-plan.json` 为准。

## OpenShift AI

当前[红帽支持矩阵](https://access.redhat.com/articles/rhoai-supported-configs)列出 AI 3.5 / OCP 4.22，未列出 5.0。部分安装指南仍保留较早的平台范围，应以支持矩阵和具体补丁组合核对。

| 功能 | 必需或配套内容 | 脚本处理 |
|---|---|---|
| Dashboard、CPU 工作台 | `rhods-operator`；动态 StorageClass、IDP 用户 | 解析完整 bundle/relatedImages，补充 CPU 工作台和两个平台托管 Gateway 镜像；存储提供者按需选 LVMS/ODF 等 |
| NVIDIA GPU 工作台 | `nfd` + certified 目录的 `gpu-operator-certified`；匹配平台的 DTK、驱动、CUDA 工作台 | 新 AI 计划默认准备此组，交互可选 no；命令行仅 CPU 用 `--no-ai-nvidia` |
| KServe | `openshift-cert-manager-operator` | 可显式选包；模型服务、运行时、模型权重及对象存储须按实际功能另外准备 |
| Kueue、Ray、训练 | `kueue-operator`、cert-manager；Trainer 另需 `job-set` | 可显式选包并解析 OLM 依赖；未把训练镜像、数据集和任意 Ray 镜像当作已准备 |
| llm-d | cert-manager、`rhcl-operator`、`leader-worker-set`；看板另需 `cluster-observability-operator` | 可选包；推理运行时、模型和拓扑需另行核实 |
| RAG/OGX | AI 中的 OGX 组件、`servicemeshoperator3`、cert-manager、GPU、S3 | 不虚构同名独立 OLM 包；当前基础配置关闭此功能 |
| 遥测与追踪 | `opentelemetry-product`、`tempo-product`、Cluster Observability，按功能选取 | Collector 基础关联镜像可随包准备；自动插桩、存储后端和自定义 Collector 镜像按实际配置补充 |

以上功能划分依据[AI 3.5 组件要求](https://docs.redhat.com/en/documentation/red_hat_openshift_ai_self-managed/3.5/html-single/installing_and_uninstalling_openshift_ai_self-managed_in_a_disconnected_environment/index)。不会把所有可选 Operator 都说成安装 Dashboard 的强制依赖。

### NVIDIA 基础路径

真实 4.22 目录中为 **NFD 4.22.0-202611040403**、**NVIDIA GPU Operator 26.7.2 / v26.7**。后者位于 `registry.redhat.io/redhat/certified-operator-index:v4.22`，不在默认 redhat 目录。AI 新计划需要 GPU 时自动加入该目录并锁定摘要；也可预先通过 `--catalog certified=...` 指定已核实的目录。

NVIDIA bundle 声明 21 条 relatedImages，包含默认驱动及其他声明的驱动分支、Container Toolkit、Device Plugin/GFD、DCGM/Exporter、Validator 等。脚本完整保留这些声明，并自动补入 **4.22.22 发布清单中的 DTK** 和 **9 个固定摘要的 CUDA/Python 3.12 工作台镜像**。默认驱动摘要必须真实存在于 bundle 中；不能只下载 Operator 控制器就标记 GPU 已准备。

驱动和 DTK 的匹配由 GPU 节点的 RHCOS 决定，与 Helper 使用 RHEL 9 还是 RHEL 10 无关。

[NVIDIA 的 26.7 安装说明](https://docs.nvidia.com/datacenter/cloud-native/openshift/26.7/steps-overview.html)明确：OCP 4.22 常规驱动采用 `rhel9.8` 后缀；不能猜成 `rhcos4.22` 或沿用 `rhel9.6`。本轮使用厂商已声明的驱动摘要和 DTK 路径，避免手拼 tag。驱动分支仍须按 GPU 型号、固件和 CUDA 需求核对。

镜像可以离线准备，**驱动已生效需要真实 GPU 另验**。后置配置只生成分阶段参考：先安装 NFD、创建 NodeFeatureDiscovery 并确认 PCI 标签；再安装 GPU Operator、审阅 DTK ClusterPolicy；确认 `nvidia-smi`、节点 `nvidia.com/gpu` 资源和真实 CUDA Pod 后，再创建 AI hardware profile/GPU 工作台。DTK ImageStream、构建账户凭据和仓库信任也必须可用。KMM 是否需要取决于加速器/驱动方案，本轮 NVIDIA 常规 DTK 路径不将 KMM 当作强制依赖。

vGPU、预编译/自定义驱动、RDMA、GDS、MIG、多卡分布式推理有各自的硬件、内核、网络或许可条件，不能由基础镜像包推断已经可用。[NVIDIA 预编译驱动说明](https://docs.nvidia.com/datacenter/cloud-native/openshift/26.7/gpu-operator-with-precompiled-drivers.html)要求核对目标内核对应镜像。

```bash
# 默认同时准备 NFD/NVIDIA/DTK/CUDA 工作台；实际下载使用 export。
bash v4.22/prepare-operators.sh plan --non-interactive \
  --bundle '/data/ai422 gpu' --authfile /secure/pull-secret.json \
  --select redhat/rhods-operator:stable-3.5=3.5.2

# 无 GPU 时，使用新目录显式准备原有 CPU 基础范围：
bash v4.22/prepare-operators.sh plan --non-interactive \
  --bundle '/data/ai422 cpu' --authfile /secure/pull-secret.json \
  --select redhat/rhods-operator:stable-3.5=3.5.2 --no-ai-nvidia
```

完整交付模式同样支持 `--ai-nvidia/--no-ai-nvidia`。已有 CPU 包不会原地变成 GPU 包，增加功能须用新目录重新准备。当前自动 DTK/Gateway 规则仅核实到 **4.22.22**；更换补丁先核对对应发布清单，禁止借用旧 DTK。

## OpenShift Virtualization

必需的顶层包是 **`kubevirt-hyperconverged:stable`，当前 4.22.16**，部署命名空间必须为 `openshift-cnv`。HCO 的 69 条 relatedImages 包含其 KubeVirt、CDI、SSP、网络附加组件及其他声明的操作数，不能把其中每个内部控制器都当成独立 OLM 包重复选取。来源见[官方安装说明](https://docs.redhat.com/en/documentation/openshift_container_platform/4.22/html-single/virtualization/index)。

| 需求 | 配套内容 | 离线处理 |
|---|---|---|
| 启动基础 VM | HCO 关联镜像、来宾系统 containerDisk | 可选 RHEL 9/10、Fedora、CentOS Stream 9/10，固定 amd64 摘要并进入归档 |
| 持久磁盘、迁移 | 合适的 CSI/StorageClass；ODF 是一种选择 | ODF 补全 12 个同补丁包，本地盘模式再带 LSO；不自动初始化磁盘 |
| 外部二层桥接 | 平台 Multus，通常配 `kubernetes-nmstate-operator` 配置主机网络 | Multus 已在 OCP 发布载荷；NMState 可按需选包 |
| SR-IOV 网络 | `sriov-network-operator`、受支持网卡/VF/固件 | 按需选包；不宣称下载后网卡已配置 |
| 导入现有 VM | `mtv-operator`；VMware 某些场景另需 VDDK | MTV 关联镜像随包；VDDK 许可镜像由用户提供后以 `--image` 加入 |
| 节点故障后的自动恢复 | `node-healthcheck-operator` + remediation provider | 默认补齐 Self Node Remediation；显式 FAR/Machine Deletion 选择会保留；不创建修复任务 |

**Multus 不是需要另找的同名 OperatorHub 包。** 已真实读取 4.22.22/x86_64 发布清单，确认 CNO、Multus CNI、admission、network-policy、Whereabouts 等镜像在平台载荷中；完整平台包会一并准备。只准备 Operator 包时，目标集群本身应已有匹配平台。网络定义和网卡桥接仍需配置，见[官方多网络说明](https://docs.redhat.com/en/documentation/openshift_container_platform/4.22/observability/multiple_networks/use-cases-secondary-network)。

系统镜像归档不等于 DataSource/模板已经注册。导入后 `guest-images-local.json` 给出实际 Harbor digest 地址；公共自动引导源保持关闭，持久化模板按需配置，见 [OPERATORS.md](OPERATORS.md)。

## 您列出的常用包

| 包 | 4.22 实际默认 channel / 版本 | 5.0 预览核对 |
|---|---|---|
| local-storage-operator | stable / 4.22.0-202611031655 | 5.0.0-202611030132 |
| mtv-operator | release-v2.12 / 2.12.10；另有受支持的 5.0 | release-v5.0 / 5.0.0 |
| node-healthcheck-operator | stable / 0.12.1 | 5.8.0 |
| self-node-remediation | stable / 0.13.1 | 5.8.0 |
| odf-dependencies、odf-operator | stable-4.22 / 4.22.7-rhodf | 声明最高 OCP 4.23，不能组成 ODF/5.0 计划 |
| odf-prometheus-operator、recipe | stable-4.22 / 4.22.7-rhodf | 目录可见旧包不等于 ODF/5.0 获支持 |
| opentelemetry-product | stable / 0.158.0-202611041238 | 同版本；Operator 版本无需改成 5 |
| web-terminal | fast / 1.17.2 | 同版本；递归补齐 DevWorkspace 1.0.0 |
| Multus | 平台内置 | 5.0.1 发布载荷也已确认包含 |

常用包一起选择时，4.22 计划解析为 19 个 Operator；5.0 排除不兼容 ODF 组后为 7 个。NHC 默认配套 SNR 是业务依赖补齐，不能只依赖当前目录中为空的依赖字段；配置仍需核对[节点修复文档](https://docs.redhat.com/en/documentation/workload_availability_for_red_hat_openshift/4.22-0)。

## 当前结论与边界

脚本能够为以上基础范围生成固定版本、完整声明依赖及附加镜像的离线计划；归档成功还需由原生 oc-mirror 下载，并通过 manifest/config/layer 完整性检查。切换路径可搬迁，导入不依赖原下载绝对路径。

**可以准备基础 AI/NVIDIA 和 Virtualization 的镜像，不等于已经覆盖 AI 全部功能或已经验证 GPU 驱动运行。** 本轮只做 x86_64 目录、依赖、配置、源镜像可达性及回归核对，没有新建 AWS 资源、重装集群或做 GPU/MTV/ODF 运行验收。实际记录见 [VALIDATION.md](VALIDATION.md)。5.0 的 AI/NVIDIA 组合暂不可交付：官方 AI 支持矩阵未列出 5.0，5.0 certified 目录也没有 `gpu-operator-certified`。
