# 5.0 预览：AI、Virtualization 与常用 Operator

核对日期：2026-11-17，范围仅 linux/amd64。优先交付版本为独立的 4.22.22；[完整依赖梳理与官方来源](../v4.22/DEPENDENCIES.md)解释了各组件的必需项、按功能选配项和运行时镜像边界。

| 组件 | 5.0.1 实际目录核对 |
|---|---|
| Virtualization | `kubevirt-hyperconverged:stable` / 5.0.0；69 条 relatedImages |
| MTV | `mtv-operator:release-v5.0` / 5.0.0 |
| Local Storage | `local-storage-operator:stable` / 5.0.0-202611030132 |
| Node Health Check / Self Node Remediation | stable / 5.8.0；NHC 默认补齐 SNR，或保留显式选择的其他修复提供者 |
| OpenTelemetry | `opentelemetry-product:stable` / 0.158.0-202611041238；不强制同号 |
| Web Terminal | fast / 1.17.2，解析补齐 DevWorkspace 1.0.0 |
| ODF | 主包及依赖包声明最高 OCP 4.23；其他 4.22 子包可见也不代表 ODF/5.0 可安装 |
| OpenShift AI | 当前[支持矩阵](https://access.redhat.com/articles/rhoai-supported-configs)未列 5.0；本版拒绝该组合 |
| NVIDIA GPU Operator | 当前 5.0 certified 目录没有 `gpu-operator-certified`；[NVIDIA 26.7 支持范围](https://docs.nvidia.com/datacenter/cloud-native/gpu-operator/26.7/platform-support.html)止于 OCP 4.22，不借用 4.22 包冒充兼容 |
| Multus / DTK | 已真实读取 5.0.1/x86_64 平台发布清单确认存在；它们属于平台载荷，不是独立同名 OLM 包 |

本版仍提供与 4.22 相同的系统 containerDisk 多选、固定摘要、实际 Harbor 地址报告和归档校验功能。公共引导源自动导入保持关闭；RHEL/Fedora/CentOS 镜像已下载不表示所有模板已注册。

同样可以按实际功能选择 NMState、SR-IOV、cert-manager、Kueue、JobSet 等目录中的包，但不能由“单个包可下载”推断“AI/5.0 组合获支持”。脚本包含共享的 4.22 GPU 准备规则和数据文件用于独立回归，平台版本检查仍禁止在 5.0 上套用它们。

本轮未新增集群安装或 GPU 运行测试。新 GPU 参考清单仅生成，不会自动应用到集群；具体镜像、回归结果和历史功能验收见 [VALIDATION.md](VALIDATION.md)。
