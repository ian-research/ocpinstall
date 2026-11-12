# Operator 离线脚本版本导航

| OpenShift 版本 | 交互入口 | 使用说明 | 导入后的集群配置 |
|---|---|---|---|
| 4.22 | `bash v4.22/prepare-operators.sh` | [4.22 README](v4.22/README.md) | `v4.22/setup-cluster.sh`（独立包也可 `apply-operators.sh`） |
| 5.0 | `bash v5/prepare-operators.sh` | [5.x README](v5/README.md)、[Operator 详细指南](v5/OPERATORS.md) | `v5/setup-cluster.sh` |

两版分别保存，锁定各自版本的 catalog，生成独立的镜像目录与集群资源名称；不会将 4.22 包当作 5.x 包导入，反之亦然。Operator 的版本独立于平台版本。

均支持交互搜索和多次选择 Operator、选择 channel/版本、自定义下载路径、递归依赖解析、下载预检查、SHA256 校验、完整离线转移和本地 OCI 导入。

**离线包可移动到另一台机器的不同路径，顶层目录也可改名；包内目录结构需完整保留。** 导入时指定新 `--bundle`，不需要源端缓存。请带上 `catalogs/`、`images/` 和全部 JSON 清单，不只复制 tar。凭据放在包外，导入端使用同一份 oc-mirror 二进制。

完整包模式同时收集平台、工具、RHCOS ISO、Helper 软件和 Operator，并生成可搬迁的安装/配置入口：见 [4.22 完整流程](v4.22/DELIVERY.md)、[5.x 完整流程](v5/DELIVERY.md)。实际验收范围分别见各目录 `VALIDATION.md`；4.22 尚未完成实机验收，5.0 的成功不能替代它。
