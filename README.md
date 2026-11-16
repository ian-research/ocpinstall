# ocpinstall

按目标 OpenShift 版本选择对应目录；各版本的脚本及说明独立保存。

| 平台 | 安装与配置说明 | Operator 说明 | 验证范围 |
|---|---|---|---|
| 4.18.10（历史版） | [4.18 原始脚本与说明](v4.18/README.md) | 沿用原有配置脚本 | 历史归档，保留原脚本 |
| 4.22.22 | [4.22 完整离线流程](v4.22/DELIVERY.md)、[README](v4.22/README.md) | [4.22 Operator](v4.22/OPERATORS.md) | [4.22 验证记录](v4.22/VALIDATION.md) |
| 5.0.1 | [5.x 完整离线流程](v5/DELIVERY.md)、[README](v5/README.md) | [5.x Operator](v5/OPERATORS.md) | [5.x 验证记录](v5/VALIDATION.md) |

```text
v4.18/  原有 4.18.10 安装、配置脚本和历史说明
v4.22/  4.22.22 离线准备、安装和配置
v5/     5.0.1 离线准备、安装和配置
```

4.18 的两个 `x-*.sh` 脚本已归档至 `v4.18/`，名称和内容保持原样，使用方式见该目录 README。

4.22 和 5.x 运行对应目录的 `prepare-operators.sh`，首层选择完整交付或仅 Operator；完整包生成 `verify.sh`、`install.sh`、`configure.sh` 三个入口。完成下载不代表所有组件均已获运行验收，请查看相应版本的验证记录。
