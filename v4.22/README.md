# OpenShift 4.22 离线准备、安装和配置

**完整离线准备入口：** `bash v4.22/prepare-operators.sh`，选择“准备完整离线包”。包含 OpenShift 本体、工具、RHCOS、Helper 软件和 Operator；搬迁后依次运行 `verify.sh`、`install.sh`、`configure.sh`。详见 [完整交付流程](DELIVERY.md) 和 [实测范围](VALIDATION.md)。

本目录独立保存 4.22 版交互脚本，默认目标为 **4.22.22**，目录镜像为 `registry.redhat.io/redhat/redhat-operator-index:v4.22`。5.x 版在 [`../v5/`](../v5/)，两版的脚本、默认配置、离线包和集群资源名称分别管理，不能互相混用。

首层菜单提供完整交付与仅 Operator 两种模式。完整模式包含本目录独立的安装、配置脚本；仅 Operator 的 `plan/export/import/verify` 命令不重复准备平台。旧版根目录脚本不被覆盖。

授时默认使用真正可达的内部上游 `NTP_SERVER`，不能填写 Helper 自己。没有上游的完全隔离环境，可显式设置 `NTP_MODE=local` 并省略 `NTP_SERVER`，以 Helper 时钟统一节点；请先核对 Helper 时间。上游模式未同步会停止安装。完整交付路径与重试方法见 [DELIVERY.md](DELIVERY.md)。

## 交互操作

联网准备机需要 Linux、Python 3.9+、PyYAML 6.0.3、skopeo、Podman/Docker，以及支持目标版本的 `oc`、`oc-mirror v2`。首次解析会编译使用 OLM 同类 semver/CEL 库的工具；没有 Go 时自动下载固定官方 Go 工具链并校验 SHA256。离线导入端只需 Python、oc 和同一份 oc-mirror 二进制，不需要 Go、skopeo 或 Docker。

```bash
python3 -m pip install PyYAML==6.0.3
bash v4.22/prepare-operators.sh
```

首层选择完整交付或仅 Operator；仅 Operator 子菜单提供下载、计划、导入和校验。

选择下载后依次填写保存路径、catalog 和凭据文件路径；搜索 Operator、按序号选择 channel/版本，可反复添加，输入 `done` 结束。脚本显示自动补齐的依赖、版本约束和提供者，可补充额外运行时镜像，输入 `yes` 确认下载。可以先选“只生成依赖计划”，检查之后再下载。

凭据放在包目录之外，只填写文件路径。脚本读取真实 FBC 元数据并锁定 catalog digest，支持多个目录中的包依赖、GVK 依赖、传统 dependencies 和 all/any/not/CEL 约束。缺失依赖、版本冲突、重复 API 提供者或未知约束会停止并说明原因。

自动解析目录声明的依赖和 relatedImages；另对已核实的 ACM 5.0/MCE 5.0、Virtualization 和 AI 3.5.2/3.5.3 基础功能执行业务依赖及支持组合检查，详见 [验证范围](VALIDATION.md)。厂商未声明的外部数据库、授权、存储和运行时镜像仍需根据其文档补充。计划用于新安装，不代替已有 Subscription 的升级路径规划。

## 命令行、预检查与下载

```bash
bash v4.22/prepare-operators.sh plan --non-interactive \
  --bundle '/data/ocp422 operators' \
  --authfile /secure/pull-secret.json \
  --select redhat/web-terminal

bash v4.22/prepare-operators.sh export --non-interactive --dry-run \
  --bundle '/data/ocp422 operators' --authfile /secure/pull-secret.json

# 检查计划和 images/working-dir/dry-run，然后实际下载。
bash v4.22/prepare-operators.sh export --non-interactive \
  --bundle '/data/ocp422 operators' --authfile /secure/pull-secret.json

bash v4.22/prepare-operators.sh verify --bundle '/data/ocp422 operators'
```

`--select ALIAS/PACKAGE[:CHANNEL][=VERSION]`、`--catalog ALIAS=IMAGE` 和 `--image REGISTRY/REPO:TAG` 可重复。默认使用所选 channel 的图终点，也可以指定实际版本。安装的是 Operator 自己的版本，不将其版本号改成 OpenShift 的 4.22。

`--target-version` 可指定目标集群实际的 4.22 补丁版本。`--cache-dir` 指定独立缓存位置，默认在下载目录外加 `-cache`；`--archive-size` 设置归档 GiB。已有计划会复用，换一组 Operator/版本请换新的包目录，不直接修改生成配置。

目标集群已有的 API 可通过 `--provided-apis` 显式声明为 JSON 数组，条目包含 `group`、`version`、`kind`。只有目标离线集群确实具备这些 API 时才能使用，不将其他集群上额外安装的 Operator 当作平台基线。

高级复用参数：`--catalog-metadata ALIAS=PATH` 与 `--catalog-oci ALIAS=PATH`，要求调用者明确核实本地文件来自指定的 digest。常规使用无需这两个参数。

## 搬迁离线包和导入

**导入路径可以与下载路径不同，也可以重命名顶层目录。** 脚本使用相对 OCI 引用和相对 SHA256 清单，执行时以 `--bundle` 为工作目录。内部目录结构保持不变，完整复制整个包，不能只带 tar；源端缓存不需要转移。

```text
离线包/
├── operators-plan.json
├── imagesetconfiguration.json
├── imagesetconfiguration-oci.json
├── operator-catalogs.json
├── mirror-tool.json
├── checksums.json
├── catalogs/
│   └── redhat/              # 本地 OCI layout
└── images/
    └── mirror_*.tar
```

脚本逐个验证 OCI blob 与归档摘要，禁止把凭据复制进包。采用本地 OCI catalog，使导入无需回访红帽源目录；保留原始 registry digest 配置和来源记录。准备足够空间，目录布局和镜像归档都占用磁盘。

```bash
# 假设已从 /data 拷贝到另一台机器的 /mnt/usb，并换了顶层目录名。
bash v4.22/prepare-operators.sh import --non-interactive \
  --bundle '/mnt/usb/ocp422 operator bundle' \
  --authfile /secure/harbor-auth.json \
  --registry helper.poc.example.com:8443/openshift42222
```

导入端使用与导出端 SHA256 一致的 oc-mirror。目标项目必须已存在，仓库证书信任和集群 pull secret 权限需事先准备。目标 Harbor 地址、项目和凭据路径可以与源环境不同。每份计划使用独立的 catalog 和资源名称，避免分批导入互相覆盖。

## 应用到已安装的 4.22 集群

```bash
bash v4.22/apply-operators.sh \
  --bundle '/mnt/usb/ocp422 operator bundle' \
  --kubeconfig /secure/kubeconfig --dry-run

# 审阅预检查结果后，去掉 --dry-run 应用。
bash v4.22/apply-operators.sh \
  --bundle '/mnt/usb/ocp422 operator bundle' \
  --kubeconfig /secure/kubeconfig
```

脚本先核对集群是 4.22，并校验离线包，再应用独立命名的 CatalogSource、ClusterCatalog、IDMS/ITMS，并禁用默认在线目录。只改变资源 metadata，保留 oc-mirror 生成的 image 与镜像映射。不会配置 Helper 的 SELinux、防火墙、SCC、存储或管理员账号。

等待 MachineConfigPool 完成更新、CatalogSource 为 READY 后，在 Console 中选择离线目录和计划中的 channel/version。首次建议手动审批 InstallPlan，核对依赖包，再验证 CSV Succeeded 和实际 CR 的运行。仅下载或导入成功不等于所有 Operator 功能已验证。

## 官方依据与验证范围

- [Red Hat 4.22：oc-mirror v2 与依赖筛选限制](https://docs.redhat.com/en/documentation/openshift_container_platform/4.22/html/disconnected_environments/about-installing-oc-mirror-v2)
- [OLM Dependency Resolution](https://olm.operatorframework.io/docs/concepts/olm-architecture/dependency-resolution/)
- [OLM File-Based Catalogs](https://olm.operatorframework.io/docs/reference/file-based-catalogs/)
- [上游 diskToMirror 源 catalog 访问修复](https://github.com/openshift/oc-mirror/commit/4cfbc254b92f34b456f44ca3540e36d09f79fffa)

实际测试结果单独记录；5.0 集群上的成功不作为 4.22 集群安装验证的替代。
