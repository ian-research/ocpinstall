# RHEL 10 Helper 验证范围

2026-11-14：**RHEL 10.2 x86_64 Helper 基础功能已通过实际验收和独立复核。** 实际调用 `v4.22/install-cluster.sh` 的 Helper 函数，没有重复部署集群或 Operator；官方 5.0.1 工具也在同一更新后环境通过运行检查。5.x 的独立 Helper 初始化未另外执行。

准备机和目标 Helper 的完整 RHEL `VERSION_ID`、架构和软件基线须匹配。共享 `lib/helper_profile.py` 决定准备与安装的软件清单：RHEL 9 保留 Python 3.11，RHEL 10 使用默认 Python 3。缓存复用前核对 OS、架构及事务缓存隔离标记，禁止跨版本混用 RPM 包。

| 实测项目 | 结果 |
|---|---|
| RHEL / DNF / Python | RHEL 10.2、DNF 4.20.0、Python 3.12.16、系统 PyYAML 6.0.1 |
| 离线软件 | 匹配 RHUI/Docker 源准备，搬迁后仅启用包内源；GPG 完整事务预检和真实安装通过，374 个 RPM 路径及摘要保持一致 |
| DNS / NTP | 正反向、通配解析；显式本地 stratum 10，从允许的节点网段完成真实 NTP 查询 |
| HAProxy / HTTP | 使用独立命名空间中的模拟后端验证四个转发端口、受信任 TLS 和统计页；临时公开测试文件可读、私有路径拒绝访问 |
| NFS / SELinux | NFSv4 实际挂载、写入读取及正常卸载；SELinux 始终 Enforcing |
| Docker / Harbor | Docker 29.9.3、Compose 5.7.1、cgroup v2、Harbor 2.12.2；所有健康组件、TLS、项目及本地镜像推送拉取通过 |
| 工具 | 官方 4.22.22/5.0.1 客户端、安装器及同一 oc-mirror；ELF、依赖、执行、oc/kubectl 硬链接和 0755 权限通过 |
| 原生 oc-mirror | 仅一个已有本地镜像，实际导出、更名为含空格路径、隔离源缓存、新缓存导入；按实际 ITMS 范围验证目标 manifest 及全部层一致 |

官方工具保留原始 RHEL 9 构建名称及 SHA256；本次证明它们在上述 RHEL 10 环境可运行，没有将其改名为 RHEL 10 原生包。镜像拉取使用受信任 CA；空 OCI layout 的回读保留 schema2 manifest、配置和层摘要。

被测进程阻断外网，只允许回环、隔离模拟网段和本地 Harbor 的明确地址；Docker 守护进程仅放行所属本地容器及网关。相同外部镜像源在受限进程中连接失败，在独立联网对照中返回 401。准备阶段使用联网 RHUI，真实软件安装阶段使用已搬迁的包内 RPM。

## 两个需要保留的恢复处理

- AWS `amazon-id` 插件在关闭 RHUI 软件源时仍会访问 EC2 元数据。包内源预检、缓存和安装只跳过这个插件，保留 GPG 校验及其他 DNF 插件；联网准备流程继续使用正常 RHUI。
- 本次 AMI 的旧运行内核缺少 Docker 网络模块 `xt_addrtype`，离线事务安装的新默认内核已有匹配模块。确认后正常重启同一 Helper，使用同一离线包续跑成功。脚本给出明确诊断，不自动重启、不关闭 Docker 网络过滤。管理员应先确认匹配模块和维护条件。

## 范围限制与记录

AWS 按已确认设置跳过 firewalld 和 DVD/ISO；这两项的物理服务器行为需另行验收。HAProxy 使用明确标记的模拟后端，未生成集群用的 install-config、Ignition、handoff、kubeconfig、虚拟机或 Operator 状态。未在 RHEL 10 上重传完整平台/大型 Operator 包，也未做容量或性能认证。

精简证据见 [RHEL 10 Helper 实测](tests/evidence/rhel10-helper-2026-11-14.json)。完整私有记录保留首次失败、内核重启、版本化检查修正、全部阶段和源代码摘要；独立复核核对了与当前待发布代码一致的 90 个代码文件。其他平台与组件的验收范围见 [VALIDATION.md](VALIDATION.md)。
