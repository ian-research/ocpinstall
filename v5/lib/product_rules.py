"""Product runtime dependencies that are not declared as OLM catalog edges."""
import json
from pathlib import Path

LIFECYCLE = 'https://access.redhat.com/support/policy/updates/openshift_operators'
AI_SUPPORT = 'https://access.redhat.com/articles/rhoai-supported-configs'
ODF_SOURCE = 'https://docs.redhat.com/en/documentation/red_hat_openshift_data_foundation/4.22/html/planning_your_deployment/disconnected-environment_rhodf'
GPU_SUPPORT = 'https://docs.nvidia.com/datacenter/cloud-native/gpu-operator/26.7/platform-support.html'
# Both catalogs carry ODF 4.22, but its maxOpenShiftVersion=4.23 excludes OCP 5.
# Match the complete ODF release, including its suffix, on the verified platform.
ODF_PACKAGES = (
    'odf-operator', 'odf-dependencies', 'ocs-operator', 'mcg-operator',
    'odf-csi-addons-operator', 'ocs-client-operator', 'odf-prometheus-operator',
    'recipe', 'rook-ceph-operator', 'cephcsi-operator',
    'odf-external-snapshotter-operator', 'ocs-tls-profiles',
)


def odf_option(args, selections, interactive=False, prompt=None):
    chosen = any(package_of(s) == 'odf-operator' for s in selections)
    option = getattr(args, 'odf_local_storage', None)
    if not chosen:
        if option is not None:
            raise ValueError('--odf-local-storage/--no-odf-local-storage 需要选择 odf-operator')
        return False
    if option is None and interactive:
        answer = prompt('ODF 是否使用本地数据盘，并下载 Local Storage Operator？yes/no', 'yes')
        if answer not in ('yes', 'no'):
            raise ValueError('ODF 本地存储选项必须为 yes 或 no')
        option = answer == 'yes'
    return True if option is None else option


def add_package(catalogs, selections, preferred_alias, package, version=None):
    existing = [s for s in selections if package_of(s) == package]
    if existing:
        if len(existing) != 1:
            raise ValueError('请为配套包选择唯一的目录/channel: ' + package)
        spec = existing[0]
    else:
        aliases = sorted(a for a, p in catalogs.packages if p == package)
        if preferred_alias in aliases:
            alias = preferred_alias
        elif len(aliases) == 1:
            alias = aliases[0]
        else:
            raise ValueError('缺少或无法唯一定位配套包，请补充目录并明确选择: ' + package)
        spec = alias + '/' + package + ('=' + version if version else '')
        selections.append(spec)
    root = catalogs.root(spec)
    bundle = catalogs.bundles[next(iter(root['allowed']))]
    if version and bundle['version'] != version:
        raise ValueError(f'ODF 配套包 {package} 必须与主包版本 {version} 一致；当前为 {bundle["version"]}')
    return bundle


def package_of(selection):
    return selection.split('/', 1)[-1].split(':', 1)[0].split('=', 1)[0]


def expand(catalogs, selections, target, guest_images=None, odf_local_storage=True):
    result = list(selections)
    requirements, images = [], []
    minor = target.rsplit('.', 1)[0]
    if any(package_of(s) == 'rhods-operator' for s in selections) and minor != '4.22':
        raise ValueError('当前官方 AI 支持矩阵未列出 OpenShift 5.0；请使用 4.22 交付入口')
    roots = [(s, catalogs.bundles[next(iter(catalogs.root(s)['allowed']))]) for s in selections]
    for selection, bundle in roots:
        package, version = bundle['package'], bundle['version']
        family = '.'.join(version.split('.')[:2])
        if package == 'kubevirt-hyperconverged':
            if family != minor:
                raise ValueError(f'Virtualization {version} 不属于 OpenShift {minor} 的官方支持组合；请改选对应版本/channel')
            images += (['registry.redhat.io/rhel9/rhel-guest-image:latest']
                       if guest_images is None else guest_images)
            requirements.append({'product': 'virtualization', 'version': version,
                'scope': '基础虚拟机镜像准备；包含 HCO relatedImages 和所选 container disk',
                'bootSourcePolicy': 'manual-offline',
                'prerequisites': ['需在平台工作负载之外为控制组件和虚拟机预留 CPU/内存；多组件同时部署需叠加资源预算',
                    '节点具有可用 /dev/kvm；实际创建 VM 验证硬件虚拟化',
                    '基础清单关闭公共引导源自动导入；所选系统归档后仍需配置本地引导源或使用本地 containerDisk 地址',
                    '持久化 VM 需相应 StorageClass；NMState/SR-IOV/MetalLB 按所选网络功能另选'],
                'supportSource': LIFECYCLE})
        elif package == 'mtv-operator':
            supported = {'4.22': ('2.12', '5.0'), '5.0': ('5.0',)}
            if family not in supported.get(minor, ()):
                raise ValueError(f'MTV {version} / OpenShift {minor} 不在当前已核实的下载组合中')
            requirements.append({'product': 'mtv', 'version': version,
                'scope': 'MTV Operator、bundle 和全部 relatedImages；仅准备镜像',
                'prerequisites': ['目标端须另行安装兼容的 OpenShift Virtualization；如需一起交付，请同时选择 kubevirt-hyperconverged',
                    'VMware VDDK 不包含在 Operator 镜像中；需要时自行取得 SDK、构建私有镜像并通过 --image 一并准备',
                    '不创建迁移源、网络/存储映射或迁移任务；源平台、权限和 VDDK 要求按迁移场景另行核对'],
                'supportSource': LIFECYCLE})
        elif package == 'odf-operator':
            if family != '4.22' or minor != '4.22':
                raise ValueError(f'ODF {version} / OpenShift {minor} 的兼容下载组合尚未核实；当前 5.0 目录中的 ODF 4.22 声明最高 OpenShift 4.23，不能用于 5.0 计划')
            alias = selection.split('/', 1)[0]
            for dependency in ODF_PACKAGES:
                add_package(catalogs, result, alias, dependency, version)
            if odf_local_storage:
                storage = add_package(catalogs, result, alias, 'local-storage-operator')
                if '.'.join(storage['version'].split('.')[:2]) != minor:
                    raise ValueError('Local Storage Operator 版本必须匹配目标 OpenShift 版本')
            requirements.append({'product': 'odf', 'version': version,
                'scope': 'ODF 完整配套 Operator、bundle 和 relatedImages；仅准备镜像',
                'downloadPackages': list(ODF_PACKAGES) + (['local-storage-operator'] if odf_local_storage else []),
                'localStorageIncluded': odf_local_storage,
                'prerequisites': ['ODF 配套包锁定与主包完全相同的版本，包含 odf-dependencies 声明的 TLS 等依赖',
                    '本地盘模式额外准备匹配平台版本的 Local Storage Operator；动态/外部存储可显式选择不包含',
                    '不创建 StorageCluster、不选择或初始化磁盘；实际部署时另行核对支持组合、拓扑和容量',
                    '灾备/多集群组件不在基础下载组内，需要时另外选择对应 Operator'],
                'supportSource': ODF_SOURCE})
        elif package == 'node-healthcheck-operator':
            providers = {'self-node-remediation', 'fence-agents-remediation', 'machine-deletion-remediation'}
            if not any(package_of(s) in providers for s in result):
                add_package(catalogs, result, selection.split('/', 1)[0], 'self-node-remediation')
            requirements.append({'product': 'node-healthcheck', 'version': version,
                'scope': '节点健康检测与所选修复提供者的镜像准备；默认配套 Self Node Remediation',
                'prerequisites': ['安装 Operator 后仍需创建并审阅 NodeHealthCheck 与 remediation template；本脚本不触发节点重启或修复',
                    '如显式选择 FAR 或 Machine Deletion Remediation，则保留该选择；硬件隔离/看门狗/控制平面仲裁要求需按拓扑核对'],
                'supportSource': 'https://docs.redhat.com/en/documentation/workload_availability_for_red_hat_openshift/4.22-0'})
        elif package == 'gpu-operator-certified':
            if family != '26.7' or minor != '4.22':
                raise ValueError('已核实的 NVIDIA GPU Operator 26.7 支持到 OCP 4.22；5.0 certified 目录无此包，不能借用 4.22 组合')
            add_package(catalogs, result, selection.split('/', 1)[0], 'nfd')
            path = Path(__file__).resolve().parent.parent / f'config/ocp-{target}-gpu-images.json'
            if not path.is_file():
                raise ValueError(f'GPU Driver Toolkit 尚未核实目标补丁 {target}；请先核对该平台实际发布镜像')
            toolkit = json.loads(path.read_text())
            if toolkit.get('platformVersion') != target or toolkit.get('architecture') != 'amd64':
                raise ValueError('GPU Driver Toolkit 清单与目标平台/架构不一致')
            declared = {i['name']: i['image'] for i in bundle.get('relatedImages', [])}
            if not declared.get('driver-image'):
                raise ValueError('NVIDIA bundle 缺少默认 driver-image，不能声称已准备驱动')
            images += toolkit['images']
            requirements.append({'product': 'nvidia-gpu', 'version': version,
                'scope': 'NFD、GPU Operator、全部官方 relatedImages 和匹配平台 DTK；基础容器 GPU/默认驱动路径',
                'driverMode': 'openshift-driver-toolkit', 'defaultDriverImage': declared['driver-image'],
                'driverToolkitImageSource': toolkit['source'], 'driverToolkitImages': toolkit['images'],
                'prerequisites': ['需要真正可用的受支持 NVIDIA GPU；按 GPU 型号选择受支持驱动分支，不代表当前机器已具备 GPU 功能',
                    '先创建 NodeFeatureDiscovery 并确认硬件标签，再安装 GPU Operator/ClusterPolicy，保持 use_ocp_driver_toolkit=true',
                    'OCP 4.22 常规驱动使用 rhel9.8 后缀，不能套用旧版 rhcos4.18/rhel9.6；DTK 必须匹配实际运行内核',
                    '离线集群的 driver-toolkit ImageStream、镜像规则、构建服务账户凭据和本地仓库信任需就绪',
                    '本轮只验证镜像准备；须另验 nvidia-smi、nvidia.com/gpu allocatable 和真实 CUDA 工作负载',
                    'vGPU、GDS、RDMA、自定义/预编译驱动需另外准备许可、内核镜像或网络配套，不属于此基础路径'],
                'supportSource': GPU_SUPPORT})
        elif package == 'advanced-cluster-management':
            if family != '5.0':
                raise ValueError('自动业务依赖规则当前只覆盖 ACM 5.0 + MCE 5.0；其他组合请先补充并验证版本规则')
            existing = [s for s in result if package_of(s) == 'multicluster-engine']
            if not existing:
                alias = selection.split('/', 1)[0]
                candidates = [a for a, p in catalogs.packages if p == 'multicluster-engine']
                if alias not in candidates:
                    if len(candidates) != 1:
                        raise ValueError('ACM 需要 multicluster-engine，请加入包含 MCE 的目录并明确选择')
                    alias = candidates[0]
                existing = [alias + '/multicluster-engine:stable-5.0']
                result += existing
            mce = catalogs.bundles[next(iter(catalogs.root(existing[0])['allowed']))]
            if '.'.join(mce['version'].split('.')[:2]) != '5.0':
                raise ValueError('ACM 5.0 必须搭配经过核实的 MCE 5.0')
            requirements.append({'product': 'acm', 'version': version,
                'runtimeDependency': 'multicluster-engine', 'scope': '基础 Hub、MCE、本地集群管理',
                'prerequisites': ['按 Hub/MCE 及所启用组件的 Pod requests 规划额外 CPU/内存；平台最低规格不代表叠加组件可运行',
                    'MCH 的 mce-subscription-spec 必须指向本包离线 CatalogSource',
                    'Search 等持久组件需要动态 StorageClass；备份/跨集群网络另选 OADP/Submariner'],
                'supportSource': LIFECYCLE})
        elif package == 'rhods-operator':
            if version not in ('3.5.2', '3.5.3'):
                raise ValueError('AI 运行镜像规则当前覆盖 3.5.2/3.5.3；请选择目录中存在的版本，其他版本需单独核实')
            runtime = json.loads((Path(__file__).resolve().parent.parent / f'config/ai-{version}-cpu-images.json').read_text())
            gateway_path = Path(__file__).resolve().parent.parent / f'config/ocp-{target}-gateway-images.json'
            if not gateway_path.is_file():
                raise ValueError(f'AI 网关运行镜像尚未核实 OpenShift {target}；当前固定验收组合为 4.22.22，请先补充该平台补丁版本的网关镜像清单')
            gateway = json.loads(gateway_path.read_text())
            if gateway.get('platformVersion') != target or gateway.get('architecture') != 'amd64':
                raise ValueError('AI 网关镜像清单与目标平台或架构不一致')
            images += runtime['images'] + gateway['images']
            gpu = any(package_of(s) == 'gpu-operator-certified' for s in result)
            if gpu:
                cuda = json.loads((Path(__file__).resolve().parent.parent / f'config/ai-{version}-nvidia-images.json').read_text())
                images += cuda['images']
            requirements.append({'product': 'ai', 'version': version,
                'scope': 'Dashboard + CPU/NVIDIA CUDA Workbenches 镜像准备' if gpu else 'Dashboard + CPU Workbenches',
                'runtimeImageSource': runtime['source'], 'supportSource': AI_SUPPORT,
                'gatewayRuntimeImageSource': gateway['source'], 'gatewayPlatformVersion': target,
                'gatewayRuntimeImages': gateway['images'],
                'prerequisites': ['官方常规拓扑要求至少两个 8 CPU/32 GiB 工作节点；控制组件与实际负载另预留资源',
                    'SNO 按官方要求至少 32 CPU/128 GiB；另需默认动态 StorageClass 和真实 IDP 用户',
                    'KServe 需 cert-manager；训练/KubeRay 需 Kueue；Trainer 另需 JobSet',
                    'llm-d 需 Connectivity Link 和 LWS；GPU、对象存储、模型数据需按实际功能另外准备'],
                'nvidiaImagesIncluded': gpu,
                'acceleratorImageSource': cuda['source'] if gpu else None,
                'excludedFeatures': ([] if gpu else ['GPU']) + ['KServe/model serving', 'distributed training', 'llm-d', 'RAG'],
                'acceleratorScope': 'NVIDIA CUDA/Python 3.12 工作台镜像准备；硬件、驱动及 GPU 工作台运行尚未验收' if gpu else 'CPU only'})
    return result, sorted(set(images)), requirements
