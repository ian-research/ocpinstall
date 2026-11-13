"""Product runtime dependencies that are not declared as OLM catalog edges."""
import json
from pathlib import Path

LIFECYCLE = 'https://access.redhat.com/support/policy/updates/openshift_operators'
AI_SUPPORT = 'https://access.redhat.com/articles/rhoai-supported-configs'


def package_of(selection):
    return selection.split('/', 1)[-1].split(':', 1)[0].split('=', 1)[0]


def expand(catalogs, selections, target):
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
            images.append('registry.redhat.io/rhel9/rhel-guest-image:latest')
            requirements.append({'product': 'virtualization', 'version': version,
                'scope': '基础虚拟机；包含 HCO relatedImages 和 RHEL 9 guest container disk',
                'bootSourcePolicy': 'manual-offline',
                'prerequisites': ['需在平台工作负载之外为控制组件和虚拟机预留 CPU/内存；多组件同时部署需叠加资源预算',
                    '节点具有可用 /dev/kvm；实际创建 VM 验证硬件虚拟化',
                    '基础清单关闭公共引导源自动导入；Fedora/CentOS 等系统需另行镜像并配置本地引导源',
                    '持久化 VM 需相应 StorageClass；NMState/SR-IOV/MetalLB 按所选网络功能另选'],
                'supportSource': LIFECYCLE})
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
            requirements.append({'product': 'ai', 'version': version, 'scope': 'Dashboard + CPU Workbenches',
                'runtimeImageSource': runtime['source'], 'supportSource': AI_SUPPORT,
                'gatewayRuntimeImageSource': gateway['source'], 'gatewayPlatformVersion': target,
                'gatewayRuntimeImages': gateway['images'],
                'prerequisites': ['官方常规拓扑要求至少两个 8 CPU/32 GiB 工作节点；控制组件与实际负载另预留资源',
                    'SNO 按官方要求至少 32 CPU/128 GiB；另需默认动态 StorageClass 和真实 IDP 用户',
                    'KServe 需 cert-manager；训练/KubeRay 需 Kueue；Trainer 另需 JobSet',
                    'llm-d 需 Connectivity Link 和 LWS；GPU、对象存储、模型数据需按实际功能另外准备'],
                'excludedFeatures': ['GPU', 'KServe/model serving', 'distributed training', 'llm-d', 'RAG']})
    return result, sorted(set(images)), requirements
