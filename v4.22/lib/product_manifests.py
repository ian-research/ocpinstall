"""Render reviewed product installation stages against the actual offline sources."""
import json
from pathlib import Path
import re

import offline
from operators import image_config
from operator_profile import catalog_repository

PRODUCTS = {
    'kubevirt-hyperconverged': ('openshift-cnv', 'OwnNamespace'),
    'multicluster-engine': ('multicluster-engine', 'OwnNamespace'),
    'advanced-cluster-management': ('open-cluster-management', 'OwnNamespace'),
    'rhods-operator': ('redhat-ods-operator', 'AllNamespaces'),
    'lvms-operator': ('openshift-lvm-storage', 'OwnNamespace'),
}


def api_version(selected, group, kind):
    versions = {p['value']['version'] for p in selected.get('properties', [])
                if p.get('type') == 'olm.gvk' and p['value'].get('group') == group
                and p['value'].get('kind') == kind}
    stable = [v for v in versions if re.fullmatch(r'v[0-9]+', v)]
    if stable:
        version = max(stable, key=lambda v: int(v[1:]))
    elif versions:
        version = sorted(versions)[-1]
    else:
        raise ValueError(f'{selected["package"]} 没有声明 {kind} API，拒绝猜测组件清单')
    return group + '/' + version


def vendor_example(selected, group, kind):
    version = api_version(selected, group, kind)
    metadata = [p['value'] for p in selected.get('properties', []) if p.get('type') == 'olm.csv.metadata']
    raw = metadata[0].get('annotations', {}).get('alm-examples', '') if len(metadata) == 1 else ''
    if not isinstance(raw, str) or not raw or len(raw) > 1024 * 1024:
        raise ValueError(f'{selected["package"]} 缺少有效的厂商 {kind} 示例，拒绝猜测组件配置')
    examples = json.loads(raw)
    if not isinstance(examples, list):
        raise ValueError('厂商 alm-examples 必须是资源数组')
    matching = [item for item in examples if isinstance(item, dict) and
                item.get('kind') == kind and item.get('apiVersion') == version]
    if len(matching) != 1 or not isinstance(matching[0].get('spec'), dict):
        raise ValueError(f'无法唯一确定厂商 {version}/{kind} 示例')
    return json.loads(json.dumps(matching[0]))


def ai_stages(plan, selected):
    if not plan['targetVersion'].startswith('4.22.') or selected.get('version') not in ('3.5.2', '3.5.3'):
        raise ValueError('AI 组件清单仅适用于已核实的 4.22 / AI 3.5.2、3.5.3 CPU Workbenches 组合')
    dsc = vendor_example(selected, 'datasciencecluster.opendatahub.io', 'DataScienceCluster')
    components = dsc['spec'].get('components')
    if not isinstance(components, dict) or not {'dashboard', 'workbenches'} <= components.keys():
        raise ValueError('厂商 AI 示例缺少 Dashboard 或 Workbenches 配置')

    def remove(value):
        if isinstance(value, dict):
            for key, item in value.items():
                if key == 'managementState':
                    value[key] = 'Removed'
                else:
                    remove(item)
        elif isinstance(value, list):
            for item in value:
                remove(item)

    remove(components)
    for name in ('dashboard', 'workbenches'):
        if not isinstance(components[name], dict):
            raise ValueError('厂商 AI 组件配置格式无效')
        components[name]['managementState'] = 'Managed'
    initialization = vendor_example(selected, 'dscinitialization.opendatahub.io', 'DSCInitialization')
    labels = {'ocpinstall.ian-research/operator-plan': plan['planHash'][:12]}
    return {
        'reference/ai-initialization.json': {'apiVersion': initialization['apiVersion'],
            'kind': 'DSCInitialization', 'metadata': {'name': 'default-dsci', 'labels': labels},
            'spec': initialization['spec']},
        '02-ai-cpu-workbenches.json': {'apiVersion': dsc['apiVersion'], 'kind': 'DataScienceCluster',
            'metadata': {'name': 'default-dsc', 'labels': labels}, 'spec': {'components': components}},
    }


def render(plan, resources, destination, availability='High'):
    selected = {p['package']: p for p in plan['selected'] if p['package'] in PRODUCTS}
    if not selected:
        return []
    if availability not in ('High', 'Basic'):
        raise ValueError('ACM_AVAILABILITY 必须为 High 或 Basic')
    if 'advanced-cluster-management' in selected and 'multicluster-engine' not in selected:
        raise ValueError('ACM 产品清单缺少运行时依赖 MCE，请使用新目录重新准备完整依赖包')
    catalogs = {}
    for config in image_config(plan)['mirror']['operators']:
        matching = [r for r in resources if r.get('kind') == 'CatalogSource' and
                    r.get('spec', {}).get('image', '').rsplit('/', 1)[-1].split('@', 1)[0].split(':', 1)[0] == config['targetCatalog']]
        if len(matching) != 1:
            raise ValueError('无法唯一确定已导入产品的离线 CatalogSource')
        alias = next(c['alias'] for c in plan['catalogs'] if c['pinned'] == config['catalog'] and
                     config['targetCatalog'] == catalog_repository(plan, c['alias']))
        catalogs[alias] = matching[0]['metadata']
    stages = {}
    subscriptions = []
    for name, (namespace, mode) in PRODUCTS.items():
        if name not in selected:
            continue
        item = selected[name]
        metadata = [p['value'] for p in item.get('properties', []) if p.get('type') == 'olm.csv.metadata']
        if len(metadata) != 1 or not any(m.get('type') == mode and m.get('supported') is True for m in metadata[0].get('installModes', [])):
            raise ValueError(f'{name} 未声明支持 {mode}，拒绝猜测 OperatorGroup 作用域')
        source = catalogs[item['catalog']]
        subscriptions += [
            {'apiVersion': 'v1', 'kind': 'Namespace', 'metadata': {'name': namespace}},
            {'apiVersion': 'operators.coreos.com/v1', 'kind': 'OperatorGroup',
             'metadata': {'name': name + '-group', 'namespace': namespace},
             'spec': {'targetNamespaces': [namespace]} if mode == 'OwnNamespace' else {}},
            {'apiVersion': 'operators.coreos.com/v1alpha1', 'kind': 'Subscription',
             'metadata': {'name': name, 'namespace': namespace},
             'spec': {'name': name, 'channel': item['channel'], 'startingCSV': item['bundle'],
                      'source': source['name'], 'sourceNamespace': source.get('namespace', 'openshift-marketplace'),
                      'installPlanApproval': 'Manual'}}]
    stages['01-subscriptions.json'] = {'apiVersion': 'v1', 'kind': 'List', 'items': subscriptions}
    if {'rhods-operator', 'lvms-operator'} <= selected.keys():
        stages['00-lvms-subscriptions.json'] = {'apiVersion': 'v1', 'kind': 'List', 'items': [
            item for item in subscriptions if item['metadata'].get('namespace') == 'openshift-lvm-storage'
            or (item['kind'] == 'Namespace' and item['metadata']['name'] == 'openshift-lvm-storage')]}
    if 'kubevirt-hyperconverged' in selected:
        version = api_version(selected['kubevirt-hyperconverged'], 'hco.kubevirt.io', 'HyperConverged')
        if version == 'hco.kubevirt.io/v1':
            boot_policy = {'workloadSources': {'enableCommonBootImageImport': False}}
        elif version == 'hco.kubevirt.io/v1beta1':
            boot_policy = {'enableCommonBootImageImport': False}
        else:
            raise ValueError('未核实该 HyperConverged API 的离线引导源字段，请先核对 CRD')
        stages['02-hyperconverged.json'] = {
            'apiVersion': version,
            'kind': 'HyperConverged', 'metadata': {'name': 'kubevirt-hyperconverged', 'namespace': 'openshift-cnv'},
            'spec': boot_policy}
    if 'multicluster-engine' in selected:
        stages['02-multiclusterengine.json'] = {
            'apiVersion': api_version(selected['multicluster-engine'], 'multicluster.openshift.io', 'MultiClusterEngine'),
            'kind': 'MultiClusterEngine', 'metadata': {'name': 'multiclusterengine'},
            'spec': {'availabilityConfig': availability}}
    if 'advanced-cluster-management' in selected:
        engine = selected['multicluster-engine']
        source = catalogs[engine['catalog']]
        override = {'source': source['name'], 'sourceNamespace': source.get('namespace', 'openshift-marketplace'),
                    'channel': engine['channel'], 'startingCSV': engine['bundle'], 'installPlanApproval': 'Manual'}
        stages['03-multiclusterhub.json'] = {
            'apiVersion': api_version(selected['advanced-cluster-management'], 'operator.open-cluster-management.io', 'MultiClusterHub'),
            'kind': 'MultiClusterHub', 'metadata': {'name': 'multiclusterhub', 'namespace': 'open-cluster-management',
                'annotations': {'installer.open-cluster-management.io/mce-subscription-spec': json.dumps(override)}},
            'spec': {'availabilityConfig': availability}}
    if 'rhods-operator' in selected:
        stages.update(ai_stages(plan, selected['rhods-operator']))
    destination = Path(destination)
    destination.mkdir(parents=True, exist_ok=True)
    for name, content in stages.items():
        (destination / name).parent.mkdir(parents=True, exist_ok=True)
        offline.save_json(destination / name, content)
    lines = ['# 产品安装顺序', '', '这些清单针对新安装，使用本次实际导入的离线 CatalogSource 与固定 CSV。',
             '等待 MachineConfigPool 更新完成、CatalogSource READY 后执行下列步骤。', '']
    if 'rhods-operator' in selected:
        lines += ['AI 必须先具备真实 IDP 用户和可用的默认动态 StorageClass，再安装 AI Operator。']
        if 'lvms-operator' in selected:
            lines += ['若使用本包 LVMS，先应用 00-lvms-subscriptions.json，仅批准 LVMS 的固定 CSV；',
                      '核对空白数据盘并创建 LVMCluster，验证默认动态 StorageClass 和实际 PVC 绑定后，再继续应用 01。',
                      '00 不包含 AI 订阅；已有满足要求的默认动态存储时，可直接按下列步骤操作。']
        lines += ['']
    lines += ['1. 审阅并应用 `01-subscriptions.json`。',
             '2. 核对各命名空间的 InstallPlan，仅批准依赖计划中列出的 CSV；等待它们 Succeeded。',
             '3. 应用需要的 `02-*` 组件清单；ACM 在 MCE 健康后应用 `03-multiclusterhub.json`。',
             '4. 检查产品健康并执行实际虚拟机、本地集群管理或 Workbench 验收。', '',
             f'ACM/MCE availabilityConfig 为 {availability}；需要调整时先审阅资源与存储要求。',
             'MCH 的 MCE 订阅源已固定到本包实际离线目录。']
    if 'kubevirt-hyperconverged' in selected:
        lines += ['', 'Virtualization 基础离线模式关闭公共引导镜像自动导入，避免尝试拉取未准备的 Fedora/CentOS 镜像。',
                  '包内已镜像的 RHEL 9 container disk 可用于基础 VM；持久化或系统模板需要另外准备存储和引导源。',
                  '其他系统请在新包中用 --image 准备所需镜像，并把自定义引导源指向实际本地镜像；不要直接重新启用在线默认源。',
                  'HCO 就绪以实际 CRD 的 Available/Progressing/Degraded 条件及组件 Deployment 就绪为准，不依赖不存在的 status.phase。']
    if 'rhods-operator' in selected:
        lines += ['', 'AI 基础范围为 Dashboard 和 CPU Workbenches；清单来自所选固定 bundle 的厂商示例，按其声明选择 API。',
                  '先准备默认动态 StorageClass、真实 IDP 用户和节点资源，等待 Operator CSV 及控制器就绪。',
                  '检查 default-dsci：已有对象应复用并确认 Ready；不要 apply 初始化参考文件覆盖已有 CA 或监控设置。',
                  '仅在 default-dsci 不存在时，用 oc create -f reference/ai-initialization.json 创建并等待其就绪。',
                  '审阅并应用 02-ai-cpu-workbenches.json；它关闭其他组件及嵌套的可选功能，等待 DSC Ready 和实际控制器就绪。',
                  '使用真实 IDP 用户登录 Dashboard，创建 CPU Workbench、动态 PVC，验证 Python 执行和重启后的数据保留。',
                  '这些是新安装清单；已有 DSC 时先核对正在使用的功能，不能直接覆盖已有组件配置。']
    if 'lvms-operator' in selected:
        lines += ['', 'LVMS 订阅使用本包实际离线目录和固定 CSV；不会自动创建 LVMCluster 或选择磁盘。',
                  '先逐节点核对可用空白数据盘的身份、容量、文件系统和挂载状态，再按实际 CRD 创建 LVMCluster。',
                  'deviceSelector.paths 必须显式填写已核对的数据盘；保持 deviceSelector.forceWipeDevicesAndDestroyAllData=false，不能选择系统盘。',
                  '等待 LVMCluster、节点状态和 CSI 健康，验证动态 PVC 能够绑定后，再用于 AI 或其他工作负载。',
                  'AI 需要默认动态 StorageClass；已有默认类时先核对，避免无意变更已有工作负载的存储策略。']
    for product in plan.get('productRequirements', []):
        lines += ['', '## ' + product['product'] + ' ' + product['version'], product['scope']]
        lines += ['- ' + prerequisite for prerequisite in product.get('prerequisites', [])]
    (destination / 'README.md').write_text('\n'.join(lines) + '\n')
    print('产品安装清单已生成：' + str(destination) + '；请按目录 README 的前置条件和顺序分阶段执行。')
    return [destination / name for name in stages]
