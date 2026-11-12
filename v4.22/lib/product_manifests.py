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
    if 'kubevirt-hyperconverged' in selected:
        stages['02-hyperconverged.json'] = {
            'apiVersion': api_version(selected['kubevirt-hyperconverged'], 'hco.kubevirt.io', 'HyperConverged'),
            'kind': 'HyperConverged', 'metadata': {'name': 'kubevirt-hyperconverged', 'namespace': 'openshift-cnv'}, 'spec': {}}
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
    destination = Path(destination)
    destination.mkdir(parents=True, exist_ok=True)
    for name, content in stages.items():
        offline.save_json(destination / name, content)
    lines = ['# 产品安装顺序', '', '这些清单针对新安装，使用本次实际导入的离线 CatalogSource 与固定 CSV。',
             '等待 MachineConfigPool 更新完成、CatalogSource READY 后执行下列步骤。',
             '', '1. 审阅并应用 `01-subscriptions.json`。',
             '2. 核对各命名空间的 InstallPlan，仅批准依赖计划中列出的 CSV；等待它们 Succeeded。',
             '3. 应用需要的 `02-*` 组件清单；ACM 在 MCE 健康后应用 `03-multiclusterhub.json`。',
             '4. 检查产品健康并执行实际虚拟机、本地集群管理或 Workbench 验收。', '',
             f'ACM/MCE availabilityConfig 为 {availability}；需要调整时先审阅资源与存储要求。',
             'MCH 的 MCE 订阅源已固定到本包实际离线目录。']
    if 'rhods-operator' in selected:
        lines += ['', 'AI 此处生成固定版本的 Operator 订阅。DSCI/DSC 与 Workbench 应在受支持的 4.22 平台上，',
                  '确认动态 StorageClass、IDP 和节点资源后按 CPU Workbenches 范围配置；此清单未生成未经实机验收的 AI 业务 CR。']
    for product in plan.get('productRequirements', []):
        lines += ['', '## ' + product['product'] + ' ' + product['version'], product['scope']]
        lines += ['- ' + prerequisite for prerequisite in product.get('prerequisites', [])]
    (destination / 'README.md').write_text('\n'.join(lines) + '\n')
    print('产品安装清单已生成：' + str(destination) + '；先审批 01 订阅，再按顺序应用组件清单。')
    return [destination / name for name in stages]
