"""Resolve a portable, single-version Operator dependency closure from FBC metadata.

This is a fresh-install plan, not an upgrade planner for an existing namespace.
The final cluster's OLM remains the authority for installation and namespace scope.
"""
import json
from pathlib import Path
import re
import operator_profile


def read_documents(folder):
    paths = [folder] if folder.is_file() else sorted(folder.rglob('*'))
    decoder = json.JSONDecoder()
    for path in paths:
        if path.is_symlink():
            raise ValueError(f'目录元数据不允许符号链接: {path}')
        if not path.is_file() or path.suffix not in ('.json', '.yaml', '.yml'):
            continue
        text = path.read_text()
        if not text.strip():
            continue
        if text.lstrip().startswith(('{', '[')):
            offset = 0
            while offset < len(text):
                while offset < len(text) and text[offset].isspace():
                    offset += 1
                if offset == len(text):
                    break
                value, offset = decoder.raw_decode(text, offset)
                for item in value if isinstance(value, list) else [value]:
                    yield item
        else:
            try:
                import yaml
            except ImportError as error:
                raise ValueError('YAML 元数据需要 PyYAML：python3 -m pip install PyYAML==6.0.3') from error
            yield from (item for item in yaml.safe_load_all(text) if item is not None)


def gvk_key(value):
    return tuple(value[key] for key in ('group', 'version', 'kind'))


def required(bundle):
    result = []
    for prop in bundle.get('properties', []):
        kind, value = prop['type'], prop['value']
        if kind == 'olm.package.required':
            result.append({'package': value})
        elif kind == 'olm.gvk.required':
            result.append({'gvk': value})
        elif kind == 'olm.constraint':
            result.append(value)
        elif kind.endswith('.required'):
            raise ValueError(f'{bundle["name"]}: 不认识依赖类型 {kind}，不能断言依赖完整')
    for dep in bundle.get('dependencies', []):
        value = dict(dep['value'])
        if dep['type'] == 'olm.package':
            value['versionRange'] = value.pop('version', value.get('versionRange', '*'))
            result.append({'package': value})
        elif dep['type'] == 'olm.gvk':
            result.append({'gvk': value})
        elif dep['type'] == 'olm.constraint':
            result.append(value)
        else:
            raise ValueError(f'{bundle["name"]}: 不认识 dependencies 类型 {dep["type"]}')
    return result


class Catalogs:
    def __init__(self, sources, semantics, target_version=None):
        target_version = target_version or operator_profile.release()
        self.sources = sources
        self.semantics = semantics
        self.packages, self.channels, self.bundles = {}, {}, []
        for source in sources:
            alias = source['alias']
            for item in read_documents(Path(source['metadata'])):
                schema = item.get('schema')
                if schema == 'olm.package':
                    key = (alias, item['name'])
                    if key in self.packages:
                        raise ValueError(f'重复 package: {key}')
                    self.packages[key] = item
                elif schema == 'olm.channel':
                    key = (alias, item['package'], item['name'])
                    if key in self.channels:
                        raise ValueError(f'重复 channel: {key}')
                    self.channels[key] = item
                elif schema == 'olm.bundle':
                    props = [p['value'] for p in item.get('properties', []) if p['type'] == 'olm.package']
                    if len(props) != 1 or props[0]['packageName'] != item['package']:
                        raise ValueError(f'{item["name"]}: 缺少唯一且一致的 olm.package property')
                    self.bundles.append(dict(item, alias=alias, version=props[0]['version']))
        names = set()
        for bundle in self.bundles:
            key = (bundle['alias'], bundle['name'])
            if key in names:
                raise ValueError(f'重复 bundle: {key}')
            names.add(key)
            bundle['channels'] = sorted(c for a, p, c in self.channels
                                        if a == bundle['alias'] and p == bundle['package'] and
                                        any(e['name'] == bundle['name'] for e in self.channels[(a, p, c)]['entries']))
            if not bundle['channels']:
                continue  # Orphaned bundles cannot be exported as channel selections.
            package = self.packages.get((bundle['alias'], bundle['package']))
            if not package:
                raise ValueError('bundle 的 package 元数据缺失')
            bundle['preferredChannel'] = (package['defaultChannel'] if package['defaultChannel'] in bundle['channels']
                                          else bundle['channels'][0])
        self.bundles = [b for b in self.bundles if b['channels']]
        self.incompatible = {}
        for b in self.bundles:
            for prop in b.get('properties', []):
                if prop['type'] == 'olm.maxOpenShiftVersion':
                    maximum = prop['value']
                    # Some historical YAML catalogs encode 4.8 as a YAML number.
                    # Never let unrelated malformed history block every package.
                    if isinstance(maximum, (float, int)) and not isinstance(maximum, bool):
                        maximum = str(maximum)
                    if not isinstance(maximum, str) or not re.fullmatch(r'\d+\.\d+(?:\.\d+)?', maximum):
                        self.incompatible[(b['alias'], b['name'])] = 'invalid maxOpenShiftVersion'
                        continue
                    major, minor = map(int, maximum.split('.')[:2])
                    supported = semantics.call(op='range', range=f'<{major}.{minor + 1}.0', versions=[target_version])[0]
                    if not supported:
                        self.incompatible[(b['alias'], b['name'])] = maximum
        self.bundles = [b for b in self.bundles if (b['alias'], b['name']) not in self.incompatible]
        order = semantics.call(op='sort', versions=[b['version'] for b in self.bundles])
        self.bundles = [self.bundles[i] for i in order]
        # OLM prefers default channels. Keep version order within each preference.
        self.bundles.sort(key=lambda b: b['preferredChannel'] != self.packages[(b['alias'], b['package'])]['defaultChannel'])
        self.by_package = {}
        self.by_gvk = {}
        for i, bundle in enumerate(self.bundles):
            self.by_package.setdefault(bundle['package'], set()).add(i)
            for prop in bundle.get('properties', []):
                if prop['type'] == 'olm.gvk':
                    self.by_gvk.setdefault(gvk_key(prop['value']), set()).add(i)

    def root(self, spec):
        # alias/package[:channel][=version]; no version means the channel graph head.
        selection, _, version = spec.partition('=')
        path, _, channel = selection.partition(':')
        alias, slash, package = path.partition('/')
        if not slash or (alias, package) not in self.packages:
            raise ValueError(f'未找到 {path}，格式为 catalog别名/package[:channel][=version]')
        channel = channel or self.packages[(alias, package)]['defaultChannel']
        record = self.channels.get((alias, package, channel))
        if not record:
            raise ValueError(f'{path}: 未找到 channel {channel}')
        entries = {entry['name'] for entry in record['entries']}
        if not version:
            replaced = {name for entry in record['entries'] for name in [entry.get('replaces'), *entry.get('skips', [])]}
            for entry in record['entries']:
                if entry.get('skipRange'):
                    members = [b for b in self.bundles if b['alias'] == alias and b['package'] == package and b['name'] in entries and b['name'] != entry['name']]
                    skips = self.semantics.call(op='range', range=entry['skipRange'], versions=[b['version'] for b in members])
                    replaced.update(b['name'] for b, match in zip(members, skips) if match)
            heads = entries - replaced
            if len(heads) != 1:
                raise ValueError(f'{path}:{channel}: channel 不是单一 head，请显式选择版本')
            allowed = {i for i, b in enumerate(self.bundles) if b['alias'] == alias and b['name'] in heads}
        else:
            allowed = {i for i, b in enumerate(self.bundles) if b['alias'] == alias and b['package'] == package
                       and channel in b['channels'] and b['version'] == version}
        if len(allowed) != 1:
            raise ValueError(f'{spec}: 不能唯一定位 bundle，请核对版本和目录')
        return {'selection': spec, 'channel': channel, 'allowed': allowed}


class Resolver:
    def __init__(self, catalogs, provided=(), max_states=50000):
        self.catalogs = catalogs
        self.provided = {gvk_key(value) for value in provided}
        self.max_states = max_states
        self.states = 0
        self.compiled = {}
        self.failures = []
        self.visited = set()

    def expression(self, constraint, negate=False):
        allowed_keys = {'failureMessage', 'package', 'gvk', 'cel', 'all', 'any', 'not'}
        if set(constraint) - allowed_keys:
            raise ValueError('不支持的依赖约束字段: ' + ', '.join(set(constraint) - allowed_keys))
        kinds = [k for k in allowed_keys - {'failureMessage'} if k in constraint]
        if len(kinds) != 1:
            raise ValueError('依赖约束必须且只能声明一种类型')
        kind = kinds[0]
        value = constraint[kind]
        if kind in ('all', 'any', 'not'):
            children = value['constraints']
            if not children:
                raise ValueError('复合依赖不能为空')
            # OLM not means none of the children (not OR).
            op = 'all' if kind in ('all', 'not') else 'any'
            inverted = negate != (kind == 'not')
            if negate:
                op = 'any' if op == 'all' else 'all'
            return (op, tuple(self.expression(c, inverted) for c in children))
        base = False
        if kind == 'package':
            package = value['packageName']
            candidates = sorted(self.catalogs.by_package.get(package, ()))
            version_range = value.get('versionRange') or '>=0.0.0-0'
            if version_range == '*':
                version_range = '>=0.0.0-0'
            matches = self.catalogs.semantics.call(op='range', range=version_range,
                                                 versions=[self.catalogs.bundles[i]['version'] for i in candidates])
            providers = frozenset(i for i, match in zip(candidates, matches) if match)
        elif kind == 'gvk':
            key = gvk_key(value)
            providers = frozenset(self.catalogs.by_gvk.get(key, ()))
            base = key in self.provided
        else:
            matches = self.catalogs.semantics.call(op='cel', rule=value['rule'],
                                                 properties=[b.get('properties', []) for b in self.catalogs.bundles])
            providers = frozenset(i for i, match in enumerate(matches) if match)
        return ('negative' if negate else 'positive', providers, base)

    def requirements(self, index):
        if index not in self.compiled:
            self.compiled[index] = [(self.expression(c), json.dumps(c, ensure_ascii=False))
                                    for c in required(self.catalogs.bundles[index])]
        return self.compiled[index]

    def satisfied(self, expr, selected):
        kind = expr[0]
        if kind in ('positive', 'negative'):
            present = expr[2] or bool(expr[1] & selected)
            return present if kind == 'positive' else not present
        values = (self.satisfied(child, selected) for child in expr[1])
        return all(values) if kind == 'all' else any(values)

    def repairs(self, expr, selected):
        kind = expr[0]
        if kind == 'positive':
            return sorted(expr[1] - selected)
        if kind == 'negative':
            return []
        if kind == 'all':
            return next((self.repairs(c, selected) for c in expr[1] if not self.satisfied(c, selected)), [])
        return list(dict.fromkeys(i for c in expr[1] for i in self.repairs(c, selected)))

    def compatible(self, index, selected):
        bundle = self.catalogs.bundles[index]
        provided = {gvk_key(p['value']) for p in bundle.get('properties', []) if p['type'] == 'olm.gvk'}
        if provided & self.provided:
            return False  # Do not introduce a second owner of an API supplied by the target baseline.
        for chosen in selected:
            other = self.catalogs.bundles[chosen]
            if bundle['package'] == other['package']:
                return False
            other_gvk = {gvk_key(p['value']) for p in other.get('properties', []) if p['type'] == 'olm.gvk'}
            if provided & other_gvk:
                return False
        return True

    def solve(self, roots):
        requirements = [('positive', frozenset(r['allowed']), False) for r in roots]
        def search(selected):
            key = frozenset(selected)
            if key in self.visited:
                return None
            self.visited.add(key)
            self.states += 1
            if self.states > self.max_states:
                raise ValueError('依赖搜索超过上限；请缩小目录/固定版本，未生成成功计划')
            checks = [(r, '用户选择', root['selection']) for r, root in zip(requirements, roots)]
            for i in sorted(selected):
                checks.extend((r, self.catalogs.bundles[i]['name'], detail) for r, detail in self.requirements(i))
            for expr, owner, detail in checks:
                if self.satisfied(expr, selected):
                    continue
                candidates = [i for i in self.repairs(expr, selected) if self.compatible(i, selected)]
                if not candidates and len(self.failures) < 20:
                    self.failures.append(owner + ': ' + detail)
                for candidate in candidates:
                    result = search(selected | {candidate})
                    if result is not None:
                        return result
                return None
            return selected
        result = search(set())
        if result is None:
            names = ', '.join(r['selection'] for r in roots)
            raise ValueError(f'依赖不存在可行组合: {names}。可能缺少提供依赖的目录、版本冲突或 API 冲突。详情: ' + '; '.join(self.failures[-5:]))
        return sorted(result)

    def plan(self, roots, selected):
        records = []
        for i in selected:
            b = self.catalogs.bundles[i]
            root = next((r for r in roots if i in r['allowed']), None)
            channel = root['channel'] if root else b['preferredChannel']
            # Equal semver (different build metadata) cannot be distinguished by oc-mirror filters.
            same_channel = [j for j, candidate in enumerate(self.catalogs.bundles)
                            if candidate['alias'] == b['alias'] and candidate['package'] == b['package'] and channel in candidate['channels']]
            equal = self.catalogs.semantics.call(op='range', range='=' + b['version'],
                                                versions=[self.catalogs.bundles[j]['version'] for j in same_channel])
            if sum(equal) != 1:
                raise ValueError(f'{b["name"]}: 同一 channel 存在语义版本相同的多个 bundle，不能安全精确筛选')
            witnesses = []
            for requirement in required(b):
                expr = self.expression(requirement)
                def providers(e):
                    if e[0] in ('positive', 'negative'):
                        return [self.catalogs.bundles[j]['name'] for j in sorted(e[1] & set(selected))] if e[0] == 'positive' else []
                    return [name for c in e[1] for name in providers(c)]
                witnesses.append({'constraint': requirement, 'selectedProviders': sorted(set(providers(expr))),
                                  'satisfied': self.satisfied(expr, set(selected))})
            records.append({'catalog': b['alias'], 'package': b['package'], 'channel': channel,
                            'version': b['version'], 'bundle': b['name'], 'image': b['image'],
                            'requested': root is not None, 'dependencies': witnesses,
                            'relatedImages': b.get('relatedImages', []),
                            'properties': b.get('properties', [])})
        return records
