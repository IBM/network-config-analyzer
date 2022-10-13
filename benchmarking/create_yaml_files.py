from collections.abc import Iterable
from pathlib import Path

import yaml

from benchmarking.utils import get_benchmarks_dir

# TODO: check out what happens when I change it from giving it the path and giving it /**, does it find more resources?


def _get_scheme_file_path(benchmark_dir: Path) -> Path:
    return get_benchmarks_dir() / f'{benchmark_dir.name}-scheme.yaml'


def _select_min_len_policy_file(benchmark_dir: Path) -> Path:
    """Searches for the shortest file in benchmark_dir that contains a network policy."""
    # TODO: I select the shortest policy file. is that the correct thing to do?
    policy_type_list = ['NetworkPolicy', 'GlobalNetworkPolicy', 'AuthorizationPolicy']
    min_len = None
    min_len_file = None
    for yaml_file in benchmark_dir.rglob('*.yaml'):
        file_text = yaml_file.read_text()
        if any(policy_type in file_text for policy_type in policy_type_list):
            if min_len is None or len(file_text) < min_len:
                min_len = len(file_text) if min_len is None else min(len(file_text), min_len)
                min_len_file = yaml_file

    assert min_len_file is not None, f'No policies in {benchmark_dir}'
    return min_len_file


def _get_scheme_dict(benchmark_dir: Path) -> dict:
    scheme_dict = {
        'namespaceList': f'{benchmark_dir.name}',
        'podList': f'{benchmark_dir.name}',
        'networkConfigList': [
            {
                'name': 'network',
                'networkPolicyList': [f'{benchmark_dir.name}'],
            }
        ],
        'queries': []
    }
    min_len_policy_path = _select_min_len_policy_file(benchmark_dir)
    min_len_policy_path = min_len_policy_path.relative_to(get_benchmarks_dir())
    min_len_policy_path = str(min_len_policy_path)
    other_network_configs = {
        'allow-all-default': _get_allow_all_default_policy_file().name,
        'min-len-policy': min_len_policy_path
    }
    for policy_name, policy_file in other_network_configs.items():
        scheme_dict['networkConfigList'].append({
            'name': policy_name,
            'networkPolicyList': [policy_file]
        })
    scheme_dict['queries'].append({'name': 'sanity', 'sanity': ['network']})
    scheme_dict['queries'].append({
        'name': 'connectivityMap-txt',
        'connectivityMap': ['network'],
        'outputConfiguration': {'outputFormat': 'txt'}
    })
    scheme_dict['queries'].append({
        'name': 'connectivityMap-dot',
        'connectivityMap': ['network'],
        'outputConfiguration': {'outputFormat': 'dot'}
    })
    two_policy_queries = ['permits', 'forbids', 'semanticDiff']
    for query in two_policy_queries:
        for policy_name in other_network_configs.keys():
            scheme_dict['queries'].append({'name': f'{query}-{policy_name}', query: ['network', policy_name]})

    return scheme_dict


def _iter_benchmark_dirs() -> Iterable[Path]:
    return filter(lambda file: file.is_dir(), get_benchmarks_dir().iterdir())


def create_scheme_file_for_benchmarks():
    for benchmark_dir in _iter_benchmark_dirs():
        scheme_file = _get_scheme_file_path(benchmark_dir)
        scheme_data = _get_scheme_dict(benchmark_dir)
        with scheme_file.open('w') as f:
            yaml.dump(scheme_data, f)


def _get_allow_all_default_policy_dict():
    return {
        'apiVersion': 'networking.k8s.io/v1',
        'kind': 'NetworkPolicy',
        'metadata': {
            'name': 'allow-all-default',
            'namespace': 'default',
        },
        'spec': {
            'podSelector': {},
            'policyTypes': ['Ingress', 'Egress'],
            'ingress': [{}],
            'egress': [{}]
        }
    }


def _get_allow_all_default_policy_file():
    return get_benchmarks_dir() / 'allow-all-default-policy.yaml'


def create_allow_all_default_policy_file():
    yaml_data = _get_allow_all_default_policy_dict()
    with _get_allow_all_default_policy_file().open('w') as f:
        yaml.dump(yaml_data, f)
