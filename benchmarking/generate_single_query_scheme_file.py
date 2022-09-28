from collections.abc import Iterable
from copy import deepcopy
from pathlib import Path

from yaml import load, dump, Loader


def _relative_to_absolute_path(relative_path_str: str, relative_to_file: Path) -> str:
    """Takes a path relative to a given path and return it's absolute path"""
    path = relative_to_file.parent / relative_path_str
    path = path.resolve()
    path = path.absolute()
    return str(path)


def _is_file(data, relative_to: Path) -> bool:
    if isinstance(data, str):
        path = relative_to.parent / data
        path.resolve()
        return path.exists()
    return False


def _recursive_convert_all_relative_to_absolute(data, relative_to: Path):
    if isinstance(data, list):
        return [_recursive_convert_all_relative_to_absolute(value, relative_to) for value in data]
    elif isinstance(data, dict):
        return {key: _recursive_convert_all_relative_to_absolute(value, relative_to) for key, value in data.items()}
    elif _is_file(data, relative_to):
        return _relative_to_absolute_path(data, relative_to)
    elif isinstance(data, str) and data.endswith('/**'):
        data = data[:-3]
        return _relative_to_absolute_path(data, relative_to) + '/**'
    else:
        return data


def _get_query_type(query: dict):
    return next(iter(filter(lambda key: key not in {'name', 'expected'}, query.keys())))


def generate_single_query_scheme_file(scheme_file: Path, temp_dir: Path) -> Iterable[tuple[Path, str, str]]:
    """Takes a scheme file, and for each query, generates a new scheme file with only that query and only the required
    network configurations."""
    with scheme_file.open('r') as f:
        scheme = load(f, Loader)

    network_config_list = scheme['networkConfigList']
    scheme_name = scheme_file.stem[:-len('-scheme')]

    if 'queries' not in scheme:
        return

    for query in scheme['queries']:
        query_name = query['name']
        query_type = _get_query_type(query)
        query_network_config_list = query[query_type]
        query_network_config_list = [network_policy_name.split('/')[0]
                                     for network_policy_name in query_network_config_list]

        new_scheme = deepcopy(scheme)
        new_scheme['queries'] = [query]
        new_scheme['networkConfigList'] = [network_config for network_config in new_scheme['networkConfigList']
                                           if network_config['name'] in query_network_config_list]

        new_scheme = _recursive_convert_all_relative_to_absolute(new_scheme, scheme_file)

        new_scheme_name = f'{scheme_name}-{query_name}-scheme.yaml'
        new_scheme_file = temp_dir / new_scheme_name
        with new_scheme_file.open('w') as f:
            dump(new_scheme, f)

        yield new_scheme_file, query_type, query_name


if __name__ == '__main__':
    sf = r'C:\Users\018130756\repos\network-config-analyzer\tests\calico_testcases\example_policies\testcase1\testcase1-scheme.yaml'
    sf = Path(sf)
    cwd = Path.cwd()
    for nsf, qt in generate_single_query_scheme_file(sf, cwd):
        print(nsf)
        nsf.unlink()

