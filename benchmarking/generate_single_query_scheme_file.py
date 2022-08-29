from collections.abc import Iterable
from copy import deepcopy
from pathlib import Path

from yaml import load, dump, Loader


def to_absolute_path_str(relative_path_str: str, relative_to_file: Path) -> str:
    # TODO: I assumed that the scheme files should work with absolute paths... make sure this works!
    path = relative_to_file.parent
    path = path / relative_path_str
    path = path.resolve()
    path = path.absolute()
    return str(path)


def process_network_config_list(original_network_config_list: list[dict], original_scheme_file: Path,
                                required_network_config_list: list[str]) -> list[dict]:
    network_config_list = []
    for original_network_config in original_network_config_list:
        if original_network_config['name'] in required_network_config_list:
            network_config = deepcopy(original_network_config)
            if 'networkPolicyList' in network_config:
                network_config['networkPolicyList'] = [to_absolute_path_str(path, original_scheme_file)
                                                       for path in original_network_config['networkPolicyList']]
            if 'resourceList' in network_config:
                network_config['resourceList'] = [to_absolute_path_str(path, original_scheme_file)
                                                  for path in original_network_config['resourceList']]
            network_config_list.append(network_config)

    return network_config_list


def get_query_type(query: dict):
    return next(iter(filter(lambda key: key not in {'name', 'expected'}, query.keys())))


def generate_single_query_scheme_file(scheme_file: Path, temp_dir: Path) -> Iterable[Path]:
    with scheme_file.open('r') as f:
        scheme = load(f, Loader)

    network_config_list = scheme['networkConfigList']
    scheme_name = scheme_file.stem[:-len('-scheme')]

    if 'queries' not in scheme:
        return

    for query in scheme['queries']:
        query_name = query['name']
        query_type = get_query_type(query)
        query_network_config_list = query[query_type]

        new_scheme = {}
        path_fields_to_convert = ['resourceList', 'namespaceList', 'podList']
        for field in path_fields_to_convert:
            if field in scheme:
                if isinstance(scheme[field], list):
                    new_scheme[field] = [to_absolute_path_str(path, scheme_file) for path in scheme[field]]
                else:
                    new_scheme[field] = to_absolute_path_str(scheme[field], scheme_file)

        new_scheme['queries'] = [query]
        new_scheme['networkConfigList'] = process_network_config_list(network_config_list, scheme_file,
                                                                      query_network_config_list)

        new_scheme_name = f'{scheme_name}-{query_name}-scheme.yaml'
        new_scheme_file = temp_dir / new_scheme_name
        with new_scheme_file.open('w') as f:
            dump(new_scheme, f)

        yield new_scheme_file




if __name__ == '__main__':
    sf = r'C:\Users\018130756\repos\network-config-analyzer\tests\calico_testcases\example_policies\testcase1\testcase1-scheme.yaml'
    # rp = r'../../example_podlist/ns_list.json'
    # ap = to_absolute_path_str(rp, Path(sf))
    # print(ap)
    sf = Path(sf)
    cwd = Path.cwd()
    for nsf in generate_single_query_scheme_file(sf, cwd):
        print(nsf)
        nsf.unlink()

