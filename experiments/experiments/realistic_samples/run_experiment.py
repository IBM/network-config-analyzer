import json
import logging
from argparse import ArgumentParser
from pathlib import Path

from nca.CoreDS.CanonicalHyperCubeSet import CanonicalHyperCubeSet
from experiments.experiments.experiment_utils import Timer
from experiments.experiments.realistic_samples.connection_attributes import ConnectionAttributes
from experiments.experiments.realistic_samples.connection_attributes_list import SIMPLE_CONNECTION_ATTR_LIST, \
    COMPLEX_CONNECTION_ATTR_LIST
from experiments.experiments.realistic_samples.create_connection_set_combinations import get_allow_deny_combinations
from decision_diagram.cache import clear_cache
from decision_diagram.hyper_cube_set_dd import HyperCubeSetDD
from nca.CoreDS.MinDFA import MinDFA
from z3_sets.z3_product_set import Z3ProductSet

logging.basicConfig(level=logging.INFO)


def clear_hyper_cube_set_dd_and_min_dfa_cache():
    clear_cache()
    for key, value in MinDFA.__dict__.items():
        if hasattr(value, 'cache_clear'):
            value.cache_clear()


def get_dim_names():
    return ['src_ports', 'dst_ports', 'methods', 'paths', 'hosts']


def get_operations():
    return ['creation+emptiness', 'creation+equivalence', 'creation+contained_in']


def create_set(cls, allow_list, deny_list):
    s = cls(get_dim_names())
    for connection_attr in allow_list:
        cube, dims = connection_attr.to_cube(cls)
        s.add_cube(cube, dims)
    for connection_attr in deny_list:
        cube, dims = connection_attr.to_cube(cls)
        s.add_hole(cube, dims)
    return s


def run_creation_and_emptiness(cls, allow_list: list[ConnectionAttributes],
                               deny_list: list[ConnectionAttributes]) -> dict:
    clear_hyper_cube_set_dd_and_min_dfa_cache()
    with Timer() as timer:
        s = create_set(cls, allow_list, deny_list)
        is_empty = not bool(s)

    return dict(
        time=timer.elapsed_time,
        input_description=f'<allow_list={str(allow_list)}; deny_list={str(deny_list)}>',
        output=is_empty
    )


def run_creation_and_equivalence(cls, allow_list1: list[ConnectionAttributes], deny_list1: list[ConnectionAttributes],
                                 allow_list2: list[ConnectionAttributes], deny_list2: list[ConnectionAttributes]) \
        -> dict:
    clear_hyper_cube_set_dd_and_min_dfa_cache()
    with Timer() as timer:
        s1 = create_set(cls, allow_list1, deny_list1)
        s2 = create_set(cls, allow_list2, deny_list2)
        equivalent = s1 == s2

    return dict(
        time=timer.elapsed_time,
        input_description=f'<allow_list1={str(allow_list1)}; deny_list1={str(deny_list1)},'
                          f'allow_list2={str(allow_list2)}; deny_list2={str(deny_list2)}>',
        output=equivalent
    )


def run_creation_and_contained_in(cls, allow_list1: list[ConnectionAttributes], deny_list1: list[ConnectionAttributes],
                                  allow_list2: list[ConnectionAttributes], deny_list2: list[ConnectionAttributes]) \
        -> dict:
    clear_hyper_cube_set_dd_and_min_dfa_cache()
    with Timer() as timer:
        s1 = create_set(cls, allow_list1, deny_list1)
        s2 = create_set(cls, allow_list2, deny_list2)
        contained_in = s1.contained_in(s2)

    return dict(
        time=timer.elapsed_time,
        input_description=f'<allow_list1={str(allow_list1)}; deny_list1={str(deny_list1)};'
                          f'allow_list2={str(allow_list2)}; deny_list2={str(deny_list2)}>',
        output=contained_in
    )


def run_experiment(allow_deny_combinations: list[tuple[list[ConnectionAttributes], list[ConnectionAttributes]]],
                   cls):
    """
    :param allow_deny_combinations: list of pairs of allow policies and deny policies
    :param cls: the class to run the experiment on.
    :return: a result dict, organized in the following levels:
    1. the operation, one of {'creation', 'emptiness', 'contained_in', 'equivalence'}
    2. for each operation, a list of OperationResults.
    """
    results = {}
    for operation in get_operations():
        results[operation] = []

    n = len(allow_deny_combinations)
    # creation and emptiness
    for i in range(n):
        logging.info(f'{cls.__name__} creation+emptiness {i + 1} out of {n}')
        allow_list, deny_list = allow_deny_combinations[i]
        operation_result = run_creation_and_emptiness(cls, allow_list, deny_list)
        results['creation+emptiness'].append(operation_result)
    # creation and equivalence
    count = 1
    for i in range(n):
        for j in range(i + 1, n):
            logging.info(f'{cls.__name__} creation+equivalence {count} out of {n * (n - 1) // 2}')
            allow_list1, deny_list1 = allow_deny_combinations[i]
            allow_list2, deny_list2 = allow_deny_combinations[j]
            operation_result = run_creation_and_equivalence(cls, allow_list1, deny_list1, allow_list2, deny_list2)
            results['creation+equivalence'].append(operation_result)
            count += 1
    # creation and contained_in
    for i in range(n):
        for j in range(n):
            logging.info(f'{cls.__name__} creation+contained_in {i * n + j + 1} out of {n ** 2}')
            allow_list1, deny_list1 = allow_deny_combinations[i]
            allow_list2, deny_list2 = allow_deny_combinations[j]
            operation_result = run_creation_and_contained_in(cls, allow_list1, deny_list1, allow_list2, deny_list2)
            results['creation+contained_in'].append(operation_result)

    return results


def get_cls_choices():
    return [CanonicalHyperCubeSet, HyperCubeSetDD, Z3ProductSet]


def get_cls_name_choices():
    return [cls.__name__ for cls in get_cls_choices()]


def cls_name_to_cls(cls_name: str):
    return eval(cls_name)


def get_experiment_results_dir():
    experiment_results_dir = Path() / f'experiment_results'
    experiment_results_dir.mkdir(exist_ok=True)
    return experiment_results_dir


def get_results_file(cls_name, mode):
    experiment_results_dir = get_experiment_results_dir()
    results_file = experiment_results_dir / f'{cls_name}_{mode}.json'
    return results_file


def main(cls_name: str, mode: str):
    logging.info(f'cls_name={cls_name}, mode={mode}')
    cls = cls_name_to_cls(cls_name)
    if mode == 'simple':
        connection_attr_list = SIMPLE_CONNECTION_ATTR_LIST
    else:
        connection_attr_list = COMPLEX_CONNECTION_ATTR_LIST
    allow_deny_combinations = list(get_allow_deny_combinations(connection_attr_list))
    results_file = get_results_file(cls_name, mode)
    results = run_experiment(allow_deny_combinations, cls)
    with results_file.open('w') as f:
        json.dump(results, f)


def get_mode_choices():
    return ['simple', 'complex']


if __name__ == '__main__':
    parser = ArgumentParser()
    parser.add_argument('--cls', choices=get_cls_name_choices(),
                        help='Which class to run experiment with. '
                             'If not specified, runs all classes.')
    parser.add_argument('--mode', choices=get_mode_choices(),
                        help='Which set of samples to use. '
                             'If not specified, runs all modes.')
    args = parser.parse_args()
    if args.cls is None:
        cls_list = get_cls_name_choices()
    else:
        cls_list = [args.cls]
    if args.mode is None:
        mode_list = get_mode_choices()
    else:
        mode_list = [args.mode]
    for cls in cls_list:
        for mode in mode_list:
            main(cls, mode)
