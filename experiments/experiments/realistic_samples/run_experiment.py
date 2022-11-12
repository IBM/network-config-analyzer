"""Experiment design:
- We start with a set of connection attributes.
- We create sets of configurations, which is a set of allow and deny subsets.
- For each of those configurations, we construct it, and check emptiness.
    This is the first data point.
- For each pair of configurations, we check equivalence, and containment for each side.
    This is the second data point.

Presenting the results:
- I want to somehow order the samples, maybe on their hyper-cube-set creation time.
- graph for creation and emptiness check.
- graph with the containment checks time for each pair.
- graph with equivalence check times.
- table with all the results.
"""
# TODO: fill up README.md
# TODO: extract class names from the data!
# TODO: create 2 different files, one for running the experiment and collecting the raw data,
#  and a second for analyzing it

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
from set_valued_decision_diagram.cache import reset_cache
from set_valued_decision_diagram.hyper_cube_set_dd import HyperCubeSetDD
from z3_sets.z3_product_set import Z3ProductSet

logging.basicConfig(level=logging.INFO)


# TODO: maybe move this to utils?
def get_dim_names():
    return ['src_ports', 'dst_ports', 'methods', 'paths', 'hosts']


def get_operations():
    return ['creation+emptiness', 'creation+equivalence', 'creation+contained_in']


# TODO: maybe move this to utils?
def cls_name_to_marker(cls_name):
    if cls_name == 'Z3ProductSet':
        return '+'
    elif cls_name == 'CanonicalHyperCubeSet':
        return 'x'
    elif cls_name == 'HyperCubeSetDD':
        return '*'


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
    reset_cache()
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
    reset_cache()
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
    reset_cache()
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
    for i in range(n):
        for j in range(i+1, n):
            logging.info(f'{cls.__name__} creation+equivalence {i * n + j + 1} out of {n * (n - 1) // 2}')
            allow_list1, deny_list1 = allow_deny_combinations[i]
            allow_list2, deny_list2 = allow_deny_combinations[j]
            operation_result = run_creation_and_equivalence(cls, allow_list1, deny_list1, allow_list2, deny_list2)
            results['creation+equivalence'].append(operation_result)
    # creation and contained_in
    for i in range(n):
        for j in range(n):
            logging.info(f'{cls.__name__} creation+contained_in {i * n + j + 1} out of {n ** 2}')
            allow_list1, deny_list1 = allow_deny_combinations[i]
            allow_list2, deny_list2 = allow_deny_combinations[j]
            operation_result = run_creation_and_contained_in(cls, allow_list1, deny_list1, allow_list2, deny_list2)
            results['creation+contained_in'].append(operation_result)

    return results


def supported_cls_choices():
    return [CanonicalHyperCubeSet, HyperCubeSetDD, Z3ProductSet]


def supported_cls_names_choices():
    return [cls.__name__ for cls in supported_cls_choices()]


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


if __name__ == '__main__':
    arg_parser = ArgumentParser()
    arg_parser.add_argument('--cls', choices=supported_cls_names_choices(),
                            help='which class to compare first.')
    arg_parser.add_argument('--mode', choices=['simple', 'complex'],
                            help='which set of samples to use.')
    args = arg_parser.parse_args()
    main(args.cls, args.mode)
