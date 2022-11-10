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
# TODO: add support for HyperCubeSetDD
# TODO: fill up README.md
# TODO: extract class names from the data!
# TODO: add the ability to direct the output to a specific directory with the CLI, should be interesting


import itertools
import json
import logging
from argparse import ArgumentParser
from copy import deepcopy
from csv import DictWriter
from pathlib import Path

from matplotlib import pyplot as plt

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
def get_all_dims():
    return ['src_ports', 'dst_ports', 'methods', 'paths', 'hosts']


# TODO: maybe move this to utils?
def cls_name_to_marker(cls_name):
    if cls_name == 'Z3ProductSet':
        return '+'
    elif cls_name == 'CanonicalHyperCubeSet':
        return 'x'
    elif cls_name == 'HyperCubeSetDD':
        return '*'


def config_to_str(config):
    return f'allow_list={config[0]}; deny_list={config[1]}'


def run_experiment(allow_deny_combinations: list[tuple[list[ConnectionAttributes], list[ConnectionAttributes]]],
                   cls_list: list):
    """
    :param allow_deny_combinations: list of pairs of allow policies and deny policies
    :param cls_list: a list of classes to run the experiment on.
    :return: a result dict, organized in the following levels:
    1. the operation, one of {'creation', 'emptiness', 'contained_in', 'equivalence'}
    2. the class name
    3. the type of data, one of {'times', 'outcomes', 'indices'}
    4. a list with the according data.
    """
    results = {}
    for level_1_key in ['creation', 'emptiness', 'equivalence', 'contained_in']:
        results[level_1_key] = {}
        for level_2_key in [cls.__name__ for cls in cls_list]:
            results[level_1_key][level_2_key] = {}
            for level_3_key in ['times', 'outcomes', 'indices']:
                results[level_1_key][level_2_key][level_3_key] = []

    all_dims = get_all_dims()
    n = len(allow_deny_combinations)
    for cls in cls_list:
        s_list = []
        for i in range(n):
            reset_cache()
            allow_list, deny_list = allow_deny_combinations[i]

            logging.info(f'cls={cls.__name__} | creation | {i+1} out of {n}')
            with Timer() as creation_timer:
                s = cls(all_dims)
                for connection_attr in allow_list:
                    cube, dims = connection_attr.to_cube(cls)
                    s.add_cube(cube, dims)
                for connection_attr in deny_list:
                    cube, dims = connection_attr.to_cube(cls)
                    s.add_hole(cube, dims)
            results['creation'][cls.__name__]['times'].append(creation_timer.elapsed_time)
            results['creation'][cls.__name__]['outcomes'].append(None)
            results['creation'][cls.__name__]['indices'].append([i])
            s_list.append(s)

            logging.info(f'cls={cls.__name__} | emptiness | {i+1} out of {n}')
            with Timer() as emptiness_timer:
                emptiness_outcome = bool(s)
            results['emptiness'][cls.__name__]['times'].append(emptiness_timer.elapsed_time)
            results['emptiness'][cls.__name__]['outcomes'].append(emptiness_outcome)
            results['emptiness'][cls.__name__]['indices'].append([i])

        # second part - for each of configuration pair, check containment in both directions, and equivalence.
        all_pairs = list(itertools.combinations(range(n), 2))
        for i, (j1, j2) in enumerate(all_pairs, 1):
            s1, s2 = s_list[j1], s_list[j2]

            logging.info(f'cls={cls.__name__} | equivalence | {i} out of {len(all_pairs)}')
            with Timer() as equivalence_timer:
                equivalence_outcome = s1 == s2
            results['equivalence'][cls.__name__]['times'].append(equivalence_timer.elapsed_time)
            results['equivalence'][cls.__name__]['outcomes'].append(equivalence_outcome)
            results['equivalence'][cls.__name__]['indices'].append([j1, j2])

            logging.info(f'cls={cls.__name__} | contained_in_12 | {i} out of {len(all_pairs)}')
            with Timer() as contained_in_12_timer:
                contained_in_12_outcome = s1.contained_in(s2)
            results['contained_in'][cls.__name__]['times'].append(contained_in_12_timer.elapsed_time)
            results['contained_in'][cls.__name__]['outcomes'].append(contained_in_12_outcome)
            results['contained_in'][cls.__name__]['indices'].append([j1, j2])

            logging.info(f'cls={cls.__name__} | contained_in_21 | {i} out of {len(all_pairs)}')
            with Timer() as contained_in_21_timer:
                contained_in_21_outcome = s2.contained_in(s1)
            results['contained_in'][cls.__name__]['times'].append(contained_in_21_timer.elapsed_time)
            results['contained_in'][cls.__name__]['outcomes'].append(contained_in_21_outcome)
            results['contained_in'][cls.__name__]['indices'].append([j2, j1])

    return results


def add_creation_times(results):
    for operation in ['emptiness', 'equivalence', 'contained_in']:
        level_1_key = f'{operation}+creation'
        results[level_1_key] = deepcopy(results[operation])

        for cls_name in results['creation'].keys():
            creation_times = results['creation'][cls_name]['times']
            for i in range(len(results[operation][cls_name]['times'])):
                for j in results[operation][cls_name]['indices'][i]:
                    results[level_1_key][cls_name]['times'][i] += creation_times[j]

    return results


def draw_graphs(results, mode, output_dir: Path):
    for operation, operation_results in results.items():
        for cls_name, cls_results in operation_results.items():
            x = list(range(len(cls_results['times'])))
            plt.scatter(
                x,
                cls_results['times'],
                marker=cls_name_to_marker(cls_name),
                alpha=0.5,
                label=cls_name
            )
        plt.legend()
        title = f'{operation} {mode}'
        plt.title(title)
        plt.xlabel('sample id')
        plt.ylabel('time [seconds]')
        file = output_dir / f'{operation}_{mode}.png'
        plt.savefig(str(file))
        plt.clf()


def create_tables(results, allow_deny_combinations, mode, output_dir: Path):
    for operation, operation_results in results.items():
        cls_names = list(operation_results.keys())
        first_cls_name = cls_names[0]
        n_items = len(operation_results[first_cls_name]['times'])
        rows = [{} for _ in range(n_items)]

        for i in range(n_items):
            # time
            for cls_name in cls_names:
                rows[i][cls_name+'_time'] = operation_results[cls_name]['times'][i]
            # outcome
            for cls_name in cls_names:
                rows[i][cls_name+'_outcome'] = operation_results[cls_name]['outcomes'][i]
            # description
            sub_descriptions = []
            for j in operation_results[first_cls_name]['indices'][i]:
                allow_list, deny_list = allow_deny_combinations[j]
                sub_descriptions.append(f'<allow_list={allow_list}; deny_list={deny_list}>')
            description = ';'.join(sub_descriptions)
            rows[i]['description'] = description

        file = output_dir / f'{operation}_{mode}.csv'
        with open(file, 'w', newline='') as f:
            writer = DictWriter(f, fieldnames=rows[0].keys())
            writer.writeheader()
            writer.writerows(rows)


def sort_results_by_list_sizes(results, allow_deny_combinations):
    results_copy = deepcopy(results)
    for operation, operation_results in results.items():
        for cls_name, cls_results in operation_results.items():
            def sort_key(i):
                allow_len = 0
                deny_len = 0
                indices = cls_results['indices'][i]
                for j in indices:
                    allow_list, deny_list = allow_deny_combinations[j]
                    allow_len += len(allow_list)
                    deny_len += len(deny_list)
                return allow_len + deny_len, deny_len, allow_len

            sorted_order = sorted(range(len(cls_results['indices'])), key=sort_key)
            for key, value_list in cls_results.items():
                results_copy[operation][cls_name][key] = [value_list[i] for i in sorted_order]

    return results_copy


def main(first_cls_name: str, second_cls_name: str, skip_run: bool, mode: str):
    # TODO: create a more compact representation for ConnectionAttr, maybe this will make things more clear.
    # TODO: check that the outputs align
    logging.info(f'first_cls_name={first_cls_name}, second_cls_name={second_cls_name}, mode={mode}, '
                 f'skip_run={skip_run}.')
    first_cls = cls_name_to_cls(first_cls_name)
    second_cls = cls_name_to_cls(second_cls_name)
    if mode == 'simple':
        connection_attr_list = SIMPLE_CONNECTION_ATTR_LIST
    else:
        connection_attr_list = COMPLEX_CONNECTION_ATTR_LIST
    allow_deny_combinations = list(get_allow_deny_combinations(connection_attr_list))
    # allow_deny_combinations = allow_deny_combinations[:5]  # TODO: comment
    output_dir = Path() / f'{first_cls_name}_{second_cls_name}_{mode}_results'
    output_dir.mkdir(exist_ok=True)

    results_file = output_dir / f'results.json'

    if not skip_run:
        results = run_experiment(allow_deny_combinations, [first_cls, second_cls])
        results = add_creation_times(results)
        with open(results_file, 'w') as f:
            json.dump(results, f)

    with open(results_file, 'r') as f:
        results = json.load(f)

    results = sort_results_by_list_sizes(results, allow_deny_combinations)
    draw_graphs(results, mode, output_dir)
    create_tables(results, allow_deny_combinations, mode, output_dir)
    check_results_align(results)


def check_results_align(results):
    # TODO: debug the examples
    for operation, operation_result in results.items():
        cls1, cls2 = list(operation_result.keys())
        cls1_results = operation_result[cls1]
        error_count = 0
        total = len(cls1_results['outcomes'])
        cls2_results = operation_result[cls2]
        for i in range(total):
            cls1_res = cls1_results['outcomes'][i]
            cls2_res = cls2_results['outcomes'][i]
            if cls1_res != cls2_res:
                error_count += 1
                # logging.info(f'outcomes in operation={operation} do not align.'
                #              f'{cls1} is {cls1_res} and {cls2} is {cls2_res}.')
        logging.info(f'operation={operation}, {error_count} out of {total} errors.')


def supported_cls_choices():
    return [CanonicalHyperCubeSet, HyperCubeSetDD, Z3ProductSet]


def supported_cls_names_choices():
    return [cls.__name__ for cls in supported_cls_choices()]


def cls_name_to_cls(cls_name: str):
    return eval(cls_name)


if __name__ == '__main__':
    arg_parser = ArgumentParser()
    arg_parser.add_argument('--first_cls', choices=supported_cls_names_choices(),
                            help='which class to compare first.')
    arg_parser.add_argument('--second_cls', choices=supported_cls_names_choices(),
                            help='which class to compare second.')
    arg_parser.add_argument('--skip_run', action='store_true',
                            help='run results analysis without running the experiment again.')
    arg_parser.add_argument('--mode', choices=['simple', 'complex'],
                            help='which set of samples to use.')
    args = arg_parser.parse_args()
    main(args.first_cls, args.second_cls, args.skip_run, args.mode)
