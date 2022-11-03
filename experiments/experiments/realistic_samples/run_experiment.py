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
#   - (think about this a little more) The analyze_results is redundant.
#   I can do this check with Excel once I have the results in .csv format.
#   Delete the python file and create a workbook, and upload to github.

# TODO: add more simple policies that are more realistic, and compare performance on those.
#   I hope that this will show us that CanonicalHyperCubeSet is definitely better than z3 on the common cubes.


import itertools
import json
import logging
from copy import deepcopy
from csv import DictWriter

from matplotlib import pyplot as plt

from nca.CoreDS.CanonicalHyperCubeSet import CanonicalHyperCubeSet
from experiments.experiments.experiment_utils import Timer
from experiments.experiments.realistic_samples.connection_attributes import ConnectionAttributes
from experiments.experiments.realistic_samples.connection_attributes_list import SIMPLE_CONNECTION_ATTR_LIST, \
    COMPLEX_CONNECTION_ATTR_LIST
from experiments.experiments.realistic_samples.create_connection_set_combinations import get_allow_deny_combinations
from experiments.z3_sets.z3_product_set import Z3ProductSet

logging.basicConfig(level=logging.INFO)


def get_all_dims():
    return ['src_ports', 'dst_ports', 'methods', 'paths', 'hosts']


def cls_name_to_marker(cls_name):
    if cls_name == 'Z3ProductSet':
        return '+'
    elif cls_name == 'CanonicalHyperCubeSet':
        return 'x'


def get_cls_list():
    return [CanonicalHyperCubeSet, Z3ProductSet]


def config_to_str(config):
    return f'allow_list={config[0]}; deny_list={config[1]}'


def run_experiment(allow_deny_combinations: list[tuple[list[ConnectionAttributes], list[ConnectionAttributes]]]):
    cls_list = get_cls_list()

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

        for cls in get_cls_list():
            creation_times = results['creation'][cls.__name__]['times']
            for i in range(len(results[operation][cls.__name__]['times'])):
                for j in results[operation][cls.__name__]['indices'][i]:
                    results[level_1_key][cls.__name__]['times'][i] += creation_times[j]

    return results


def draw_graphs(results, mode):
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
        file_name = f'{operation}_{mode}.png'
        plt.savefig(file_name)
        plt.clf()


def create_tables(results, allow_deny_combinations, mode):
    for operation, operation_results in results.items():
        rows = []
        z3_results = operation_results['Z3ProductSet']
        canonical_results = operation_results['CanonicalHyperCubeSet']
        assert z3_results['indices'] == canonical_results['indices']

        for i in range(len(z3_results['times'])):
            sub_descriptions = []
            for j in z3_results['indices'][i]:
                allow_list, deny_list = allow_deny_combinations[j]
                sub_descriptions.append(f'<allow_list={allow_list}; deny_list={deny_list}>')
            description = ';'.join(sub_descriptions)

            rows.append({
                'Z3ProductSet_time': z3_results['times'][i],
                'CanonicalHyperCubeSet_time': canonical_results['times'][i],
                'Z3ProductSet_outcome': z3_results['outcomes'][i],
                'CanonicalHyperCubeSet_outcome': canonical_results['outcomes'][i],
                'description': description
            })
        file_name = f'{operation}_{mode}.csv'
        with open(file_name, 'w', newline='') as f:
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


def main():
    # TODO: create a more compact representation for ConnectionAttr, maybe this will make things more clear.
    # TODO: add simple / complex to the title of the plot
    # TODO: I would like to make a random experiment with 1 dim with integers only.
    skip_run = True
    for mode in ['simple', 'complex']:
        logging.info(f'mode={mode}')
        if mode == 'simple':
            connection_attr_list = SIMPLE_CONNECTION_ATTR_LIST
        else:
            connection_attr_list = COMPLEX_CONNECTION_ATTR_LIST
        allow_deny_combinations = list(get_allow_deny_combinations(connection_attr_list))
        # allow_deny_combinations = allow_deny_combinations[:5]  # TODO: comment
        results_file = f'results_{mode}.json'

        if not skip_run:
            results = run_experiment(allow_deny_combinations)
            results = add_creation_times(results)
            with open(results_file, 'w') as f:
                json.dump(results, f)

        with open(results_file, 'r') as f:
            results = json.load(f)

        results = sort_results_by_list_sizes(results, allow_deny_combinations)
        draw_graphs(results, mode)
        create_tables(results, allow_deny_combinations, mode)


if __name__ == '__main__':
    main()
