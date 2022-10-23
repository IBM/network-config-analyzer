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
import itertools
import json
import logging
from csv import DictWriter

from matplotlib import pyplot as plt

from nca.CoreDS.CanonicalHyperCubeSet import CanonicalHyperCubeSet
from smt_experiments.experiments.experiment_utils import Timer
from smt_experiments.experiments.realistic_samples.create_connection_set_combinations import get_allow_deny_combinations
from smt_experiments.z3_sets.z3_product_set import Z3ProductSet

logging.basicConfig(level=logging.INFO)


def get_all_dims():
    return ['src_ports', 'dst_ports', 'methods', 'paths', 'hosts']


def config_to_str(config):
    return f'allow_list={config[0]}; deny_list={config[1]}'


def run_experiment():
    cls_list = [CanonicalHyperCubeSet, Z3ProductSet]
    # a `configuration` is an allow_list and a deny_list of connection attributes.
    config_list = list(get_allow_deny_combinations())
    all_dims = get_all_dims()

    creation_and_emptiness_results = {cls.__name__: [] for cls in cls_list}
    equivalence_results = {cls.__name__: [] for cls in cls_list}
    contained_in_results = {cls.__name__: [] for cls in cls_list}

    for cls in cls_list:
        # first part - for each of configuration, create a hyper-cube and check emptiness.
        hyper_cube_set_list = []
        for i, config in enumerate(config_list, 1):
            logging.info(f'cls={cls.__name__}, creation and emptiness check {i} out of {len(config_list)}')
            with Timer() as t:
                allow_list, deny_list = config
                hyper_cube_set = cls(all_dims)
                for connection_attr in allow_list:
                    cube, dims = connection_attr.to_cube(cls)
                    hyper_cube_set.add_cube(cube, dims)
                for connection_attr in deny_list:
                    cube, dims = connection_attr.to_cube(cls)
                    hyper_cube_set.add_hole(cube, dims)
                is_empty = bool(hyper_cube_set)
                hyper_cube_set_list.append(hyper_cube_set)

            creation_and_emptiness_results[cls.__name__].append({
                'value': is_empty,
                'time': t.elapsed_time,
                'descriptor': config_to_str(config)
            })

        def config_pair_to_str(config_i1, config_i2):
            return f'config1=<{config_to_str(config_list[config_i1])}>;' \
                   f'config2=<{config_to_str(config_list[config_i2])}>'

        # second part - for each of configuration pair, check containment in both directions, and equivalence.
        all_pairs = list(itertools.combinations(range(len(hyper_cube_set_list)), 2))
        for i, (j1, j2) in enumerate(all_pairs, 1):
            hyper_cube_set_1, hyper_cube_set_2 = hyper_cube_set_list[j1], hyper_cube_set_list[j2]
            logging.info(f'cls={cls.__name__}, equivalence check {i} out of {len(all_pairs)}')
            with Timer() as t:
                are_equivalent = hyper_cube_set_1 == hyper_cube_set_2

            equivalence_results[cls.__name__].append({
                'value': are_equivalent,
                'time': t.elapsed_time,
                'descriptor': config_pair_to_str(j1, j2)
            })

            logging.info(f'cls={cls.__name__}, containment check {i} out of {len(all_pairs)}')
            with Timer() as t:
                contained_in_1_2 = hyper_cube_set_1.contained_in(hyper_cube_set_2)
            contained_in_results[cls.__name__].append({
                'value': contained_in_1_2,
                'time': t.elapsed_time,
                'descriptor': config_pair_to_str(j1, j2)
            })
            with Timer() as t:
                contained_in_2_1 = hyper_cube_set_2.contained_in(hyper_cube_set_1)
            contained_in_results[cls.__name__].append({
                'value': contained_in_2_1,
                'time': t.elapsed_time,
                'descriptor': config_pair_to_str(j2, j1)
            })

    return creation_and_emptiness_results, equivalence_results, contained_in_results


def check_results(results: dict[str, list[dict]]):
    results1 = results['CanonicalHyperCubeSet']
    results2 = results['Z3ProductSet']
    for v1, v2 in zip(results1, results2):
        assert v1['value'] == v2['value']


def draw_graph(data: dict[str, list[dict]], name: str):
    z3_times = [r['time'] for r in data['Z3ProductSet']]
    canonical_times = [r['time'] for r in data['CanonicalHyperCubeSet']]

    plt.clf()
    plt.title(name)
    plt.xlabel('sample id')
    plt.ylabel('time [seconds]')

    assert len(canonical_times) == len(z3_times)
    x = [i for i in range(len(canonical_times))]
    plt.scatter(x, canonical_times, marker='x', alpha=0.5, label='CanonicalHyperCubeSet')
    plt.scatter(x, z3_times, marker='+', alpha=0.5, label='Z3ProductSet')
    plt.legend()
    plt.savefig(name + '.png')


def save_results_to_csv(data: dict[str, list[dict]], name: str):
    z3_data = data['Z3ProductSet']
    canonical_data = data['CanonicalHyperCubeSet']
    assert len(z3_data) == len(canonical_data)
    rows = []
    for i in range(len(z3_data)):
        assert z3_data[i]['descriptor'] == canonical_data[i]['descriptor']
        rows.append({
            'Z3ProductSet': z3_data[i]['time'],
            'CanonicalHyperCubeSet': canonical_data[i]['time'],
            'descriptor': z3_data[i]['descriptor']
        })

    with open(name + '.csv', 'w', newline='') as f:
        writer = DictWriter(f, fieldnames=['Z3ProductSet', 'CanonicalHyperCubeSet', 'descriptor'])
        writer.writeheader()
        writer.writerows(rows)


def save_results(data, category: str):
    with open(category + '_results.json', 'w') as f:
        json.dump(data, f)


def load_results(category: str):
    with open(category + '_results.json', 'r') as f:
        return json.load(f)


def main():
    skip_run = False
    skip_check = True
    if not skip_run:
        creation_and_emptiness_results, equivalence_results, contained_in_results = run_experiment()
        save_results(creation_and_emptiness_results, 'creation_and_emptiness')
        save_results(equivalence_results, 'equivalence')
        save_results(contained_in_results, 'contained_in')

    creation_and_emptiness_results = load_results('creation_and_emptiness')
    equivalence_results = load_results('equivalence')
    contained_in_results = load_results('contained_in')

    # check that the results align
    if not skip_check:
        check_results(creation_and_emptiness_results)
        check_results(equivalence_results)
        check_results(contained_in_results)

    draw_graph(creation_and_emptiness_results, 'creation_and_emptiness')
    draw_graph(equivalence_results, 'equivalence')
    draw_graph(contained_in_results, 'contained_in')

    save_results_to_csv(creation_and_emptiness_results, 'creation_and_emptiness')
    save_results_to_csv(equivalence_results, 'equivalence')
    save_results_to_csv(contained_in_results, 'contained_in')


if __name__ == '__main__':
    main()
