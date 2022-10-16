"""Comparing Z3SimpleStringSet and MinDFA for string sets with equality, prefix and suffix constraints.
I only consider constant, prefix, and prefix + suffix, because we know from previous experiments that those are the
interesting cases.

Question:
- How does Z3SimpleStringSet compare to MinDFA when the string constraints are exact string match, prefix, or
prefix + suffix?
- How does the number of constraints affect the performance?

Sketch:
- The alpha-bet is going to be lower-case english letters.
- fix the random seed.
- Generate a set of strings of varying length.
    - Each time sample a letter, and with some probability, this could be end-of-string letter.
- Randomly sample subsets of those, with varying lengths.
- We can know what the ground truth is supposed to be since we can use python's set implementation.
- Measure creation time, membership test, containment, union, intersection, (negation is not yet tested).
- Save the inputs for each operation for farther analysis.
- Plot the time per-operation over the number of strings. [It is not clear how to plot this when we have two sets]
- repeat for prefix and prefix + suffix constraints by adding '*' at the start and end of the strings.

Expectations:
- I expect that MinDFA will increase more rapidly with complexity, I think it is going to be linear increase.
Especially creation time. Also, Z3SimpleStringSet will show a linear increase in time.
- The content of the strings will affect MinDFA more than Z3SimpleStringSet,
since it affects the underlying automata construction.
- using prefix will increase the advantage that Z3 has on MinDFA.
- using prefix + suffix will increase the advantage even more.

List of operations to compare:
- Construction
- Membership test
- Set containment test
- Intersection
- Union
"""
# TODO: add an experiment with regex.

import itertools
import logging
import random
import string
from collections import defaultdict
from csv import DictWriter
from pathlib import Path

from matplotlib import pyplot as plt
from matplotlib.figure import Figure

from nca.CoreDS.MinDFA import MinDFA
from smt_experiments.experiments.experiment_utils import Timer, save_results, load_results, filter_on_key_value, \
    get_unique_values_for_key
from smt_experiments.z3_sets.z3_simple_string_set import Z3SimpleStringSet

random.seed(42)
logging.basicConfig(level=logging.INFO)


def generate_random_string(alphabet: list[str], stop_probability: float) -> str:
    assert 0 < stop_probability < 1
    s = ''
    while random.random() >= stop_probability:
        s += random.choice(alphabet)
    return s


def run_experiment(mode: str):
    assert mode in ['constant', 'prefix', 'prefix_and_suffix']
    alphabet = list(string.ascii_lowercase)
    n_strings = 100
    stop_prob = 0.1
    size_start = 2
    size_end = 20
    size_step = 2
    n_sets_per_size = 10
    n_str_for_membership = 5
    n_pairs = 100
    set_types = [Z3SimpleStringSet, MinDFA]

    random_strings = set()
    while len(random_strings) < n_strings:
        random_strings.add(generate_random_string(alphabet, stop_prob))

    random_strings = list(random_strings)
    membership_sample = random.sample(random_strings, n_str_for_membership)

    if mode == 'prefix':
        random_strings = [s + '*' for s in random_strings]
    if mode == 'prefix_and_suffix':
        new_random_strings = []
        for i, s in enumerate(random_strings):
            if i % 2 == 0:
                s = s + '*'
            else:
                s = '*' + s
            new_random_strings.append(s)
        random_strings = new_random_strings

    # generate subsets of changing lengths
    set_of_sets = set()
    for set_size in range(size_start, size_end + 1, size_step):
        initial_size = len(set_of_sets)
        while len(set_of_sets) < initial_size + n_sets_per_size:
            s = frozenset(random.sample(random_strings, k=set_size))
            set_of_sets.add(s)

    results = []
    sets_of_all_types = []

    # compute the creation time
    for i, string_set in enumerate(set_of_sets, 1):
        logging.info(f'{i} out of {len(set_of_sets)} in mode={mode}')
        set_of_all_type = {'frozenset': string_set}

        results_check = {}
        for set_type in set_types:
            # creation time
            with Timer() as t:
                s = None
                for s0 in string_set:
                    if s is None:
                        s = set_type.from_wildcard(s0)
                    else:
                        s = s | set_type.from_wildcard(s0)
            set_of_all_type[set_type] = s
            results.append({
                'class': set_type.__name__,
                'time': t.elapsed_time,
                'string_set': list(string_set),
                'operation': 'creation',
            })

            # membership
            for s0 in membership_sample:
                with Timer() as t:
                    out = s0 in s
                if mode == 'constant':
                    assert (s0 in string_set) == out
                else:
                    if set_type == set_types[0]:
                        results_check[s0] = out
                    else:
                        assert results_check[s0] == out

                results.append({
                    'class': set_type.__name__,
                    'time': t.elapsed_time,
                    'string_set': list(string_set),
                    'string': s0,
                    'operation': 'membership',
                })

            sets_of_all_types.append(set_of_all_type)

    # select pairs of sets, and compute their intersection, union, and containment test
    pairs_of_sets = list(itertools.combinations(sets_of_all_types, 2))
    pairs_of_sets = random.sample(pairs_of_sets, n_pairs)
    for i, (all_types_of_set1, all_types_of_set2) in enumerate(pairs_of_sets, 1):
        logging.info(f'pair {i} out of {len(pairs_of_sets)} in mode={mode}')
        gt_set1 = all_types_of_set1['frozenset']
        gt_set2 = all_types_of_set2['frozenset']
        gt_intersection_set = gt_set1 & gt_set2
        gt_union_set = gt_set1 | gt_set2

        results_check1, results_check2 = {}, {}
        for set_type in set_types:
            set1 = all_types_of_set1[set_type]
            set2 = all_types_of_set2[set_type]

            # intersection
            with Timer() as t:
                intersection_set = set1 & set2
            results.append({
                'class': set_type.__name__,
                'time': t.elapsed_time,
                'string_set1': list(gt_set1),
                'string_set2': list(gt_set2),
                'operation': 'intersection',
            })

            # union
            with Timer() as t:
                union_set = set1 | set2
            results.append({
                'class': set_type.__name__,
                'time': t.elapsed_time,
                'string_set1': list(gt_set1),
                'string_set2': list(gt_set2),
                'operation': 'union',
            })

            # containment
            with Timer() as t:
                out = set1.contained_in(set2)
            if mode == 'constant':
                assert out == (gt_set1.issubset(gt_set2))
            else:
                if set_type == set_types[0]:
                    results_check1[(gt_set1, gt_set2)] = out
                else:
                    assert results_check1[(gt_set1, gt_set2)] == out
            results.append({
                'class': set_type.__name__,
                'time': t.elapsed_time,
                'string_set1': list(gt_set1),
                'string_set2': list(gt_set2),
                'operation': 'contained_in',
            })
            with Timer() as t:
                out = set2.contained_in(set1)
            if mode == 'constant':
                assert out == (gt_set2.issubset(gt_set1))
            else:
                if set_type == set_types[0]:
                    results_check2[(gt_set1, gt_set2)] = out
                else:
                    assert results_check2[(gt_set1, gt_set2)] == out
            results.append({
                'class': set_type.__name__,
                'time': t.elapsed_time,
                'string_set1': list(gt_set2),
                'string_set2': list(gt_set1),
                'operation': 'contained_in',
            })
            with Timer() as t:
                out = intersection_set.contained_in(set2)
            assert out
            results.append({
                'class': set_type.__name__,
                'time': t.elapsed_time,
                'string_set1': list(gt_intersection_set),
                'string_set2': list(gt_set2),
                'operation': 'contained_in',
            })
            with Timer() as t:
                out = set1.contained_in(union_set)
            assert out
            results.append({
                'class': set_type.__name__,
                'time': t.elapsed_time,
                'string_set1': list(gt_set1),
                'string_set2': list(gt_union_set),
                'operation': 'contained_in',
            })

    return results


def plot_results_per_operation(results: list[dict], operation: str, mode: str):
    """
    x variable is the number of elements in the set.
    y variable is the time of the operation.
    """
    results_filtered_on_operation = filter_on_key_value(results, 'operation', operation)
    scale = 1.5
    figsize = (6.4 * scale, 4.8 * scale)
    fig, ax = plt.subplots(1, 1, figsize=figsize)
    fig: Figure
    fig.supxlabel('set size')
    fig.suptitle(f'{operation} time over set size')
    fig.supylabel(f'{operation} time [sec]')
    fig.subplots_adjust(hspace=0.4)

    markers = ['x', '+', '1']

    cls_names = get_unique_values_for_key(results_filtered_on_operation, 'class')

    for cls_index, cls_name in enumerate(cls_names):
        results_filtered_on_operation_and_cls = filter_on_key_value(results_filtered_on_operation, 'class', cls_name)
        set_sizes = []
        operation_times = []
        for result in results_filtered_on_operation_and_cls:
            if 'string_set1' in result and 'string_set2' in result:
                size = len(result['string_set1']) + len(result['string_set2'])
            else:
                size = len(result['string_set'])
            set_sizes.append(size)
            operation_times.append(result['time'])

        ax.scatter(set_sizes, operation_times, label=cls_name, alpha=0.5, marker=markers[cls_index])

    ax.legend()

    # plt.show()  # TODO: comment
    fig_path = Path(__file__).with_stem(f'{mode}_{operation}').with_suffix('.png')
    fig.savefig(fig_path)


def create_csv_table():
    all_results = []
    for mode in ['constant', 'prefix', 'prefix_and_suffix']:
        result_file = get_results_file(mode)
        results = load_results(result_file)
        for result in results:
            result['mode'] = mode
        all_results += results

    field_names = [
        'mode',         # key
        'operation',    # key
        'string_set1',  # key
        'string_set2',  # key - default value = ''
        'string',       # key - default value = ''
        'MinDFA',
        'Z3SimpleStringSet'
    ]
    table = defaultdict(dict)
    for result in all_results:
        mode = result['mode']
        operation = result['operation']
        string_set1 = frozenset(result.get('string_set', result.get('string_set1')))
        string_set2 = frozenset(result.get('string_set2', []))
        string = result.get('string', '')

        key = (mode, operation, string_set1, string_set2, string)
        table[key][result['class']] = result['time']

    rows = []   # TODO
    for key, value in table.items():
        mode, operation, string_set1, string_set2, string = key
        row = {
            'mode': mode,
            'operation': operation,
            'string_set1': list(string_set1),
            'string_set2': list(string_set2),
            'string': string,
            'MinDFA': value['MinDFA'],
            'Z3SimpleStringSet': value['Z3SimpleStringSet']
        }
        rows.append(row)

    csv_file = Path(__file__).with_stem('table').with_suffix('.csv')
    with csv_file.open('w', newline='') as f:
        writer = DictWriter(f, field_names)
        writer.writeheader()
        writer.writerows(rows)


def main():
    # for mode in ['constant']:
    for mode in ['constant', 'prefix', 'prefix_and_suffix']:
        results_file = get_results_file(mode)
        results = run_experiment(mode)          # TODO: comment to avoid re-running the experiment
        save_results(results, results_file)     # TODO: comment to avoid re-running the experiment
        results = load_results(results_file)
        for operation in ['creation', 'membership', 'intersection', 'union', 'contained_in']:
            plot_results_per_operation(results, operation, mode)


def get_results_file(mode: str):
    return Path(__file__).with_stem(f'{mode}_results').with_suffix('.json')


if __name__ == '__main__':
    # main()
    create_csv_table()

