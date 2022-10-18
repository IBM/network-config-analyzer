"""Comparing Z3SimpleStringSet, Z3RegularStringSet and MinDFA for string sets with general regex constraints.

# TODO: hard-code the basic regular expressions.
#

"""
# TODO: implement and run.
# TODO: add timeout for Z3SimpleStringSet.

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
from smt_experiments.z3_sets.z3_regular_string_set import Z3RegularStringSet
from smt_experiments.z3_sets.z3_simple_string_set import Z3SimpleStringSet

logging.basicConfig(level=logging.INFO)


def run_experiment():
    set_types = [Z3SimpleStringSet, Z3RegularStringSet, MinDFA]
    for cls in set_types:
        # TODO: hard-code the sets and operations.
        regex1 = 'aabb'
        regex2 = '(ab)+'
        regex3 = '(f)?zz(x)*'
        s1 = cls.dfa_from_regex(regex1)
        s2 = cls.dfa_from_regex(regex2)
        s3 = cls.dfa_from_regex(regex3)
    print('done')



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
        'mode',  # key
        'operation',  # key
        'string_set1',  # key
        'string_set2',  # key - default value = ''
        'string',  # key - default value = ''
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

    rows = []  # TODO
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
        results = run_experiment(mode)  # TODO: comment to avoid re-running the experiment
        save_results(results, results_file)  # TODO: comment to avoid re-running the experiment
        results = load_results(results_file)
        for operation in ['creation', 'membership', 'intersection', 'union', 'contained_in']:
            plot_results_per_operation(results, operation, mode)


def get_results_file(mode: str):
    return Path(__file__).with_stem(f'{mode}_results').with_suffix('.json')


if __name__ == '__main__':
    # main()
    # create_csv_table()
    run_experiment()
