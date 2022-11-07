"""Description:
Question:
    How n_cubes affects runtime of different operations, when n_dims is fixed,
    and the cubes are non-overlapping?

Experiment Design:
    Fix the value of n_dims to one of {5, 10, 15}, and increase n_cubes from ??? to ??? with steps of ???.
    Then plot 3 graphs, one for each value of n_dims, with the runtime over the n_cubes parameter.

Expectations:
    - The rate of increase will be linear with Z3ProductSet and with the CanonicalHyperCubeSet.
    - The rate of increase will be greater for CanonicalHyperCubeSet when the number of dimensions is greater.
    - With n_dims=5, CanonicalHyperCubeSet will always outperform Z3.
    - With n_dims=15, at the start CanonicalHyperCubeSet will outperform Z3, but at some point, Z3 will outperform
    CanonicalHyperCube.
"""
# TODO: Analyze.
# TODO: Write ideas for more experiments.
# TODO: Maybe use randomly generated (inputs, cubes)?
# TODO: I don't think that we should have `overall time` since we can just add the two figures.
# TODO: add another figure with only the Z3ProductSet times, to look at the increase rate more closely.
# TODO: also consider Z3ProductSetDNF, Try to optimize it. Currently it is much slower than the other two, so I don't
#   place it in same plot (as it dominates the plot).
# TODO: analyze what profile of operations is more efficient with z3 and which is more efficient with
#   CanonicalHyperCubeSet, in terms of different combination of operations.
#   For example, if we have 1 creation followed by 10 contained_in, which engine is more efficient?

import logging
from csv import DictWriter
from pathlib import Path

import matplotlib.pyplot as plt
from matplotlib.axes import Axes
from matplotlib.figure import Figure

from nca.CoreDS.CanonicalHyperCubeSet import CanonicalHyperCubeSet
from nca.CoreDS.CanonicalIntervalSet import CanonicalIntervalSet
from nca.CoreDS.DimensionsManager import DimensionsManager
from experiments.experiments.experiment_utils import Timer, get_dimension_names, load_results, \
    get_unique_values_for_key, filter_on_key_value, save_results
from experiments.experiments.realistic_samples.run_experiment import cls_name_to_marker
from z3_sets.z3_integer_set import Z3IntegerSet
from z3_sets.z3_product_set import Z3ProductSet

logging.basicConfig(level=logging.INFO)
MIN_VALUE = 0
MAX_VALUE = 100_000


def generate_non_overlapping_integer_cubes(n_dims: int, n_cubes: int) -> list[list[tuple[int, int]]]:
    """
    Returns cubes that look like: (for n_dims=2, n_cubes=3)
    [[[0-10], [0-10]], # n_dims=2 so there are 2 columns, n_cubes=3 so there are 3 rows
     [[20-30], [20-30]],
     [[40-50], [40-50]]]
    """
    start = 0
    step = 10
    cubes = []
    for _ in range(n_cubes):
        cube = [(start, start + step) for _ in range(n_dims)]
        cubes.append(cube)
        start = start + 2 * step
    return cubes


def generate_overlapping_integer_cubes(n_dims: int, n_cubes: int) -> list[list[tuple[int, int]]]:
    """
    Returns cubes that look like: (for n_dims=2, n_cubes=4)
    [[[0-10], [20-30], [MIN_VALUE-MAX_VALUE], # n_dims=3 so there are 3 columns, n_cubes=4 so there are 4 rows
     [[MIN_VALUE-MAX_VALUE], [20-30], [40-50]],
     [[60-70], [MIN_VALUE-MAX_VALUE], [40-50]]
     [[60-70], [80-90], [MIN_VALUE-MAX_VALUE]]]

    Each time we have 2 dimensions that are active, those shift right every step.
    """
    assert n_dims >= 3
    assert n_cubes >= 3
    cubes = []
    start = 0
    step = 10
    for i in range(n_cubes):
        cube = [(MIN_VALUE, MAX_VALUE) for _ in range(n_dims)]
        cube[i % n_dims] = (start, start + step)
        cube[(i + 1) % n_dims] = (start + 2 * step, start + 3 * step)
        cubes.append(cube)
        start += 2 * step
    return cubes


def convert_cube(cube: list[tuple[int, int]], cls):
    if cls == Z3ProductSet:
        dim_cls = Z3IntegerSet
    elif cls == CanonicalHyperCubeSet:
        dim_cls = CanonicalIntervalSet
    else:
        raise ValueError

    converted_cube = [dim_cls.get_interval_set(start, end) for start, end in cube]
    return converted_cube


def init_dim_manager(dim_names: list[str]):
    dim_manager = DimensionsManager()
    for dim_name in dim_names:
        dim_manager.set_domain(dim_name, DimensionsManager.DimensionType.IntervalSet, (MIN_VALUE, MAX_VALUE))


def get_member(cubes: list[list[tuple[int, int]]]) -> list[int]:
    i = len(cubes) // 2
    cube = cubes[i]
    member = [(start + end) // 2 for start, end in cube]
    return member


def get_not_member(cubes: list[list[tuple[int, int]]]) -> list[int]:
    mid_cube = cubes[len(cubes) // 2]
    not_member = []
    for start, end in mid_cube:
        if start == MIN_VALUE and end == MAX_VALUE:
            entry = (MAX_VALUE + MIN_VALUE) // 2
        elif end == MAX_VALUE:
            entry = start - 1
        else:
            entry = end + 1
        not_member.append(entry)
    return not_member


def run_experiment_aux(overlapping: bool, n_dims: int, n_cubes_start: int, n_cubes_end: int, n_cubes_step: int):
    results = []
    if overlapping:
        cubes = generate_overlapping_integer_cubes(n_dims, n_cubes_end + 1)  # I add one for the containment test
    else:
        cubes = generate_non_overlapping_integer_cubes(n_dims, n_cubes_end + 1)

    dim_names = get_dimension_names(n_dims)
    init_dim_manager(dim_names)

    for n_cubes in range(n_cubes_start, n_cubes_end + 1, n_cubes_step):
        cubes_subset = cubes[:n_cubes]
        for cls in [CanonicalHyperCubeSet, Z3ProductSet]:
            logging.info(f'n_dims: {n_dims}, n_cubes: {n_cubes}, cls: {cls.__name__}.')
            # TODO: add times for creation + containment
            # creation
            with Timer() as t:
                converted_cubes = [convert_cube(cube, cls) for cube in cubes_subset]
                s = cls(dim_names)
                for converted_cube in converted_cubes:
                    s.add_cube(converted_cube)
            s_creation_time = t.elapsed_time
            results.append({
                'n_dims': n_dims,
                'n_cubes': n_cubes,
                'class': cls.__name__,
                'operation': 'creation',
                'time': s_creation_time
            })

            # membership test
            member = get_member(cubes_subset)
            with Timer() as t:
                out = member in s
            assert out
            results.append({
                'n_dims': n_dims,
                'n_cubes': n_cubes,
                'class': cls.__name__,
                'operation': 'membership_test',
                'time': t.elapsed_time,
            })

            not_member = get_not_member(cubes_subset)
            with Timer() as t:
                out = not_member in s
            assert not out
            results.append({
                'n_dims': n_dims,
                'n_cubes': n_cubes,
                'class': cls.__name__,
                'operation': 'membership_test',
                'time': t.elapsed_time,
            })

            # add cube
            cube_to_add = cubes[n_cubes]
            superset = s.copy()
            with Timer() as t:
                converted_cube = convert_cube(cube_to_add, cls)
                superset.add_cube(converted_cube)
            superset_creation_time = s_creation_time + t.elapsed_time
            results.append({
                'n_dims': n_dims,
                'n_cubes': n_cubes,
                'class': cls.__name__,
                'operation': 'add_cube',
                'time': t.elapsed_time,
            })

            # add hole
            cube_to_subtract = cubes[n_cubes // 2]
            subset = s.copy()
            with Timer() as t:
                converted_cube = convert_cube(cube_to_subtract, cls)
                subset.add_hole(converted_cube)
            subset_creation_time = s_creation_time + t.elapsed_time
            results.append({
                'n_dims': n_dims,
                'n_cubes': n_cubes,
                'class': cls.__name__,
                'operation': 'add_hole',
                'time': t.elapsed_time,
            })

            # containment
            with Timer() as t:
                out = subset.contained_in(s)
            assert out
            results.append({
                'n_dims': n_dims,
                'n_cubes': n_cubes,
                'class': cls.__name__,
                'operation': 'contained_in',
                'time': t.elapsed_time,
            })
            results.append({
                'n_dims': n_dims,
                'n_cubes': n_cubes,
                'class': cls.__name__,
                'operation': 'contained_in+creation',
                'time': t.elapsed_time + subset_creation_time + s_creation_time
            })

            with Timer() as t:
                out = s.contained_in(subset)
            assert not out
            results.append({
                'n_dims': n_dims,
                'n_cubes': n_cubes,
                'class': cls.__name__,
                'operation': 'contained_in',
                'time': t.elapsed_time,
            })
            results.append({
                'n_dims': n_dims,
                'n_cubes': n_cubes,
                'class': cls.__name__,
                'operation': 'contained_in+creation',
                'time': t.elapsed_time + subset_creation_time + s_creation_time
            })

            with Timer() as t:
                out = superset.contained_in(s)
            assert not out
            results.append({
                'n_dims': n_dims,
                'n_cubes': n_cubes,
                'class': cls.__name__,
                'operation': 'contained_in',
                'time': t.elapsed_time,
            })
            results.append({
                'n_dims': n_dims,
                'n_cubes': n_cubes,
                'class': cls.__name__,
                'operation': 'contained_in+creation',
                'time': t.elapsed_time + superset_creation_time + s_creation_time
            })

            with Timer() as t:
                out = s.contained_in(superset)
            assert out
            results.append({
                'n_dims': n_dims,
                'n_cubes': n_cubes,
                'class': cls.__name__,
                'operation': 'contained_in',
                'time': t.elapsed_time,
            })
            results.append({
                'n_dims': n_dims,
                'n_cubes': n_cubes,
                'class': cls.__name__,
                'operation': 'contained_in+creation',
                'time': t.elapsed_time + subset_creation_time + s_creation_time
            })
    return results


def run_experiment(overlapping: bool):
    n_dims_options = [5, 10, 15]
    n_cubes_start = 3
    n_cubes_step = 3
    if overlapping:
        n_cubes_end = 24
    else:
        n_cubes_end = 150

    results = []
    for n_dims in n_dims_options:
        results += run_experiment_aux(overlapping, n_dims, n_cubes_start, n_cubes_end, n_cubes_step)

    return results


def plot_result_for_operation(results: list[dict], operation: str, overlapping: bool):
    results_filtered_on_operation = filter_on_key_value(results, 'operation', operation)

    # a new subplot for each value of n_dims
    n_dims_options = get_unique_values_for_key(results_filtered_on_operation, 'n_dims')

    scale = 1.5
    figsize = (6.4 * scale, 4.8 * scale)
    fig, axes = plt.subplots(len(n_dims_options), 1, figsize=figsize)
    fig: Figure
    fig.supxlabel('#cubes')
    if overlapping:
        fig.suptitle(f'Effect of #cubes on {operation} time with fixed #dimensions and overlapping cubes')
    else:
        fig.suptitle(f'Effect of #cubes on {operation} time with fixed #dimensions and non-overlapping cubes')
    fig.supylabel(f'{operation} time [sec]')
    fig.subplots_adjust(hspace=0.4)
    markers = ['x', '+', '1']

    for ax, n_dims in zip(axes, n_dims_options):
        results_filtered_on_operation_and_n_dims = filter_on_key_value(results_filtered_on_operation, 'n_dims', n_dims)
        cls_names = get_unique_values_for_key(results_filtered_on_operation_and_n_dims, 'class')

        for cls_index, cls_name in enumerate(cls_names):
            results_filtered_on_operation_and_n_dims_and_cls = filter_on_key_value(
                results_filtered_on_operation_and_n_dims,
                'class',
                cls_name
            )
            n_cubes = []
            operation_times = []
            for result in results_filtered_on_operation_and_n_dims_and_cls:
                n_cubes.append(result['n_cubes'])
                operation_times.append(result['time'])

            ax.scatter(n_cubes, operation_times, label=cls_name, alpha=0.5, marker=markers[cls_index])

        ax.set_title(f'#dims = {n_dims}')
        ax.legend()

    if overlapping:
        stem = f'{operation}_overlapping'
    else:
        stem = f'{operation}_non_overlapping'

    fig_path = Path(__file__).with_stem(stem).with_suffix('.png')
    fig.savefig(fig_path)


def save_results_to_csv(results: list[dict], result_csv_file: Path):
    z3_results = filter_on_key_value(results, 'class', 'Z3ProductSet')
    tree_results = filter_on_key_value(results, 'class', 'CanonicalHyperCubeSet')
    assert len(z3_results) == len(tree_results)
    table_rows = []

    for i in range(len(z3_results)):
        z3_res = z3_results[i]
        tree_res = tree_results[i]
        row = z3_res.copy()
        row.pop('time')
        row.pop('class')
        row['Z3ProductSet'] = z3_res['time']
        row['CanonicalHyperCubeSet'] = tree_res['time']
        table_rows.append(row)

    with result_csv_file.open('w', newline='') as f:
        writer = DictWriter(f, table_rows[0].keys())
        writer.writeheader()
        writer.writerows(table_rows)


def plot_results(results: list[dict], overlapping: bool):
    operations = get_unique_values_for_key(results, 'operation')
    for operation in operations:
        plot_result_for_operation(results, operation, overlapping)


def run_experiment_and_plot(overlapping: bool):
    skip_run = True
    if overlapping:
        stem = 'results_overlapping'
    else:
        stem = 'results_non_overlapping'
    results_file = Path(__file__).with_stem(stem).with_suffix('.json')

    if not skip_run:
        results = run_experiment(overlapping)
        save_results(results, results_file)

    results = load_results(results_file)
    save_results_to_csv(results, results_file.with_suffix('.csv'))
    plot_results(results, overlapping)


def main():
    for overlapping in [False, True]:
        run_experiment_and_plot(overlapping)


def plot_ax(ax, data):
    ax: Axes
    data = filter_on_key_value(data, 'operation', 'contained_in+creation')
    for cls_name in get_unique_values_for_key(data, 'class'):
        cls_data = filter_on_key_value(data, 'class', cls_name)
        n_cubes_list = [d['n_cubes'] for d in cls_data]
        time_list = [d['time'] for d in cls_data]
        marker = cls_name_to_marker(cls_name)
        ax.scatter(n_cubes_list, time_list, marker=marker, alpha=0.5, label=cls_name)
    ax.legend()


def generate_graphs_for_presentation():
    n_dims = 5
    n_cubes_start = 2
    n_cubes_step = 2
    n_cubes_end = 50

    non_overlapping_results = run_experiment_aux(False, n_dims, n_cubes_start, n_cubes_end, n_cubes_step)
    overlapping_results = run_experiment_aux(True, n_dims, n_cubes_start, n_cubes_end, n_cubes_step)

    fig, (non_overlapping_ax, overlapping_ax) = plt.subplots(1, 2)
    fig: Figure
    non_overlapping_ax: Axes
    overlapping_ax: Axes

    non_overlapping_ax.set_title('Non-Overlapping')
    overlapping_ax.set_title('Overlapping')
    # fig.suptitle('Containment + Creation Times with 5 Integer Dimensions')
    fig.supylabel('contained_in+creation time [seconds]')
    fig.supxlabel('#cubes')
    fig.set_size_inches(w=12, h=4.8)

    plot_ax(non_overlapping_ax, non_overlapping_results)
    plot_ax(overlapping_ax, overlapping_results)
    fig.savefig('presentation_graph.png')


if __name__ == '__main__':
    generate_graphs_for_presentation()
