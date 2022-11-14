import logging
from csv import DictWriter
from pathlib import Path
from typing import Type

import matplotlib.pyplot as plt
from matplotlib.figure import Figure

from nca.CoreDS.CanonicalHyperCubeSet import CanonicalHyperCubeSet
from nca.CoreDS.CanonicalIntervalSet import CanonicalIntervalSet
from nca.CoreDS.MinDFA import MinDFA
from experiments.experiments.experiment_utils import Timer, get_dimension_names, load_results, \
    get_unique_values_for_key, filter_on_key_value, save_results
from experiments.experiments.multiple_string_dimensions.run_experiment import non_overlapping_cube_generator, \
    init_dim_manager
from z3_sets.z3_integer_set import Z3IntegerSet
from z3_sets.z3_product_set_dnf import Z3ProductSetDNF
from z3_sets.z3_regular_string_set import Z3RegularStringSet

logging.basicConfig(level=logging.INFO)


def convert_cube(cube: list, cls, dim_types: list[Type], dim_names: list[str]):
    if cls == Z3ProductSetDNF:
        interval_cls = Z3IntegerSet
        str_cls = Z3RegularStringSet
    elif cls == CanonicalHyperCubeSet:
        interval_cls = CanonicalIntervalSet
        str_cls = MinDFA
    else:
        raise ValueError

    converted_cube = []
    active_dims = []
    for i, (s, t) in enumerate(zip(cube, dim_types)):
        if s is None:
            continue
        if t == int:
            converted_s = interval_cls.get_interval_set(s[0], s[1])
        else:
            converted_s = str_cls.from_wildcard(s[0]) | str_cls.from_wildcard(s[1])
        converted_cube.append(converted_s)
        active_dims.append(i)

    active_dims = [dim_names[d] for d in active_dims]
    return converted_cube, active_dims


def run_experiment(type_: Type):
    assert type_ in [str, int]
    n_dims_options = [1, 2, 3]
    n_cubes_start = 1
    n_cubes_step = 1
    n_cubes_end = 4
    n_cubes_options = list(range(n_cubes_start, n_cubes_end + 1, n_cubes_step))

    hyper_cube_set_classes = [CanonicalHyperCubeSet, Z3ProductSetDNF]

    results = []
    for n_dims in n_dims_options:
        dim_types = [type_ for _ in range(n_dims)]
        dim_names = get_dimension_names(n_dims)
        init_dim_manager(dim_names, dim_types)

        cubes_generator = non_overlapping_cube_generator(dim_types)
        cubes = [next(cubes_generator) for _ in range(n_cubes_end + 1)]

        for n_cubes in n_cubes_options:
            for cls in hyper_cube_set_classes:
                logging.info(f'n_dims: {n_dims}, n_cubes: {n_cubes}, cls: {cls.__name__}.')

                # creation
                with Timer() as t:
                    s = cls(dim_names)
                    for cube in cubes[:n_cubes]:
                        converted_cube, active_dims = convert_cube(cube, cls, dim_types, dim_names)
                        s.add_cube(converted_cube, active_dims)
                results.append({
                    'n_dims': n_dims,
                    'n_cubes': n_cubes,
                    'class': cls.__name__,
                    'operation': 'creation',
                    'time': t.elapsed_time
                })

                # add cube
                cube_to_add = cubes[n_cubes]
                superset = s.copy()
                with Timer() as t:
                    converted_cube, active_dims = convert_cube(cube_to_add, cls, dim_types, dim_names)
                    superset.add_cube(converted_cube, active_dims)
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
                    converted_cube, active_dims = convert_cube(cube_to_subtract, cls, dim_types, dim_names)
                    subset.add_hole(converted_cube, active_dims)
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

                # This is the check that takes most time with Z3ProductSet.
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

    return results


def save_results_to_csv(results: list[dict], result_csv_file: Path):
    z3_results = filter_on_key_value(results, 'class', 'Z3ProductSetDNF')
    tree_results = filter_on_key_value(results, 'class', 'CanonicalHyperCubeSet')
    assert len(z3_results) == len(tree_results)
    table_rows = []

    for i in range(len(z3_results)):
        z3_res = z3_results[i]
        tree_res = tree_results[i]
        row = z3_res.copy()
        row.pop('time')
        row.pop('class')
        row['Z3ProductSetDNF'] = z3_res['time']
        row['CanonicalHyperCubeSet'] = tree_res['time']
        table_rows.append(row)

    with result_csv_file.open('w', newline='') as f:
        writer = DictWriter(f, table_rows[0].keys())
        writer.writeheader()
        writer.writerows(table_rows)


def plot_result_for_operation(results: list[dict], operation: str, t: Type):
    results_filtered_on_operation = filter_on_key_value(results, 'operation', operation)

    # a new subplot for each value of n_dims
    n_dims_options = get_unique_values_for_key(results_filtered_on_operation, 'n_dims')

    scale = 1.5
    figsize = (6.4 * scale, 4.8 * scale)
    fig, axes = plt.subplots(len(n_dims_options), 1, figsize=figsize)
    fig: Figure
    fig.supxlabel('#cubes')
    if t == int:
        fig.suptitle(f'Effect of #cubes on {operation} time with fixed #dimensions and int cubes')
    else:
        fig.suptitle(f'Effect of #cubes on {operation} time with fixed #dimensions and string cubes')
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

    if t == int:
        stem = f'{operation}_int'
    else:
        stem = f'{operation}_str'

    fig_path = Path(__file__).with_stem(stem).with_suffix('.png')
    fig.savefig(fig_path)


def plot_results(results: list[dict], t: Type):
    operations = get_unique_values_for_key(results, 'operation')
    for operation in operations:
        plot_result_for_operation(results, operation, t)


def run_experiment_and_plot(t: Type):
    results_file = get_results_file(t)
    results = run_experiment(t)  # TODO: uncomment to re-run the experiment
    save_results(results, results_file)  # TODO: uncomment to re-run the experiment
    results = load_results(results_file)
    save_results_to_csv(results, results_file.with_suffix('.csv'))
    plot_results(results, t)


def get_results_file(t: Type):
    if t == int:
        stem = 'results_int'
    else:
        stem = 'results_str'
    results_file = Path(__file__).with_stem(stem).with_suffix('.json')
    return results_file


def main():
    run_experiment_and_plot(int)
    run_experiment_and_plot(str)


if __name__ == '__main__':
    main()
