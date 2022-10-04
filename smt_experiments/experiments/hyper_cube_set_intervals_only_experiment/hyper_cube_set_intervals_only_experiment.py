"""Description:
Question:
    How n_cubes affects runtime (creation + containment), when the n_dims is fixed,
    and the cubes are non-overlapping.

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
# TODO: add another figure with membership test time.
# TODO: add another figure with containment test time.
# TODO: Analyze.
# TODO: Write ideas for more experiments.
# TODO: maybe use randomly generated (inputs, cubes)?
# TODO: I don't think that we should have `overall time` since we can just add the two figures.
# TODO: add another figure with only the Z3ProductSet times, to look at the increase rate more closely.
# TODO: also consider Z3ProductSetDNF, maybe try to optimize it.


import json
import logging
from collections import defaultdict
from pathlib import Path

import matplotlib.pyplot as plt
from matplotlib.axes import Axes
from matplotlib.figure import Figure

from nca.CoreDS.CanonicalHyperCubeSet import CanonicalHyperCubeSet
from nca.CoreDS.CanonicalIntervalSet import CanonicalIntervalSet
from nca.CoreDS.DimensionsManager import DimensionsManager
from smt_experiments.old_experiments.experiment_utils import Timer
from smt_experiments.z3_sets.z3_integer_set import Z3IntegerSet
from smt_experiments.z3_sets.z3_product_set import Z3ProductSet
from smt_experiments.z3_sets.z3_product_set_dnf import Z3ProductSetDNF


logging.basicConfig(level=logging.INFO)


def generate_non_overlapping_integer_cubes(n_dims: int, n_cubes: int) -> list[list[tuple[int, int]]]:
    # TODO: I think that this function is clear enough, and I don't need to save this output to a file. Ask Adi.
    start = 0
    step = 10
    cubes = []
    for _ in range(n_cubes):
        cube = [(start, start + step) for _ in range(n_dims)]
        cubes.append(cube)
        start = start + 2 * step
    return cubes


def convert_cubes_aux(cubes: list[list[tuple[int, int]]], cls):
    converted_cubes = []
    for cube in cubes:
        converted_cube = [cls.get_interval_set(start, end) for start, end in cube]
        converted_cubes.append(converted_cube)
    return converted_cubes


def convert_cubes_to_canonical_interval_set(cubes: list[list[tuple[int, int]]]) -> list[list[CanonicalIntervalSet]]:
    return convert_cubes_aux(cubes, CanonicalIntervalSet)


def convert_cubes_to_z3_integer_set(cubes: list[list[tuple[int, int]]]) -> list[list[Z3IntegerSet]]:
    return convert_cubes_aux(cubes, Z3IntegerSet)


def get_dimension_names(n_dims: int) -> list[str]:
    return [str(i) for i in range(n_dims)]


def init_dim_manager(dim_names: list[str]):
    dim_manager = DimensionsManager()
    for dim_name in dim_names:
        dim_manager.set_domain(dim_name, DimensionsManager.DimensionType.IntervalSet, (0, 100000))


def get_member(cubes: list[list[tuple[int, int]]]) -> list[int]:
    i = len(cubes) // 2
    cube = cubes[i]
    member = [(start + end) // 2 for start, end in cube]
    return member


def get_not_member(cubes: list[list[tuple[int, int]]]) -> list[int]:
    not_member = get_member(cubes)
    # assumes that cubes are not touching
    not_member[-1] += 1
    return not_member


def run_experiment():
    # TODO: convert the result to a list of dictionaries, and filter the list accordingly. I have this implemented in
    #   run_experiment.
    n_dims_options = [5, 10, 15]
    n_cubes_start = 2
    n_cubes_step = 2
    # n_cubes_end = 150    # TODO: uncomment this
    n_cubes_end = 30    # for running quickly TODO: comment this

    n_cubes_options = list(range(n_cubes_start, n_cubes_end + 1, n_cubes_step))
    # hyper_cube_set_classes = [CanonicalHyperCubeSet, Z3ProductSet, Z3ProductSetDNF]
    hyper_cube_set_classes = [CanonicalHyperCubeSet, Z3ProductSet]
    results = []

    for n_dims in n_dims_options:
        cubes = generate_non_overlapping_integer_cubes(n_dims, n_cubes_end + 1)  # I add one for the containment test

        dim_names = get_dimension_names(n_dims)
        init_dim_manager(dim_names)

        for n_cubes in n_cubes_options:
            cubes_subset = cubes[:n_cubes]

            for cls in hyper_cube_set_classes:
                logging.info(f'n_dims: {n_dims}, n_cubes: {n_cubes}, cls: {cls.__name__}.')

                with Timer() as t:
                    if cls == CanonicalHyperCubeSet:
                        converted_cubes = convert_cubes_to_canonical_interval_set(cubes_subset)
                    else:
                        converted_cubes = convert_cubes_to_z3_integer_set(cubes_subset)
                    s = cls(dim_names)
                    for converted_cube in converted_cubes:
                        s.add_cube(converted_cube)

                results.append({
                    'n_dims': n_dims,
                    'n_cubes': n_cubes,
                    'class': cls.__name__,
                    'operation': 'creation',
                    'time': t.elapsed_time
                })

                member = get_member(cubes_subset)
                with Timer() as t:
                    out = member in s

                results.append({
                    'n_dims': n_dims,
                    'n_cubes': n_cubes,
                    'class': cls.__name__,
                    'operation': 'membership test',
                    'time': t.elapsed_time,
                })

                not_member = get_not_member(cubes_subset)
                with Timer() as t:
                    out = not_member in s

                results.append({
                    'n_dims': n_dims,
                    'n_cubes': n_cubes,
                    'class': cls.__name__,
                    'operation': 'membership test',
                    'time': t.elapsed_time,
                })

                # TODO: I can also time the add_hole operation.
                # TODO: add timing for containment test (I can do that by subtracting a cube or adding a new cube)

    return results


def save_dict(data: dict, file: Path):
    with file.open('w') as f:
        json.dump(data, f, indent=4)


def load_dict(file: Path) -> dict:
    with file.open('r') as f:
        return json.load(f)


def get_unique_values_for_key(data: list[dict], key: str) -> list[dict]:
    return sorted(set(x[key] for x in data))


def filter_on_key_value(data: list[dict], key: str, value) -> list[dict]:
    return [x for x in data if x[key] == value]


def plot_results(results: list[dict]):
    # TODO: convert the result to a list of dictionaries, and filter the list accordingly. I have this implemented in
    #   run_experiment.
    # TODO: refactor this to support creation, membership, add_hole, containment.
    # TODO: I broke this, need to review.
    scale = 1.5
    figsize = (6.4 * scale, 4.8 * scale)
    # fig, axes = plt.subplots(1, len(results), figsize=figsize)
    fig, axes = plt.subplots(len(results), 1, figsize=figsize)
    fig: Figure
    fig.supxlabel('#cubes')
    # fig.align_labels()
    fig.suptitle('Effect of #cubes on creation time with fixed #dimensions and non-overlapping cubes')
    fig.supylabel('creation time [sec]')
    fig.subplots_adjust(hspace=0.4)
    # fig.tight_layout()

    # now, we only plot the 'creation' results
    results = filter_on_key_value(results, 'operation', 'creation')
    n_dims_options = get_unique_values_for_key(results, 'n_dims')

    for i, n_dims in enumerate(n_dims_options):
        n_dims_results = filter_on_key_value(results, 'n_dims', n_dims)
        n_cubes_values_per_cls = defaultdict(list)
        creation_times_per_cls = defaultdict(list)
        class_names = get_unique_values_for_key(results, 'class')
        for class_name in class_names:
            for result in filter_on_key_value(n_dims_results, 'class', class_name):
                n_cubes_values_per_cls[class_name].append(result['n_cubes'])
                creation_times_per_cls[class_name].append(result['time'])

        ax: Axes = axes[i]
        ax.set_title(f'#dims = {n_dims}')
        for cls_name, creation_times in creation_times_per_cls.items():
            ax.scatter(n_cubes_values_per_cls[cls_name], creation_times, label=cls_name)
        ax.legend()

    # This snippet is for creating a single legend for the entire figure.
    # handles, labels = fig.gca().get_legend_handles_labels()
    # by_label = dict(zip(labels, handles))
    # fig.legend(by_label.values(), by_label.keys())
    # fig.legend()

    # plt.show()
    fig.savefig(Path(__file__).with_suffix('.png'))


def main():
    results_file = Path(__file__).with_suffix('.json')
    results = run_experiment()
    save_dict(results, results_file)
    results = load_dict(results_file)
    plot_results(results)


if __name__ == '__main__':
    main()
