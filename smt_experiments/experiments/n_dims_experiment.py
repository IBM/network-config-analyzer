"""
An experiment that measures how the time for element containment is influenced by the number of dimensions of a
hyper cube, when the number of intervals is fixed.
"""
import itertools
from collections.abc import Iterable
from enum import auto

from CanonicalHyperCubeSet import CanonicalHyperCubeSet
from CanonicalIntervalSet import CanonicalIntervalSet
from DimensionsManager import DimensionsManager
from smt_experiments.experiments.experiment_utils import EngineType, \
    EnumWithStr, get_y_var_list, Variable
from smt_experiments.experiments.plot_experiment_results import plot_results
from smt_experiments.experiments.run_experiment import run_experiment, Operation
from smt_experiments.z3_sets.z3_integer_set import Z3IntegerSet
from smt_experiments.z3_sets.z3_product_set import Z3ProductSet


# TODO: maybe do more experiments with the LINEAR option
# TODO: convert this to use the generic run_experiment and plot_results functions


class CubeIncreaseMode(EnumWithStr):
    CONSTANT = auto()
    LINEAR = auto()
    EXPONENTIAL = auto()


def get_dimension_names(n_dims: int) -> list[str]:
    return [str(i) for i in range(n_dims)]


def iter_cubes(n_dims: int, mode: CubeIncreaseMode) -> Iterable[tuple[tuple[int, int]]]:
    intervals = ((0, 100), (200, 300))

    if mode == CubeIncreaseMode.CONSTANT:
        yield tuple(intervals[0] for _ in range(n_dims))

    elif mode == CubeIncreaseMode.LINEAR:
        for i in range(n_dims):
            cube = tuple(intervals[1] if i == j else intervals[0] for j in range(n_dims))
            yield cube

    elif mode == CubeIncreaseMode.EXPONENTIAL:
        for cube in itertools.product(intervals, repeat=n_dims):
            yield cube


def get_z3_hyper_cube_set(n_dims: int, mode: CubeIncreaseMode) -> Z3ProductSet:
    dimension_names = get_dimension_names(n_dims)
    hyper_cube = Z3ProductSet(dimension_names)
    for cube in iter_cubes(n_dims, mode):
        hyper_cube.add_cube(cube)
    return hyper_cube


def get_our_hyper_cube_set(n_dims: int, mode: CubeIncreaseMode) -> CanonicalHyperCubeSet:
    dimension_names = get_dimension_names(n_dims)
    hyper_cube = CanonicalHyperCubeSet(dimension_names)
    for cube in iter_cubes(n_dims, mode):
        cube = [CanonicalIntervalSet.get_interval_set(start, end) for (start, end) in cube.values()]
        hyper_cube.add_cube(cube, dimension_names)

    return hyper_cube


def get_hyper_cube_set(n_dims: int, cube_increase_mode: CubeIncreaseMode, engine: EngineType):
    cube_list = list(iter_cubes(n_dims, cube_increase_mode))
    if len(cube_list) <= 20:
        representation = f'intervals={cube_list}'
    else:
        representation = f'intervals={cube_list[:20]}...'

    if engine == EngineType.Z3:
        dim_types = tuple(int for _ in range(n_dims))
        s = Z3ProductSet(dim_types)
        for cube in cube_list:
            cube = tuple(Z3IntegerSet.get_interval_set(start, end) for start, end in cube)
            s.add_cube(cube)

    if engine == EngineType.OUR:
        s = CanonicalHyperCubeSet(dimensions=get_dimension_names(n_dims))
        for cube in cube_list:
            cube = [CanonicalIntervalSet.get_interval_set(start, end) for start, end in cube]
            s.add_cube(cube)

    return s, representation


def get_contained_elements(n_dims: int, engine: EngineType, cube_increase_mode: CubeIncreaseMode) -> list[tuple]:
    elements = []

    if cube_increase_mode == CubeIncreaseMode.CONSTANT:
        for i in range(n_dims):
            element = (i,) * n_dims
            elements.append(element)

    if cube_increase_mode in [CubeIncreaseMode.LINEAR, CubeIncreaseMode.EXPONENTIAL]:

        for i in range(n_dims):
            element = tuple(50 if i != j else 250 for j in range(n_dims))
            elements.append(element)

    return elements


def get_not_contained_elements(n_dims: int, engine: EngineType, cube_increase_mode: CubeIncreaseMode) -> list[tuple]:
    elements = []
    for i in range(n_dims):
        element = tuple(50 if i != j else 150 for j in range(n_dims))
        elements.append(element)
    return elements


def _init_dim_manager(max_dims: int):
    dim_manager = DimensionsManager()
    dim_names = get_dimension_names(max_dims)
    for n in dim_names:
        dim_manager.set_domain(n, DimensionsManager.DimensionType.IntervalSet, (0, 100000))


def run():
    experiment_name = 'n_dims_experiment'
    min_dims = 1
    max_dims = 15
    step = 1
    _init_dim_manager(max_dims)

    operation_list = [
        Operation(
            name='positive_membership',
            get_input_list=get_contained_elements,
            run_operation=lambda set_0, element: element in set_0,
        ),
        Operation(
            name='negative_membership',
            get_input_list=get_not_contained_elements,
            run_operation=lambda set_0, element: element in set_0
        ),
    ]
    set_params_options = {
        'engine': list(EngineType),
        'n_dims': list(range(min_dims, max_dims + 1, step)),
        'cube_increase_mode': list(CubeIncreaseMode),
    }
    run_experiment(
        experiment_name=experiment_name,
        set_params_options=set_params_options,
        get_set_from_params=get_hyper_cube_set,
        operation_list=operation_list,
    )


def plot():
    experiment_name = 'n_dims_experiment'
    x_var = Variable(
        'n_dims',
        lambda result: result['set_params']['n_dims']
    )

    horizontal_var_list = [
        Variable(
            'cube_increase_mode',
            lambda result: result['set_params']['cube_increase_mode']
        )
    ]

    legend_var_list = [
        Variable(
            'engine',
            lambda result: result['set_params']['engine']
        )
    ]
    plot_results(
        experiment_name=experiment_name,
        x_var=x_var,
        y_var_list=get_y_var_list(),
        horizontal_var_list=horizontal_var_list,
        legend_var_list=legend_var_list,
    )


if __name__ == '__main__':
    # test_iter_cubes()
    run()
    plot()
