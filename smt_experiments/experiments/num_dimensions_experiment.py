"""
An experiment that measures how the time for element containment is influenced by the number of dimensions of a
hyper cube, when the number of intervals is fixed.
"""
import itertools
import timeit
from collections import defaultdict
from collections.abc import Iterable
from enum import Enum, auto
from statistics import mean

import matplotlib.pyplot as plt

from CanonicalHyperCubeSet import CanonicalHyperCubeSet
from CanonicalIntervalSet import CanonicalIntervalSet
from DimensionsManager import DimensionsManager
from smt_experiments.z3_sets.z3_hyper_cube_set import Z3HyperCubeSet

INTERVALS = [(0, 100), (200, 300)]
MAX_DIMENSIONS = 18
MIN_DIMENSIONS = 1
STEP = 1
N_TIMES = 10


# TODO: create different plots by the different number of cubes that we have in the hyper cube,
# TODO: we don't count the time that it takes to create the cubes... should we?


class CubeIncreaseMode(Enum):
    CONSTANT = auto()
    LINEAR = auto()
    EXPONENTIAL = auto()


class EngineType(Enum):
    Z3 = auto()
    OUR = auto()


class CheckType(Enum):
    CONTAINED = auto()
    NOT_CONTAINED = auto()


def get_dimension_names(n_dimensions: int) -> list[str]:
    return [str(i) for i in range(n_dimensions)]


def iter_cubes(n_dimensions: int, mode: CubeIncreaseMode) -> Iterable[dict[str, tuple[int, int]]]:
    dimension_names = get_dimension_names(n_dimensions)

    if mode == CubeIncreaseMode.CONSTANT:
        yield {dimension_name: INTERVALS[0] for dimension_name in dimension_names}

    elif mode == CubeIncreaseMode.LINEAR:
        for i in range(n_dimensions):
            cube_limits = []
            for j in range(n_dimensions):
                if i == j:
                    cube_limits.append(INTERVALS[1])
                else:
                    cube_limits.append(INTERVALS[0])
            yield dict(zip(dimension_names, cube_limits))

    elif mode == CubeIncreaseMode.EXPONENTIAL:
        for cube_limits in itertools.product(INTERVALS, repeat=n_dimensions):
            yield dict(zip(dimension_names, cube_limits))


def get_z3_hyper_cube(n_dimensions: int, mode: CubeIncreaseMode) -> Z3HyperCubeSet:
    dimension_names = get_dimension_names(n_dimensions)
    hyper_cube = Z3HyperCubeSet(dimension_names)
    for cube in iter_cubes(n_dimensions, mode):
        hyper_cube.add_cube(cube)
    return hyper_cube


def get_our_hyper_cube(n_dimensions: int, mode: CubeIncreaseMode) -> CanonicalHyperCubeSet:
    dimension_names = get_dimension_names(n_dimensions)
    hyper_cube = CanonicalHyperCubeSet(dimension_names)
    for cube in iter_cubes(n_dimensions, mode):
        cube = [CanonicalIntervalSet.get_interval_set(start, end) for (start, end) in cube.values()]
        hyper_cube.add_cube(cube, dimension_names)

    return hyper_cube


def get_hyper_cube(n_dimensions: int, mode: CubeIncreaseMode, engine: EngineType):
    if engine == EngineType.Z3:
        return get_z3_hyper_cube(n_dimensions, mode)
    if engine == EngineType.OUR:
        return get_our_hyper_cube(n_dimensions, mode)


def get_contained_elements(n_dims: int, mode: CubeIncreaseMode) -> list[dict[str, int]]:
    dim_names = get_dimension_names(n_dims)
    elements = []

    if mode == CubeIncreaseMode.CONSTANT:
        for i in range(n_dims):
            elements.append({dim_name: i for dim_name in dim_names})

    if mode in [CubeIncreaseMode.LINEAR, CubeIncreaseMode.EXPONENTIAL]:
        for i in range(n_dims):
            element = {dim_name: 50 for dim_name in dim_names}
            element[dim_names[i]] = 250
            elements.append(element)

    return elements


def get_not_contained_in_elements(n_dims: int, mode: CubeIncreaseMode) -> list[dict[str, int]]:
    dim_names = get_dimension_names(n_dims)
    elements = []
    for i in range(n_dims):
        element = {dim_name: 50 for dim_name in dim_names}
        element[dim_names[i]] = 150
        elements.append(element)
    return elements


def get_elements(n_dims: int, mode: CubeIncreaseMode, check_type: CheckType) -> list[dict[str, int]]:
    if check_type == CheckType.CONTAINED:
        return get_contained_elements(n_dims, mode)
    if check_type == CheckType.NOT_CONTAINED:
        return get_not_contained_in_elements(n_dims, mode)


def containment_time(hyper_cube, element: dict[str, int]) -> float:
    if isinstance(hyper_cube, CanonicalHyperCubeSet):
        element = list(element.values())
        return timeit.timeit(lambda: element in hyper_cube, number=N_TIMES)
    if isinstance(hyper_cube, Z3HyperCubeSet):
        return timeit.timeit(lambda: element in hyper_cube, number=N_TIMES)


def avg_containment_time(hyper_cube, elements: list[dict[str, int]]) -> float:
    return mean(containment_time(hyper_cube, element) for element in elements)


def run_experiment():
    n_dims_list = list(range(MIN_DIMENSIONS, MAX_DIMENSIONS + 1, STEP))

    dim_manager = DimensionsManager()
    dim_names = get_dimension_names(MAX_DIMENSIONS)

    for n in dim_names:
        dim_manager.set_domain(n, DimensionsManager.DimensionType.IntervalSet, (0, 100000))

    option_list = list(itertools.product(n_dims_list, CubeIncreaseMode, EngineType, CheckType))
    results = defaultdict(list)

    for i, (n_dims, mode, engine, check) in enumerate(option_list, 1):
        print(f'{i} / {len(option_list)}')
        hyper_cube = get_hyper_cube(n_dims, mode, engine)
        elements = get_elements(n_dims, mode, check)
        avg_time = avg_containment_time(hyper_cube, elements)
        results[(mode, engine, check)].append(avg_time)

    # TODO: maybe split into different axes?
    def get_label(engine: EngineType, check: CheckType) -> str:
        return f'{engine.name.lower()}.{check.name.lower()}'

    fig, axes = plt.subplots(1, len(CubeIncreaseMode), )  # figsize=(10, 10))
    for mode, ax in zip(CubeIncreaseMode, axes):
        for engine, check in itertools.product(EngineType, CheckType):
            avg_times = results[(mode, engine, check)]
            ax.scatter(n_dims_list, avg_times, label=get_label(engine, check))

        ax.legend()
        ax.set_xlabel('#dimensions')
        ax.set_ylabel('contains time')
        ax.set_title(mode.name.lower())

    plt.show()


def test_iter_cubes():
    for n_dimensions in range(1, 10):
        constant = list(iter_cubes(n_dimensions, CubeIncreaseMode.CONSTANT))
        print(constant)
        assert len(constant) == 1

        linear = list(iter_cubes(n_dimensions, CubeIncreaseMode.LINEAR))
        print(linear)
        assert len(linear) == n_dimensions

        exponential = list(iter_cubes(n_dimensions, CubeIncreaseMode.EXPONENTIAL))
        print(exponential)
        assert len(exponential) == 2 ** n_dimensions


if __name__ == '__main__':
    run_experiment()
    # test_iter_cubes()