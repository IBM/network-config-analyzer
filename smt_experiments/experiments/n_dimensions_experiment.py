"""
An experiment that measures how the time for element containment is influenced by the number of dimensions of a
hyper cube, when the number of intervals is fixed.
"""
import dataclasses
import itertools
import json
import timeit
from collections.abc import Iterable
from dataclasses import dataclass
from enum import Enum, auto
from itertools import product
from statistics import mean

import matplotlib.pyplot as plt

from CanonicalHyperCubeSet import CanonicalHyperCubeSet
from CanonicalIntervalSet import CanonicalIntervalSet
from DimensionsManager import DimensionsManager
from smt_experiments.experiments.experiment_utils import Timer, CheckType, get_results_file, get_plot_file, EngineType
from smt_experiments.z3_sets.z3_hyper_cube_set import Z3ProductSet

INTERVALS = [(0, 100), (200, 300)]
# TODO: maybe do more experiments with the LINEAR option
# MAX_DIMENSIONS = 5
MAX_DIMENSIONS = 15
MIN_DIMENSIONS = 1
STEP = 1
N_TIMES = 1





# class CubeIncreaseMode(Enum):
class CubeIncreaseMode(Enum):
    CONSTANT = auto()
    LINEAR = auto()
    EXPONENTIAL = auto()


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


def get_z3_hyper_cube_set(n_dimensions: int, mode: CubeIncreaseMode) -> Z3ProductSet:
    dimension_names = get_dimension_names(n_dimensions)
    hyper_cube = Z3ProductSet(dimension_names)
    for cube in iter_cubes(n_dimensions, mode):
        hyper_cube.add_cube(cube)
    return hyper_cube


def get_our_hyper_cube_set(n_dimensions: int, mode: CubeIncreaseMode) -> CanonicalHyperCubeSet:
    dimension_names = get_dimension_names(n_dimensions)
    hyper_cube = CanonicalHyperCubeSet(dimension_names)
    for cube in iter_cubes(n_dimensions, mode):
        cube = [CanonicalIntervalSet.get_interval_set(start, end) for (start, end) in cube.values()]
        hyper_cube.add_cube(cube, dimension_names)

    return hyper_cube


def get_hyper_cube(n_dimensions: int, mode: CubeIncreaseMode, engine: EngineType):
    if engine == EngineType.Z3:
        return get_z3_hyper_cube_set(n_dimensions, mode)
    if engine == EngineType.OUR:
        return get_our_hyper_cube_set(n_dimensions, mode)


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


def measure_containment_time(hyper_cube, element: dict[str, int]) -> float:
    if isinstance(hyper_cube, CanonicalHyperCubeSet):
        element = list(element.values())
        return timeit.timeit(lambda: element in hyper_cube, number=N_TIMES)
    if isinstance(hyper_cube, Z3ProductSet):
        return timeit.timeit(lambda: element in hyper_cube, number=N_TIMES)


def measure_avg_containment_time(hyper_cube, elements: list[dict[str, int]]) -> float:
    return mean(measure_containment_time(hyper_cube, element) for element in elements)


@dataclass
class ExperimentResult:
    n_dims: int
    mode: CubeIncreaseMode
    engine: EngineType
    check: CheckType
    containment_time: float
    creation_time: float

    def to_dict(self):
        d = self.__dict__
        for key, value in d.items():
            if isinstance(value, Enum):
                d[key] = value.name.lower()
        return d

    @classmethod
    def from_dict(cls, d: dict):
        fields = dataclasses.fields(cls)
        for field in fields:
            if issubclass(field.type, Enum):
                d[field.name] = field.type[d[field.name].upper()]
        return cls(**d)


def save_results(results: list[ExperimentResult]) -> None:
    results = [result.to_dict() for result in results]
    results_file = get_results_file(__file__)
    with results_file.open('w') as f:
        json.dump(results, f)


def load_results() -> list[ExperimentResult]:
    results_file = get_results_file(__file__)
    with results_file.open('r') as f:
        results = json.load(f)
    return [ExperimentResult.from_dict(result) for result in results]


def run_experiment() -> list[ExperimentResult]:
    _init_dim_manager()

    n_dims_list = list(range(MIN_DIMENSIONS, MAX_DIMENSIONS + 1, STEP))
    n_options = len(list(product(n_dims_list, CubeIncreaseMode, EngineType, CheckType)))

    results = []
    i = 1
    for (n_dims, mode, engine) in product(n_dims_list, CubeIncreaseMode, EngineType):
        with Timer() as creation_timer:
            hyper_cube = get_hyper_cube(n_dims, mode, engine)

        for check in CheckType:
            print(f'{i} / {n_options}')
            i += 1
            elements = get_elements(n_dims, mode, check)
            containment_time = measure_avg_containment_time(hyper_cube, elements)
            result = ExperimentResult(
                n_dims=n_dims,
                mode=mode,
                engine=engine,
                check=check,
                containment_time=containment_time,
                creation_time=creation_timer.elapsed_time
            )
            results.append(result)

    save_results(results)
    return results


def _init_dim_manager():
    dim_manager = DimensionsManager()
    dim_names = get_dimension_names(MAX_DIMENSIONS)
    for n in dim_names:
        dim_manager.set_domain(n, DimensionsManager.DimensionType.IntervalSet, (0, 100000))


def plot_results() -> None:
    results = load_results()

    def get_label(engine: EngineType, check: CheckType) -> str:
        return f'{engine.name.lower()}.{check.name.lower()}'

    fig, (containment_axes, creation_axes) = plt.subplots(2, len(CubeIncreaseMode), figsize=(16, 10))
    for mode, containment_ax, creation_ax in zip(CubeIncreaseMode, containment_axes, creation_axes):
        plotted = []
        for engine, check in product(EngineType, CheckType):
            filtered_results = [result for result in results if
                                result.mode == mode and result.engine == engine and result.check == check]
            n_dims_list = [result.n_dims for result in filtered_results]
            containment_time_list = [result.containment_time for result in filtered_results]
            containment_ax.scatter(n_dims_list, containment_time_list, label=get_label(engine, check))
            containment_ax.legend()
            containment_ax.set_xlabel('#dimensions')
            containment_ax.set_ylabel('containment time')
            containment_ax.set_title(mode.name.lower())

            if engine not in plotted:
                creation_time_list = [result.creation_time for result in filtered_results]
                plotted.append(engine)
                print(engine, creation_time_list)
                creation_ax.scatter(n_dims_list, creation_time_list, label=engine.name.lower())
                creation_ax.legend()
                creation_ax.set_xlabel('#dimensions')
                creation_ax.set_ylabel('creation time')
                creation_ax.set_title(mode.name.lower())

    plt.savefig(get_plot_file(__file__))


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
    # test_iter_cubes()
    # run_experiment()
    plot_results()
