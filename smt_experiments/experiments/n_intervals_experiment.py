"""
An experiment that measures how the time for element containment is influenced by the number of intervals in a single
interval set.
"""

from CanonicalIntervalSet import CanonicalIntervalSet
from smt_experiments.experiments.experiment_utils import EngineType, Variable, get_y_var_list, \
    get_positive_membership_operation, get_negative_membership_operation
from smt_experiments.experiments.plot_experiment_results import plot_results
from smt_experiments.experiments.run_experiment import run_experiment
from smt_experiments.z3_sets.z3_integer_set import Z3IntegerSet

JUMP = 100
INTERVAL_HALF_SIZE = 25
START_FROM = 0
N_TIMES = 1_000


def get_intervals(n_intervals: int) -> list[tuple[int, int]]:
    intervals = []
    for i in range(n_intervals):
        middle = START_FROM + i * JUMP
        start = middle - INTERVAL_HALF_SIZE
        end = middle + INTERVAL_HALF_SIZE
        intervals.append((start, end))
    return intervals


def get_integer_set(engine: EngineType, n_intervals: int):
    intervals = get_intervals(n_intervals)
    if len(intervals) <= 20:
        representation = f'intervals={intervals}'
    else:
        representation = f'intervals={intervals[:20]}...'

    first_start, first_end = intervals[0]
    if engine == EngineType.Z3:
        interval_constructor = Z3IntegerSet.get_interval_set
    else:
        interval_constructor = CanonicalIntervalSet.get_interval_set

    integer_set = interval_constructor(first_start, first_end)
    for start, end in intervals[1:]:
        integer_set_0 = interval_constructor(start, end)
        integer_set |= integer_set_0

    return integer_set, representation


def get_contained_elements(engine: EngineType, n_intervals: int) -> list[int]:
    return [START_FROM + i * JUMP for i in range(n_intervals)]


def get_not_contained_elements(engine: EngineType, n_intervals: int) -> list[int]:
    return [START_FROM + i * JUMP - INTERVAL_HALF_SIZE - 1 for i in range(n_intervals)]


def run():
    experiment_name = 'n_intervals_experiment'

    min_intervals = 1
    # max_intervals = 2_000
    max_intervals = 200
    step = 10

    set_params_options = {
        'engine': EngineType,
        'n_intervals': list(range(min_intervals, max_intervals + 1, step))
    }

    operation_list = [
        get_positive_membership_operation(get_contained_elements),
        get_negative_membership_operation(get_not_contained_elements),
    ]

    run_experiment(
        experiment_name=experiment_name,
        set_params_options=set_params_options,
        get_set_from_params=get_integer_set,
        operation_list=operation_list,
    )


def plot():
    experiment_name = 'n_intervals_experiment'
    x_var = Variable(
        'n_intervals',
        lambda result: result['set_params']['n_intervals']
    )

    horizontal_var_list = [
        Variable(
            '',
            lambda result: None
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
    run()
    plot()
