"""
An experiment that measures how the time for element containment is influenced by the number of intervals in a single
interval set.
"""
import timeit
from statistics import mean

import matplotlib.pyplot as plt

from CanonicalIntervalSet import CanonicalIntervalSet
from smt_experiments.z3_integer_set import Z3IntegerSet

# TODO: convert to use the generic plot / run_experiment functions

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


def get_integer_set(n_intervals: int, cls):
    intervals = get_intervals(n_intervals)
    first_start, first_end = intervals[0]
    integer_set = cls.get_interval_set(first_start, first_end)
    for start, end in intervals[1:]:
        integer_set_0 = cls.get_interval_set(start, end)
        integer_set |= integer_set_0
    return integer_set


def get_set_z3(n_intervals: int) -> Z3IntegerSet:
    return get_integer_set(n_intervals, Z3IntegerSet)


def get_set_ours(n_intervals: int) -> CanonicalIntervalSet:
    return get_integer_set(n_intervals, CanonicalIntervalSet)


def get_contained_elements(n_intervals: int) -> list[int]:
    return [START_FROM + i * JUMP for i in range(n_intervals)]


def get_not_contained_elements(n_intervals: int) -> list[int]:
    return [START_FROM + i * JUMP - INTERVAL_HALF_SIZE - 1 for i in range(n_intervals)]


def time_containment(integer_set, element: int) -> float:
    return timeit.timeit(lambda: element in integer_set, number=N_TIMES)


def average_time_containment(integer_set, element_list: list[int]) -> float:
    return mean(time_containment(integer_set, element) for element in element_list)


def run_experiment():
    min_intervals = 1
    max_intervals = 100
    step = 2
    n_intervals_list = list(range(min_intervals, max_intervals + 1, step))

    contained_z3_time = []
    contained_our_time = []
    not_contained_z3_time = []
    not_contained_our_time = []

    for i, n_interval in enumerate(n_intervals_list, 1):
        print(f'{i} / {len(n_intervals_list)}')

        z3_set = get_set_z3(n_interval)
        our_set = get_set_ours(n_interval)
        contained_elements = get_contained_elements(n_interval)
        not_contained_elements = get_not_contained_elements(n_interval)

        contained_z3_time.append(average_time_containment(z3_set, contained_elements))
        not_contained_z3_time.append(average_time_containment(z3_set, not_contained_elements))

        contained_our_time.append(average_time_containment(our_set, contained_elements))
        not_contained_our_time.append(average_time_containment(our_set, not_contained_elements))

    # TODO: change it to save the figure instead of showing it
    plt.figure(figsize=(10, 10), layout='constrained')
    plt.scatter(n_intervals_list, contained_z3_time, label='z3_contained')
    plt.scatter(n_intervals_list, contained_our_time, label='ours_contained')
    plt.scatter(n_intervals_list, not_contained_z3_time, label='z3_not_contained')
    plt.scatter(n_intervals_list, not_contained_our_time, label='ours_not_contained')
    plt.xlabel('number of intervals')
    plt.ylabel('element containment time')
    plt.title("element containment time / number of intervals")
    plt.legend()
    plt.show()


if __name__ == '__main__':
    run_experiment()
