"""
An experiment that measures how the time for element containment is influenced by the number of dimensions of a
hyper cube, when the number of intervals is fixed.
"""
import string

import matplotlib.pyplot as plt

from CanonicalHyperCubeSet import CanonicalHyperCubeSet
from CanonicalIntervalSet import CanonicalIntervalSet
from DimensionsManager import DimensionsManager


def get_hyper_cube_z3(n_dimensions: int):
    pass


def get_hyper_cube_our(n_dimensions: int) -> CanonicalHyperCubeSet:
    pass


def run_experiment():
    min_n_dimensions = 2
    max_n_dimensions = 100
    step = 2
    n_dimensions_list = list(range(min_n_dimensions, max_n_dimensions + 1, step))

    contained_z3_time = []
    contained_our_time = []
    not_contained_z3_time = []
    not_contained_our_time = []

    for i, n_interval in enumerate(n_dimensions_list, 1):
        print(f'{i} / {len(n_dimensions_list)}')

        z3_set = get_set_z3(n_interval)
        our_set = get_set_ours(n_interval)
        contained_elements = get_contained_elements(n_interval)
        not_contained_elements = get_not_contained_elements(n_interval)

        contained_z3_time.append(average_time_containment(z3_set, contained_elements))
        not_contained_z3_time.append(average_time_containment(z3_set, not_contained_elements))

        contained_our_time.append(average_time_containment(our_set, contained_elements))
        not_contained_our_time.append(average_time_containment(our_set, not_contained_elements))

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


# CODE EXAMPLE
def cubes_test_1(num_dims):
    dim_manager = DimensionsManager()
    chars = list(string.ascii_lowercase)
    dim_names = chars[0:20]
    interval_domain_object = CanonicalIntervalSet.get_interval_set(1, 100000)
    dim_domains_values = {}

    for n in dim_names:
        dim_domains_values[n] = interval_domain_object
        dim_manager.set_domain(n, DimensionsManager.DimensionType.IntervalSet, (1, 100000))

    dimensions_new = dim_names

    x = CanonicalHyperCubeSet(dimensions_new)
    a1 = CanonicalIntervalSet.get_interval_set(1, 20)
    x.add_cube([a1, a1], ["a", "b"])
    a2 = CanonicalIntervalSet.get_interval_set(15, 40)
    x.add_cube([a2], ["b"])
    cube = [CanonicalIntervalSet.get_interval_set(100, 200), CanonicalIntervalSet.get_interval_set(300, 400)]
    x_sub_cube = CanonicalHyperCubeSet(dimensions_new)
    sub_range = CanonicalIntervalSet.get_interval_set(1, 5)
    x_sub_cube.add_cube([sub_range] * 20, dim_names)

    for i in range(1, num_dims):
        cube_dims = [dim_names[i], dim_names[i + 1]]
        x.add_cube(cube, cube_dims)
        res = x_sub_cube.contained_in(x)
        w = next(iter(cube[0]))
        y = next(iter(cube[1]))
        w.start += 200
        w.end += 200
        y.start += 200
        y.end += 200
        cube = [CanonicalIntervalSet.get_interval_set(w.start, w.end),
                CanonicalIntervalSet.get_interval_set(y.start, y.end)]


if __name__ == '__main__':
    run_experiment()
