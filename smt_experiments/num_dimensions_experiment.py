"""
An experiment that measures how the time for element containment is influenced by the number of dimensions of a
hyper cube, when the number of intervals is fixed.
"""
from CanonicalHyperCubeSet import CanonicalHyperCubeSet


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

if __name__ == '__main__':
    run_experiment()
