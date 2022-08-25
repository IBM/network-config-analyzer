import timeit

from CanonicalIntervalSet import CanonicalIntervalSet
from smt_experiments.z3_integer_set import Z3IntegerSet


def z3_timing():
    """Timing basic z3 operations"""
    n_times = 1_000

    # instantiating a z3 solver
    t = timeit.timeit(stmt='solver = Solver()', number=n_times, globals=globals())
    print(f'time to instantiate a new Solver: {t}')

    # instantiating a z3 integer
    t = timeit.timeit(stmt='x = Int("x")', number=n_times, globals=globals())
    print(f'time to instantiate a new Int: {t}')

    # creating a simple formula
    t = timeit.timeit(
        stmt='formula = And(x <= 10, x >= 1)',
        setup='x = Int("x")',
        number=n_times,
        globals=globals()
    )
    print(f'time to create z3 formula: {t}')

    # adding a simple formula to z3
    t = timeit.timeit(
        stmt='solver.add(formula)',
        setup='x = Int("x"); formula = And(x <= 10, x >= 1); solver = Solver()',
        number=n_times,
        globals=globals()
    )
    print(f'time to add z3 formula to solver: {t}')

    # checking a simple formula to z3
    t = timeit.timeit(
        stmt='result = solver.check()',
        setup='x = Int("x"); formula = And(x <= 10, x >= 1); solver = Solver(); solver.add(formula)',
        number=n_times,
        globals=globals()
    )
    print(f'time to check z3 formula: {t}')

    # substituting variables
    t = timeit.timeit(
        stmt='new_formula = substitute(formula, (x, y))',
        setup='x = Int("x"); formula = And(x <= 10, x >= 1); y = Int("y")',
        number=n_times,
        globals=globals()
    )
    print(f'time to substitute variables: {t}')

    # push and pop to solver
    t = timeit.timeit(
        stmt='solver.push(); solver.pop()',
        setup='x = Int("x"); formula = And(x <= 10, x >= 1); solver = Solver(); solver.add(formula)',
        number=n_times,
        globals=globals()
    )
    print(f'time to push and pop to solver: {t}')


def integer_sets_experiment():
    # TODO: split each test to a separate function so I would not have to run it all every time
    # creation
    n_times = 1_000
    start = 0
    end = 100

    t1 = timeit.timeit(lambda: CanonicalIntervalSet.get_interval_set(start, end), number=n_times)
    t2 = timeit.timeit(lambda: Z3IntegerSet.get_interval_set(start, end), number=n_times)
    print(f'CanonicalIntervalSet creation time: {t1}')
    print(f'Z3IntegerSet creation time: {t2}')

    interval_set = CanonicalIntervalSet.get_interval_set(start, end)
    z3_set = Z3IntegerSet.get_interval_set(start, end)

    # single element contained in
    contains_timing(interval_set, z3_set, 50, n_times)

    # single element not contained in
    contains_timing(interval_set, z3_set, 300, n_times)

    # subset
    start1 = 10
    end1 = 90
    interval_set1 = CanonicalIntervalSet.get_interval_set(start1, end1)
    z3_set1 = Z3IntegerSet.get_interval_set(start1, end1)
    contained_in_timing(interval_set, interval_set1, z3_set, z3_set1, n_times)

    # not subset
    start2 = 10
    end2 = 150
    interval_set2 = CanonicalIntervalSet.get_interval_set(start2, end2)
    z3_set2 = Z3IntegerSet.get_interval_set(start2, end2)
    contained_in_timing(interval_set, interval_set2, z3_set, z3_set2, n_times)

    # equivalence
    interval_set_eq = CanonicalIntervalSet.get_interval_set(start, end)
    z3_set_eq = Z3IntegerSet.get_interval_set(start, end)
    eq_timing(interval_set, interval_set_eq, z3_set, z3_set_eq, n_times)

    # copy
    copy_timing(interval_set, z3_set, n_times)

    # union
    union_timing(interval_set, interval_set1, z3_set, z3_set1, n_times)

    # intersection
    intersect_timing(interval_set, interval_set1, z3_set, z3_set1, n_times)

    # difference
    difference_timing(interval_set, interval_set1, z3_set, z3_set1, n_times)

    # now do all the tests when we take the union over disjoint sets (increasing number)
    # for i in range(2, 101, 2):
    for i in range(2, 11, 2):
        print(f'***{i // 2} intervals***')
        low = i * 100
        high = (i + 1) * 100
        interval_set |= CanonicalIntervalSet.get_interval_set(low, high)
        z3_set |= Z3IntegerSet.get_interval_set(low, high)

        in_element = low + 50
        contains_timing(interval_set, z3_set, in_element, n_times)

        not_in_element = low - 50
        contains_timing(interval_set, z3_set, not_in_element, n_times)

        middle_element = (start + high) // 2
        contains_timing(interval_set, z3_set, middle_element, n_times)


def contains_timing(interval_set: CanonicalIntervalSet, z3_set: Z3IntegerSet, element: int, n_times: int):
    t1 = timeit.timeit(lambda: element in interval_set, number=n_times)
    t2 = timeit.timeit(lambda: element in z3_set, number=n_times)
    print(f'CanonicalIntervalSet contained in time: {t1}')
    print(f'Z3IntegerSet contained in time: {t2}')


def copy_timing(interval_set: CanonicalIntervalSet, z3_set: Z3IntegerSet, n_times: int):
    t1 = timeit.timeit(lambda: interval_set.copy(), number=n_times)
    t2 = timeit.timeit(lambda: z3_set.copy(), number=n_times)
    print(f'CanonicalIntervalSet copy time: {t1}')
    print(f'Z3IntegerSet copy time: {t2}')


def contained_in_timing(interval_set: CanonicalIntervalSet, interval_set1: CanonicalIntervalSet,
                        z3_set: Z3IntegerSet, z3_set1: Z3IntegerSet, n_times: int):
    t1 = timeit.timeit(lambda: interval_set1.contained_in(interval_set), number=n_times)
    t2 = timeit.timeit(lambda: z3_set1.contained_in(z3_set), number=n_times)
    print(f'CanonicalIntervalSet contained_in time: {t1}')
    print(f'Z3IntegerSet contained_in time: {t2}')


def eq_timing(interval_set: CanonicalIntervalSet, interval_set1: CanonicalIntervalSet,
              z3_set: Z3IntegerSet, z3_set1: Z3IntegerSet, n_times: int):
    t1 = timeit.timeit(lambda: interval_set1 == interval_set, number=n_times)
    t2 = timeit.timeit(lambda: z3_set1 == z3_set, number=n_times)
    print(f'CanonicalIntervalSet __eq__ time: {t1}')
    print(f'Z3IntegerSet __eq__ time: {t2}')


def union_timing(interval_set: CanonicalIntervalSet, interval_set1: CanonicalIntervalSet,
                 z3_set: Z3IntegerSet, z3_set1: Z3IntegerSet, n_times: int):
    interval_set = interval_set.copy()
    z3_set = z3_set.copy()

    t1 = timeit.timeit(lambda: interval_set.__ior__(interval_set1), number=n_times)
    t2 = timeit.timeit(lambda: z3_set.__ior__(z3_set1), number=n_times)
    print(f'CanonicalIntervalSet __ior__ time: {t1}')
    print(f'Z3IntegerSet __ior__ time: {t2}')


def intersect_timing(interval_set: CanonicalIntervalSet, interval_set1: CanonicalIntervalSet,
                     z3_set: Z3IntegerSet, z3_set1: Z3IntegerSet, n_times: int):
    interval_set = interval_set.copy()
    z3_set = z3_set.copy()

    t1 = timeit.timeit(lambda: interval_set.__iand__(interval_set1), number=n_times)
    t2 = timeit.timeit(lambda: z3_set.__iand__(z3_set1), number=n_times)
    print(f'CanonicalIntervalSet __iand__ time: {t1}')
    print(f'Z3IntegerSet __iand__ time: {t2}')


def difference_timing(interval_set: CanonicalIntervalSet, interval_set1: CanonicalIntervalSet,
                      z3_set: Z3IntegerSet, z3_set1: Z3IntegerSet, n_times: int):
    interval_set = interval_set.copy()
    z3_set = z3_set.copy()

    t1 = timeit.timeit(lambda: interval_set.__isub__(interval_set1), number=n_times)
    t2 = timeit.timeit(lambda: z3_set.__isub__(z3_set1), number=n_times)
    print(f'CanonicalIntervalSet __isub__ time: {t1}')
    print(f'Z3IntegerSet __isub__ time: {t2}')


# TODO: save results to a file and make a graph of it.


if __name__ == "__main__":
    integer_sets_experiment()