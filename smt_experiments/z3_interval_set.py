from copy import copy

from z3 import Int, Solver, sat, unsat, And, Not, BoolVal, FreshInt, substitute, Or, BoolRef, SimpleSolver
import timeit

from CanonicalIntervalSet import CanonicalIntervalSet


# TODO: CanonicalIntervalSet offers the following actions
#   - equivalence
#   - set containment
#   - element containment
#   - intersection
#   - union
#   - difference
#  Lets figure out when z3 works better and when CanonicalIntervalSet works better

# TODO: maybe create some unittests to make sure that the functionality is correct
# TODO: first, implement the same functionality, then think about how to optimize it
# TODO: maybe look at others code using Z3 to get ideas on how to optimize implementation
# TODO: search for the z3 paper, it might offer some interesting feedback.
# TODO: check out z3 simple solver, or other optimization options


class Z3IntegerSet:
    _solver = Solver()
    # _solver = SimpleSolver()

    # TODO: every time that the set is updated we need to update the solver.
    #  every time we instantiate something with z3 could be expensive
    def __init__(self):
        self.constraints = BoolVal(False)
        self.var = FreshInt()

    @staticmethod
    def _solve(constraints: BoolRef):
        # TODO: this function has a lot of effect on the timing. experiment with different options
        Z3IntegerSet._solver.push()
        Z3IntegerSet._solver.add(constraints)
        result = Z3IntegerSet._solver.check()
        Z3IntegerSet._solver.pop()
        return result

    @staticmethod
    def get_interval_set(start: int, end: int):
        integer_set = Z3IntegerSet()
        integer_set.constraints = And(integer_set.var <= end, integer_set.var >= start)
        return integer_set

    def __contains__(self, item: int) -> bool:
        constraints = And(self.constraints, self.var == item)
        if self._solve(constraints) == sat:
            return True
        return False

    def contained_in(self, other) -> bool:
        other: Z3IntegerSet
        constraints = And(self.constraints, Not(other.constraints), self.var == other.var)
        if self._solve(constraints) == unsat:
            return True
        return False

    def __eq__(self, other):
        other: Z3IntegerSet
        constraint = And(
            Or(
                And(self.constraints, Not(other.constraints)),
                And(Not(self.constraints), other.constraints)
            ),
            self.var == other.var
        )
        if self._solve(constraint) == unsat:
            return True
        return False

    def copy(self):
        new = Z3IntegerSet()
        new.constraints = substitute(self.constraints, (self.var, new.var))
        return new

    def __iand__(self, other):
        other: Z3IntegerSet
        other_constraints = substitute(other.constraints, (other.var, self.var))
        self.constraints = And(self.constraints, other_constraints)
        return self

    def __ior__(self, other):
        other: Z3IntegerSet
        other_constraints = substitute(other.constraints, (other.var, self.var))
        self.constraints = Or(self.constraints, other_constraints)
        return self

    def __isub__(self, other):
        other: Z3IntegerSet
        other_constraints = substitute(other.constraints, (other.var, self.var))
        self.constraints = And(self.constraints, Not(other_constraints))
        return self


def integer_sets_experiment():
    # TODO: split each test to a separate function so I would not have to run it all every time
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

    # creation
    start = 0
    end = 100

    t1 = timeit.timeit(lambda: CanonicalIntervalSet.get_interval_set(start, end), number=n_times)
    t2 = timeit.timeit(lambda: Z3IntegerSet.get_interval_set(start, end), number=n_times)
    print(f'CanonicalIntervalSet creation time: {t1}')
    print(f'Z3IntegerSet creation time: {t2}')

    set_1 = CanonicalIntervalSet.get_interval_set(start, end)
    set_2 = Z3IntegerSet.get_interval_set(start, end)

    # single element contained in
    # TODO: maybe make this check with assert?
    x = 50
    if x in set_1:
        print(f'{x} is in set_1')
    else:
        print(f'{x} is not in set_1')

    if x in set_2:
        print(f'{x} is in set_2')
    else:
        print(f'{x} is not in set_2')

    t1 = timeit.timeit(lambda: x in set_1, number=n_times)
    t2 = timeit.timeit(lambda: x in set_2, number=n_times)
    print(f'CanonicalIntervalSet contained in time: {t1}')
    print(f'Z3IntegerSet contained in time: {t2}')

    # single element not contained in
    x = 300
    if x in set_1:
        print(f'{x} is in set_1')
    else:
        print(f'{x} is not in set_1')

    if x in set_2:
        print(f'{x} is in set_2')
    else:
        print(f'{x} is not in set_2')

    t1 = timeit.timeit(lambda: x in set_1, number=n_times)
    t2 = timeit.timeit(lambda: x in set_2, number=n_times)
    print(f'CanonicalIntervalSet not contained in time: {t1}')
    print(f'Z3IntegerSet not contained in time: {t2}')

    # subset
    start1 = 10
    end1 = 90
    set_1_1 = CanonicalIntervalSet.get_interval_set(start1, end1)
    set_2_1 = Z3IntegerSet.get_interval_set(start1, end1)

    if set_1_1.contained_in(set_1):
        print('set_1_1 is contained in set_1')
    else:
        print('set_1_1 is not contained in set_1')

    if set_2_1.contained_in(set_2):
        print('set_2_1 is contained in set_2')
    else:
        print('set_2_1 is not contained in set_2')

    t1 = timeit.timeit(lambda: set_1_1.contained_in(set_1), number=n_times)
    t2 = timeit.timeit(lambda: set_2_1.contained_in(set_2), number=n_times)
    print(f'CanonicalIntervalSet contained_in time: {t1}')
    print(f'Z3IntegerSet contained_in time: {t2}')

    # not subset
    start2 = 10
    end2 = 150
    set_1_2 = CanonicalIntervalSet.get_interval_set(start2, end2)
    set_2_2 = Z3IntegerSet.get_interval_set(start2, end2)

    if set_1_2.contained_in(set_1):
        print('set_1_2 is contained in set_1')
    else:
        print('set_1_2 is not contained in set_1')

    if set_2_2.contained_in(set_2):
        print('set_2_2 is contained in set_2')
    else:
        print('set_2_2 is not contained in set_2')

    t1 = timeit.timeit(lambda: set_1_2.contained_in(set_1), number=n_times)
    t2 = timeit.timeit(lambda: set_2_2.contained_in(set_2), number=n_times)
    print(f'CanonicalIntervalSet not contained_in time: {t1}')
    print(f'Z3IntegerSet not contained_in time: {t2}')

    # equivalence
    # TODO: probably, the equivalence check in the CanonicalIntervalSet will be faster
    set_1_eq = CanonicalIntervalSet.get_interval_set(start, end)
    set_2_eq = Z3IntegerSet.get_interval_set(start, end)
    if set_1_eq == set_1:
        print('set_1_eq is equal to set_1')
    else:
        print('set_1_eq is not equal to set_1')

    if set_2_eq == set_2:
        print('set_2_eq is equal to set_2')
    else:
        print('set_2_eq is not equal to set_2')

    t1 = timeit.timeit(lambda: set_1 == set_1_eq, number=n_times)
    t2 = timeit.timeit(lambda: set_2 == set_2_eq, number=n_times)
    print(f'CanonicalIntervalSet __eq__ time: {t1}')
    print(f'Z3IntegerSet __eq__ time: {t2}')

    # copy
    t1 = timeit.timeit(lambda: set_1.copy(), number=n_times)
    t2 = timeit.timeit(lambda: set_2.copy(), number=n_times)
    print(f'CanonicalIntervalSet copy time: {t1}')
    print(f'Z3IntegerSet copy time: {t2}')

    # union
    # intersection
    # difference

    # now do all the tests when we take the union over disjoint sets (increasing number)


if __name__ == "__main__":
    integer_sets_experiment()
