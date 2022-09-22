import z3
from z3 import Re, Concat, Plus, String, Union, Solver, InRe, Or, Not, And, unsat


def z3_get_stuck():
    a = Re('a')
    a_plus = Plus(a)
    two_or_more_a = Concat(a, a_plus)
    b = Re('b')
    b_plus = Plus(b)
    two_or_more_b = Concat(b, b_plus)
    union_regex = Union(two_or_more_a, two_or_more_b)

    s = String('s')
    formula_1 = InRe(s, union_regex)
    formula_2 = Or(InRe(s, two_or_more_a), InRe(s, two_or_more_b))
    formula = Or(
        And(formula_1, Not(formula_2)),
        And(Not(formula_1), formula_2)
    )
    # check if the two formulas are identical
    solver = Solver()
    # solver.set("smt.string_solver", "auto")
    # solver.set("smt.string_solver", "seq")
    solver.set("smt.string_solver", "z3str3")
    solver.add(formula)
    print(f'checking formula {formula}')
    result = solver.check()
    if result == unsat:
        print('Two formulas are identical')
    else:
        print('Found counter-example: ', solver.model())


def z3_succeeds():
    # Does not get stuck
    a = Re('a')
    a_plus = Plus(a)
    two_or_more_a = Concat(a, a_plus)
    b = Re('b')
    b_plus = Plus(b)
    two_or_more_b = Concat(b, b_plus)
    union_regex = Union(two_or_more_a, two_or_more_b)
    r = z3.Diff(union_regex, two_or_more_a)
    r1 = z3.Diff(union_regex, two_or_more_b)
    # r = z3.Diff(r, two_or_more_b)
    s = String('s')
    s1 = String('s1')
    formula = InRe(s, r)
    formula = And(formula, InRe(s1, r1))
    formula = And(formula, InRe(s, r1))
    solver = Solver()
    solver.add(formula)
    print(f'checking formula {formula}')
    result = solver.check()
    if result == unsat:
        print('Two formulas are identical')
    else:
        print('Found counter-example: ', solver.model())
    # print(solver.statistics())
    # print(solver.cube())


if __name__ == '__main__':
    z3_succeeds()
    print('=' * 20)
    z3_get_stuck()
