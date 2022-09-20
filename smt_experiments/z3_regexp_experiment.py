from z3 import Re, Concat, Plus, String, Union, Solver, InRe, Or, Not, And, unsat


# TODO: find a minimal example that gets the solver stuck
def test_0():
    # Does not get stuck
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
    solver.add(formula)
    print(f'checking formula {formula}')
    result = solver.check()
    if result == unsat:
        print('Two formulas are identical')
    else:
        print('Found counter-example: ', solver.model())


test_0()
