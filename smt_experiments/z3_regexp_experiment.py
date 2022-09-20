from z3 import Re, Concat, Plus, String, Union, Solver, InRe, Or, Not, And, unsat

from DimensionsManager import DimensionsManager
from smt_experiments.z3_sets.z3_product_set import Z3ProductSet
from smt_experiments.z3_sets.z3_string_set import Z3StringSet


dimensions = ["src_ports", "ports", "methods_dfa", "paths"]
dim_manager = DimensionsManager()
dim_manager.set_domain("methods_dfa", DimensionsManager.DimensionType.DFA)
dim_manager.set_domain("ports", DimensionsManager.DimensionType.IntervalSet, (1, 65535))
dim_manager.set_domain("x", DimensionsManager.DimensionType.IntervalSet, (1, 65535))
dim_manager.set_domain("y", DimensionsManager.DimensionType.IntervalSet, (1, 65535))
dim_manager.set_domain("z", DimensionsManager.DimensionType.IntervalSet, (1, 65535))


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



    # str_set1 = Z3StringSet.dfa_from_regex('a[a]+')
    # str_set1 |= Z3StringSet.dfa_from_regex('b[b]+')
    # str_set2 = Z3StringSet.dfa_from_regex('(a[a]+)')
    # str_set2 |= Z3StringSet.dfa_from_regex('(b[b]+)')
    #
    # result = str_set1 == str_set2
    # print(result)


def test_1():
    # Gets stuck
    # Note: now that I have changed str_set union to be taking the Union instead of Or this works.
    #   interesting
    str_set1 = Z3StringSet.dfa_from_regex('a[a]+')
    str_set1 |= Z3StringSet.dfa_from_regex('b[b]+')
    str_set2 = Z3StringSet.dfa_from_regex('(a[a]+)|(b[b]+)')

    result = str_set1 == str_set2
    print(result)


test_0()
# test_1()
# ============= Gets stuck ===================
# dfa1 = get_str_dfa("a[a]+")
# dfa1_s = get_str_dfa("b")
# dfa2 = get_str_dfa("b[b]+")
# dfa2_s = get_str_dfa("c")
# dfa3 = get_str_dfa("a|b")
# dfa3_s = get_str_dfa("b|c")
# x = Z3ProductSet(dimensions)
# x.add_cube([dfa1, dfa1_s], ["methods_dfa", "paths"])
# x.add_cube([dfa2, dfa2_s], ["methods_dfa", "paths"])
# x.add_cube([dfa3, dfa3_s], ["methods_dfa", "paths"])
#
# dfa4 = get_str_dfa("[a]+|b")
# dfa4_s = get_str_dfa("b")
# dfa5 = get_str_dfa("[b]+|a")
# dfa5_s = get_str_dfa("c")
# y = Z3ProductSet(dimensions)
# y.add_cube([dfa4, dfa4_s], ["methods_dfa", "paths"])
# y.add_cube([dfa5, dfa5_s], ["methods_dfa", "paths"])
# # print(y)
# assert x == y
