import unittest

from z3 import Re, Plus, Concat, Union, String, InRe, Or, And, Not, Diff, Distinct, sat

from z3_sets.z3_utils import solve_with_model


class Z3RegexGetsStuckExample(unittest.TestCase):
    """This test cases present examples of z3 getting stuck when we have multiple regex constraints."""
    @staticmethod
    def check_formula(formula):
        print(f'checking formula: {formula}.')
        result, model = solve_with_model(formula)
        if result == sat:
            print(f'sat. model={model}.')
        else:
            print('unsat.')

    def test_get_stuck_0(self):
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
        # check if the two formulas are identical
        formula = Distinct(formula_1, formula_2)
        self.check_formula(formula)

    def test_z3_succeeds_0(self):
        # Does not get stuck
        a = Re('a')
        a_plus = Plus(a)
        two_or_more_a = Concat(a, a_plus)
        b = Re('b')
        b_plus = Plus(b)
        two_or_more_b = Concat(b, b_plus)
        two_or_more_a_or_two_or_more_b = Union(two_or_more_a, two_or_more_b)

        two_or_more_b_0 = Diff(two_or_more_a_or_two_or_more_b, two_or_more_a)
        two_or_more_a_0 = Diff(two_or_more_a_or_two_or_more_b, two_or_more_b)
        # r = z3.Diff(r, two_or_more_b)

        s = String('s')
        formula = And(
            InRe(s, two_or_more_b_0),
            InRe(s, two_or_more_a_0)
        )
        self.check_formula(formula)

    def test_z3_succeeds_1(self):
        # Does not get stuck
        a = Re('a')
        a_plus = Plus(a)
        two_or_more_a = Concat(a, a_plus)
        b = Re('b')
        b_plus = Plus(b)
        two_or_more_b = Concat(b, b_plus)
        two_or_more_a_or_two_or_more_b = Union(two_or_more_a, two_or_more_b)

        two_or_more_b_0 = Diff(two_or_more_a_or_two_or_more_b, two_or_more_a)
        two_or_more_a_0 = Diff(two_or_more_a_or_two_or_more_b, two_or_more_b)
        # r = z3.Diff(r, two_or_more_b)

        s = String('s')
        formula = two_or_more_a_0 != two_or_more_a
        # formula = InRe(s, two_or_more_a_0) != InRe(s, two_or_more_a) -- not terminating
        self.check_formula(formula)

    def test_z3_stuck_1(self):
        # Does not get stuck
        a = Re('a')
        a_plus = Plus(a)
        two_or_more_a = Concat(a, a_plus)
        b = Re('b')
        b_plus = Plus(b)
        two_or_more_b = Concat(b, b_plus)
        two_or_more_a_or_two_or_more_b = Union(two_or_more_a, two_or_more_b)

        two_or_more_b_0 = Diff(two_or_more_a_or_two_or_more_b, two_or_more_a)
        two_or_more_a_0 = Diff(two_or_more_a_or_two_or_more_b, two_or_more_b)
        # r = z3.Diff(r, two_or_more_b)

        s = String('s')
        # formula = two_or_more_a_0 != two_or_more_a
        formula = Or(
            And(InRe(s, two_or_more_a_0), Not(InRe(s, two_or_more_a))),
            And(Not(InRe(s, two_or_more_a_0)), InRe(s, two_or_more_a))
        )
        self.check_formula(formula)


if __name__ == '__main__':
    unittest.main()
