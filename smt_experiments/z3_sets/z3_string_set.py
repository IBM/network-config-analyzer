# Exact - "bla": only "bla"
# Prefix - "bla*": starts with "bla"
# Suffix - "*bla": ends with "bla"
# Presence - "*": any non-empty
# TODO: how should we take into account the set of allowed alphabet?
#   especially the "is_all_words" function
# TODO: take the tests for the MinDFA module and compare it to the Z3
#  implementation
from copy import copy
from typing import Optional

import z3
from z3 import And, BoolRef, Solver, sat, PrefixOf, \
    SuffixOf, Length, unsat, Not, substitute, Or, BoolVal, ModelRef, SeqRef, Int, Exists, String

from smt_experiments.z3_sets.z3_utils import solve_without_model, solve_with_model


class Z3StringSet:
    _var_name = 's'
    _var = String(_var_name)

    def __init__(self):
        self.constraints = BoolVal(False)

    def __contains__(self, item: str):
        constraints = And(
            self._var == item,
            self.constraints
        )
        return solve_without_model(constraints) == sat

    def __eq__(self, other):
        constraints = Or(
            And(self.constraints, Not(other.constraints)),
            And(Not(self.constraints), other.constraints)
        )
        return solve_without_model(constraints) == unsat

    @classmethod
    def from_str(cls, s: str):
        str_set = cls()

        if '*' not in s:
            str_set.constraints = str_set._var == s
        elif '*' == s:
            # TODO: is it true that this means that the string is not empty?
            str_set.constraints = Length(str_set._var) > 0
        elif '*' == s[-1]:
            str_set.constraints = PrefixOf(s[:-1], str_set._var)
        elif '*' == s[0]:
            str_set.constraints = SuffixOf(s[1:], str_set._var)

        else:
            raise RuntimeError(f'* should only appear at the start or end of the string. got {s}.')

        return str_set

    @classmethod
    def get_all_words_set(cls):
        str_set = cls()
        str_set.constraints = BoolVal(True)
        return str_set

    @classmethod
    def get_empty_set(cls):
        str_set = cls()
        str_set.constraints = BoolVal(False)
        return str_set

    def is_all_words(self) -> bool:
        constraints = Not(self.constraints)
        return solve_without_model(constraints) == unsat

    def is_empty(self):
        return solve_without_model(self.constraints) == unsat

    def contained_in(self, other) -> bool:
        constraints = And(self.constraints, Not(other.constraints))
        return solve_without_model(constraints) == unsat

    def copy(self):
        str_set = Z3StringSet()
        str_set.constraints = self.constraints
        return str_set

    def __ior__(self, other):
        self.constraints = Or(self.constraints, other.constraints)
        return self

    def __or__(self, other):
        str_set = self.copy()
        str_set |= other
        return str_set

    def __iand__(self, other):
        self.constraints = And(self.constraints, other.constraints)
        return self

    def __and__(self, other):
        str_set = self.copy()
        str_set &= other
        return str_set

    def __isub__(self, other):
        self.constraints = And(self.constraints, Not(other.constraints))
        return self

    def __sub__(self, other):
        str_set = self.copy()
        str_set -= other
        return str_set

    def get_example_from_set(self) -> Optional[str]:
        result, model = solve_with_model(self.constraints)
        if result == sat:
            model: ModelRef
            example = model.eval(self._var).as_string()
            return example
        return None
