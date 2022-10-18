# TODO: how should we take into account the set of allowed alphabet?
#   especially the "is_all_words" function
from typing import Optional

import z3
from z3 import sat, PrefixOf, SuffixOf, ModelRef, String, Or, BoolVal, unsat, And, Not

from smt_experiments.z3_sets.z3_set import Z3Set
from smt_experiments.z3_sets.z3_utils import solve_with_model, solve_without_model


# TODO: create a new version that supports regexps
class Z3SimpleStringSet(Z3Set):
    @property
    def python_type(self):
        return str

    def __init__(self):
        self._var = String('s')
        self._constraints = BoolVal(False)

    @classmethod
    def get_universal_set(cls):
        new = cls()
        new._constraints = BoolVal(True)
        return new

    def is_empty(self):
        return solve_without_model(self._constraints) == unsat

    @classmethod
    def get_empty_set(cls):
        return cls()

    def __contains__(self, item: str) -> bool:
        if not isinstance(item, str):
            raise TypeError
        constraint = And(self._var == item, self._constraints)
        return solve_without_model(constraint) == sat

    def copy(self):
        new = Z3SimpleStringSet()
        new._constraints = self._constraints
        return new

    def __iand__(self, other):
        if not isinstance(other, Z3SimpleStringSet):
            raise TypeError
        self._constraints = And(self._constraints, other._constraints)
        return self

    def __ior__(self, other):
        if not isinstance(other, Z3SimpleStringSet):
            raise TypeError
        self._constraints = Or(self._constraints, other._constraints)
        return self

    def __invert__(self):
        new = self.copy()
        new._constraints = Not(self._constraints)
        return new

    def __str__(self):
        return str(self._constraints)

    @classmethod
    def from_wildcard(cls, s: str):
        str_set = cls()
        if '*' not in s:
            str_set._constraints = str_set._var == s
        elif '*' == s:
            str_set._constraints = BoolVal(True)
        elif '*' == s[-1]:
            str_set._constraints = PrefixOf(s[:-1], str_set._var)
        elif '*' == s[0]:
            str_set._constraints = SuffixOf(s[1:], str_set._var)

        else:
            raise ValueError(f'* should only appear at the start or end of the string. got {s}.')

        return str_set

    @classmethod
    def dfa_from_regex(cls, regex: str):
        str_set = cls()
        z3_regex = z3.Re(regex)
        str_set._constraints = z3.InRe(str_set._var, z3_regex)
        return z3_regex
