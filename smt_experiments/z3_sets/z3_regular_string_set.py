import sre_parse

from z3 import Empty, ReSort, Full, sat, StringSort, InRe, Intersect, Union, Complement

from smt_experiments.role_analyzer import regex_to_z3_expr
from smt_experiments.z3_sets.z3_set import Z3Set
from smt_experiments.z3_sets.z3_utils import solve_without_model


class Z3RegularStringSet(Z3Set):
    def __init__(self):
        self._regex = self._get_empty_regex()

    @classmethod
    def get_universal_set(cls):
        new = cls()
        new._regex = Full(ReSort(StringSort()))
        return new

    @staticmethod
    def _get_empty_regex():
        return Empty(ReSort(StringSort()))

    def is_empty(self):
        constraint = self._regex == self._get_empty_regex()
        return solve_without_model(constraint) == sat

    @classmethod
    def get_empty_set(cls):
        return cls()

    @property
    def python_type(self):
        return str

    @classmethod
    def from_regex(cls, regex: str):
        parsed_regex = sre_parse.parse(regex)
        z3_regex = regex_to_z3_expr(parsed_regex)
        new = cls()
        new._regex = z3_regex
        return new

    def __contains__(self, item: str) -> bool:
        constraint = InRe(item, self._regex)
        return solve_without_model(constraint) == sat

    def copy(self):
        new = Z3RegularStringSet()
        new._regex = self._regex
        return new

    def __iand__(self, other):
        other: Z3RegularStringSet
        self._regex = Intersect(self._regex, other._regex)
        return self

    def __ior__(self, other):
        other: Z3RegularStringSet
        self._regex = Union(self._regex, other._regex)
        return self

    def __invert__(self):
        new = Z3RegularStringSet()
        new._regex = Complement(self._regex)
        return new

    def __str__(self):
        return str(self._regex)

