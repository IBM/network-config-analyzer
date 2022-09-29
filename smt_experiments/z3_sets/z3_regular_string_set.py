# TODO: implement
from z3 import Re, Empty, ReSort, String, Full, sat, StringSort

from smt_experiments.z3_sets.z3_set import Z3Set
from smt_experiments.z3_sets.z3_utils import solve_without_model


class Z3RegularStringSet(Z3Set):
    def __init__(self):
        self._regex = self._get_empty_regex()
        # self._regex = Empty()
    @classmethod
    def get_universal_set(cls):
        new = cls()
        new._regex = Full(ReSort(StringSort()))
        return new

    @staticmethod
    def _get_empty_regex():
        return Empty(ReSort(StringSort()))

    # TODO: implement, write tests.
    def is_empty(self):
        constraint = self._regex == self._get_empty_regex()
        return solve_without_model(constraint) == sat

    @classmethod
    def get_empty_set(cls):
        pass

    @property
    def python_type(self):
        return str

    def __contains__(self, item) -> bool:
        pass

    def copy(self):
        pass

    def __iand__(self, other):
        pass

    def __ior__(self, other):
        pass

    def __invert__(self):
        pass

    def __str__(self):
        pass

