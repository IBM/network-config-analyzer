from z3 import And, Int, BoolVal, unsat, sat, Or, Not

from smt_experiments.z3_sets.z3_set import Z3Set
from smt_experiments.z3_sets.z3_utils import solve_without_model


class Z3IntegerSet(Z3Set):

    def __init__(self):
        self._var = Int('x')
        self._constraints = BoolVal(False)

    @classmethod
    def get_universal_set(cls):
        s = cls()
        s._constraints = BoolVal(True)
        return s

    @classmethod
    def get_empty_set(cls):
        return cls()

    def is_empty(self):
        return solve_without_model(self._constraints) == unsat

    def __contains__(self, item: int) -> bool:
        if not isinstance(item, int):
            raise TypeError
        constraint = And(self._var == item, self._constraints)
        return solve_without_model(constraint) == sat

    def copy(self):
        new = Z3IntegerSet()
        new._constraints = self._constraints
        return new

    def __iand__(self, other):
        if not isinstance(other, Z3IntegerSet):
            raise TypeError
        self._constraints = And(self._constraints, other._constraints)
        return self

    def __ior__(self, other):
        if not isinstance(other, Z3IntegerSet):
            raise TypeError
        self._constraints = Or(self._constraints, other._constraints)
        return self

    def __invert__(self):
        new = self.copy()
        new._constraints = Not(new._constraints)
        return new

    def __str__(self):
        return str(self._constraints)

    @classmethod
    def get_interval_set(cls, start: int, end: int):
        new = cls()
        new._constraints = And(new._var >= start, new._var <= end)
        return new

    @property
    def python_type(self):
        return int
