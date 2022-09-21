import z3
from z3 import sat, unsat, And, Not, BoolVal, Or, Int, ExprRef, simplify, substitute, Distinct

from smt_experiments.z3_sets.z3_utils import solve_without_model


# TODO: maybe look at others code using Z3 to get ideas on how to optimize implementation
# TODO: search for the z3 paper, it might offer some interesting feedback.


class Z3Set:
    _var_name = 'x'
    _var: ExprRef

    def __init__(self):
        self.constraints = BoolVal(False)

    @classmethod
    def get_universal_set(cls):
        z3_set = cls()
        z3_set.constraints = BoolVal(True)
        return z3_set

    @classmethod
    def get_empty_set(cls):
        z3_set = cls()
        z3_set.constraints = BoolVal(False)
        return z3_set

    def is_universal(self) -> bool:
        constraints = Not(self.constraints)
        return solve_without_model(constraints) == unsat

    def is_empty(self):
        return solve_without_model(self.constraints) == unsat

    def __contains__(self, item: int) -> bool:
        constraints = And(self.constraints, self._var == item)
        return solve_without_model(constraints) == sat

    def contained_in(self, other) -> bool:
        constraints = And(self.constraints, Not(other.constraints))
        return solve_without_model(constraints) == unsat

    def __eq__(self, other):
        # constraint = Or(And(self.constraints, Not(other.constraints)),
        #                 And(Not(self.constraints), other.constraints))
        constraint = Distinct(self.constraints, other.constraints)
        return solve_without_model(constraint) == unsat

    def copy(self):
        new = self.__class__()
        new.constraints = self.constraints
        return new

    def __iand__(self, other):
        self.constraints = And(self.constraints, other.constraints)
        return self

    def __and__(self, other):
        new = self.copy()
        new &= other
        return new

    def __ior__(self, other):
        self.constraints = Or(self.constraints, other.constraints)
        return self

    def __or__(self, other):
        new = self.copy()
        new |= other
        return new

    def __isub__(self, other):
        self.constraints = And(self.constraints, Not(other.constraints))
        return self

    def __sub__(self, other):
        new = self.copy()
        new -= other
        return new

    def __str__(self):
        return str(self.constraints)

    def get_constraints_with_different_var(self, new_var: z3.ExprRef) -> z3.ExprRef:
        return substitute(self.constraints, (self._var, new_var))
