from z3 import Solver, sat, unsat, And, Not, BoolVal, FreshInt, substitute, Or, BoolRef

# TODO: maybe look at others code using Z3 to get ideas on how to optimize implementation
# TODO: search for the z3 paper, it might offer some interesting feedback.
# TODO: check out z3 simple solver, or other optimization options


class Z3IntegerSet:
    _solver = Solver()
    # _solver = SimpleSolver()

    def __init__(self):
        self.constraints = BoolVal(False)
        self.var = FreshInt()

    @staticmethod
    def _solve(constraints: BoolRef):
        # TODO: this function has a lot of effect on the timing. experiment with different options
        Z3IntegerSet._solver.push()
        Z3IntegerSet._solver.add(constraints)
        result = Z3IntegerSet._solver.check()
        Z3IntegerSet._solver.pop()
        return result

    @staticmethod
    def get_interval_set(start: int, end: int):
        integer_set = Z3IntegerSet()
        integer_set.constraints = And(integer_set.var <= end, integer_set.var >= start)
        return integer_set

    def __contains__(self, item: int) -> bool:
        constraints = And(self.constraints, self.var == item)
        if self._solve(constraints) == sat:
            return True
        return False

    def contained_in(self, other) -> bool:
        other: Z3IntegerSet
        constraints = And(self.constraints, Not(other.constraints), self.var == other.var)
        if self._solve(constraints) == unsat:
            return True
        return False

    def __eq__(self, other):
        other: Z3IntegerSet
        constraint = And(
            Or(
                And(self.constraints, Not(other.constraints)),
                And(Not(self.constraints), other.constraints)
            ),
            self.var == other.var
        )
        if self._solve(constraint) == unsat:
            return True
        return False

    def copy(self):
        new = Z3IntegerSet()
        new.constraints = substitute(self.constraints, (self.var, new.var))
        return new

    def __repr__(self):
        return f'<Z3IntegerSet: {str(self.constraints)}>'

    def __iand__(self, other):
        other: Z3IntegerSet
        other_constraints = substitute(other.constraints, (other.var, self.var))
        self.constraints = And(self.constraints, other_constraints)
        return self

    def __ior__(self, other):
        other: Z3IntegerSet
        other_constraints = substitute(other.constraints, (other.var, self.var))
        self.constraints = Or(self.constraints, other_constraints)
        return self

    def __isub__(self, other):
        other: Z3IntegerSet
        other_constraints = substitute(other.constraints, (other.var, self.var))
        self.constraints = And(self.constraints, Not(other_constraints))
        return self

