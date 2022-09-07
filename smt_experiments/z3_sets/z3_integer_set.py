from z3 import And, Int

from smt_experiments.z3_sets.z3_set import Z3Set


# TODO: maybe look at others code using Z3 to get ideas on how to optimize implementation
# TODO: search for the z3 paper, it might offer some interesting feedback.


class Z3IntegerSet(Z3Set):
    _var = Int(Z3Set._var_name)

    @classmethod
    def get_interval_set(cls, start: int, end: int):
        integer_set = cls()
        integer_set.constraints = And(integer_set._var <= end, integer_set._var >= start)
        return integer_set
