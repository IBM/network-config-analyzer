import z3
from z3 import BoolRef, Solver, sat


# TODO: check out z3 simple solver, or other optimization options
# TODO: maybe don't instantiate a new solver every time
# TODO: use the pop, push mechanism for z3


def solve_without_model(constraints: BoolRef, timeout=False):
    solver = Solver()
    if timeout:
        solver.set('timeout', 5)
    solver.add(constraints)
    result = solver.check()
    return result


def solve_with_model(constraints: BoolRef):
    solver = Solver()
    solver.add(constraints)
    result = solver.check()
    if result == sat:
        return result, solver.model()
    return result, None
