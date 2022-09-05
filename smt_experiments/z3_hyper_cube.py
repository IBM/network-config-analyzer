"""Z3 implementation of hyper cube"""
from typing import Any

from z3 import BoolVal, And, sat, Or, Not, Int, unsat

from smt_experiments.z3_utils import solve_without_model

# TODO: create unittests to make sure that this works


class Z3HyperCube:
    def __init__(self, dimension_names: list[str]):
        self.constraints = BoolVal(False)
        self._variable_name_to_z3_var = {dimension_name: Int(dimension_name) for dimension_name in dimension_names}

    def __eq__(self, other):
        other: Z3HyperCube
        assert self._check_dimensions(other._variable_name_to_z3_var)
        constraint = Or(
            And(self.constraints, Not(other.constraints)),
            And(Not(self.constraints), other.constraints)
        )
        return solve_without_model(constraint) == unsat

    def copy(self):
        pass

    def __contains__(self, item: dict[str, int]):
        self._check_dimensions(item)
        constraint = And([self._variable_name_to_z3_var[varname] == value for
                          varname, value in item.items()])
        constraint = And(constraint, self.constraints)
        result = solve_without_model(constraint)
        return result == sat

    def __and__(self, other):
        pass

    def __iand__(self, other):
        pass

    def __or__(self, other):
        pass

    def __ior__(self, other):
        pass

    def __sub__(self, other):
        pass

    def __isub__(self, other):
        pass

    def is_all(self):
        pass

    def contained_in(self, other) -> bool:
        other: Z3HyperCube
        assert self._check_dimensions(other._variable_name_to_z3_var)
        constraint = And(self.constraints, Not(other.constraints))
        return solve_without_model(constraint) == unsat

    def _check_dimensions(self, cube: dict[str, Any]) -> bool:
        return set(cube.keys()) == set(self._variable_name_to_z3_var.keys())

    def _cube_to_formula(self, cube: dict[str, tuple[int, int]]):
        assert self._check_dimensions(cube)
        formulas = []
        for varname, (start, end) in cube.items():
            z3_var = self._variable_name_to_z3_var[varname]
            formulas.append(And(z3_var >= start, z3_var <= end))
        return And(formulas)

    def add_cube(self, cube: dict[str, tuple[int, int]]):
        self.constraints = Or(self.constraints, self._cube_to_formula(cube))

    def subtract_cube(self, cube: dict[str, tuple[int, int]]):
        self.constraints = And(self.constraints, Not(self._cube_to_formula(cube)))
