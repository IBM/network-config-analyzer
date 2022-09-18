"""Z3 implementation of hyper cube"""
from typing import Type

from z3 import BoolVal, And, sat, Or, Not, Int, String, substitute

from smt_experiments.z3_sets.z3_integer_set import Z3IntegerSet
from smt_experiments.z3_sets.z3_set import Z3Set
from smt_experiments.z3_sets.z3_string_set import Z3StringSet
from smt_experiments.z3_sets.z3_utils import solve_without_model


# TODO: refactor this so it will inherit from Z3Set
# TODO: maybe use interval set and string set instead of what we currently do
class Z3ProductSet(Z3Set):
    _type_to_var_constructor = {
        int: Int,
        str: String
    }
    
    _type_to_z3_set = {
        int: Z3IntegerSet,
        str: Z3StringSet,
    }

    def __init__(self, dim_types: tuple[Type]):
        super(Z3ProductSet, self).__init__()
        self.dim_types = dim_types
        self._vars = [self._type_to_var_constructor[t](str(i)) for i, t in enumerate(dim_types)]
        self.constraints = BoolVal(False)

    def _check_types(self, item: tuple) -> bool:
        return all(type(element) == t for element, t in zip(item, self.dim_types))

    def __contains__(self, item: tuple) -> bool:
        assert self._check_types(item)
        constraint = self.constraints
        for var, value in zip(self._vars, item):
            constraint = And(constraint, var == value)
        return solve_without_model(constraint) == sat

    def copy(self):
        new = Z3ProductSet(self.dim_types)
        new.constraints = self.constraints
        return new

    def __eq__(self, other):
        assert self.dim_types == other.dim_types
        return super(Z3ProductSet, self).__eq__(other)
    
    def __and__(self, other):
        assert self.dim_types == other.dim_types
        return super(Z3ProductSet, self).__and__(other) 
    
    def __iand__(self, other):
        assert self.dim_types == other.dim_types
        return super(Z3ProductSet, self).__iand__(other)

    def __or__(self, other):
        assert self.dim_types == other.dim_types
        return super(Z3ProductSet, self).__or__(other)
        
    def __ior__(self, other):
        assert self.dim_types == other.dim_types
        return super(Z3ProductSet, self).__ior__(other)

    def __sub__(self, other):
        assert self.dim_types == other.dim_types
        return super(Z3ProductSet, self).__sub__(other)

    def __isub__(self, other):
        assert self.dim_types == other.dim_types
        return super(Z3ProductSet, self).__isub__(other)
    
    def contained_in(self, other) -> bool:
        assert self.dim_types == other.dim_types
        return super(Z3ProductSet, self).contained_in(other)
    
    def _check_cube(self, cube: tuple[Z3Set]) -> bool:
        return all(type(z3_set) == self._type_to_z3_set[t]
                   for z3_set, t in zip(cube, self.dim_types))
        
    def _cube_to_formula(self, cube: tuple[Z3Set]):
        formulas = [substitute(z3_set.constraints, (z3_set._var, dim_var)) 
                    for dim_var, z3_set in zip(self._vars, cube)]
        return And(formulas)
    
    def add_cube(self, cube: tuple[Z3Set]) -> object:
        assert self._check_cube(cube)
        self.constraints = Or(self.constraints, self._cube_to_formula(cube))
        return self

    def subtract_cube(self, cube: tuple[Z3Set]):
        assert self._check_cube(cube)
        self.constraints = And(self.constraints, Not(self._cube_to_formula(cube)))
        return self
