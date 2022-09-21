"""Z3 implementation of hyper cube"""
# TODO: inherit from HyperCubeSet interface and implement it, try to pass tests
#   from `test_z3_hyper_cube_set`
#   update when finished
from typing import Type, Union

from z3 import BoolVal, And, sat, Or, Not, Int, String, substitute, unsat

from DimensionsManager import DimensionsManager
from smt_experiments.hyper_cube_set import HyperCubeSet
from smt_experiments.z3_sets.z3_integer_set import Z3IntegerSet
from smt_experiments.z3_sets.z3_set import Z3Set
from smt_experiments.z3_sets.z3_string_set import Z3StringSet
from smt_experiments.z3_sets.z3_utils import solve_without_model


class Z3ProductSet(Z3Set, HyperCubeSet):
    _type_to_var_constructor = {
        int: Int,
        str: String
    }
    
    _type_to_z3_set = {
        int: Z3IntegerSet,
        str: Z3StringSet,
    }

    _z3_set_to_type = {v: k for k, v in _type_to_z3_set.items()}

    _dim_manager_type_to_primitive_type = {
        DimensionsManager.DimensionType.IntervalSet: int,
        DimensionsManager.DimensionType.DFA: str,
    }

    def __init__(self, dimensions: list[str], allow_all: bool = False):
        super(Z3ProductSet, self).__init__()

        self._dim_dict = {}
        for dim_name in dimensions:
            dim_type = DimensionsManager().get_dimension_type_by_name(dim_name)
            dim_type = self._dim_manager_type_to_primitive_type[dim_type]
            dim_var = self._type_to_var_constructor[dim_type](dim_name)
            self._dim_dict[dim_name] = {'type': dim_type, 'var': dim_var}

        self.constraints = BoolVal(allow_all)

    def __bool__(self):
        return not self.is_empty()

    @classmethod
    def create_from_cube(cls, all_dims: list[str], cube: list[Z3Set],
                         cube_dims: list[str]):
        assert cube
        assert len(cube) == len(cube_dims)
        s = cls(all_dims, False)
        s.add_cube(cube, cube_dims)
        return s

    def add_cube(self, cube: list[Z3Set], cube_dimensions: list[str] = None):
        if cube_dimensions is None:
            cube_dimensions = list(self._dim_dict.keys())[:len(cube)]

        self._check_cube(cube, cube_dimensions)

        if len(cube) == 0:  # or any(dim_value.is_empty() for dim_value in cube):
            return

        cube_formula = self._cube_to_formula(cube, cube_dimensions)
        self.constraints = Or(self.constraints, cube_formula)

    def _check_cube(self, cube: list[Z3Set], cube_dimensions: list[str]) -> None:
        if not isinstance(cube, list):
            raise ValueError(f'cube must be a list, got {type(cube)}')

        if len(cube_dimensions) != len(cube):
            raise ValueError(f'mismatch in the number of dimensions. '
                             f'cube_dimensions has {len(cube_dimensions)}, '
                             f'cube has {len(cube)}.')

        given_types = [self._z3_set_to_type[type(z3_set)] for z3_set in cube]
        expected_types = [self._dim_dict[dim_name]['type'] for dim_name in cube_dimensions]
        if given_types != expected_types:
            raise ValueError('given types do not match expected types. '
                             f'given={given_types}, '
                             f'expected={expected_types}.')

    def _cube_to_formula(self, cube: list[Z3Set], cube_dimensions: list[str]):
        formula_list = []
        for z3_set, dim_name in zip(cube, cube_dimensions):
            z3_var = self._dim_dict[dim_name]['var']
            formula = z3_set.get_constraints_with_different_var(z3_var)
            formula_list.append(formula)

        return And(formula_list)

    def add_hole(self, cube: list[Z3Set],
                 cube_dimensions: list[str] = None) -> None:
        if cube_dimensions is None:
            cube_dimensions = list(self._dim_dict.keys())[:len(cube)]

        self._check_cube(cube, cube_dimensions)

        if len(cube) == 0:  # or any(dim_value.is_empty() for dim_value in cube):
            return

        cube_formula = self._cube_to_formula(cube, cube_dimensions)
        self.constraints = And(self.constraints, Not(cube_formula))

    def _check_other(self, other) -> None:
        other: Z3ProductSet
        for dim_name1, dim_name2 in zip(self._dim_dict, other._dim_dict):
            if dim_name1 != dim_name2:
                raise ValueError
            dim_type1 = self._dim_dict[dim_name1]['type']
            dim_type2 = other._dim_dict[dim_name2]['type']
            if dim_type1 != dim_type2:
                raise ValueError

    def __eq__(self, other):
        self._check_other(other)
        return super(Z3ProductSet, self).__eq__(other)

    def __and__(self, other):
        self._check_other(other)
        return super(Z3ProductSet, self).__and__(other)

    def __iand__(self, other):
        self._check_other(other)
        return super(Z3ProductSet, self).__iand__(other)

    def __or__(self, other):
        self._check_other(other)
        return super(Z3ProductSet, self).__or__(other)

    def __ior__(self, other):
        self._check_other(other)
        return super(Z3ProductSet, self).__ior__(other)

    def __sub__(self, other):
        self._check_other(other)
        return super(Z3ProductSet, self).__sub__(other)

    def __isub__(self, other):
        self._check_other(other)
        return super(Z3ProductSet, self).__isub__(other)

    def copy(self):
        new = Z3ProductSet(list(self._dim_dict.keys()))
        new.constraints = self.constraints
        return new

    def _check_item(self, item: list[Union[int, str]]) -> None:
        if len(item) != len(self._dim_dict):
            raise ValueError('number of dimensions mismatch. '
                             f'expected {len(self._dim_dict)}, '
                             f'got {len(item)}.')

        given_types = [type(i) for i in item]
        expected_types = [dim_data['type'] for _, dim_data in self._dim_dict.items()]
        if given_types != expected_types:
            raise ValueError(f'types mismatch. '
                             f'expected types {expected_types}, '
                             f'got {given_types}.')

    def __contains__(self, item: list[Union[int, str]]) -> bool:
        self._check_item(item)
        var_list = [dim_data['var'] for _, dim_data in self._dim_dict.items()]
        value_eq_constraint = And([var == value for var, value in zip(var_list, item)])
        constraint = And(value_eq_constraint, self.constraints)
        return solve_without_model(constraint) == sat

    def contained_in(self, other) -> bool:
        self._check_other(other)
        return super(Z3ProductSet, self).contained_in(other)

    def is_all(self) -> bool:
        return super(Z3ProductSet, self).is_universal()

    def clear(self) -> None:
        self.constraints = BoolVal(False)

    def set_all(self) -> None:
        self.constraints = BoolVal(True)


