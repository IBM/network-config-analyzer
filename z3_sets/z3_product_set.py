from typing import Union

from z3 import BoolVal, And, sat, Or, Not, Int, String, unsat, substitute

from nca.CoreDS.DimensionsManager import DimensionsManager
from z3_sets.hyper_cube_set import HyperCubeSet
from z3_sets.z3_integer_set import Z3IntegerSet
from z3_sets.z3_set import Z3Set
from z3_sets.z3_simple_string_set import Z3SimpleStringSet
from z3_sets.z3_utils import solve_without_model


class Z3ProductSet(Z3Set, HyperCubeSet):
    """Z3 implementation of hyper cube, implemented by creating a single long formula."""
    _type_to_var_constructor = {
        int: Int,
        str: String
    }
    _type_to_z3_set = {
        int: Z3IntegerSet,
        str: Z3SimpleStringSet,
    }
    _z3_set_to_type = {v: k for k, v in _type_to_z3_set.items()}
    _dim_manager_type_to_primitive_type = {
        DimensionsManager.DimensionType.IntervalSet: int,
        DimensionsManager.DimensionType.DFA: str,
    }

    def __init__(self, dimensions: list[str], allow_all: bool = False):
        self._dim_dict = {}
        for dim_name in dimensions:
            dim_type = DimensionsManager().get_dimension_type_by_name(dim_name)
            dim_type = self._dim_manager_type_to_primitive_type[dim_type]
            dim_var = self._type_to_var_constructor[dim_type](dim_name)
            self._dim_dict[dim_name] = {'type': dim_type, 'var': dim_var}

        self._constraints = BoolVal(allow_all)

    def __iand__(self, other):
        assert isinstance(other, Z3ProductSet)
        self._check_other(other)
        self._constraints = And(self._constraints, other._constraints)
        return self

    def __ior__(self, other):
        assert isinstance(other, Z3ProductSet)
        self._check_other(other)
        self._constraints = Or(self._constraints, other._constraints)
        return self

    def __invert__(self):
        new = self.copy()
        new._constraints = Not(self._constraints)
        return new

    def is_empty(self):
        return solve_without_model(self._constraints) == unsat

    def __str__(self):
        return str(self._constraints)

    @staticmethod
    def create_from_cube(all_dims: list[str], cube: list[Union[Z3IntegerSet, Z3SimpleStringSet]], cube_dims: list[str]):
        assert cube
        assert len(cube) == len(cube_dims)
        s = Z3ProductSet(all_dims, False)
        s.add_cube(cube, cube_dims)
        return s

    def add_cube(self, cube: list[Union[Z3IntegerSet, Z3SimpleStringSet]], cube_dimensions: list[str] = None):
        if cube_dimensions is None:
            cube_dimensions = list(self._dim_dict.keys())[:len(cube)]

        self._check_cube(cube, cube_dimensions)

        if len(cube) == 0:  # or any(dim_value.is_empty() for dim_value in cube):
            return

        cube_formula = self._cube_to_formula(cube, cube_dimensions)
        self._constraints = Or(self._constraints, cube_formula)

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

    def _cube_to_formula(self, cube: list[Union[Z3IntegerSet, Z3SimpleStringSet]], cube_dimensions: list[str]):
        formula_list = []
        for z3_set, dim_name in zip(cube, cube_dimensions):
            z3_var = self._dim_dict[dim_name]['var']
            formula = substitute(z3_set._constraints, (z3_set._var, z3_var))
            formula_list.append(formula)

        return And(formula_list)

    def add_hole(self, cube: list[Union[Z3IntegerSet, Z3SimpleStringSet]],
                 cube_dimensions: list[str] = None) -> None:
        if cube_dimensions is None:
            cube_dimensions = list(self._dim_dict.keys())[:len(cube)]

        self._check_cube(cube, cube_dimensions)

        if len(cube) == 0:  # or any(dim_value.is_empty() for dim_value in cube):
            return

        cube_formula = self._cube_to_formula(cube, cube_dimensions)
        self._constraints = And(self._constraints, Not(cube_formula))

    def _check_other(self, other) -> None:
        other: Z3ProductSet
        for dim_name1, dim_name2 in zip(self._dim_dict, other._dim_dict):
            if dim_name1 != dim_name2:
                raise ValueError
            dim_type1 = self._dim_dict[dim_name1]['type']
            dim_type2 = other._dim_dict[dim_name2]['type']
            if dim_type1 != dim_type2:
                raise ValueError

    def copy(self):
        new = Z3ProductSet(list(self._dim_dict.keys()))
        new._constraints = self._constraints
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
        constraint = And(value_eq_constraint, self._constraints)
        return solve_without_model(constraint) == sat

    def is_all(self) -> bool:
        return self.is_universal()

    def clear(self) -> None:
        self._constraints = BoolVal(False)

    def set_all(self) -> None:
        self._constraints = BoolVal(True)

    # those are implemented so we can inherit from Z3Set.
    @classmethod
    def get_universal_set(cls):
        raise NotImplementedError

    @classmethod
    def get_empty_set(cls):
        raise NotImplementedError

    @property
    def python_type(self):
        raise NotImplementedError
