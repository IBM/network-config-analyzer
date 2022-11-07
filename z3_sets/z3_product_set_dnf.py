from copy import deepcopy
from typing import Union

from nca.CoreDS.DimensionsManager import DimensionsManager
from experiments.hyper_cube_set import HyperCubeSet
from experiments.z3_sets.z3_set import Z3Set


# TODO: implement z3 regular string set, pass tests
# TODO: change string set to regular, pass tests with regex
# TODO: ideas for optimization:
#  - trying to use a single solver might make things more efficient. Try that.
#  - creating a benchmark for this set, to consider different implementations.


class Z3ProductSetDNF(Z3Set, HyperCubeSet):
    @classmethod
    def get_universal_set(cls):
        raise NotImplementedError

    @classmethod
    def get_empty_set(cls):
        raise NotImplementedError

    @property
    def python_type(self):
        raise NotImplementedError

    _dim_manager_type_to_primitive_type = {
        DimensionsManager.DimensionType.IntervalSet: int,
        DimensionsManager.DimensionType.DFA: str,
    }

    def __init__(self, dimensions: list[str], allow_all: bool = False):
        # If a cube is empty, it will not be added.
        self._dim_name_to_type = {}
        for dim_name in dimensions:
            dim_type = DimensionsManager().get_dimension_type_by_name(dim_name)
            dim_type = self._dim_manager_type_to_primitive_type[dim_type]
            self._dim_name_to_type[dim_name] = dim_type

        # each cube is a dictionary from dim name to a set.
        # If a give dim does not appear in there then it is assumed to be the universal set
        self.cubes = []

        if allow_all:
            universal_cube = self._get_universal_cube()
            self.cubes.append(universal_cube)

    @staticmethod
    def _get_universal_cube():
        return {}

    def is_empty(self) -> bool:
        return len(self.cubes) == 0
        # for cube in self.cubes:
        #     if not self._cube_is_empty(cube):
        #         return False
        # return True

    @staticmethod
    def create_from_cube(all_dims: list[str], cube: list[Z3Set], cube_dims: list[str]):
        assert len(cube) > 0
        assert len(cube) == len(cube_dims)
        s = Z3ProductSetDNF(all_dims, False)
        s.add_cube(cube, cube_dims)
        return s

    def add_cube(self, cube: list[Z3Set], cube_dimensions: list[str] = None):
        if cube_dimensions is None:
            cube_dimensions = list(self._dim_name_to_type.keys())[:len(cube)]

        self._check_cube(cube, cube_dimensions)
        if len(cube) == 0:
            return

        cube = dict(zip(cube_dimensions, cube))

        if self._cube_is_empty(cube):
            return

        self.cubes.append(cube)

    def _add_hole_aux(self, cube: dict[str, Z3Set]):
        if self._cube_is_empty(cube):
            return

        new_cubes = []
        for contained_cube in self.cubes:
            for dim_name, dim_set in cube.items():
                new_cube = deepcopy(contained_cube)
                if dim_name in new_cube:
                    new_cube[dim_name] -= dim_set
                else:
                    new_cube[dim_name] = ~dim_set
                if not self._cube_is_empty(new_cube):
                    new_cubes.append(new_cube)
        self.cubes = new_cubes

    def add_hole(self, cube: list[Z3Set], cube_dimensions: list[str] = None) -> None:
        if cube_dimensions is None:
            cube_dimensions = list(self._dim_name_to_type.keys())[:len(cube)]
        self._check_cube(cube, cube_dimensions)
        if len(cube) == 0:
            return

        cube = dict(zip(cube_dimensions, cube))
        self._add_hole_aux(cube)

    @staticmethod
    def _cube_is_empty(cube: dict[str, Z3Set]) -> bool:
        for s in cube.values():
            if s.is_empty():
                return True
        return False

    def _check_cube(self, cube: list[Z3Set], cube_dimensions: list[str]) -> None:
        if not isinstance(cube, list):
            raise ValueError(f'cube must be a list, got {type(cube)}')

        if len(cube_dimensions) != len(cube):
            raise ValueError(f'mismatch in the number of dimensions. '
                             f'cube_dimensions has {len(cube_dimensions)}, '
                             f'cube has {len(cube)}.')

        given_types = [s.python_type for s in cube]
        expected_types = [self._dim_name_to_type[dim_name] for dim_name in cube_dimensions]
        if given_types != expected_types:
            raise ValueError('given types do not match expected types. '
                             f'given={given_types}, '
                             f'expected={expected_types}.')

    def _check_other(self, other) -> None:
        other: Z3ProductSetDNF

        dim_names_1 = list(self._dim_name_to_type.keys())
        dim_names_2 = list(other._dim_name_to_type.keys())
        if dim_names_1 != dim_names_2:
            raise ValueError(f'dimensions names do not match: {dim_names_1}!={dim_names_2}.')

        dim_types_1 = list(self._dim_name_to_type.values())
        dim_types_2 = list(self._dim_name_to_type.values())
        if dim_types_1 != dim_types_2:
            raise ValueError(f'dimensions types do not match: {dim_types_1}!={dim_types_2}.')

    def _check_item(self, item: list[Union[int, str]]) -> None:
        if len(item) != len(self._dim_name_to_type):
            raise ValueError('number of dimensions mismatch. '
                             f'expected {len(self._dim_name_to_type)}, '
                             f'got {len(item)}.')

        given_types = [type(i) for i in item]
        expected_types = [dim_type for _, dim_type in self._dim_name_to_type.items()]
        if given_types != expected_types:
            raise ValueError(f'types mismatch. '
                             f'expected types {expected_types}, '
                             f'got {given_types}.')

    def _cube_contains(self, cube: dict[str, Z3Set], item: list[Union[int, str]]) -> bool:
        for dim_name, dim_value in zip(self._dim_name_to_type.keys(), item):
            if dim_name in cube:
                if dim_value not in cube[dim_name]:
                    return False
        return True

    def __contains__(self, item: list[Union[int, str]]) -> bool:
        self._check_item(item)
        for cube in self.cubes:
            if self._cube_contains(cube, item):
                return True
        return False

    def copy(self):
        dimensions = list(self._dim_name_to_type.keys())
        new = Z3ProductSetDNF(dimensions)
        new.cubes = deepcopy(self.cubes)
        return new

    def __ior__(self, other):
        self._check_other(other)
        self.cubes += other.cubes
        return self

    def __str__(self):
        return str(self.cubes)

    def is_all(self) -> bool:
        return self.is_universal()

    def set_all(self) -> None:
        self.cubes = [self._get_universal_cube()]

    def clear(self) -> None:
        self.cubes = []

    def __invert__(self):
        new = Z3ProductSetDNF(list(self._dim_name_to_type.keys()), allow_all=True)
        for cube in self.cubes:
            new._add_hole_aux(cube)
        return new

    @staticmethod
    def _and_cubes(cube1: dict[str, Z3Set], cube2: dict[str, Z3Set]) -> dict[str, Z3Set]:
        new_cube = deepcopy(cube1)

        for dim_name, dim_set in cube2.items():
            if dim_name in new_cube:
                new_cube[dim_name] &= dim_set
            else:
                new_cube[dim_name] = dim_set

        return new_cube

    def __iand__(self, other):
        self._check_other(other)

        new_cubes = []
        for cube1 in self.cubes:
            for cube2 in other.cubes:
                new_cube = self._and_cubes(cube1, cube2)
                if not self._cube_is_empty(new_cube):
                    new_cubes.append(new_cube)
        self.cubes = new_cubes
        return self


def example():
    dims = ['0', '1', '2']
    from experiments.experiments.multiple_integer_dimensions.run_experiment import init_dim_manager
    init_dim_manager(dims)
    s = Z3ProductSetDNF(dims)
    from experiments.z3_sets.z3_integer_set import Z3IntegerSet
    start = 0
    step = 10
    s.add_cube([
        Z3IntegerSet.get_interval_set(start, start+step),
        Z3IntegerSet.get_interval_set(start, start+step),
        Z3IntegerSet.get_interval_set(start, start+step),
    ])
    assert [5, 5, 5] in s
    assert [0, 10, 11] not in s
    s1 = s.copy()

    start += 2 * step
    s.add_cube([
        Z3IntegerSet.get_interval_set(start, start + step),
        Z3IntegerSet.get_interval_set(start, start + step),
        Z3IntegerSet.get_interval_set(start, start + step),
    ])

    s1.contained_in(s)


if __name__ == '__main__':
    example()
