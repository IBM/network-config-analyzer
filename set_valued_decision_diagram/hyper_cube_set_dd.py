from typing import Union

from hyper_cube_set_interface import HyperCubeSetInterface
from nca.CoreDS.DimensionsManager import DimensionsManager
from set_valued_decision_diagram.set_valued_decision_diagram import SetValuedDecisionDiagram

DIM_MANAGER = DimensionsManager()


def convert_cube(cube: list, cube_dims: list[str]):
    cube = zip(cube_dims, cube)
    cube = sorted(cube, key=lambda c: DIM_MANAGER.dimension_order(c[0]))
    cube = tuple(cube)
    return cube


class HyperCubeSetDD(HyperCubeSetInterface):
    """Implementation of HyperCubeSet based on SetValuedDecisionDiagram."""
    def __init__(self, dimensions: list[str], allow_all: bool = False):
        self.dimensions = dimensions
        if allow_all:
            self.s = SetValuedDecisionDiagram.get_universal_set()
        else:
            self.s = SetValuedDecisionDiagram.get_empty_set()

    def __bool__(self):
        return bool(self.s)

    def __eq__(self, other):
        return self.s == other.s

    @staticmethod
    def create_from_cube(all_dims: list[str], cube: list, cube_dims: list[str]):
        s = HyperCubeSetDD(all_dims)
        cube = convert_cube(cube, cube_dims)
        s.s = SetValuedDecisionDiagram.from_cube(cube)
        return s

    def copy(self):
        new = HyperCubeSetDD(self.dimensions.copy())
        new.s = self.s
        return new

    def __contains__(self, item: list[Union[int, str]]):
        item = convert_cube(item, self.dimensions)
        return item in self.s

    def __iand__(self, other):
        self.s = self.s & other.s
        return self

    def __and__(self, other):
        new = HyperCubeSetDD(self.dimensions)
        new.s = self.s & other.s
        return new

    def __ior__(self, other):
        self.s = self.s | other.s
        return self

    def __or__(self, other):
        new = HyperCubeSetDD(self.dimensions)
        new.s = self.s | other.s
        return new

    def __isub__(self, other):
        self.s = self.s - other.s
        return self

    def __sub__(self, other):
        new = HyperCubeSetDD(self.dimensions)
        new.s = self.s - other.s
        return new

    def is_all(self) -> bool:
        return self.s.is_all()

    def set_all(self) -> None:
        self.s = SetValuedDecisionDiagram.get_universal_set()

    def contained_in(self, other) -> bool:
        return self.s.contained_in(other.s)

    def clear(self) -> None:
        self.s = SetValuedDecisionDiagram.get_empty_set()

    def __str__(self):
        return str(self.s)

    def add_cube(self, cube_to_add: list, cube_dimensions: list[str] = None) -> None:
        if len(cube_to_add) == 0:
            return
        if cube_dimensions is None:
            cube_dimensions = self.dimensions[:len(cube_to_add)]
        cube = convert_cube(cube_to_add, cube_dimensions)
        s = SetValuedDecisionDiagram.from_cube(cube)
        self.s = self.s | s

    def add_hole(self, hole_to_add: list, hole_dimensions: list[str] = None) -> None:
        if len(hole_to_add) == 0:
            return
        if hole_dimensions is None:
            hole_dimensions = self.dimensions[:len(hole_to_add)]
        cube = convert_cube(hole_to_add, hole_dimensions)
        s = SetValuedDecisionDiagram.from_cube(cube)
        self.s = self.s - s

    def __hash__(self):
        return hash(self.s)
