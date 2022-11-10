from typing import Union

from hyper_cube_set_interface import HyperCubeSetInterface


class HyperCubeSetDD(HyperCubeSetInterface):
    # TODO: implement
    def __init__(self, dimensions: list[str], allow_all: bool = False):
        pass

    def __bool__(self):
        pass

    def __eq__(self, other):
        pass

    @staticmethod
    def create_from_cube(all_dims: list[str], cube: list, cube_dims: list[str]):
        pass

    def copy(self):
        pass

    def __contains__(self, item: list[Union[int, str]]):
        pass

    def __iand__(self, other):
        pass

    def __and__(self, other):
        pass

    def __ior__(self, other):
        pass

    def __or__(self, other):
        pass

    def __isub__(self, other):
        pass

    def __sub__(self, other):
        pass

    def is_all(self) -> bool:
        pass

    def set_all(self) -> None:
        pass

    def contained_in(self, other) -> bool:
        pass

    def clear(self) -> None:
        pass

    def __str__(self):
        pass

    def add_cube(self, cube_to_add: list, cube_dimensions: list[str] = None) -> None:
        pass

    def add_hole(self, hole_to_add: list, hole_dimensions: list[str] = None) -> None:
        pass

