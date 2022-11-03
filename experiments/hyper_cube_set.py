"""Shared interface for hyper cube set"""
from abc import ABC, abstractmethod
from typing import Union


class HyperCubeSet(ABC):
    @abstractmethod
    def __init__(self, dimensions: list[str], allow_all: bool = False):
        pass

    @abstractmethod
    def __bool__(self):
        pass

    @abstractmethod
    def __eq__(self, other):
        pass

    @staticmethod
    @abstractmethod
    def create_from_cube(all_dims: list[str], cube: list, cube_dims: list[str]):
        pass

    @abstractmethod
    def copy(self):
        pass

    @abstractmethod
    def __contains__(self, item: list[Union[int, str]]):
        pass

    @abstractmethod
    def __iand__(self, other):
        pass

    @abstractmethod
    def __and__(self, other):
        pass

    @abstractmethod
    def __ior__(self, other):
        pass

    @abstractmethod
    def __or__(self, other):
        pass

    @abstractmethod
    def __isub__(self, other):
        pass

    @abstractmethod
    def __sub__(self, other):
        pass

    @abstractmethod
    def is_all(self) -> bool:
        pass

    @abstractmethod
    def set_all(self) -> None:
        pass

    @abstractmethod
    def contained_in(self, other) -> bool:
        pass

    @abstractmethod
    def clear(self) -> None:
        pass

    @abstractmethod
    def __str__(self):
        pass

    @abstractmethod
    def add_cube(self, cube_to_add: list, cube_dimensions: list[str] = None) -> None:
        pass

    @abstractmethod
    def add_hole(self, hole_to_add: list, hole_dimensions: list[str] = None) -> None:
        pass
