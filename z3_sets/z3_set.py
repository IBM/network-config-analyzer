from abc import abstractmethod, ABC


class Z3Set(ABC):
    """An abstract class that is the interface of z3 sets."""
    @classmethod
    @abstractmethod
    def get_universal_set(cls):
        """
        :return: a set that contains all the elements.
        """
        pass

    @abstractmethod
    def is_empty(self):
        pass

    @classmethod
    @abstractmethod
    def get_empty_set(cls):
        """
        :return: a set that contains no elements.
        """
        pass

    @property
    @abstractmethod
    def python_type(self):
        """
        :return: the corresponding python type of the elements that are contained in the set.
        Could be either `int` of `str`.
        """
        pass

    @abstractmethod
    def __contains__(self, item):
        pass

    @abstractmethod
    def copy(self):
        pass

    @abstractmethod
    def __iand__(self, other):
        pass

    @abstractmethod
    def __ior__(self, other):
        pass

    @abstractmethod
    def __invert__(self):
        """
        :return: the complement of the set.
        """
        pass

    @abstractmethod
    def __str__(self):
        pass

    def __bool__(self):
        return not self.is_empty()

    def is_universal(self) -> bool:
        """Check if the set contains all elements."""
        return (~self).is_empty()

    def contained_in(self, other) -> bool:
        return (self - other).is_empty()

    def __eq__(self, other):
        other: Z3Set
        if not self.contained_in(other):
            return False
        if other.contained_in(self):
            return True
        return False

    def __copy__(self):
        return self.copy()

    def __isub__(self, other):
        self.__iand__(~other)
        return self

    def __and__(self, other):
        new = self.copy()
        new &= other
        return new

    def __or__(self, other):
        new = self.copy()
        new |= other
        return new

    def __sub__(self, other):
        new = self.copy()
        new -= other
        return new
