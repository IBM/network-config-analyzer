from abc import abstractmethod, ABC


# TODO: maybe look at others code using Z3 to get ideas on how to optimize implementation


class Z3Set(ABC):
    @classmethod
    @abstractmethod
    def get_universal_set(cls):
        pass

    @abstractmethod
    def is_empty(self):
        pass

    @classmethod
    @abstractmethod
    def get_empty_set(cls):
        pass

    @property
    @abstractmethod
    def python_type(self):
        pass

    @abstractmethod
    def __contains__(self, item) -> bool:
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
        pass

    @abstractmethod
    def __str__(self):
        pass

    def is_universal(self) -> bool:
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
