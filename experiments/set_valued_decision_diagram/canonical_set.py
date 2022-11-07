from abc import ABC, abstractmethod


class CanonicalSet(ABC):
    @abstractmethod
    def __and__(self, other):
        """Set intersection"""
        pass

    @abstractmethod
    def __or__(self, other):
        """Set union"""
        pass

    @abstractmethod
    def __sub__(self, other):
        pass

    @abstractmethod
    def __bool__(self):
        """Set emptiness"""
        pass

    @abstractmethod
    def __eq__(self, other):
        pass

    @abstractmethod
    def contained_in(self, other):
        pass

    @abstractmethod
    def __repr__(self):
        """Canonic representation"""
        pass

    @abstractmethod
    def __contains__(self, item):
        pass

    @abstractmethod
    def __copy__(self):
        pass

    def __le__(self, other):
        """Total order for canonical representation"""
        return repr(self) <= repr(other)

    def __hash__(self):
        return hash(repr(self))
