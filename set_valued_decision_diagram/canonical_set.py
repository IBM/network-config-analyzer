from abc import ABC, abstractmethod


class CanonicalSet(ABC):
    @abstractmethod
    def is_all(self):
        pass

    @classmethod
    @abstractmethod
    def get_universal_set(cls):
        pass

    @classmethod
    @abstractmethod
    def get_empty_set(cls):
        pass

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

    def __bool__(self):
        """:return: True if the set is not empty, otherwise False"""
        return not self.is_empty()

    @abstractmethod
    def is_empty(self):
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
    def __hash__(self):
        pass
