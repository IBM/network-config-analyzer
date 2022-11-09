from abc import abstractmethod, ABC


class Node(ABC):
    @abstractmethod
    def is_all(self):
        pass

    @abstractmethod
    def __and__(self, other):
        pass

    @abstractmethod
    def __or__(self, other):
        pass

    @abstractmethod
    def __sub__(self, other):
        pass

    def __bool__(self):
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
        pass

    @abstractmethod
    def __contains__(self, item):
        pass

    @abstractmethod
    def __hash__(self):
        pass
