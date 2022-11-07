""" Requirements
properties that we want to preserve / graph transformations:
- in every level, the different branches are disjoint on the separating variable
- if two subtrees are identical, we merge the parents
- (new) we skip dont-cares variable
- (new) DAG: if two subtrees are isomorphic, we use a pointer. only one copy of each.
- note that DAG and merging might conflict. and create a different tree based on the order of operations
"""
from typing import Any

from set_valued_decision_diagram.canonical_set import CanonicalSet

"""Ideas
- since each set takes space, if we have the same value (set) that is represented over and over again,
we might want to create a cache, the has indices to the object instead of a copy of it, and we share?
"""
# TODO:
#   * skip don't-care dimensions
#   * create a more general framework, under what assumptions something can be used as a dimension type?
#   * DAG instead of tree. If a a subtree already exists somewhere, instead of duplicating it, point it a the same
#   direction.

"""Papers To Read:
- Binary Decision Diagrams and Beyond: Enabling Technologies for Formal Verification
- Disjunctive Interval Analysis
- An Interval Decision Diagram Based Firewall
- Model Checking I Binary Decision Diagrams
"""
# TODO: for now, only use pythons frozenset as the basic set. Later check what assumptions are taken, and create an
#   interface for that
# TODO: possible implementation - make it a binary tree, so we would not have to compare all pairs, but only by search
#   for the correct one.
# TODO: create benchmarks for that in order to check how small changes affect behavior.
# TODO: split between TerminalNode and Non-Terminal Nodes
# TODO: add caching at the Interval and MinDFA level also?
# TODO: write down the data structure invariants that we have, and try to test them.
# TODO: hash without full representation, using edges indices
# TODO: need to figure out how to treat the terminal node. Leave it to the end
#   after I have added support for the other aspects. I think that I want to do that with
#   inheritance and polymorphism
# TODO: use real variable ordering, for now it is just variable names that matter
# TODO: I somehow need to make sure that the dimensions align and are
#   correctly typed.
# TODO: add support for don't cares


class SetValuedDecisionDiagram(CanonicalSet):
    """Data Structure Invariants:
    - __UNIQUE_LIST contains no repetitions / equivalent elements
    - Canonical form
    - edges are sorted
    """
    # Special index for the terminal node
    __TERMINAL = -1
    # List for all the created decision diagrams, no duplicates
    __UNIQUE_LIST = []
    # a dictionary for quick searching __UNIQUE_LIST
    __UNIQUE_ID_LOOKUP = {}
    # Map from (operation, *args (indices)) -> index of result in UNIQUE_LIST
    __COMPUTE_CACHE: dict[tuple, int] = {}

    def __init__(self, var: str, edges: tuple[tuple[CanonicalSet, int]]):
        """Constructor should not be called directly."""
        self.var = var
        self.edges = edges

    @staticmethod
    def from_cube(cube: tuple[tuple[str, CanonicalSet]]):
        """
        :param cube: a tuple of cubes, with (var, set) combinations. We want it to be a tuple so
        we can use hash(cube)
        :return:
        """
        # TODO: I think that I might need to return the index so that I can do the recursive call
        assert len(cube) > 0, 'Cube must contain at least 1 dimension.'

        compute_cache_key = ('from_cube', cube)
        result_index = SetValuedDecisionDiagram.__COMPUTE_CACHE.get(compute_cache_key, None)
        if result_index is not None:
            return SetValuedDecisionDiagram.__UNIQUE_LIST[result_index]

        var, dim_value = cube[0]

        if len(cube) == 1:
            s = SetValuedDecisionDiagram(
                var=var,
                edges=((dim_value, SetValuedDecisionDiagram.__TERMINAL),),
            )

        else:
            sub_cube = cube[1:]
            sub_graph = SetValuedDecisionDiagram.from_cube(sub_cube)
            sub_graph_id = SetValuedDecisionDiagram.__UNIQUE_ID_LOOKUP[sub_graph]
            s = SetValuedDecisionDiagram(
                var=var,
                edges=((dim_value, sub_graph_id),)
            )

        unique_id = SetValuedDecisionDiagram.__get_unique_id(s)
        SetValuedDecisionDiagram.__COMPUTE_CACHE[compute_cache_key] = unique_id
        return s

    @staticmethod
    def __get_unique_id(s):
        assert isinstance(s, SetValuedDecisionDiagram)

        unique_id = SetValuedDecisionDiagram.__UNIQUE_ID_LOOKUP.get(s, None)
        if unique_id is None:
            unique_id = len(SetValuedDecisionDiagram.__UNIQUE_LIST)
            SetValuedDecisionDiagram.__UNIQUE_LIST.append(s)
            SetValuedDecisionDiagram.__UNIQUE_ID_LOOKUP[s] = unique_id
        return unique_id

    def __repr_aux(self):
        return self.var, self.edges

    def __hash__(self):
        return hash(self.__repr_aux())

    def __eq__(self, other):
        assert isinstance(other, SetValuedDecisionDiagram)
        return self.__repr_aux() == other.__repr_aux()

    def __repr__(self):
        return repr(self.__repr_aux())

    def __le__(self, other):
        return self.__repr_aux() <= other.__repr_aux()

    def __contains__(self, item: tuple[str, Any]):
        assert len(item) > 0

        var, value = item[0]
        if var == self.var:
            for edge_value, child_index in self.edges:
                if value in edge_value:
                    # TODO: better treatment of terminals
                    if child_index == self.__TERMINAL:
                        return True
                    return item[1:] in self.__UNIQUE_LIST[child_index]
            return False
        elif var < self.var:    # var is a don't care
            return item[1:] in self
        else:
            assert False, 'should not get here.'

    def __and__(self, other):
        assert isinstance(other, SetValuedDecisionDiagram)

        children = {}
        for value1, subtree1 in self.children.items():
            for value2, subtree2 in other.children.items():
                intersection = value1 & value2
                if intersection:
                    # TODO: add check if the subtree is not empty. if so we don't want to add it.
                    subtree = subtree1 & subtree2
                    children[intersection] = subtree
        return SetValuedDecisionDiagram(children)

    def __or__(self, other):
        assert isinstance(other, SetValuedDecisionDiagram)
        self_children_list = [[value, subtree] for value, subtree in self.children.items()]
        other_children_list = []
        intersection_list = []
        # To add - since all sets are disjoint, each intersection must be unique, so we can solve that.
        # then, add what's left of each of the children.
        for value2, subtree2 in other.children.items():
            for i in range(len(self_children_list)):
                value1, subtree1 = self_children_list[i]
                intersection = value1 & value2
                if intersection:
                    value1 = value1 - intersection
                    self_children_list[i][0] = value1
                    value2 = value2 - intersection
                    intersection_list.append([intersection, subtree1 | subtree2])

            if value2:
                other_children_list.append([value2, subtree2])

        children = self_children_list + other_children_list + intersection_list
        children = {value: subtree for value, subtree in children}
        return SetValuedDecisionDiagram(children)

    def __sub__(self, other):
        assert isinstance(other, SetValuedDecisionDiagram)
        # TODO: implement
        children = {}
        for value1, subtree1 in self.children.items():
            for value2, subtree2 in other.children.items():
                intersection = value1 & value2
                if intersection:
                    value1 = value1 - intersection
                    subtree = subtree1 - subtree2
                    children[intersection] = subtree
            if value1:
                children[value1] = subtree1
        return SetValuedDecisionDiagram(children)

    def contained_in(self, other):
        pass

    def __iter__(self):
        pass

    @classmethod
    def get_empty_set(cls):
        pass

    def __bool__(self):
        pass

    @classmethod
    def get_universal_set(cls):
        pass

    def is_all(self):
        pass
