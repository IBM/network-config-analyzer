""" Requirements
properties that we want to preserve / graph transformations:
- in every level, the different branches are disjoint on the separating variable
- if two subtrees are identical, we merge the parents
- (new) we skip dont-cares variable
- (new) DAG: if two subtrees are isomorphic, we use a pointer. only one copy of each.
- note that DAG and merging might conflict. and create a different tree based on the order of operations
"""
from typing import Union

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

TERMINAL = -1


class SetValuedDecisionDiagram:
    def __init__(self, children: dict):
        """Constructor should not be called directly."""
        self.children = children

    @staticmethod
    def from_cube(cube: list[Union[frozenset, set]]):
        assert len(cube) > 0
        value = cube[0]
        if isinstance(value, set):
            value = frozenset(value)

        if len(cube) == 1:
            return SetValuedDecisionDiagram({value: TERMINAL})

        return SetValuedDecisionDiagram({value: SetValuedDecisionDiagram.from_cube(cube[1:])})

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

    def __sub__(self, other):
        pass

    def __bool__(self):     # if not empty
        pass

    def is_universal(self):
        pass

    @staticmethod
    def get_empty():
        pass

    @staticmethod
    def get_universal():
        pass

    def __eq__(self, other):
        # TODO: probably need to sort that in some way so it will be consistent.
        assert isinstance(other, SetValuedDecisionDiagram)
        for (value1, subtree1), (value2, subtree2) in zip(self.children.items(), other.children.items()):
            return value1 == value2 and subtree1 == subtree2

    def __hash__(self):
        pass

    def __iter__(self):
        pass

    def __contains__(self, item: list):
        assert len(item) > 0
        for value, subtree in self.children.items():
            if item[0] in value:
                if len(item) == 1:
                    return True
                elif item[1:] in subtree:
                    return True
                else:
                    return False
        return False

    def issubset(self, other):
        pass
