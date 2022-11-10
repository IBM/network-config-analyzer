"""Ideas for improvement:
- I think that after I have a basic implementation, I might find useful optimization ideas
for that if I check out papers, I will bookmark things that I see.
- The set operations on CanonicalHyperCubeSet, MinDFA, CanonicalIntervalSet also take time.
Might we benefit from caching those?
"""
from typing import Union

from set_valued_decision_diagram.cache import get_true_terminal, get_false_terminal
from set_valued_decision_diagram.canonical_set import CanonicalSet
from set_valued_decision_diagram.internal_node import InternalNode
from set_valued_decision_diagram.node import Node


class SetValuedDecisionDiagram(CanonicalSet):
    def is_empty(self):
        return self.root == get_false_terminal()

    def __init__(self, root: Node):
        """Constructor should not be called directly."""
        self.root = root

    @staticmethod
    def from_cube(cube: tuple[tuple[str, CanonicalSet]]):
        root = InternalNode.from_cube(cube)
        return SetValuedDecisionDiagram(root)

    def __hash__(self):
        return hash(self.root)

    def __eq__(self, other):
        assert isinstance(other, SetValuedDecisionDiagram)
        return self.root == other.root

    def __repr__(self):
        return repr(self.root)

    def __contains__(self, item: tuple[str, Union[int, str]]):
        return item in self.root

    def __or__(self, other):
        assert isinstance(other, SetValuedDecisionDiagram)
        new_root = self.root | other.root
        return SetValuedDecisionDiagram(new_root)

    def __and__(self, other):
        assert isinstance(other, SetValuedDecisionDiagram)
        new_root = self.root & other.root
        return SetValuedDecisionDiagram(new_root)

    def __sub__(self, other):
        assert isinstance(other, SetValuedDecisionDiagram)
        new_root = self.root - other.root
        return SetValuedDecisionDiagram(new_root)

    def contained_in(self, other):
        assert isinstance(other, SetValuedDecisionDiagram)
        return self.root.contained_in(other.root)

    @classmethod
    def get_empty_set(cls):
        root = get_false_terminal()
        return SetValuedDecisionDiagram(root)

    @classmethod
    def get_universal_set(cls):
        root = get_true_terminal()
        return SetValuedDecisionDiagram(root)

    def is_all(self):
        return self.root == get_true_terminal()

    def complement(self):
        new_root = self.root.complement()
        return SetValuedDecisionDiagram(new_root)

    def __iter__(self):
        # TODO: implement? should we place this here or in InternalNode?
        pass
