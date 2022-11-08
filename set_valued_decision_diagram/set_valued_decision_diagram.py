""" Requirements
properties that we want to preserve / graph transformations:
- in every level, the different branches are disjoint on the separating variable
- if two subtrees are identical, we merge the parents
- (new) we skip dont-cares variable
- (new) DAG: if two subtrees are isomorphic, we use a pointer. only one copy of each.
- note that DAG and merging might conflict. and create a different tree based on the order of operations

Ideas
- I think that after I have some basic implementation, I might find useful optimization ideas
for that if I check out papers, I will bookmark things that I see
- Reduced BDD:
  - Dealing with dont-cares (eliminate nodes whose children are isomorphic)
  - merging isomorphic sub-graphs
  - MDD is an extension to BDD with the branching parameter being some other number, BDD.
  - Edge-Valued MultiValued Decision Diagram (EVMDD) - MDD with costs on the edges.
  - Algebric Decision Diagram - output might not be binary, inputs are.

## TODO:
- [ ] try including skipping don't-cares -- how to include that into the hyper cube set
- [ ]

Papers To Read:
- Binary Decision Diagrams and Beyond: Enabling Technologies for Formal Verification
- Disjunctive Interval Analysis
- An Interval Decision Diagram Based Firewall
- Model Checking I Binary Decision Diagrams

Ideas
- since each set takes space, if we have the same value (set) that is represented over and over again,
we might want to create a cache, the has indices to the object instead of a copy of it, and we share?

"""

# TODO:
#   * skip don't-care dimensions
#   * create a more general framework, under what assumptions something can be used as a dimension type?
#   * DAG instead of tree. If a a subtree already exists somewhere, instead of duplicating it, point it a the same
#   direction.
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
# TODO: remove all cache operations to the outside
# TODO: sort children according to their unique table id
# TODO: check input validity with asserts
from typing import Any

from set_valued_decision_diagram.canonical_set import CanonicalSet
from set_valued_decision_diagram.internal_node import InternalNode
from set_valued_decision_diagram.node import Node
from set_valued_decision_diagram.terminal_node import TerminalNode


class SetValuedDecisionDiagram(CanonicalSet):
    def is_empty(self):
        return self.root == TerminalNode(False)

    def __init__(self, root: Node):
        """Constructor should not be called directly."""
        self.root = root

    @staticmethod
    def from_cube(cube: tuple[tuple[str, CanonicalSet]]):
        root, root_index = InternalNode.from_cube(cube)
        return SetValuedDecisionDiagram(root)

    def __hash__(self):
        return hash(self.root)

    def __eq__(self, other):
        assert isinstance(other, SetValuedDecisionDiagram)
        return self.root == other.root

    def __repr__(self):
        return repr(self.root)

    def __contains__(self, item: tuple[str, Any]):
        return item in self.root

    def __and__(self, other):
        assert isinstance(other, SetValuedDecisionDiagram)
        new_root = self.root & other.root
        return SetValuedDecisionDiagram(new_root)

    def __or__(self, other):
        assert isinstance(other, SetValuedDecisionDiagram)
        new_root = self.root | other.root
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
        root = TerminalNode(False)
        return SetValuedDecisionDiagram(root)

    @classmethod
    def get_universal_set(cls):
        root = TerminalNode(True)
        return SetValuedDecisionDiagram(root)

    def is_all(self):
        return self.root == TerminalNode(True)

    def complement(self):
        new_root = self.root.complement()
        return SetValuedDecisionDiagram(new_root)

    def __iter__(self):
        # TODO: implement? should we place this here or in InternalNode?
        pass
