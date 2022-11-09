
from typing import Any, Union

from nca.CoreDS.CanonicalIntervalSet import CanonicalIntervalSet
from nca.CoreDS.DimensionsManager import DimensionsManager
from nca.CoreDS.MinDFA import MinDFA
from set_valued_decision_diagram.cache import search_compute_cache, get_true_terminal, node_to_id, \
    update_compute_cache, id_to_node
from set_valued_decision_diagram.canonical_set import CanonicalSet
from set_valued_decision_diagram.node import Node
from set_valued_decision_diagram.terminal_node import TerminalNode

# TODO: create a real variable ordering (using DimensionsManager?),
#  and set the appropriate domain for each. Use this to support complement and universality check.
# TODO: add the ability to check if a CanonicalIntervalSet is all
# TODO: add the ability to complement CanonicalIntervalSet
# TODO: add checks for invariants
# TODO: add the ability to give as input to the experiments the sets that we
#  want to test. This will enable us to benchmark the results of a single implementation.
# TODO: I'm not sure that we want to use a complement. Do we?


DIM_MANAGER = DimensionsManager()


class InternalNode(Node):
    """
    Invariants:
    - every pair of edges is disjoint
    - edges are sorted by the child_id.
    - if two edges point to the same child_id, then they should be merged into one.
    - if we have a single outgoing edge to the entire space, then skip the node.
    - if two nodes have the same id, then they must be identical
    -
    """
    # TODO: write down the data structure invariant properties and make sure to keep them.
    # TODO: for each operation, first check terminal cases, then check the cache, then use recursion.
    def __init__(self, var: str, children: tuple[tuple[CanonicalSet, int]]):
        """Constructor should not be called directly."""
        self.var = var
        self.children = children

    @staticmethod
    def from_cube(cube: tuple[tuple[str, CanonicalSet]]) -> tuple[Node, int]:
        """
        :param cube: a tuple of cubes, each cube is a pair (var, var_set). We use tuple for hash(cube)
        :return: A node that represents the Product of the cubes

        Notes:
        - if the cube is of length 0, then we get the universal set.
        - any skipped dimension will be a dont-care.
        """
        if len(cube) == 0:
            return get_true_terminal()

        compute_cache_key = ('from_cube', cube)
        result_idx, found = search_compute_cache(compute_cache_key)
        if found:
            return id_to_node(result_idx), result_idx

        var, var_set = cube[0]
        sub_cube = cube[1:]
        child, child_id = InternalNode.from_cube(sub_cube)
        node = InternalNode(
            var=var,
            children=((var_set, child_id),)
        )

        unique_id = node_to_id(node)
        update_compute_cache(compute_cache_key, unique_id)
        return node, unique_id

    def is_empty(self):
        return False

    def is_all(self):
        return False

    def __contains__(self, item: tuple[str, Any]):
        assert len(item) > 0

        var, value = item[0]
        if var == self.var:
            for edge_value, child_index in self.children:
                if value in edge_value:
                    child = id_to_node(child_index)
                    return item[1:] in child
            return False
        elif var < self.var:    # var is a don't care
            return item[1:] in self
        else:
            assert False, 'a variable was skipped in the input.'

    def __repr_aux(self):
        return self.var, self.children

    def __hash__(self):
        return hash(self.__repr_aux())

    def __repr__(self):
        return repr(self.__repr_aux())

    def __eq__(self, other):
        assert isinstance(other, Node)
        return isinstance(other, InternalNode) and self.__repr_aux() == other.__repr_aux()

    def contained_in(self, other):
        assert isinstance(other, Node)
        if isinstance(other, TerminalNode):
            return other.value

        self_id = node_to_id(self)
        other_id = node_to_id(other)
        compute_cache_key = ('contained_in', self_id, other_id)
        result, found = search_compute_cache(compute_cache_key)
        if found:
            return result

        result = self.__contained_in_aux(other)
        update_compute_cache(compute_cache_key, result)
        return result

    def __contained_in_aux(self, other):
        if self.var == other.var:
            for var_set1, child_id1 in self.children:
                child1 = id_to_node(child_id1)
                for var_set2, child_id2 in other.children:
                    intersection = var_set1 & var_set2
                    if intersection:
                        var_set1 = var_set1 - intersection
                        child2 = id_to_node(child_id2)
                        if not child1.contained_in(child2):
                            return False
                        if not var_set1:
                            break
                if var_set1:
                    return False
            return True

        elif self.var < other.var:
            for _, child_id in self.children:
                child = id_to_node(child_id)
                if not child.contained_in(other):
                    return False
            return True

        else:
            # TODO: This is not correct, but CanonicalIntervalSet does not support ".is_all()"
            #  so this will default to false. How to check that we have covered the entire dimensions?
            return False
            # union = None
            # for var_set, child_id in other.children:
            #     child = id_to_node(child_id)
            #     if not self.contained_in(child):
            #         return False
            #     if union is None:
            #         union = var_set
            #     else:
            #         union = union | var_set
            # return union.is_all()

    def __or__(self, other):
        assert isinstance(other, Node)
        # terminal condition
        if isinstance(other, TerminalNode):
            return other | self

        # check the cache
        other: InternalNode
        self_id = node_to_id(self)
        other_id = node_to_id(other)
        # using frozenset to utilize the fact that the operation is symmetric
        compute_cache_key = ('|', frozenset({self_id, other_id}))
        result_id, found = search_compute_cache(compute_cache_key)
        if found:
            return id_to_node(result_id)

        # compute according to variable ordering
        # TODO: make sure to sort the edges and to merge ones with identical subtrees

    def __and__(self, other):
        assert isinstance(other, Node)
        # terminal condition
        if isinstance(other, TerminalNode):
            return other | self

        # check the cache
        other: InternalNode
        self_id = node_to_id(self)
        other_id = node_to_id(other)
        # using frozenset to utilize the fact that the operation is symmetric
        compute_cache_key = ('|', frozenset({self_id, other_id}))
        result_id, found = search_compute_cache(compute_cache_key)
        if found:
            return id_to_node(result_id)

        # compute according to variable ordering
        # TODO: make sure to sort the edges and to merge ones with identical subtrees

    def __sub__(self, other):
        pass
