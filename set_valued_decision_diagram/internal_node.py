import functools
from typing import Union

from nca.CoreDS.DimensionsManager import DimensionsManager
from set_valued_decision_diagram.cache import search_compute_cache, get_true_terminal, allocate_new_node_id, \
    update_compute_cache, id_to_node, get_false_terminal
from set_valued_decision_diagram.canonical_set import CanonicalSet
from set_valued_decision_diagram.node import Node
from set_valued_decision_diagram.terminal_node import TerminalNode

# TODO: add the ability to give as input to the experiments the sets that we
#  want to test. This will enable us to benchmark the results of a single implementation.

# TODO: reduce the size of the functions by extracting subroutines and refactoring
# TODO: add checks for invariants
# TODO: go over CanonicalHyperCubeSet code and try understand if the algorithms are the same.
# TODO: validate dimensions correctness

DIM_MANAGER = DimensionsManager()


class InternalNode(Node):
    """Canonical form requires:
    1. every edge labels pair is disjoint. (split)
    2. no edge label is empty. (remove)
    3. no edges point to the empty set. (remove)
    4. edges are sorted by `child_id`. (sort)
    5. no two edges point at the same child. (merge)
    6. no redundant nodes, that is, a node with single edge labeled with the entire domain. (skip)
    7. at least one edge. (replace with false terminal)
    """
    def __init__(self, var: str, edges: tuple[tuple[CanonicalSet, int]]):
        """Constructor should not be called directly."""
        self.var = var
        self.edges = edges
        super().__init__(allocate_new_node_id(self))

    @staticmethod
    def from_cube(cube: tuple[tuple[str, CanonicalSet]]) -> Node:
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
        result_id, found = search_compute_cache(compute_cache_key)
        if found:
            return id_to_node(result_id)

        var, edge_label = cube[0]
        if edge_label:
            child = InternalNode.from_cube(cube[1:])
            edges = [(edge_label, child.id)]
            node = InternalNode.__create_canonical_node(var, edges)
        else:
            node = get_false_terminal()
        update_compute_cache(compute_cache_key, node.id)
        return node

    def is_empty(self):
        return False

    def is_all(self):
        return False

    def __repr_aux(self):
        return self.var, self.edges

    def __hash__(self):
        return hash(self.__repr_aux())

    def __repr__(self):
        return repr(self.__repr_aux())

    def __eq__(self, other):
        assert isinstance(other, Node)
        return isinstance(other, InternalNode) and self.__repr_aux() == other.__repr_aux()

    def __contains__(self, item: tuple[str, Union[int, str]]):
        assert len(item) > 0

        var, value = item[0]
        if var == self.var:
            for edge_label, child_id in self.edges:
                if value in edge_label:
                    child = id_to_node(child_id)
                    return item[1:] in child
            return False

        # var is a don't-care, skip it
        elif DIM_MANAGER.dimension_precedence(var, self.var):
            return item[1:] in self

        else:
            assert False, f'Variable {self.var} was skipped in the input.'

    @staticmethod
    def __canonize_edges(edges: list[tuple[CanonicalSet, int]]) -> tuple[tuple[CanonicalSet, int]]:
        """Deals with the following requirements for canonical representation:
        3. no edges point to the empty set. (remove)
        4. edges are sorted by `child_id`. (sort)
        5. no two edges point at the same child. (merge)
        """
        false_terminal = get_false_terminal()
        edges = filter(lambda edge: edge[1] != false_terminal.id, edges)
        edges = sorted(edges, key=lambda edge: edge[1])
        if len(edges) == 0:
            return ()
        # merge edges with the same child_id
        canonic_edges = []
        curr_edge_label, curr_child_id = edges[0]
        for edge_label, child_id in edges[1:]:
            if child_id != curr_child_id:
                canonic_edges.append((curr_edge_label, curr_child_id))
                curr_child_id = child_id
                curr_edge_label = edge_label
            else:
                curr_edge_label = curr_edge_label | edge_label
        canonic_edges.append((curr_edge_label, curr_child_id))
        return tuple(canonic_edges)

    @staticmethod
    def __skip_or_create_new_node(var: str, edges: tuple[tuple[CanonicalSet, int]]) -> Node:
        """Deals with the following requirements for canonical representation:
        6. no redundant nodes, that is, a node with single edge labeled with the entire domain. (skip)
        7. at least one edge. (replace with false terminal)
        """
        if len(edges) == 0:
            false_terminal_node = get_false_terminal()
            return false_terminal_node
        if len(edges) == 1:
            edge_label, child_id = edges[0]
            if edge_label == DIM_MANAGER.get_dimension_domain_by_name(var):
                return id_to_node(child_id)

        return InternalNode(var, edges)

    @staticmethod
    def __create_canonical_node(var: str, edges: list[tuple[CanonicalSet, int]]):
        edges = InternalNode.__canonize_edges(edges)
        return InternalNode.__skip_or_create_new_node(var, edges)

    def contained_in(self, other):
        assert isinstance(other, Node)
        if isinstance(other, TerminalNode):
            return other.value
        other: InternalNode

        compute_cache_key = ('contained_in', self.id, other.id)
        result, found = search_compute_cache(compute_cache_key)
        if found:
            return result

        result = self.__contained_in_aux(other)
        update_compute_cache(compute_cache_key, result)
        return result

    def __get_edge_labels_union(self):
        edge_labels = [edge_label for edge_label, _ in self.edges]
        union = functools.reduce(lambda s1, s2: s1 | s2, edge_labels)
        return union

    def __contained_in_aux(self, other):
        assert isinstance(other, InternalNode)

        if self.var == other.var:
            # need to make sure that all `self` edges are covered by `other` edges,
            # otherwise `self` is not contained in `other`
            if not self.__get_edge_labels_union().contained_in(other.__get_edge_labels_union()):
                return False

            # then, for each child of `self`, if it intersects with a child of `other`
            # make sure that it is contained in it
            for self_edge_label, self_child_id in self.edges:
                self_child = id_to_node(self_child_id)
                for other_edge_label, other_child_id in other.edges:
                    intersection = self_edge_label & other_edge_label
                    if intersection:
                        other_child = id_to_node(other_child_id)
                        if not self_child.contained_in(other_child):
                            return False
            return True

        # dont-care dimension in `other` and not `self`.
        elif DIM_MANAGER.dimension_precedence(self.var, other.var):
            # make sure that all children of `self` are contained in `other`
            for _, self_child_id in self.edges:
                self_child = id_to_node(self_child_id)
                if not self_child.contained_in(other):
                    return False
            return True

        # dont-care dimension in `self` and not in `other`.
        else:
            # we need to make sure that edges of `other` cover the entire domain,
            # otherwise `self` is not contained in `other`.
            if other.__get_edge_labels_union() != DIM_MANAGER.get_dimension_domain_by_name(other.var):
                return False

            # Then, we need to make sure that `self` is contained in every child of `other`.
            for _, other_child_id in other.edges:
                other_child = id_to_node(other_child_id)
                if not self.contained_in(other_child):
                    return False
            return True

    def __or__(self, other) -> Node:
        assert isinstance(other, Node)
        if isinstance(other, TerminalNode):
            return other | self
        other: InternalNode

        # using frozenset to utilize the fact that the operation is symmetric
        compute_cache_key = ('|', frozenset({self.id, other.id}))
        result_id, found = search_compute_cache(compute_cache_key)
        if found:
            return id_to_node(result_id)

        result = self.__or_aux(other)
        update_compute_cache(compute_cache_key, result.id)
        return result

    def __or_aux(self, other) -> Node:
        assert isinstance(other, InternalNode)
        if self.var == other.var:
            edges = []
            # We have 3 types of edges in the new node:
            # 1. Pairwise intersection between all pairs of `self` and `other`.
            # The child in those nodes will be the union of the children.
            for self_edge_label, self_child_id in self.edges:
                self_child = id_to_node(self_child_id)
                for other_edge_label, other_child_id in other.edges:
                    intersection = self_edge_label & other_edge_label
                    if intersection:
                        other_child = id_to_node(other_child_id)
                        child = self_child | other_child
                        edges.append((intersection, child.id))
            # 2. Leftover edges from `self`
            edges += self.__get_leftover_edges(other)
            # 3. Leftover edges from `other`
            edges += other.__get_leftover_edges(self)
            return self.__create_canonical_node(self.var, edges)

        elif DIM_MANAGER.dimension_precedence(self.var, other.var):
            return self.__or_aux_self_var_precedes_other_var(other)

        else:
            return other.__or_aux_self_var_precedes_other_var(self)

    def __get_leftover_edges(self, other) -> list[tuple[CanonicalSet, int]]:
        other: InternalNode
        edges = []
        other_edge_labels_union = other.__get_edge_labels_union()
        for self_edge_label, self_child_id in self.edges:
            self_leftover_edge_label = self_edge_label - other_edge_labels_union
            if self_leftover_edge_label:
                edges.append((self_leftover_edge_label, self_child_id))
        return edges

    def __or_aux_self_var_precedes_other_var(self, other) -> Node:
        assert isinstance(other, InternalNode)
        assert DIM_MANAGER.dimension_precedence(self.var, other.var)
        # `self.var` is a dont-care in `other`.
        # the new edges are with the same edge_labels of `self`
        edges = []
        for self_edge_label, self_child_id in self.edges:
            self_child = id_to_node(self_child_id)
            new_child = self_child | other
            edges.append((self_edge_label, new_child.id))
        # in addition, an extra edge that contains the leftover from `other` that is not covered by `self`
        leftover_edge_label = DIM_MANAGER.get_dimension_domain_by_name(self.var) - self.__get_edge_labels_union()
        if leftover_edge_label:
            edges.append((leftover_edge_label, other.id))
        return self.__create_canonical_node(self.var, edges)

    def __and__(self, other) -> Node:
        assert isinstance(other, Node)
        if isinstance(other, TerminalNode):
            return other & self
        other: InternalNode

        # using frozenset to utilize the fact that the operation is symmetric
        compute_cache_key = ('&', frozenset({self.id, other.id}))
        result_id, found = search_compute_cache(compute_cache_key)
        if found:
            return id_to_node(result_id)

        result = self.__and_aux(other)
        update_compute_cache(compute_cache_key, result.id)
        return result

    def __and_aux(self, other) -> Node:
        assert isinstance(other, InternalNode)

        if self.var == other.var:
            # The new edges are the intersection between the labels and the children
            edges = []
            for self_edge_label, self_child_id in self.edges:
                self_child = id_to_node(self_child_id)
                for other_edge_label, other_child_id in other.edges:
                    edge_label = self_edge_label & other_edge_label
                    if edge_label:
                        other_child = id_to_node(other_child_id)
                        child = self_child & other_child
                        edges.append((edge_label, child.id))
            return self.__create_canonical_node(self.var, edges)

        elif DIM_MANAGER.dimension_precedence(self.var, other.var):
            return self.__and_aux_self_var_precedes_other_var(other)

        else:
            return other.__and_aux_self_var_precedes_other_var(self)

    def __and_aux_self_var_precedes_other_var(self, other) -> Node:
        assert isinstance(other, InternalNode)
        assert DIM_MANAGER.dimension_precedence(self.var, other.var)
        # In this case, we intersect each of `self` children other.
        edges = []
        for self_edge_label, self_child_id in self.edges:
            self_child = id_to_node(self_child_id)
            child = self_child & other
            edges.append((self_edge_label, child.id))
        return self.__create_canonical_node(self.var, edges)

    def __sub__(self, other) -> Node:
        assert isinstance(other, Node)
        if isinstance(other, TerminalNode):
            if other.value:
                return get_false_terminal()
            else:
                return self

        other: InternalNode
        compute_cache_key = ('-', self.id, other.id)
        result_id, found = search_compute_cache(compute_cache_key)
        if found:
            return id_to_node(result_id)

        result = self.__sub_aux(other)
        update_compute_cache(compute_cache_key, result.id)
        return result

    def __sub_aux(self, other) -> Node:
        assert isinstance(other, InternalNode)

        if self.var == other.var:
            # There are two types of edges in this case,
            # 1. Leftover edges - with the same children
            edges = self.__get_leftover_edges(other)
            # 2. intersection edges - with subtraction
            for self_edge_label, self_child_id in self.edges:
                self_child = id_to_node(self_child_id)
                for other_edge_label, other_child_id in other.edges:
                    intersection = self_edge_label & other_edge_label
                    if intersection:
                        other_child = id_to_node(other_child_id)
                        child = self_child - other_child
                        edges.append((intersection, child.id))
            return self.__create_canonical_node(self.var, edges)

        elif DIM_MANAGER.dimension_precedence(self.var, other.var):
            # In this case `self.var` is a dont-care in `other`, so subtract other from each child
            edges = []
            for self_edge_label, self_child_id in self.edges:
                self_child = id_to_node(self_child_id)
                child = self_child - other
                edges.append((self_edge_label, child.id))
            return self.__create_canonical_node(self.var, edges)

        else:
            # In this case, `other.var` is a dont-care in `self`, we split the dimension as follows:
            edges = []
            # 1. what is not covered by `other`, we keep with the same set
            other_edge_label_union = other.__get_edge_labels_union()
            leftover_edge_label = DIM_MANAGER.get_dimension_domain_by_name(other.var) - other_edge_label_union
            if leftover_edge_label:
                edges.append((leftover_edge_label, self.id))
            # 2. from the edge_labels that appear in `other` we subtract their values
            for other_edge_label, other_child_id in other.edges:
                other_child = id_to_node(other_child_id)
                child = self - other_child
                edges.append((other_edge_label, child.id))
            return self.__create_canonical_node(other.var, edges)

    def complement(self):
        # check if the result is in the cache
        compute_cache_key = ('complement', self.id)
        result_id, found = search_compute_cache(compute_cache_key)
        if found:
            return id_to_node(result_id)

        # The new edges are going to be the same edges but the child complemented,
        edges = []
        for edge_label, child_id in self.edges:
            child = id_to_node(child_id)
            child_complement = child.complement()
            edges.append((edge_label, child_complement.id))
        # and another edge that is the complement of all the edge labels
        leftover_edge_label = DIM_MANAGER.get_dimension_domain_by_name(self.var) - self.__get_edge_labels_union()
        if leftover_edge_label:
            edges.append((leftover_edge_label, get_true_terminal().id))

        result = self.__create_canonical_node(self.var, edges)
        update_compute_cache(compute_cache_key, result.id)
        return result
