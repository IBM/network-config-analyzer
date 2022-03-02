#
# Copyright 2020- IBM Inc. All rights reserved
# SPDX-License-Identifier: Apache2.0
#
from CanonicalIntervalSet import CanonicalIntervalSet
from DimensionsManager import DimensionsManager
from MinDFA import MinDFA


class CanonicalHyperCubeSet:
    """
    This class provides canonical representation for a set of cubes (n-dimensional), allowing comparison.
    Supporting dimensions of types: (1) Interval sets (2) DFAs
    - all_dimensions_list is an array of ordered dimension names : [dim{1}, dim{2},..., dim{n}]
    - active_dimensions: array of ordered dimension names, subset of dimensions.
        For inactive dimensions, the entire dimension values are included.
    Thus, cubes in hyper-cube set object are restricted to the n-dimensional space defined by dimensions.
    - dimensions_manager is a DimensionsManager instance (singleton) that manages the supported dimension names,
      and their association to type and domain.
    the representation is defined by an map 'layers', where each pair of the map is of the form:
    <interval-set, sub-cube> or <dfa, sub-cube> where:
    - The type of the first elem for this pair corresponds to type(active_dimensions[0])
    - interval-set is a CanonicalIntervalSet object,
    - dfa is a MinDFA object
    - sub-cube is a hyper-cube object with dimensions: active_dimensions[1:]
    In addition :
    (1) No two interval-sets/dfas in layers overlap. (they are all disjoint).
    (2) There are no two paris in layers with identical sub-cube.
    (3) For the last active dimension, the 'layers' map is of the form :
        (dfa, empty_interval) or (interval-set, empty-interval)

    * A hyper-cube object always has minimal required active_dimensions.
    * An object that consists of the entire space defined by dimensions has an empty active_dimensions list.
    * An empty object has at least one active dimension and an empty 'layers' map.

    """

    empty_interval = CanonicalIntervalSet()

    # TODO: should move dimensions order to DimensionsManager?
    def __init__(self, dimensions, allow_all=False):
        self.layers = dict()  # layers are w.r.t active dimensions
        self.dimensions_manager = DimensionsManager()
        self.all_dimensions_list = dimensions  # ordered list of all dimensions
        self.all_dim_types = [self.dimensions_manager.get_dimension_type_by_name(dim_name) for dim_name in dimensions]
        # init ordered list of active dimensions:
        if allow_all:
            self.active_dimensions = []  # names (for non-active dimensions everything is allowed)
        else:
            # initialize as empty with all dimensions considered active.
            # in the next operations reducing to relevant active dimensions
            self.active_dimensions = self.all_dimensions_list

    def __bool__(self):
        # if all dimensions are inactive -> everything is allowed
        if not self.active_dimensions:
            return True
        return bool(self.layers)

    def __eq__(self, other):
        if not isinstance(other, CanonicalHyperCubeSet):
            return False
        if self.all_dimensions_list != other.all_dimensions_list:
            return False
        # if both objects have no cubes they are equal, even if they have different active dimensions
        if not self and not other:
            return True
        return self.active_dimensions == other.active_dimensions and self.layers == other.layers

    @staticmethod
    def create_from_cube(all_dims, cube, cube_dims):
        """
        Create a CanonicalHyperCubeSet object from an input cube (single cube)
        Assumptions:
        - cube is not empty, and cube_dims is consistent with cube values (same length, consistent types)
        - cube_dims is ordered based on the order in all_dims
        :param list[str] all_dims: the list of all dimensions  in the CanonicalHyperCubeSet object
        :param list[Union[CanonicalIntervalSet, MinDFA]] cube: list of cube values
        :param list[str] cube_dims: list of cube dimensions
        :return: CanonicalHyperCubeSet object, containing the input cube
        """
        assert cube
        assert len(cube) == len(cube_dims)
        # TODO: check that cube_dims are ordered by all_dims order ...
        # reduce cube to required dimensions only (those which are not entirely covered)
        cube, cube_dims, is_empty = CanonicalHyperCubeSet._reduce_cube(cube, cube_dims)
        if is_empty:
            return CanonicalHyperCubeSet(all_dims)
        if not cube:
            # if the reduced cube is empty -> it was the entire space
            return CanonicalHyperCubeSet(all_dims, True)
        return CanonicalHyperCubeSet._create_from_cube_aux(all_dims, cube, cube_dims)

    @staticmethod
    def _create_from_cube_aux(all_dims, cube, cube_dims):
        """
        recursive function to create CanonicalHyperCubeSet object from input cube
        assuming that required cube reductions were already applied on the input cube
        :param list[str] all_dims: the list of all dimensions  in the CanonicalHyperCubeSet object
        :param list[Union[CanonicalIntervalSet, MinDFA]] cube: list of cube values
        :param list[str] cube_dims: list of cube dimensions
        :return: CanonicalHyperCubeSet object, containing the input cube
        """
        res = CanonicalHyperCubeSet(all_dims)
        res.active_dimensions = cube_dims
        if len(cube) == 1:
            res.layers[cube[0]] = CanonicalHyperCubeSet.empty_interval
            return res
        res.layers[cube[0]] = CanonicalHyperCubeSet._create_from_cube_aux(all_dims, cube[1:], cube_dims[1:])
        return res

    @staticmethod
    def _reduce_cube(cube, cube_dims):
        """
        Reduce cube's dimensions on which the value is equivalent to the entire domain of this dimension
        :param list[Union[CanonicalIntervalSet, MinDFA]] cube: list of cube values (MinDFA or CanonicalIntervalSet)
        :param list[str] cube_dims: list of cube dimensions
        :return: tuple(res_cube, res_dims, is_empty) , where:
                is_empty: bool flag to indicate if the result is empty cube
                res_cube: list of reduced cube values
                res_dims: list of reduced cube dimensions
        """
        res_cube = []
        res_dims = []
        dimensions_manager = DimensionsManager()
        for dim_index, dim_val in enumerate(cube):
            dim_domain = dimensions_manager.get_dimension_domain_by_name(cube_dims[dim_index])
            dim_type = dimensions_manager.get_dimension_type_by_name(cube_dims[dim_index])
            # if one of the cube's dimensions is empty, the cartesian product is empty
            if not dim_val:
                return None, None, True
            # if dim_domain != dim_val:
            if (dim_type == DimensionsManager.DimensionType.DFA and not dim_val.is_dfa_wll_words(dim_domain)) or (
                    dim_type == DimensionsManager.DimensionType.IntervalSet and dim_domain != dim_val):
                res_cube.append(dim_val)
                res_dims.append(cube_dims[dim_index])
        return res_cube, res_dims, False

    def _get_cubes_list_from_layers(self):
        """
        :return: list of cubes in self (each cube is a list of domain values range, consistent with active dimensions).
        :rtype list[list[Union[CanonicalIntervalSet, MinDFA]]]
        """
        res = []
        if self._is_last_dimension():
            return list([key] for key in self.layers.keys())
        for layer0, layer1 in self.layers.items():
            sub_res = layer1._get_cubes_list_from_layers()
            for sub_arr in sub_res:
                res.append(([layer0] + sub_arr))
        return res

    def _get_cubes_set(self):
        """
        :return: a set of tuples with all cubes in self. (a cube is a tuple with len(self.active_dimensions)
        """
        return set(tuple(cube) for cube in self._get_cubes_list_from_layers())

    def _get_dimensions_subset_by_order(self, dimensions_subset):
        """
        :param Union[list,set] dimensions_subset: an iterable object with subset of self.all_dimensions_list
        :return: an ordered list of dimensions in dimensions_subset that corresponds to the ordering in
                 self.all_dimensions_list.
        """
        return [dim for dim in self.all_dimensions_list if dim in dimensions_subset]

    def _get_entire_space_cube(self, dimensions_list_restriction=None):
        """
        :param Union[list,set] dimensions_list_restriction: an iterable object with subset of self.all_dimensions_list
        :return: a cube (as a list) with all domain values, per required dimensions.
        """
        if dimensions_list_restriction is None:
            dimensions_list_restriction = self.all_dimensions_list
        dimensions_list_ordered = self._get_dimensions_subset_by_order(dimensions_list_restriction)
        cube_res = []
        for dim_name in dimensions_list_ordered:
            cube_res.append(self.dimensions_manager.get_dimension_domain_by_name(dim_name))
        return cube_res

    def __len__(self):
        """
        :return: int: number of cubes in self.
        """
        if not self.active_dimensions:
            return 1  # considered as 1 cube of the entire space (everything allowed for all dimensions)
        # return the number of cubes in the hypercubeset
        return len(self._get_cubes_list_from_layers())

    def __hash__(self):
        if not self.active_dimensions:  # obj represents the entire space
            return hash(frozenset(self.all_dimensions_list))
        if self.active_dimensions and not self.layers:  # obj represents nothing in the entire space
            return hash((frozenset(self.layers), frozenset(self.all_dimensions_list)))
        # obj represents some cubes in the entire space
        return hash((frozenset(self.layers), frozenset(self.active_dimensions), (frozenset(self.all_dimensions_list))))

    # iterate the relevant list of cubes
    def __iter__(self):
        if not self.active_dimensions:
            return iter([self._get_entire_space_cube()])
        return iter(self._get_cubes_list_from_layers())

    def _override_by_other(self, other):
        self.layers = other.layers
        self.active_dimensions = other.active_dimensions

    def copy(self):
        res = CanonicalHyperCubeSet(self.all_dimensions_list)
        for layer in self.layers:
            res.layers[self._copy_layer_elem(layer)] = self.layers[layer].copy()
        res.active_dimensions = self.active_dimensions.copy()
        return res

    @staticmethod
    def _copy_layer_elem(elem):
        if isinstance(elem, MinDFA):
            return elem
        return elem.copy()

    # TODO: should handle input item without all dimensions specified?
    def __contains__(self, item):
        """
        :param list item: an ordered list of items representing "n-tuple" element in the n-dimensional space defined by
                     self.all_dimensions_list
                     if type(all_dimensions_list[i]) is DFA, then type(item[i]) is str.
                     if type(all_dimensions_list[i]) is IntervalSet, then type(item[i]) is int.
                     len(item) should equal len(all_dimensions_list)
        :return: bool indicating if item is contained in self.
        """
        if len(item) < len(self.all_dimensions_list):
            raise Exception("input item len mismatch")
        for index, dim_type in enumerate(self.all_dim_types):
            if dim_type == DimensionsManager.DimensionType.DFA:
                assert (isinstance(item[index], str))
            else:
                assert (isinstance(item[index], int))
        if self.is_all():
            return True
        if not self:
            return False
        # reduce item to active dimensions only
        relevant_input_item = self._get_aligned_cube_by_new_active_dimensions(item, self.all_dimensions_list,
                                                                              self.active_dimensions)
        for layer_elem, layer_sub_elem in self.layers.items():
            if relevant_input_item[0] in layer_elem:
                if self._is_last_dimension():
                    return True
                return item in layer_sub_elem
        return False

    def __and__(self, other):
        res = self.copy()
        res &= other
        return res

    def __iand__(self, other):
        if other.is_all():
            return self
        if not other or not self:
            self.clear()
            return self
        if self.is_all():
            self._override_by_other(other.copy())
            return self
        other_copy = self._prepare_common_active_dimensions(other)
        self._and_aux(other_copy)
        self._reduce_active_dimensions()
        return self

    def _and_aux(self, other):
        """
        Recursive function to compute 'and' between two CanonicalHyperCubeSet objects.
        Assuming that self and other have common active dimensions.
        :type other: CanonicalHyperCubeSet
        :return: self
        """
        assert self.active_dimensions == other.active_dimensions
        res_layers = dict()
        for self_layer in self.layers:
            for other_layer in other.layers:
                common_elem = self_layer & other_layer
                if not common_elem:
                    continue
                if self._is_last_dimension():
                    res_layers[common_elem] = self.layers[self_layer]
                    continue
                # TODO: use type hint to avoid warning on access to a protected member?
                # self_sub_elem: CanonicalHyperCubeSet = self.layers[self_layer]
                # new_sub_elem = self_sub_elem._and_aux(other.layers[other_layer])
                new_sub_elem = self.layers[self_layer]._and_aux(other.layers[other_layer])
                if new_sub_elem:
                    res_layers[common_elem] = new_sub_elem

        self.layers = res_layers
        self._apply_layer_elements_union()
        return self

    def __or__(self, other):
        res = self.copy()
        res |= other
        return res

    def __ior__(self, other):
        if other.is_all() or self.is_all():
            self.set_all()
            return self
        if not other:
            return self
        if not self:
            self._override_by_other(other.copy())
            return self
        other_copy = self._prepare_common_active_dimensions(other)
        self.or_aux(other_copy)
        self._reduce_active_dimensions()
        return self

    def or_aux(self, other):
        """
        Recursive function to compute 'or' between two CanonicalHyperCubeSet objects.
        Assuming that self and other have common active dimensions.
        :type other: CanonicalHyperCubeSet
        :return: self
        """
        assert self.active_dimensions == other.active_dimensions
        res_layers = dict()
        remaining_other_layers = dict()  # map from layer_0 elems in orig "other", to remaining parts to be added
        for layer_elem in other.layers:
            remaining_other_layers[layer_elem] = self._copy_layer_elem(layer_elem)
        for self_layer in self.layers:
            remaining_self_layer = self._copy_layer_elem(self_layer)
            for other_layer in other.layers:
                common_elem = self_layer & other_layer
                if not common_elem:
                    continue
                remaining_other_layers[other_layer] -= common_elem
                remaining_self_layer -= common_elem
                if self._is_last_dimension():
                    res_layers[common_elem] = CanonicalHyperCubeSet.empty_interval
                    continue
                new_sub_elem = (self.layers[self_layer].copy()).or_aux(other.layers[other_layer])
                res_layers[common_elem] = new_sub_elem
            if remaining_self_layer:
                res_layers[remaining_self_layer] = self.layers[self_layer]
        for layer_elem, remaining_layer_elem in remaining_other_layers.items():
            if remaining_layer_elem:
                res_layers[remaining_layer_elem] = other.layers[layer_elem]
        self.layers = res_layers
        self._apply_layer_elements_union()
        return self

    def __sub__(self, other):
        res = self.copy()
        res -= other
        return res

    def __isub__(self, other):
        if other.is_all():
            self.clear()
        if not other:
            return self
        other_copy = self._prepare_common_active_dimensions(other)
        self.sub_aux(other_copy)
        self._reduce_active_dimensions()
        return self

    def sub_aux(self, other):
        """
        Recursive function to compute 'sub' between two CanonicalHyperCubeSet objects.
        Assuming that self and other have common active dimensions.
        :type other: CanonicalHyperCubeSet
        :return: self
        """
        assert self.active_dimensions == other.active_dimensions
        res_layers = dict()
        for self_layer in self.layers:
            remaining_self_layer = self._copy_layer_elem(self_layer)
            for other_layer in other.layers:
                common_elem = self_layer & other_layer
                if not common_elem:
                    continue
                remaining_self_layer -= common_elem
                if self._is_last_dimension():
                    # do not add common_elem to self.layers here because result is empty
                    continue
                # sub-elements subtraction
                new_sub_elem = (self.layers[self_layer].copy()).sub_aux(other.layers[other_layer])
                if bool(new_sub_elem):
                    # add remaining new_sub_elem if not empty, under common
                    res_layers[common_elem] = new_sub_elem
            if remaining_self_layer:
                res_layers[remaining_self_layer] = self.layers[self_layer]
        self.layers = res_layers
        self._apply_layer_elements_union()
        return self

    def _prepare_common_active_dimensions(self, other):
        """
        change self and other so that they have common active dimensions.
        Changes to 'other' should be on a new copy, not directly on it.
        :type other: CanonicalHyperCubeSet
        :rtype CanonicalHyperCubeSet
        :return: result for 'other' (which may be copied and changed or not)
        """
        if self.active_dimensions == other.active_dimensions:
            return other
        required_active_dimensions = set(self.active_dimensions + other.active_dimensions)
        self._set_active_dimensions(required_active_dimensions)
        if set(other.active_dimensions) == required_active_dimensions:
            return other
        # should not change active dimensions for 'other' during the computation of operation between self and other
        other_copy = other.copy()
        other_copy._set_active_dimensions(required_active_dimensions)
        return other_copy

    def is_all(self):
        """
        :return: bool indicating if self is the entire defined space
        """
        return not self.active_dimensions

    def set_all(self):
        """
        update self to consist of a cube of the entire defined space
        """
        self.active_dimensions = []
        self.layers = dict()

    # TODO: use _prepare_common_active_dimensions ? (extend it?)
    def contained_in(self, other):
        """
        check containment between CanonicalHyperCubeSet objects: is self contained in other
        :type other: CanonicalHyperCubeSet
        :rtype bool
        """
        if other.is_all() or not self:
            return True
        if not other or self.is_all():
            return False

        required_active_dimensions = set(self.active_dimensions + other.active_dimensions)

        # containment check should not change active dimensions of self/other
        list_required_active_dimensions = self._get_dimensions_subset_by_order(required_active_dimensions)
        return self._contained_in_aux(other, list_required_active_dimensions)

    def _get_last_dim_cube_value(self):
        """
        assuming that self is not empty and has one active dimension, get its dimension value object
        :rtype: Union[CanonicalIntervalSet, MinDFA]
        """
        # for last dimension there is only one cube in layers
        assert len(self.active_dimensions) == 1 and len(self.layers) == 1 and bool(self)
        return list(self.layers.keys())[0]

    def _is_sub_elem_entire_sub_space(self):
        """
        check if self (a hypercubeset sub elem) is equal to the entire sub-space of its active dimensions.
        (currently this situation may occur when this sub-elem is originated from an elem with some active dimension
        that only has effect on another sub-elem).
        :rtype: bool
        """
        # self should equal the cube of all dim_values for dims: self.active_dimensions
        sub_cube_required = self._get_entire_space_cube(self.active_dimensions)
        # create res obj from cube, without reducing the input cube
        obj_from_cube = self._create_from_cube_aux(self.all_dimensions_list, sub_cube_required, self.active_dimensions)
        return obj_from_cube == self

    def _contained_in_aux(self, other, all_active_dims):  # noqa: C901
        """
        recursive function to check containment between CanonicalHyperCubeSet objects.
        :type other: CanonicalHyperCubeSet
        :param list[str] all_active_dims: ordered list of active dims from self or other
        :rtype bool
        """
        assert all_active_dims
        # current_dim is next dimension to handle, may be only in self / other, or in both
        current_dim = all_active_dims[0]
        # case 1: current_dim is only in self
        if current_dim not in other.active_dimensions:
            # can skip containment check of this dimension (any cube in 'other' allows all for this dimension)
            # sub-case (a): last dimension in self
            if self._is_last_dimension():
                if all_active_dims == self.active_dimensions:  # no more active dimensions in 'other'
                    return True
                else:
                    # remaining dimensions in all_active_dims[1:] are only from 'other'
                    # thus, for containment, other should equal the cube of all dim_values for dims: all_active_dims[1:]
                    return other._is_sub_elem_entire_sub_space()
            # sub-case (b): not last dimension in self
            res = True
            # containment check goes to self's sub-cubes, since can skip current dimension containment check
            for next_sub_elem in self.layers.values():
                res &= next_sub_elem._contained_in_aux(other, all_active_dims[1:])
            return res

        # case 2: current_dim is only in other
        if current_dim not in self.active_dimensions:
            # sub-case (a): last dimension in other: since for self it's inactive, for other it should be all sub-space
            if other._is_last_dimension():
                return other._is_sub_elem_entire_sub_space()
            # sub-case (b): not last dimension for other
            # collect into covered_elem_res the union of other's elems in current dim, for which self is contained in
            # their sub-cube [example: self : (methods: ['x']), other: (ports,methods: [5, 'x|abc', 1-4,6-65535,'x'] )
            covered_elem_res = None
            # assuming that other.layers is not empty
            assert other.layers
            for elem, sub_elem in other.layers.items():
                if not self._contained_in_aux(sub_elem, all_active_dims[1:]):
                    return False
                if covered_elem_res is None:
                    covered_elem_res = self._copy_layer_elem(elem)
                else:
                    covered_elem_res |= elem
            # since the current dim is inactive for self, the covered_elem_res should equal the entire dim's domain
            return covered_elem_res == self.dimensions_manager.get_dimension_domain_by_name(current_dim)

        # case 3: current_dim is common to both self and other
        assert(current_dim in self.active_dimensions and current_dim in other.active_dimensions)
        # sub-case (a): current_dim is last for both self and other : simple containment check
        if self._is_last_dimension() and other._is_last_dimension():
            return (self._get_last_dim_cube_value()).contained_in(other._get_last_dim_cube_value())

        # sub-case (b): current_dim is not last dimension for at least self or other
        # each cube in self should be covered by one or more cubes from other
        is_subset_count = 0  # count how many cubes originated from this layer are contained in other's cubes
        for layer in self.layers:
            current_layer_0 = self._copy_layer_elem(layer)
            for other_layer in other.layers:
                other_sub_elem = other.layers[other_layer]
                common_part = current_layer_0 & other_layer
                has_common_part = bool(common_part)
                if has_common_part:
                    if not self._is_last_dimension() and not other._is_last_dimension() and \
                            not (self.layers[layer])._contained_in_aux(other_sub_elem, all_active_dims[1:]):
                        return False
                    remaining = current_layer_0 - common_part
                    if remaining:
                        # continue exploring other's cubes for containment of the remaining part from self
                        current_layer_0 = remaining
                    else:
                        if self._is_last_dimension() and not other._is_last_dimension():
                            # if it's last dim for self but not for other: the remaining of other should be entire cube
                            if other_sub_elem._is_sub_elem_entire_sub_space():
                                is_subset_count += 1
                        else:
                            is_subset_count += 1
                        break
        return is_subset_count == len(self.layers)

    def get_first_item(self, relevant_dimensions=None):
        """
        :param list relevant_dimensions: list of dimensions to include in the result item
        get an item of values within one of self's cubes.
        returning an item with all dimensions in self.all_dimensions_list, if relevant_dimensions is None.
        :return: list[Union[int, str]]
        """
        if not self:
            return NotImplemented
        if self.is_all():
            cube = self._get_entire_space_cube()
        else:
            cube = (self._get_cubes_list_from_layers())[0]
        cube = self._get_aligned_cube_by_new_active_dimensions(cube, self.active_dimensions, self.all_dimensions_list)
        res = []
        for index, dim in enumerate(self.all_dimensions_list):
            if (relevant_dimensions and dim in relevant_dimensions) or relevant_dimensions is None:
                res.append(cube[index].rep())
        return res

    def clear(self):
        """
        update self to be empty
        """
        self.layers = dict()
        self.active_dimensions = self.all_dimensions_list

    def __str__(self):
        if not self:
            return "Empty"
        if not self.active_dimensions:
            return "All"
        active_dims_str = ",".join(dim_name for dim_name in self.active_dimensions)
        cubes_list = self._get_cubes_list_from_layers()
        return active_dims_str + ": " + ",".join(self.get_cube_str(cube) for cube in cubes_list)

    def get_cube_str(self, cube):
        """
        for an input cube, get representing str (corresponding to active dimensions)
        :param cube: list representing a cube with dimensions from self.active_dimensions
        :return: str representation for cube's values
        """
        res = ""
        for dim_index, dim_values in enumerate(cube):
            dim_name = self.active_dimensions[dim_index]
            res += self.dimensions_manager.get_dim_values_str(dim_values, dim_name) + ", "
        return f"({res})"

    def _is_last_dimension(self):
        """
        :return: bool indicating if current active dimension (self.active_dimensions[0]) is considered last dimension.
        """
        return len(self.active_dimensions) == 1

    def add_cube(self, cube_to_add, cube_dimensions=None):
        """
        add a cube to self
        :param list[Union[CanonicalIntervalSet, MinDFA]] cube_to_add: the cube to add to self
        :param list[str] cube_dimensions: (optional) the dimensions list of the input cube
        """
        assert isinstance(cube_to_add, list)
        if cube_dimensions is None and len(cube_to_add) > 0:
            cube_dimensions = self.all_dimensions_list[0:len(cube_to_add)]
        if not cube_to_add:
            return  # ignore empty cube
        for dim_value in cube_to_add:
            if not dim_value:
                return
        cube_obj = CanonicalHyperCubeSet.create_from_cube(self.all_dimensions_list, cube_to_add, cube_dimensions)
        res = self | cube_obj
        self._override_by_other(res)

    def add_hole(self, hole_to_add, hole_dimensions=None):
        """
        add a hole to self
        :param list[Union[CanonicalIntervalSet, MinDFA]] hole_to_add: the hole to add to self
        :param hole_dimensions: (optional) the dimensions list of the input hole
        """
        assert isinstance(hole_to_add, list)
        if hole_dimensions is None and len(hole_to_add) > 0:
            hole_dimensions = self.all_dimensions_list[0:len(hole_to_add)]
        if not hole_to_add:
            return  # ignore empty hole
        for dim_value in hole_to_add:
            if not dim_value:
                return
        cube_obj = CanonicalHyperCubeSet.create_from_cube(self.all_dimensions_list, hole_to_add, hole_dimensions)
        res = self - cube_obj
        self._override_by_other(res)

    @staticmethod
    # TODO: add assumption about the case where cube is point -> not adding dimensions there, only removing
    def _get_aligned_cube_by_new_active_dimensions(cube, current_active_dimensions, new_active_dimensions):
        """
        :param list cube: a cube or a point within the entire space, at some relevant dimensions
        :param list current_active_dimensions: the relevant dimensions for the input cube (ordered)
        :param list new_active_dimensions: the the relevant dimensions for the output cube (ordered)
        :return: cube (list): the input cube/point with more/less dimensions
        """
        if current_active_dimensions == new_active_dimensions:
            return cube
        current_active_dimensions_dict = dict()
        for index, dim_name in enumerate(current_active_dimensions):
            current_active_dimensions_dict[dim_name] = index
        aligned_cube_values = []
        for active_dim_name in new_active_dimensions:
            if active_dim_name in current_active_dimensions_dict:
                aligned_cube_values.append(cube[current_active_dimensions_dict[active_dim_name]])
            else:
                aligned_cube_values.append(DimensionsManager().get_dimension_domain_by_name(active_dim_name))
        return aligned_cube_values

    def _set_active_dimensions(self, dim_names_set):
        """
        update self with active dimensions from dim_names_set.
        :param set[str] dim_names_set: set of dimension names
        """
        if dim_names_set == set(self.active_dimensions):
            return
        # if not dim_names_set.issubset(set(self.all_dimensions_list)):
        #    # TODO: handle errors consistently
        #    raise Exception("Invalid dimension name")
        if dim_names_set.issubset(set(self.active_dimensions)):
            return  # already active -- nothing to do
        # new_active_dimensions should be ordered by the original order determined in self.dim_names
        new_active_dimensions_set = set(self.active_dimensions) | dim_names_set
        new_active_dimensions = self._get_dimensions_subset_by_order(new_active_dimensions_set)
        original_active_dimensions = self.active_dimensions
        # the object is "All" -> create obj of 1 concrete cube with relevant dimensions (all domain per dimension)
        if not original_active_dimensions:  # and not init_as_empty:
            self.active_dimensions = new_active_dimensions
            all_domains_cube = self._get_entire_space_cube(self.active_dimensions)
            # create res obj from cube, without reducing the input cube
            res = self._create_from_cube_aux(self.all_dimensions_list, all_domains_cube, self.active_dimensions)
            self.layers = res.layers
            return
        # update active dimensions + layers:
        self.build_new_active_dimensions(new_active_dimensions)

    def build_new_active_dimensions(self, new_active_dimensions):
        """
        Change self so that its active dimensions are as required by input list.
        :param list[str] new_active_dimensions: list of dimensions to be active in the result.
               Assuming that self's active dimensions is a subset of new_active_dimensions.
        """
        assert set(self.active_dimensions).issubset(set(new_active_dimensions))
        if self.active_dimensions == new_active_dimensions:
            return
        if self.active_dimensions[0] == new_active_dimensions[0]:
            if not self._is_last_dimension():
                for sub_elem in self.layers.values():
                    sub_elem.build_new_active_dimensions(new_active_dimensions[1:])
                self.active_dimensions = new_active_dimensions
                return
            else:
                # handle last dimension
                self.active_dimensions = new_active_dimensions
                new_sub_elem = CanonicalHyperCubeSet(self.all_dimensions_list)
                new_sub_elem.active_dimensions = [new_active_dimensions[1]]
                dim_all_values = self.dimensions_manager.get_dimension_domain_by_name(new_active_dimensions[1])
                new_sub_elem.layers[dim_all_values] = CanonicalHyperCubeSet.empty_interval
                new_sub_elem.build_new_active_dimensions(new_active_dimensions[1:])
                for layer_elem in self.layers:
                    self.layers[layer_elem] = new_sub_elem
                return
        # build new layer for new dimension: new_active_dimensions[0]
        new_layers = dict()
        new_dim = new_active_dimensions[0]
        dim_all_values = self.dimensions_manager.get_dimension_domain_by_name(new_dim)
        new_layers[dim_all_values] = self.copy()
        self.active_dimensions = new_active_dimensions
        new_layers[dim_all_values].build_new_active_dimensions(new_active_dimensions[1:])
        self.layers = new_layers

    def _remove_some_active_dimensions(self, new_active_dimensions):
        """
        Update self so that its new layers and active dimensions are according to the input new_active_dimensions.
        Assuming that the removed active dimensions are with 'allow all' values.
        :param list[str] new_active_dimensions: list of new active dimensions, should be a subset of current
                object's active dimensions
        """
        assert set(new_active_dimensions).issubset(set(self.active_dimensions))
        assert new_active_dimensions
        if self.active_dimensions == new_active_dimensions:
            return
        # case 1: active_dimensions[0] equal to new_active_dimensions[0]
        if self.active_dimensions[0] == new_active_dimensions[0]:
            # comment out redundant case: (caught by prev branch)
            # case 1 (a): last dimension equal -> end
            # if self._is_last_dimension():
            #    return
            # case 1 (b) : not last dimension + has more new_active_dimensions -> handle sub_elements
            if new_active_dimensions[1:]:
                for sub_elem in self.layers.values():
                    sub_elem._remove_some_active_dimensions(new_active_dimensions[1:])
                self.active_dimensions = new_active_dimensions
                return
            # case 1 (c) : not last dimension + no more new_active_dimensions -> should become last dimension
            else:
                for layer_elem in self.layers:
                    self.layers[layer_elem] = CanonicalHyperCubeSet.empty_interval
                self.active_dimensions = new_active_dimensions
                return
        # case 2: active_dimensions[0] should be deleted
        else:
            new_layers = dict()
            for sub_elem in self.layers.values():
                new_layers.update(sub_elem.layers)
            self.layers = new_layers
            self.active_dimensions = self.active_dimensions[1:]
            self._remove_some_active_dimensions(new_active_dimensions)

    def _set_inactive_dimensions(self, dim_names_list):
        """
        update self with inactive dimensions from dim_names_set.
        :param list[str] dim_names_list: list of dimension names
        """
        new_active_dimensions_set = set(self.active_dimensions) - set(dim_names_list)
        new_active_dimensions = self._get_dimensions_subset_by_order(new_active_dimensions_set)
        if not new_active_dimensions:
            self.active_dimensions = []
            self.layers = dict()
            return
        self._remove_some_active_dimensions(new_active_dimensions)

    def _get_values_sets_per_active_dimension(self):
        """
        :return: dict: map from dimension name to set of its possible values in all self's cubes
        """
        res = dict()
        res[self.active_dimensions[0]] = set(self.layers.keys())
        if self._is_last_dimension():
            return res
        for sub_elem in self.layers.values():
            sub_res = sub_elem._get_values_sets_per_active_dimension()
            # merge sub_res into res
            for (dim, dim_values) in sub_res.items():
                if dim not in res:
                    res[dim] = dim_values
                else:
                    res[dim] |= dim_values
        return res

    def _reduce_active_dimensions(self):
        """
        Change self so that its active dimensions are as minimal as possible:
        Inactivate dimensions for which every cube in self allows all its domain.
        """
        if not self or not self.active_dimensions:
            return
        # reduce by searching for active dimensions on which entire domain is allowed for all the cubes
        dimensions_to_reduce = []
        values_per_dimension = self._get_values_sets_per_active_dimension()
        for dim_name, values_set in values_per_dimension.items():
            dim_domain = self.dimensions_manager.get_dimension_domain_by_name(dim_name)
            if {dim_domain} == values_set:
                dimensions_to_reduce.append(dim_name)
        dimensions_to_reduce = self._get_dimensions_subset_by_order(dimensions_to_reduce)
        self._set_inactive_dimensions(dimensions_to_reduce)

    def _apply_layer_elements_union(self):
        """
        Update self's layers so that there are no two paris with identical sub-cube.
        Merging only elements on current active dimension (self.active_dimensions[0]).
        """
        new_layers = dict()
        equiv_classes = dict()
        for layer0, layer1 in self.layers.items():
            if layer1 in equiv_classes:
                equiv_classes[layer1].append(layer0)
            else:
                equiv_classes[layer1] = [layer0]
        for layer_1_elem, layer_0_elem_list in equiv_classes.items():
            layer_0_new_elem = layer_0_elem_list[0]
            for elem in layer_0_elem_list[1:]:
                layer_0_new_elem |= elem
            new_layers[layer_0_new_elem] = layer_1_elem
        self.layers = new_layers
