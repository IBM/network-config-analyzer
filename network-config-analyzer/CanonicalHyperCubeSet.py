from collections import defaultdict
from CanonicalIntervalSet import CanonicalIntervalSet
from DimensionsManager import DimensionsManager


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
    the representation is defined by an array 'layers', where each element is a pair
    <interval-set, sub-cube> or <dfa, sub-cube> where:
    - The type of the first elem for this pair corresponds to type(active_dimensions[0])
    - interval-set is a CanonicalIntervalSet object,
    - dfa is a MinDFA object
    - sub-cube is a hyper-cube object with dimensions: active_dimensions[1:]
    In addition :
    (1) No two interval-sets/dfas in layers overlap. (they are all disjoint).
    (2) There are no two paris in layers with identical sub-cube.
    (3) For the last active dimension, the layers array consists of one tuple :
        (dfa, empty_interval) or (interval-set, empty-interval)

    * A hyper-cube object always has minimal required active_dimensions.
    * An object that consists of the entire space defined by dimensions has an empty active_dimensions list.
    * An empty object has at least one active dimension and an empty 'layers' array.

    """

    empty_interval = CanonicalIntervalSet()

    def __init__(self, dimensions, allow_all=False):
        # TODO: can change layers to map?
        self.layers = []  # layers are w.r.t active dimensions
        self.dimensions_manager = DimensionsManager()
        self.all_dimensions_list = dimensions
        self.all_dim_types = [self.dimensions_manager.get_dimension_type_by_name(dim_name) for dim_name in dimensions]
        # TODO: should cubes_list be a set instead of list?
        # TODO: can do without cubes_list ?
        self.cubes_list = []  # cubes are w.r.t active dimensions
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
        # TODO: currently comparing cubes_list for testing
        return self.active_dimensions == other.active_dimensions and self.layers == other.layers and self._get_cubes_set() == other._get_cubes_set()

    def _get_cubes_set(self):
        """
        :return: a set of tuples with all cubes in self. (a cube is a tuple with len(self.active_dimensions)
        """
        return set(tuple(cube) for cube in self.cubes_list)

    def _get_dimensions_subset_by_order(self, dimensions_subset):
        """
        :param dimensions_subset: an iterable object with subset of self.all_dimensions_list
        :return: an ordered list of dimensions in dimensions_subset, that corresponds to the ordering in
                 self.all_dimensions_list.
        """
        return [dim for dim in self.all_dimensions_list if dim in dimensions_subset]

    def _get_entire_space_cube(self, dimensions_list_restriction=None):
        """
        :param dimensions_list_restriction: an iterable object with subset of self.all_dimensions_list
        :return: a cube (as a list) with all domain values per required dimensions.
        """
        if dimensions_list_restriction is None:
            dimensions_list_restriction = self.all_dimensions_list
        dimensions_list_ordered = self._get_dimensions_subset_by_order(dimensions_list_restriction)
        cube_res = []
        for dim_name in dimensions_list_ordered:
            cube_res.append(self.dimensions_manager.get_dimension_domain_by_name(dim_name))
        return cube_res

    def _get_dim_values_str(self, dim_values, dim_name):
        """
        :param dim_values: CanonicalIntervalSet of MinDFA object, depends on type(dim_name)
        :param dim_name: string of a dimension name
        :return: a string representing the values in dim_values
        """
        dim_type = self.dimensions_manager.get_dimension_type_by_name(dim_name)
        dim_domain = self.dimensions_manager.get_dimension_domain_by_name(dim_name)

        if dim_type == DimensionsManager.DimensionType.IntervalSet:
            if len(dim_values) > 1:
                return '{' + str(dim_values) + '}'
            return str(dim_values)  # dim_values should be of type CanonicalIntervalSet
        else:  # dim_values should be of type MinDFA
            if dim_values.has_finite_len():
                return str(dim_values)  # return set of words accepted by this MinDFA
            all_words_dfa = dim_domain
            # TODO: for istio regex the "*" corresponds to any string but empty
            if dim_values.is_dfa_wll_words(all_words_dfa):
                return "*"
            # complement dfa
            complement_dfa = dim_values.complement_dfa if dim_values.complement_dfa is not None else all_words_dfa - dim_values
            if complement_dfa.has_finite_len():
                return f'all but {complement_dfa}'  # return set of words not accepted by this MinDFA
            return str(dim_values)  # return regex representing this MinDFA

    def __len__(self):
        if not self.active_dimensions:
            return 1  # considered as 1 cube of the entire space (everything allowed for all dimensions)
        # return the number of cubes in the hypercubeset
        return len(self.cubes_list)

    def __hash__(self):
        dimensions_list_str = ','.join(dim_name for dim_name in self.all_dimensions_list)
        if not self.active_dimensions:  # obj represents the entire space
            return hash(dimensions_list_str)
        # TODO: consider representing cube as tuple instead of list in self.cubes_list
        cubes_tuples = set(tuple(cube) for cube in self.cubes_list)
        if self.active_dimensions and not self.cubes_list:  # obj represents nothing in the entire space
            return hash((frozenset(cubes_tuples), hash(dimensions_list_str)))
        # obj represents some cubes in the entire space
        return hash((frozenset(cubes_tuples), frozenset(self.active_dimensions), hash(dimensions_list_str)))

    # iterate the relevant list of cubes
    def __iter__(self):
        if not self.active_dimensions:
            return iter([self._get_entire_space_cube()])
        return iter(self.cubes_list)

    def copy(self):
        res = CanonicalHyperCubeSet(self.all_dimensions_list)
        for layer in self.layers:
            res.layers.append((layer[0].copy(), layer[1].copy()))
        res.cubes_list = self.cubes_list.copy()
        res.active_dimensions = self.active_dimensions.copy()
        return res

    # TODO: should handle the case that cube item doesn't have all self's active dimensions?
    def __contains__(self, item):
        """
        :param item: an ordered list of items representing an element in the n-dimensional space defined by
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
        if self.is_empty():
            return False
        # reduce item to active dimensions only
        relevant_cube_item = self._get_aligned_cube_by_new_active_dimensions(item, self.all_dimensions_list, self.active_dimensions)
        for cube in self:
            res_per_cube = True
            for index, item in enumerate(relevant_cube_item):
                if item not in cube[index]:
                    res_per_cube = False
                    break
            if res_per_cube:
                return True
        return False

    def __and__(self, other):
        res = self.copy()
        res &= other
        return res

    def __iand__(self, other):
        if other.is_all():
            return self
        if other.is_empty() or self.is_empty():
            self.clear()
            return self
        if self.is_all():
            self = other.copy()
            return self
        self._and_aux(other)
        self._reduce_active_dimensions()
        return self

    def _and_aux(self, other):
        # self and other should have common active dimensions
        required_active_dimensions = set(self.active_dimensions + other.active_dimensions)
        self._set_active_dimensions(required_active_dimensions)
        # should not change active dimensions for 'other' during the computation of intersection
        other_copy = other.copy()
        other_copy._set_active_dimensions(required_active_dimensions)
        res_layers = []
        for self_layer in self.layers:
            for other_layer in other_copy.layers:
                common_elem = self_layer[0] & other_layer[0]
                if common_elem.empty():
                    continue
                if self._is_last_dimension():
                    res_layers.append((common_elem, self_layer[1]))
                    continue
                new_sub_elem = self_layer[1]._and_aux(other_layer[1])
                if new_sub_elem:
                    res_layers.append((common_elem, new_sub_elem))

        self.layers = res_layers
        cubes_list = self._apply_layer_elements_union()
        self.cubes_list = cubes_list
        return self

    def __or__(self, other):
        add_from_other = len(other) <= len(self)
        res = self.copy() if add_from_other else other.copy()
        from_obj = other if add_from_other else self
        res |= from_obj
        return res

    def __ior__(self, other):
        if other.is_all() or self.is_all():
            self.set_all()
            return self
        if other.is_empty():
            return self
        if self.is_empty():
            self = other.copy()
            return self
        for cube in other.cubes_list:
            self._add_cube_aux(cube, other.active_dimensions)
        self._reduce_active_dimensions()
        return self

    def __sub__(self, other):
        res = self.copy()
        res -= other
        return res

    def __isub__(self, other):
        if other.is_all():
            self.clear()
        if other.is_empty():
            return self
        for cube in other:
            self.add_hole_aux(cube, other.active_dimensions)
        self._reduce_active_dimensions()
        return self

    def is_all(self):
        """
        :return: bool indicating if self is the entire defined space
        """
        return not self.active_dimensions

    def is_empty(self):
        """
        :return: bool indicating if self is empty
        """
        return not bool(self)

    def set_all(self):
        """
        update self to consist of a cube of the entire defined space
        """
        self.active_dimensions = []
        self.cubes_list = []
        self.layers = []

    def contained_in(self, other):
        required_active_dimensions = set(self.active_dimensions + other.active_dimensions)
        # containment check should not change active dimensions of self/other
        self_copy = self.copy()
        other_copy = other.copy()
        self_copy._set_active_dimensions(required_active_dimensions)
        other_copy._set_active_dimensions(required_active_dimensions)
        # each cube in self should be covered by one or more cubes from other
        is_subset_count = 0
        for layer in self_copy.layers:
            current_layer_0 = layer[0].copy()
            for other_layer in other_copy.layers:
                other_interval = other_layer[0]
                other_sub_elem = other_layer[1]
                common_part = current_layer_0 & other_interval
                has_common_part = not common_part.empty()
                remaining = current_layer_0 - common_part
                has_remaining = not remaining.empty()

                if has_common_part:
                    if not self_copy._is_last_dimension() and not layer[1].contained_in(other_sub_elem):
                        return False
                    if has_remaining:
                        current_layer_0 = remaining
                    else:
                        is_subset_count += 1
                        break
        return is_subset_count == len(self_copy.layers)

    # TODO: add argument to specify relevant dimensions, or change to active dimensions only
    def get_first_item(self):
        if not self:
            return NotImplemented
        if self.is_all():
            cube = self._get_entire_space_cube()
        else:
            cube = self.cubes_list[0]
        cube = self._get_aligned_cube_by_new_active_dimensions(cube, self.active_dimensions, self.all_dimensions_list)
        res = []
        for index, dim_type in enumerate(self.all_dim_types):
            res.append(cube[index].rep())
        return res

    def clear(self):
        self.cubes_list = []
        self.layers = []
        self.active_dimensions = self.all_dimensions_list

    def __str__(self):
        if not self:
            return "Empty"
        if not self.active_dimensions:
            return "All"
        active_dims_str = ",".join(dim_name for dim_name in self.active_dimensions)
        return active_dims_str + ": " + ",".join(self.get_cube_str(cube) for cube in self)

    def get_cube_str(self, cube):
        """
        :param cube: list representing a cube with dimensions from self.active_dimensions
        :return: str representation for cube's values
        """
        res = ""
        for dim_index, dim_values in enumerate(cube):
            dim_name = self.active_dimensions[dim_index]
            res += self._get_dim_values_str(dim_values, dim_name) + ", "
        return f"({res})"

    def _is_last_dimension(self):
        """
        :return: bool indicating if current active dimension (self.active_dimensions[0]) is considered last dimension.
        """
        return len(self.active_dimensions) == 1

    def add_cube(self, cube_to_add, cube_dimensions=None):
        """
        add cube to self:
        1. _add_cube_aux computes the result and updates self (recursive)
        2. reduce_active_dimensions : update self with minimal required active dimensions on the final result
        :param cube_to_add: list representing a cube to add, with dimensions from cube_dimensions
        :param cube_dimensions: list with the cube dimension names
        """
        if cube_dimensions is None and len(cube_to_add) > 0:
            cube_dimensions = self.all_dimensions_list[0:len(cube_to_add)]
        if not isinstance(cube_to_add, list):
            raise Exception("cube_to_add is not a list")
        if not cube_to_add:
            return  # ignore empty cube
        for dim_value in cube_to_add:
            if dim_value.empty():
                return
        if self._is_cube_entire_space(cube_to_add, cube_dimensions):
            self.set_all()
            return
        self._add_cube_aux(cube_to_add, cube_dimensions)
        # after cube was added, check if some dimensions are now 'allow all', and can be reduced
        self._reduce_active_dimensions()

    def _add_cube_aux(self, cube_to_add, cube_dimensions):
        """
        recursive function to add cube_to_add to self:
        1. add_element_item: get new_layers
        2. _apply_layer_elements_union: apply required union for tuples in layers with identical sub-"hyper-cube-set"
           objects.
        :param cube_to_add: list representing a cube to add, with dimensions from cube_dimensions
        :param cube_dimensions: list with the cube dimension names
        """
        # sanity checks
        if not set(cube_dimensions).issubset(set(self.all_dimensions_list)):
            # raise Exception("Invalid cube_dimensions: not a subset of allowed dimensions")
            return
        dimensions_to_add_as_active = set(cube_dimensions) - set(self.active_dimensions)
        # cube_active_dimensions = set(cube_dimensions) & set(self.active_dimensions)
        # for existing cubes, add this dimension with *all* values
        # align cube_values with active_dimensions by required order, and complete missing dimensions with all_domain_values

        # TODO: if there is a new dimension to be set as active, but its value in this "cube to add" is the entire domain, we can skip it.
        #  currently assuming this is not the case..
        if dimensions_to_add_as_active:
            self._set_active_dimensions(dimensions_to_add_as_active)
        # the cube_to_add should be aligned by active dimensions
        # cube should be aligned even if no dimensions are added as active, because the order may change ..?
        # TODO: (optimization): if self is empty, can change active dimensions according to those of cube...(no need to set all dimensions as active)
        cube_to_add_aligned = self._get_aligned_cube_by_new_active_dimensions(cube_to_add, cube_dimensions,
                                                                              self.active_dimensions)
        # should add the cube: aligned_cube_values, and transform all existing cubes to be consistent with active domains.
        new_item = cube_to_add_aligned[0].copy()
        new_layers = self._add_element_item(new_item, cube_to_add_aligned)
        self.layers = new_layers
        cubes_list = self._apply_layer_elements_union()
        self.cubes_list = cubes_list

    def _add_element_item(self, new_element, cube_to_add):
        """
        computation of new_layers as the result of adding cube_to_add to self.layers
        :param new_element: a MinDFA/CanonicalIntervalSet element - the first element in  cube_to_add
        :param cube_to_add: a cube as a list of elements
        :return: list : new_layers
        """
        new_layers = []
        new_elem_added = False
        for layer_index, layer in enumerate(self.layers):
            layer_elem_set = layer[0]
            layer_sub_element = layer[1]
            elem_set_intersection = layer_elem_set & new_element
            if elem_set_intersection.empty():
                new_layers.append(layer)
            else:
                # split this layer_interval_set based on intersection
                common_elem = elem_set_intersection
                only_layer_elems = layer_elem_set - common_elem
                only_new_elems = new_element - common_elem
                new_layers.append((common_elem, self._get_new_sub_elem(cube_to_add, layer_sub_element.copy())))
                if only_layer_elems:
                    new_layers.append((only_layer_elems, layer_sub_element))
                if only_new_elems:
                    new_element = only_new_elems  # continue exploring with next intervals
                else:
                    new_elem_added = True
        if not new_elem_added:
            new_layers.append((new_element, self._get_new_sub_elem(cube_to_add)))
        return new_layers

    def _get_new_sub_elem(self, cube_to_add, existing_sub_elem=None):
        """
        get the result of a sub-"hyper-cube" object with self.active_dimensions[1:]
        :param cube_to_add: list representing a cube to add, with dimensions from self.active_dimensions
        :param existing_sub_elem: either None or an object of sub-"hyper-cube" with self.active_dimensions[1:]
        :return: CanonicalHyperCubeSet object: the result of adding cube_to_add[1:] to existing_sub_elem if exists,
                 or to an empty sub-"hyper-cube" object.
        """
        if self._is_last_dimension():
            return CanonicalHyperCubeSet.empty_interval
        if existing_sub_elem is not None:
            # initialize new sub-elem with existing sub-elem copy
            res = existing_sub_elem.copy()
        else:
            # initialize an empty sub-elem
            res = CanonicalHyperCubeSet(self.all_dimensions_list)
            res.active_dimensions = self.active_dimensions[1:]
        # update sub-elem with relevant sub-cube from cube_to_add
        res._add_cube_aux(cube_to_add[1:], self.active_dimensions[1:])
        return res

    def add_hole(self, hole_to_add, hole_dimensions=None):
        """
        add hole to self:
        1. add_hole_aux computes the result and updates self (recursive)
        2. _reduce_active_dimensions : update self with minimal required active dimensions on the final result
        :param hole_to_add: list representing a hole cube to add, with dimensions from hole_dimensions
        :param hole_dimensions: list with the hole dimension names
        :return:
        """
        if hole_dimensions is None and len(hole_to_add) > 0:
            hole_dimensions = self.all_dimensions_list[0:len(hole_to_add)]
        if not isinstance(hole_to_add, list):
            raise Exception("hole_to_add is not a list")
        if not hole_to_add:
            return  # ignore empty hole
        for dim_value in hole_to_add:
            if dim_value.empty():
                return
        if self._is_cube_entire_space(hole_to_add, hole_dimensions):
            self.clear()
            return
        self.add_hole_aux(hole_to_add, hole_dimensions)
        # after cube was added, check if some dimensions are now always 'allow all', and can be reduced
        self._reduce_active_dimensions()

    def add_hole_aux(self, hole_to_add, hole_dimensions):
        """
        recursive function to add hole_to_add to self:
        1. add_element_hole: get new_layers
        2. _apply_layer_elements_union: apply required union for tuples in layers with identical sub-"hyper-cube-set"
           objects.
        :param hole_to_add: list representing a hole to add, with dimensions from cube_dimensions
        :param hole_dimensions: list with the hole dimension names
        """
        # TODO: if removing the entire domain on some dimension, the result is empty?
        dimensions_to_add_as_active = set(hole_dimensions) - set(self.active_dimensions)
        if dimensions_to_add_as_active:
            self._set_active_dimensions(dimensions_to_add_as_active)
        hole_to_add_aligned = self._get_aligned_cube_by_new_active_dimensions(hole_to_add, hole_dimensions,
                                                                              self.active_dimensions)
        hole_item = hole_to_add_aligned[0].copy()
        new_layers = self.add_element_hole(hole_item, hole_to_add_aligned)
        self.layers = new_layers
        cubes_list = self._apply_layer_elements_union()
        self.cubes_list = cubes_list

    def add_element_hole(self, hole_elem, hole_to_add):
        """
        computation of new_layers as the result of adding hole_to_add to self.layers
        :param hole_elem: a MinDFA/CanonicalIntervalSet element - the first element in  hole_to_add
        :param hole_to_add: a cube as a list of elements
        :return: list : new_layers
        """
        new_layers = []
        for layer in self.layers:
            layer_elem = layer[0]
            layer_sub_elem = layer[1]
            hole_layer_intersection = hole_elem & layer_elem
            if not hole_layer_intersection.empty():
                only_layer_elem = layer_elem - hole_layer_intersection
                # handle the hole dfa:
                new_sub_elem = self._get_new_sub_elem_hole(hole_to_add, layer_sub_elem)
                if new_sub_elem is not None:  # if the subtraction result is not empty, add the relevant part
                    new_layers.append((hole_layer_intersection, new_sub_elem))
                # handle the remaining layer dfa not impacted by the hole
                if not only_layer_elem.empty():
                    new_layers.append((only_layer_elem, layer_sub_elem))
            else:
                new_layers.append(layer)
        return new_layers

    def _get_new_sub_elem_hole(self, cube_to_remove, existing_sub_elem):
        """
        get the result of a sub-"hyper-cube" object with self.active_dimensions[1:]
        :param cube_to_remove: list representing a cube to remove, with dimensions from self.active_dimensions
        :param existing_sub_elem: an object of sub-"hyper-cube" with self.active_dimensions[1:]
        :return: CanonicalHyperCubeSet object: the result of removing cube_to_add[1:] from existing_sub_elem.
                 if the result is empty, returns None
        """
        if self._is_last_dimension():
            return None
        res = existing_sub_elem.copy()
        res.add_hole_aux(cube_to_remove[1:], self.active_dimensions[1:])
        if not res:  # empty
            return None
        return res

    def _is_cube_entire_space(self, cube, cube_dimensions):
        """
        :param cube: list representing a cube with dimensions from  cube_dimensions
        :param cube_dimensions: list with dimensions names
        :return: bool indicating if cube is equivalent to the entire n-dimensional space cube.
        """
        for dim_index, dim_name in enumerate(cube_dimensions):
            dim_type = self.dimensions_manager.get_dimension_type_by_name(dim_name)
            all_domain = self.dimensions_manager.get_dimension_domain_by_name(dim_name)
            if dim_type == DimensionsManager.DimensionType.DFA and not cube[dim_index].is_dfa_wll_words(all_domain):
                return False
            elif dim_type == DimensionsManager.DimensionType.IntervalSet and not cube[dim_index] == all_domain:
                return False
        return True

    # TODO: simplify this? (update layers directly and not from cubes?)
    def _update_layers_from_cubes_list(self, cubes_list, active_dimensions):
        """
        recursive function to compute self.layers from input cubes_list
        :param cubes_list:
        :param active_dimensions:
        """
        self.cubes_list = cubes_list
        self.active_dimensions = active_dimensions
        self.layers = []
        dim_type = self.dimensions_manager.get_dimension_type_by_name(active_dimensions[0])
        if dim_type == DimensionsManager.DimensionType.IntervalSet:
            current_layer_values = sorted(list(set(cube[0] for cube in self.cubes_list)))
        else:
            current_layer_values = sorted(list(set(cube[0] for cube in self.cubes_list)),
                                          key=lambda layer_elem: layer_elem.get_fsm_str())
        for layer_0_value in current_layer_values:
            if len(self.active_dimensions) == 1:
                self.layers.append((layer_0_value, CanonicalHyperCubeSet.empty_interval))
            else:
                new_sub_elem = CanonicalHyperCubeSet(self.all_dimensions_list)
                sub_elem_cubes_list = [cube[1:] for cube in self.cubes_list if cube[0] == layer_0_value]
                new_sub_elem._update_layers_from_cubes_list(sub_elem_cubes_list, active_dimensions[1:])
                self.layers.append((layer_0_value, new_sub_elem))

    def _get_aligned_cube_by_new_active_dimensions(self, cube, current_active_dimensions, new_active_dimensions):
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
                aligned_cube_values.append(self.dimensions_manager.get_dimension_domain_by_name(active_dim_name))
        return aligned_cube_values

    def _set_active_dimensions(self, dim_names_set):
        """
        update self with active dimensions from dim_names_set.
        :param dim_names_set: set of dimension names
        """
        if not dim_names_set.issubset(set(self.all_dimensions_list)):
            # TODO: handle errors consistently
            raise Exception("Invalid dimension name")
        if dim_names_set.issubset(set(self.active_dimensions)):
            return  # already active -- nothing to do
        # new_active_dimensions should be ordered by the original order determined in self.dim_names
        new_active_dimensions_set = set(self.active_dimensions) | dim_names_set
        new_active_dimensions = self._get_dimensions_subset_by_order(new_active_dimensions_set)
        original_active_dimensions = self.active_dimensions

        # the object is "All" -> add 1 concrete cube with relevant dimensions (all domain per dimension)
        if not original_active_dimensions:  # and not init_as_empty:
            self.active_dimensions = new_active_dimensions
            all_domains_cube = self._get_entire_space_cube(self.active_dimensions)
            self._add_cube_aux(all_domains_cube, self.active_dimensions)
            return

        # update active dimensions, update each cube with new dimensions, update each layer as well:
        self.active_dimensions = new_active_dimensions
        # transform existing cubes to be consistent with new added dimensions, according to required order
        new_cubes_list = [
            self._get_aligned_cube_by_new_active_dimensions(cube, original_active_dimensions, new_active_dimensions) for
            cube in self.cubes_list]
        self._update_layers_from_cubes_list(new_cubes_list, new_active_dimensions)

    def _set_inactive_dimensions(self, dim_names_list):
        new_active_dimensions_set = set(self.active_dimensions) - set(dim_names_list)
        original_active_dimensions = self.active_dimensions
        self.active_dimensions = self._get_dimensions_subset_by_order(new_active_dimensions_set)
        if not self.active_dimensions:
            self.cubes_list = []
            self.layers = []
            return
        new_cubes_list = [
            self._get_aligned_cube_by_new_active_dimensions(cube, original_active_dimensions, self.active_dimensions) for
            cube in self.cubes_list]
        self._update_layers_from_cubes_list(new_cubes_list, self.active_dimensions)

    def _reduce_active_dimensions(self):
        if not self or not self.active_dimensions:
            return
        # reduce by searching for active dimensions on which entire domain is allowed for all the cubes
        entire_domain_per_dimension_count_cubes = defaultdict(int)
        for cube in self:
            for dim_index, dim_name in enumerate(self.active_dimensions):
                dim_type = self.dimensions_manager.get_dimension_type_by_name(dim_name)
                if dim_type == DimensionsManager.DimensionType.DFA:
                    curr_dfa = cube[dim_index]
                    if curr_dfa.is_dfa_wll_words(self.dimensions_manager.get_dimension_domain_by_name(dim_name)):
                        entire_domain_per_dimension_count_cubes[dim_name] += 1
                elif cube[dim_index] == self.dimensions_manager.get_dimension_domain_by_name(dim_name):
                    entire_domain_per_dimension_count_cubes[dim_name] += 1
        dimensions_to_reduce = [dim for dim in entire_domain_per_dimension_count_cubes if
                                entire_domain_per_dimension_count_cubes[dim] == len(self.cubes_list)]
        self._set_inactive_dimensions(dimensions_to_reduce)

    def _apply_layer_elements_union(self):
        new_layers = []
        cubes_list = []
        dim_type = self.dimensions_manager.get_dimension_type_by_name(self.active_dimensions[0])
        equiv_classes = dict()  # map from str(l1) to tuple (list(l0) items, l1 item)
        for layer in self.layers:
            if layer[1] in equiv_classes:
                equiv_classes[layer[1]].append(layer[0])
            else:
                equiv_classes[layer[1]] = [layer[0]]
        for layer_1_elem, layer_0_elem_list in equiv_classes.items():
            layer_0_new_elem = layer_0_elem_list[0]
            for elem in layer_0_elem_list[1:]:
                layer_0_new_elem |= elem
            new_layers.append((layer_0_new_elem, layer_1_elem))
            if not self._is_last_dimension():
                for sub_cube in layer_1_elem.cubes_list:
                    new_cube = [layer_0_new_elem] + sub_cube
                    cubes_list.append(new_cube)
            else:
                cubes_list.append([layer_0_new_elem])
        if dim_type == DimensionsManager.DimensionType.IntervalSet:
            self.layers = sorted(new_layers, key=lambda layer_elem: layer_elem[0])
        else:
            self.layers = sorted(new_layers, key=lambda layer_elem: layer_elem[0].get_fsm_str())
        return cubes_list
