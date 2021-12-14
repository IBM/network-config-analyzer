#
# Copyright 2020- IBM Inc. All rights reserved
# SPDX-License-Identifier: Apache2.0
#

import copy
from CanonicalHyperCubeSet import CanonicalHyperCubeSet
from CanonicalIntervalSet import CanonicalIntervalSet
from DimensionsManager import DimensionsManager


class ICMPDataSet(CanonicalHyperCubeSet):
    """
    A class holding the set of allowed ICMP connections. Each such connection has a type and code properties.
    The class uses the CanonicalHyperCubeSet to compactly represent a set of (type,code) pairs.
    """

    dimensions_list = ["icmp_type", "icmp_code"]

    def __init__(self, add_all=False):
        super().__init__(ICMPDataSet.dimensions_list, add_all)

    def __str__(self):
        if not self:
            return 'no types'
        if self.is_all():
            return ''
        cubes_list = self._get_cubes_list_from_layers()
        return ",".join(self._get_icmp_cube_str(cube) for cube in cubes_list)

    def _get_icmp_cube_str(self, cube):
        """
        get string representation for icmp properties cube
        :param list cube: a single cube in self
        :return: string representation for the input cube
        """
        components_str_list = []
        for dim_index, dim_values in enumerate(cube):
            dim_name = (self.active_dimensions[dim_index]).replace("icmp_", "")
            components_str_list.append(f'{dim_name}={dim_values}')
        return f"({','.join(c for c in components_str_list)})"

    def get_properties_obj(self):
        """
        get an object for a yaml representation of the protocol's properties
        """
        if self.is_all():
            return {}
        cubes_list = []
        res_obj = {'Type/Code': cubes_list}
        for properties_cube in iter(self):
            # for a cube with only one dimension, the missing (inactive) dimension is icmp_code
            if len(properties_cube) == 1:
                properties_cube.append(DimensionsManager().get_dimension_domain_by_name("icmp_code"))
            cube_str = '/'.join(str(dim_val) for dim_val in properties_cube)
            cubes_list.append(cube_str)
        return res_obj

    def copy(self):
        new_copy = copy.copy(self)
        return new_copy

    @staticmethod
    def check_code_type_validity(icmp_type, icmp_code):
        """
        Checks that the type,code pair is a valid combination for an ICMP connection
        :param int icmp_type: Connection type
        :param int icmp_code: Connection code
        :return: A string with an error if the pair is invalid. An empty string otherwise
        :rtype: str
        """
        if icmp_code is not None and icmp_type is None:
            return 'ICMP code cannot be specified without a type'

        is_valid, err_message = DimensionsManager().validate_value_by_domain(icmp_type, 'icmp_type', 'ICMP type')
        if not is_valid:
            return err_message
        if icmp_code is not None:
            is_valid, err_message = DimensionsManager().validate_value_by_domain(icmp_code, 'icmp_code', 'ICMP code')
            if not is_valid:
                return err_message
        return ''

    @staticmethod
    def _get_properties_cube(icmp_type, icmp_code):
        """
        assuming the icmp_type is not None, return the relevant icmp properties cube:
        if icmp code is None -> res cube is [icmp_type]
        if icmp code is not None -> res cube is [icmp_type, icmp_code]
        For a cube with a missing dimension, all its values apply, thus a cube of [icmp_type]
        is equivalent to a cube of [icmp_type, all-icmp-code-domain]
        :param icmp_type: int : the icmp type value
        :param icmp_code: int or None : the icmp code value
        :return: list[CanonicalIntervalSet]: result cube
        """
        properties_cube = [CanonicalIntervalSet.get_interval_set(icmp_type, icmp_type)]
        if icmp_code is not None:
            properties_cube.append(CanonicalIntervalSet.get_interval_set(icmp_code, icmp_code))
        return properties_cube

    def add_to_set(self, icmp_type, icmp_code):
        """
        Add a new connection to the set of allowed connection
        :param int icmp_type: connection type
        :param int icmp_code: connection code
        :return: None
        """
        if icmp_type is None:
            self.add_all()
            return

        self.add_cube(self._get_properties_cube(icmp_type, icmp_code))

    def add_all_but_given_pair(self, icmp_type, icmp_code):
        """
        Add all possible ICMP connections except for the given (type,code) pair
        :param int icmp_type: connection type
        :param int icmp_code: connection code
        :return: None
        """
        if icmp_type is None:
            self.clear()  # all but everything == nothing
            return

        self.add_all()
        self.add_hole(self._get_properties_cube(icmp_type, icmp_code))

    def add_all(self):
        """
        Add all possible ICMP connections to the set
        :return: None
        """
        self.set_all()

    def print_diff(self, other, self_name, other_name):
        """
        Print the diff between two sets of ICMP connections
        :param ICMPDataSet other: The set of ICMP connections to compare against
        :param self_name: the name of the self set of connections
        :param other_name: the name of the other set of connections
        :return: a string showing one diff in connections (if exists).
        :rtype: str
        """
        self_does_not = ' while ' + self_name + ' does not.'
        other_does_not = ' while ' + other_name + ' does not.'
        self_minus_other = self - other
        other_minus_self = other - self
        if self_minus_other:
            item = self_minus_other.get_first_item()
            return self_name + ' allows code ' + str(item[1]) + ' for type ' + str(item[0]) + other_does_not
        if other_minus_self:
            item = other_minus_self.get_first_item()
            return other_name + ' allows code ' + str(item[1]) + ' for type ' + str(item[0]) + self_does_not
        return 'No diff.'
