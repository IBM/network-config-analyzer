#
# Copyright 2020- IBM Inc. All rights reserved
# SPDX-License-Identifier: Apache2.0
#

from CanonicalIntervalSet import CanonicalIntervalSet
from CanonicalHyperCubeSet import CanonicalHyperCubeSet
from DimensionsManager import DimensionsManager
from PortSet import PortSet
from MethodSet import MethodSet

class TcpLikeProperties(CanonicalHyperCubeSet):
    """
    A class for holding a set of cubes, each defined over dimensions from TcpLikeProperties.dimensions_list
    For UDP, SCTP protocols, the actual used dimensions are only [source ports, dest ports]
    for TCP, it may be any of the dimensions from dimensions_list.

    Also, including support for (included and excluded) named ports (relevant for dest ports only).

    The representation with named ports is considered a mid-representation, and is required due to the late binding
    of the named ports to real ports numbers.
    The method convert_named_ports is responsible for applying this late binding, and is called by a policy's method
    allowed_connections(), to get the the actual policy's allowed connections, given src peer, dest peer and direction ingress/egress.
    Given a specific context of dest peer, the pod's named ports mapping is known, and used for the named ports conversion.
    Some of the operators for TcpLikeProperties are not supported for objects with (included and excluded) named ports.
    For example, in the general case, the result for (all but port "x") | (all but port 10) has 2 options:
        (1) if the dest pod has named port "x" mapped to 10 -> the result would be: (all but port 10)
        (2) otherwise, the result would be: (all ports)
    Thus, for the 'or' operator, the assumption is that excluded named ports is empty for both input objects.
    Some methods, such as bool(), str(), may not return accurate results on objects with named ports (included/excluded),
    since they depend on the late binding with actual dest pod context.
    The current actual flow for using named ports is limited for the following:
    (1) k8s: only positive named ports, only dest named ports (no src ports), and only use of 'or' operators between these objects.
    (2) calico: positive and negative named ports, only dest named ports (no src ports), and no use of operators between these objects.
    """

    dimensions_list = ["src_ports", "dst_ports", "methods", "paths", "hosts"]

    # TODO: change constructor defaults? either all arguments in "allow all" by default, or "empty" by default
    def __init__(self, source_ports=PortSet(), dest_ports=PortSet(), methods=MethodSet(True), paths=None, hosts=None):
        """
        This will create all cubes made of the input arguments ranges/regex values.
        :param PortSet source_ports: The set of source ports (as a set of intervals/ranges)
        :param PortSet dest_ports: The set of target ports (as a set of intervals/ranges)
        :param MethodSet methods: the set of http request methods
        :param MinDFA paths: The dfa of http request paths
        :param MinDFA hosts: The dfa of http request hosts
        """
        super().__init__(TcpLikeProperties.dimensions_list)

        self.named_ports = {}  # a mapping from dst named port (String) to src ports interval set
        self.excluded_named_ports = {}  # a mapping from dst named port (String) to src ports interval set

        # create the cube from input arguments
        cube = []
        active_dims = []
        if not source_ports.is_all():
            cube.append(source_ports.port_set)
            active_dims.append("src_ports")
        if not dest_ports.is_all():
            cube.append(dest_ports.port_set)
            active_dims.append("dst_ports")
        if not methods.is_whole_range():
            cube.append(methods)
            active_dims.append("methods")
        if paths is not None:
            cube.append(paths)
            active_dims.append("paths")
        if hosts is not None:
            cube.append(hosts)
            active_dims.append("hosts")

        if not active_dims:
            self.set_all()
        else:
            has_empty_dim_value = False
            for dim_val in cube:
                if not dim_val:
                    has_empty_dim_value = True
                    break
            if not has_empty_dim_value:
                self.add_cube(cube, active_dims)

        # assuming named ports are only in dest, not src
        all_ports = PortSet.all_ports_interval.copy()
        for port_name in dest_ports.named_ports:
            self.named_ports[port_name] = source_ports.port_set
        for port_name in dest_ports.excluded_named_ports:
            # self.excluded_named_ports[port_name] = all_ports - source_ports.port_set
            self.excluded_named_ports[port_name] = all_ports

    def __bool__(self):
        return super().__bool__() or bool(self.named_ports)

    def __str__(self):
        if self.is_all():
            return ''
        if not super().__bool__():
            return 'Empty'
        if self.active_dimensions == ['dst_ports']:
            assert (len(self) == 1)
            for cube in self:
                ports_list = self.get_interval_set_list_obj(cube[0])
                ports_str = ','.join(str(ports_interval) for ports_interval in ports_list)
                return ports_str

        cubes_dict_list = [self.get_cube_dict(cube, self.active_dimensions, True) for cube in self]
        return ','.join(str(cube_dict) for cube_dict in cubes_dict_list)

    @staticmethod
    def get_interval_set_list_obj(interval_set):
        """
        get list of ports from input interval set
        the list may contain int values (for single ports) and str values (for port ranges)
        e.g. if interval_set = {1-1,3-5}, then the output would be: [1, '3-5']
        :param CanonicalIntervalSet interval_set: an interval-set object
        :return: list of intervals or int values from input interval_set
        :rtype: list
        """
        res = []
        for interval in interval_set:
            if interval.start == interval.end:
                res.append(interval.start)
            else:
                res.append(f'{interval.start}-{interval.end}')
        return res

    @staticmethod
    def get_cube_dict(cube, dims_list, is_txt=False):
        """
        represent the properties cube as dict objet, for output generation as yaml/txt format
        :param list cube: the values of the input cube
        :param list dims_list: the list of dimensions for the input cube
        :param bool is_txt: flag indicating if output is for txt or yaml format
        :return: the cube properties in dict representation
        :rtype: dict
        """
        cube_dict = {}
        for i, dim in enumerate(dims_list):
            dim_values = cube[i]
            dim_type = DimensionsManager().get_dimension_type_by_name(dim)
            dim_domain = DimensionsManager().get_dimension_domain_by_name(dim)
            if dim_domain == dim_values:
                continue  # skip dimensions with all values allowed in a cube
            if dim == 'methods':
                method_names = MethodSet.get_method_names_from_interval_set(dim_values)
                compl_method_names = MethodSet.get_compl_method_names_from_interval_set(dim_values)
                if len(method_names) <= len(compl_method_names):
                    values_list = ', '.join(method for method in method_names)
                else:
                    values_list = 'all but ' + ', '.join(method for method in compl_method_names)
            elif dim_type == DimensionsManager.DimensionType.IntervalSet:
                values_list = TcpLikeProperties.get_interval_set_list_obj(dim_values)
                if is_txt:
                    values_list = ','.join(str(interval) for interval in values_list)
            else:
                # TODO: should be a list of words for a finite len DFA?
                values_list = DimensionsManager().get_dim_values_str(dim_values, dim)
            cube_dict[dim] = values_list
        return cube_dict

    def get_properties_obj(self):
        """
        get an object for a yaml representation of the protocol's properties
        """
        if self.is_all():
            return {}
        cubs_dict_list = []
        for cube in self:
            cube_dict = self.get_cube_dict(cube, self.active_dimensions)
            cubs_dict_list.append(cube_dict)
        if self.active_dimensions == ['dst_ports']:
            assert len(cubs_dict_list) == 1
            return {'Ports': cubs_dict_list[0]['dst_ports']}
        return {'properties': cubs_dict_list}

    def __eq__(self, other):
        if isinstance(other, TcpLikeProperties):
            res = super().__eq__(other) and self.named_ports == other.named_ports and \
                  self.excluded_named_ports == other.excluded_named_ports
            return res
        return NotImplemented

    def __and__(self, other):
        res = self.copy()
        res &= other
        return res

    def __or__(self, other):
        res = self.copy()
        res |= other
        return res

    def __sub__(self, other):
        res = self.copy()
        res -= other
        return res

    def __iand__(self, other):
        assert not self.has_named_ports()
        assert not isinstance(other, TcpLikeProperties) or not other.has_named_ports()
        super().__iand__(other)
        return self

    def __ior__(self, other):
        assert not self.excluded_named_ports
        assert not isinstance(other, TcpLikeProperties) or not other.excluded_named_ports
        super().__ior__(other)
        if isinstance(other, TcpLikeProperties):
            res_named_ports = dict({})
            for port_name in self.named_ports:
                res_named_ports[port_name] = self.named_ports[port_name]
            for port_name in other.named_ports:
                if port_name in res_named_ports:
                    res_named_ports[port_name] |= other.named_ports[port_name]
                else:
                    res_named_ports[port_name] = other.named_ports[port_name]
            self.named_ports = res_named_ports
        return self

    def __isub__(self, other):
        assert not self.has_named_ports()
        assert not isinstance(other, TcpLikeProperties) or not other.has_named_ports()
        super().__isub__(other)
        return self

    def contained_in(self, other):
        """
        :param TcpLikeProperties other: Another PortSetPair
        :return: Whether all (source port, target port) pairs in self also appear in other
        :rtype: bool
        """
        assert not self.has_named_ports()
        assert not other.has_named_ports()
        return super().contained_in(other)

    def has_named_ports(self):
        return self.named_ports or self.excluded_named_ports

    def get_named_ports(self):
        res = set()
        res |= set(self.named_ports.keys())
        res |= set(self.excluded_named_ports.keys())
        return res

    def convert_named_ports(self, named_ports, protocol):
        """
        Replaces all references to named ports with actual ports, given a mapping
        NOTE: that this function modifies self
        :param dict[str, (int, int)] named_ports: The mapping from a named to port (str) to the actual port number
        :param int protocol: The relevant protocol
        :return: None
        """
        if not named_ports:
            named_ports = {}

        my_named_ports = self.named_ports
        self.named_ports = {}
        my_excluded_named_ports = self.excluded_named_ports
        self.excluded_named_ports = {}

        for port in my_named_ports:
            real_port = named_ports.get(port)
            if real_port and real_port[1] == protocol:
                real_port_number = real_port[0]
                rectangle = [my_named_ports[port], CanonicalIntervalSet.get_interval_set(real_port_number, real_port_number)]
                self.add_cube(rectangle)
        for port in my_excluded_named_ports:
            real_port = named_ports.get(port)
            if real_port and real_port[1] == protocol:
                real_port_number = real_port[0]
                rectangle = [my_excluded_named_ports[port], CanonicalIntervalSet.get_interval_set(real_port_number, real_port_number)]
                self.add_hole(rectangle)

    def copy(self):
        res = TcpLikeProperties()
        # from CanonicalHyperCubeSet.copy():
        for layer in self.layers:
            res.layers[self._copy_layer_elem(layer)] = self.layers[layer].copy()
        res.active_dimensions = self.active_dimensions.copy()

        res.named_ports = self.named_ports.copy()
        res.excluded_named_ports = self.excluded_named_ports.copy()
        return res

    # TODO: update this function: a diff item is not necessarily a [source-destination pair] as used to be on PortSetPair
    def print_diff(self, other, self_name, other_name):
        """
        :param TcpLikeProperties other: Another PortSetPair object
        :param str self_name: A name for 'self'
        :param str other_name: A name for 'other'
        :return: If self!=other, return a string showing a (source, target) pair that appears in only one of them
        :rtype: str
        """
        self_minus_other = self - other
        other_minus_self = other - self
        diff_str = self_name if self_minus_other else other_name
        if self_minus_other:
            item = self_minus_other.get_first_item()
            diff_str += f' allows communication on {item} while {other_name} does not [source-destination pair] '
            return diff_str
        if other_minus_self:
            item = other_minus_self.get_first_item()
            diff_str += f' allows communication on {item} while {self_name} does not [source-destination pair] '
            return diff_str
        return 'No diff.'
