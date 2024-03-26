#
# Copyright 2020- IBM Inc. All rights reserved
# SPDX-License-Identifier: Apache2.0
#

from .CanonicalIntervalSet import CanonicalIntervalSet
from .CanonicalHyperCubeSet import CanonicalHyperCubeSet
from .DimensionsManager import DimensionsManager
from .PortSet import PortSet
from .MethodSet import MethodSet
from .Peer import PeerSet, BasePeerSet
from .ProtocolNameResolver import ProtocolNameResolver
from .MinDFA import MinDFA
from .ConnectivityCube import ConnectivityCube


class ConnectivityProperties(CanonicalHyperCubeSet):
    """
    A class for holding a set of cubes, each defined over dimensions from ConnectivityCube.dimensions_list
    For UDP, SCTP protocols, the actual used dimensions are only [src_peers, dst_peers, src_ports, dst_ports],
    for TCP, it may be any of the dimensions from dimensions_list, except for icmp_type and icmp_code,
    for icmp data the actual used dimensions are only [src_peers, dst_peers, icmp_type, icmp_code].

    The usage of this class in the original solution:
        In the original solution ConnectivityProperties do not hold src_peers, dst_peers and protocols dimensions.
        First, ConnectivityProperties are built at parse time. Since peers are not a part of ConnectivityProperties,
        the named ports cannot be resolved at parse time, and so are kept in named_ports and excluded_named_ports,
        as explained below.
        Second, at the query time, ConnectivityProperties is calculated for every pair of peers, and the named ports
        are resolved. The pairs of peers and the protocols are kept in ConnectionSet class, together with
        the resulting ConnectivityProperties.

    The usage of this class in the optimized solution:
        In the optimized solution ConnectivityProperties potentially hold all the dimensions, including sets
        of source peers and destination peers. The connectivity properties are built at the parse time for every policy.
        The named ports are resolved during the construction, therefore in the optimized solution named_ports and
        excluded_named_ports fields are not used.

        The src_peers and dst_peers dimensions are special dimensions,  they do not have constant domain. Their domain
        depends on the current set of peers in the system (as appears in BasePeerSet singleton). This set grows when
        adding more configurations. Thus, there is no unique 'all values' representation. In particular, those
        dimensions are never reduced to inactive.
        This might be a problem in comparison and inclusion operators of ConnectivityProperties. The possible solution
        may be to keep 'reference full domain value' for these dimensions (as another member in the BasePeerSet),
        and to set it to relevant values per query, and to make a special treatment of these dimensions
        in the above operators.

    Also, including support for (included and excluded) named ports (relevant for dest ports only).

    The representation with named ports is considered a mid-representation, and is required due to the late binding
    of the named ports to real ports numbers.
    The method convert_named_ports is responsible for applying this late binding, and is called by a policy's method
    allowed_connections() to get policy's allowed connections, given <src, dest> peers and direction ingress/egress
    Given a specific dest-peer context, the pod's named ports mapping is known, and used for the named ports conversion.
    Some of the operators for ConnectivityProperties are not supported for objects with (included and excluded) named ports.
    For example, in the general case, the result for (all but port "x") | (all but port 10) has 2 options:
        (1) if the dest pod has named port "x" mapped to 10 -> the result would be: (all but port 10)
        (2) otherwise, the result would be: (all ports)
    Thus, for the 'or' operator, the assumption is that excluded named ports is empty for both input objects.
    Some methods, such as bool(), str(), may not return accurate results on objects with named ports (included/excluded)
    since they depend on the late binding with actual dest pod context.
    The current actual flow for using named ports is limited for the following:
    (1) k8s: only +ve named ports, no src named ports, and only use of 'or' operators between these objects.
    (2) calico: +ve and -ve named ports, no src named ports, and no use of operators between these objects.
    """

    def __init__(self, dimensions_list=None, create_all=False):
        """
        This will create empty or full connectivity properties, depending on create_all flag.
        :param create_all: whether to create full connectivity properties.
        """
        super().__init__(dimensions_list if dimensions_list else ConnectivityCube.all_dimensions_list)
        self.named_ports = {}  # a mapping from dst named port (String) to src ports interval set
        self.excluded_named_ports = {}  # a mapping from dst named port (String) to src ports interval set
        if create_all:
            self.set_all()

    @staticmethod
    def _make_conn_props_no_named_ports_resolution(conn_cube):
        """
        This will create connectivity properties made of the given connectivity cube.
        This includes tcp properties, non-tcp properties, icmp data properties.
        :param ConnectivityCube conn_cube: the input connectivity cube including all dimension values,
            whereas missing dimensions are represented by their default values (representing all possible values).
        """
        res = ConnectivityProperties()
        if conn_cube.is_empty():
            return res

        cube, active_dims = conn_cube.get_ordered_cube_and_active_dims()
        if not active_dims:
            res.set_all()
        else:
            res.add_cube(cube, active_dims)

        # assuming named ports may be only in dst, not in src
        src_ports = conn_cube["src_ports"]
        dst_ports = conn_cube["dst_ports"]
        assert not src_ports.named_ports and not src_ports.excluded_named_ports
        all_ports = PortSet.all_ports_interval.copy()
        for port_name in dst_ports.named_ports:
            res.named_ports[port_name] = src_ports.port_set
        for port_name in dst_ports.excluded_named_ports:
            res.excluded_named_ports[port_name] = all_ports
        return res

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
                ports_list = cube[0].get_interval_set_list_numbers_and_ranges()
                ports_str = ','.join(str(ports_interval) for ports_interval in ports_list)
                return ports_str

        cubes_dict_list = [self.get_cube_dict(cube, True) for cube in self]
        return ','.join(str(cube_dict) for cube_dict in cubes_dict_list)

    def __hash__(self):
        return super().__hash__()

    def get_connectivity_cube(self, cube):
        """
        translate the ordered cube to ConnectivityCube format
        :param list cube: the values of the ordered input cube
        :return: the cube in ConnectivityCube format
        :rtype: ConnectivityCube
        """
        res = ConnectivityCube(self.all_dimensions_list)
        for i, dim in enumerate(self.active_dimensions):
            if isinstance(cube[i], MinDFA):
                res.set_dim_directly(dim, cube[i])
            else:
                res.set_dim_directly(dim, cube[i].copy())
        return res

    def get_cube_dict(self, cube, is_txt=False):
        """
        represent the properties cube as dict object, for output generation as yaml/txt format
        :param list cube: the values of the input cube
        :param bool is_txt: flag indicating if output is for txt or yaml format
        :return: the cube properties in dict representation
        :rtype: dict
        """
        cube_dict = {}
        for i, dim in enumerate(self.active_dimensions):
            dim_values = cube[i]
            dim_type = DimensionsManager().get_dimension_type_by_name(dim)
            dim_domain = DimensionsManager().get_dimension_domain_by_name(dim)
            if dim_domain == dim_values:
                continue  # skip dimensions with all values allowed in a cube
            if dim in ['protocols', 'methods']:
                values_list = str(dim_values)
            elif dim in ["src_peers", "dst_peers"]:
                peers_set = BasePeerSet().get_peer_set_by_indices(dim_values)
                peers_str_list = sorted([str(peer.full_name()) for peer in peers_set])
                values_list = ','.join(peers_str_list) if is_txt else peers_str_list
            elif dim_type == DimensionsManager.DimensionType.IntervalSet:
                values_list = dim_values.get_interval_set_list_numbers_and_ranges()
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
            cube_dict = self.get_cube_dict(cube)
            cubs_dict_list.append(cube_dict)
        if self.active_dimensions == ['dst_ports']:
            assert len(cubs_dict_list) == 1
            return {'Ports': cubs_dict_list[0]['dst_ports']}
        return {'properties': cubs_dict_list}

    def __eq__(self, other):
        if isinstance(other, ConnectivityProperties):
            res = super().__eq__(other) and self.named_ports == other.named_ports and \
                self.excluded_named_ports == other.excluded_named_ports
            return res
        return False

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
        assert not isinstance(other, ConnectivityProperties) or not other.has_named_ports()
        super().__iand__(other)
        return self

    def __ior__(self, other):
        assert not self.excluded_named_ports
        assert not isinstance(other, ConnectivityProperties) or not other.excluded_named_ports
        super().__ior__(other)
        if isinstance(other, ConnectivityProperties):
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
        assert not isinstance(other, ConnectivityProperties) or not other.has_named_ports()
        super().__isub__(other)
        return self

    def contained_in(self, other):
        """
        :param ConnectivityProperties other: another connectivity properties
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

        active_dims = ["src_ports", "dst_ports"]
        for port in my_named_ports:
            real_port = named_ports.get(port)
            if real_port and real_port[1] == protocol:
                real_port_number = real_port[0]
                rectangle = [my_named_ports[port],
                             CanonicalIntervalSet.get_interval_set(real_port_number, real_port_number)]
                self.add_cube(rectangle, active_dims)
        for port in my_excluded_named_ports:
            real_port = named_ports.get(port)
            if real_port and real_port[1] == protocol:
                real_port_number = real_port[0]
                rectangle = [my_excluded_named_ports[port],
                             CanonicalIntervalSet.get_interval_set(real_port_number, real_port_number)]
                self.add_hole(rectangle, active_dims)

    def copy(self):
        """
        :rtype: ConnectivityProperties
        """
        res = ConnectivityProperties(self.all_dimensions_list)
        for layer in self.layers:
            res.layers[self._copy_layer_elem(layer)] = self.layers[layer].copy()
        res.active_dimensions = self.active_dimensions.copy()

        res.named_ports = self.named_ports.copy()
        res.excluded_named_ports = self.excluded_named_ports.copy()
        return res

    def print_diff(self, other, self_name, other_name):
        """
        :param ConnectivityProperties other: another connectivity properties object
        :param str self_name: A name for 'self'
        :param str other_name: A name for 'other'
        :return: If self!=other, return a string showing a (source, target) pair that appears in only one of them
        :rtype: str
        """
        self_minus_other = self - other
        other_minus_self = other - self
        diff_str = self_name if self_minus_other else other_name
        if self_minus_other:
            diff_str += f' allows communication on {self_minus_other._get_first_item_str()} while {other_name} does not'
            return diff_str
        if other_minus_self:
            diff_str += f' allows communication on {other_minus_self._get_first_item_str()} while {self_name} does not'
            return diff_str
        return 'No diff.'

    def _get_first_item_str(self):
        """
        :return: str of a first item in self
        """
        item = self.get_first_item(self.active_dimensions)
        res_list = []
        for i, dim_name in enumerate(self.active_dimensions):
            if dim_name == 'protocols':
                dim_item = ProtocolNameResolver.get_protocol_name(item[i])
            elif dim_name == 'methods':
                dim_item = MethodSet.all_methods_list[item[i]]
            else:
                dim_item = item[i]
            res_list.append(f'{dim_name}={dim_item}')
        return '[' + ','.join(s for s in res_list) + ']'

    def project_on_one_dimension(self, dim_name):
        """
        Build the projection of self to the given dimension.
        Supports any dimension except of icmp data (icmp_type and icmp_code).
        :param str dim_name: the given dimension
        :return: the projection on the given dimension, having that dimension type.
         or None if the given dimension is not active
        """
        assert dim_name not in ["icmp_type", "icmp_code"]  # not supporting icmp dimensions
        if dim_name not in self.active_dimensions:
            if dim_name == "src_peers" or dim_name == "dst_peers":
                return BasePeerSet().get_peer_set_by_indices(DimensionsManager().get_dimension_domain_by_name(dim_name))
            else:
                return DimensionsManager().get_dimension_domain_by_name(dim_name)
        if dim_name == "src_peers" or dim_name == "dst_peers":
            res = PeerSet()
        elif dim_name == "src_ports" or dim_name == "dst_ports":
            res = PortSet()
        else:
            res = DimensionsManager().get_empty_dimension_by_name(dim_name)
        for cube in self:
            conn_cube = self.get_connectivity_cube(cube)
            values = conn_cube[dim_name]
            if values and res:
                res |= values
            elif values:
                res = values
        return res

    @staticmethod
    def _resolve_named_ports(named_ports, peer, protocols):
        peer_named_ports = peer.get_named_ports()
        real_ports = PortSet()
        for named_port in named_ports:
            real_port = peer_named_ports.get(named_port)
            if not real_port:
                print(f'Warning: Missing named port {named_port} in the pod {peer}. Ignoring the pod')
                continue
            if real_port[1] not in protocols:
                print(f'Warning: Illegal protocol {real_port[1]} in the named port {named_port} '
                      f'of the pod {peer}. Ignoring the pod')
                continue
            real_ports.add_port(real_port[0])
        return real_ports

    @staticmethod
    def make_conn_props(conn_cube):
        """
        This will create connectivity properties made of the given connectivity cube.
        This includes tcp properties, non-tcp properties, icmp data properties.
        If possible (i.e., in the optimized solution, when dst_peers are supported in the given cube),
        the named ports will be resolved.

        In the optimized solution, the resulting ConnectivityProperties should not contain named ports:
            they are substituted with corresponding port numbers, per peer
        In the original solution, the resulting ConnectivityProperties may contain named ports;
            they cannot yet be resolved, since dst peers are not provided at this stage the original solution;
            they will be resolved by convert_named_ports call during query runs.

        :param ConnectivityCube conn_cube: the input connectivity cube including all dimension values,
            whereas missing dimensions are represented by their default values (representing all possible values).
        """

        src_ports = conn_cube["src_ports"]
        dst_ports = conn_cube["dst_ports"]
        assert not src_ports.named_ports and not src_ports.excluded_named_ports
        if (not dst_ports.named_ports and not dst_ports.excluded_named_ports) or \
                not conn_cube.is_active_dim("dst_peers"):
            # Should not resolve named ports
            return ConnectivityProperties._make_conn_props_no_named_ports_resolution(conn_cube)

        # Initialize conn_properties
        if dst_ports.port_set:
            dst_ports_no_named_ports = PortSet()
            dst_ports_no_named_ports.port_set = dst_ports.port_set.copy()
            conn_cube["dst_ports"] = dst_ports_no_named_ports
            conn_properties = ConnectivityProperties._make_conn_props_no_named_ports_resolution(conn_cube)
        else:
            conn_properties = ConnectivityProperties.make_empty_props()

        # Resolving dst named ports
        protocols = conn_cube["protocols"]
        dst_peers = conn_cube["dst_peers"]
        for peer in dst_peers:
            real_ports = ConnectivityProperties._resolve_named_ports(dst_ports.named_ports, peer, protocols)
            if real_ports:
                conn_cube.update({"dst_ports": real_ports, "dst_peers": PeerSet({peer})})
                conn_properties |= ConnectivityProperties._make_conn_props_no_named_ports_resolution(conn_cube)
            excluded_real_ports = ConnectivityProperties._resolve_named_ports(dst_ports.excluded_named_ports, peer, protocols)
            if excluded_real_ports:
                conn_cube.update({"dst_ports": excluded_real_ports, "dst_peers": PeerSet({peer})})
                conn_properties -= ConnectivityProperties._make_conn_props_no_named_ports_resolution(conn_cube)
        return conn_properties

    @staticmethod
    def make_conn_props_from_dict(the_dict):
        cube = ConnectivityCube.make_from_dict(the_dict)
        return ConnectivityProperties.make_conn_props(cube)

    @staticmethod
    def get_all_conns_props_per_config_peers(peer_container):
        """
        Return all possible between-peers connections.
        This is a compact way to represent all peers connections, but it is an over-approximation also containing
        IpBlock->IpBlock connections. Those redundant connections will be eventually filtered out.
        """
        all_peers_and_ips_and_dns = peer_container.get_all_peers_group(True, True, True)
        return ConnectivityProperties.make_conn_props_from_dict({"src_peers": all_peers_and_ips_and_dns,
                                                                 "dst_peers": all_peers_and_ips_and_dns})

    @staticmethod
    def get_all_conns_props_per_domain_peers():
        """
        Return all possible between-peers connections.
        This is a compact way to represent all peers connections, but it is an over-approximation also containing
        IpBlock->IpBlock connections. Those redundant connections will be eventually filtered out.
        """
        src_peers = BasePeerSet().get_peer_set_by_indices(DimensionsManager().get_dimension_domain_by_name("src_peers"))
        dst_peers = BasePeerSet().get_peer_set_by_indices(DimensionsManager().get_dimension_domain_by_name("dst_peers"))
        return ConnectivityProperties.make_conn_props_from_dict({"src_peers": src_peers, "dst_peers": dst_peers})

    @staticmethod
    def make_empty_props():
        """
        Returns empty connectivity properties, representing logical False
        :return: ConnectivityProperties
        """
        return ConnectivityProperties()

    @staticmethod
    def make_all_props():
        """
        Returns all connectivity properties, representing logical True
        :return: ConnectivityProperties
        """
        return ConnectivityProperties(create_all=True)

    def get_all_peers(self):
        """
        Return all peers appearing in self.
        :return: PeerSet
        """
        return self.project_on_one_dimension("src_peers") | self.project_on_one_dimension("dst_peers")

    def are_auto_conns(self):
        """
        :return: True iff the given connections are connections from peers to themselves,
         i.e., they include only pairs of identical src and dst peers.
        """
        if not {'src_peers', 'dst_peers'}.issubset(set(self.active_dimensions)):
            return False
        src_peers_index = None
        dst_peers_index = None
        for i, dim in enumerate(self.active_dimensions):
            if dim == "src_peers":
                src_peers_index = i
            elif dim == "dst_peers":
                dst_peers_index = i

        for cube in self:
            if cube[src_peers_index] != cube[dst_peers_index] or not cube[src_peers_index].is_single_value():
                return False
        return True

    def props_without_auto_conns(self):
        """
        Return the properties after removing all connections from peer to itself
        """
        return self - self.get_auto_conns_from_peers()

    def get_auto_conns_from_peers(self):
        """
        Build properties containing all connections from peer to itself, for all peers in the current properties
        :return: the resulting auto connections properties
        """
        peers = self.get_all_peers()
        auto_conns = ConnectivityProperties()
        for peer in peers:
            auto_conns |= ConnectivityProperties.make_conn_props_from_dict({"src_peers": PeerSet({peer}),
                                                                            "dst_peers": PeerSet({peer})})
        return auto_conns

    def minimize(self):
        """
        Try to minimize the current properties by changing the order between "src_peers" and "dst_peers" dimensions
        """
        new_props = self.reorder_by_switching_src_dst_peers()
        return self if len(self) <= len(new_props) else new_props

    def reorder_by_switching_src_dst_peers(self):
        """
        Reorder self by switching the order between "src_peers" and "dst_peers" dimensions
        """
        new_all_dims_map = [i for i in range(len(self.all_dimensions_list))]
        src_peers_index = self.all_dimensions_list.index("src_peers")
        dst_peers_index = self.all_dimensions_list.index("dst_peers")
        # switch between "src_peers" and "dst_peers" dimensions
        new_all_dims_map[src_peers_index] = dst_peers_index
        new_all_dims_map[dst_peers_index] = src_peers_index
        return self._reorder_by_dim_list(new_all_dims_map)

    def _reorder_by_dim_list(self, new_all_dims_map):
        """
        Reorder the current properties by the given dimensions order
        :param list[int] new_all_dims_map: the given dimensions order
        :return: the reordered connectivity properties
        """
        # Build reordered all dimensions list
        new_all_dimensions_list = self._reorder_list_by_map(self.all_dimensions_list, new_all_dims_map)
        new_active_dimensions = []
        new_active_dims_map = [i for i in range(len(self.active_dimensions))]
        # Build reordered active dimensions list
        for dim in new_all_dimensions_list:
            if dim in self.active_dimensions:
                new_active_dims_map[len(new_active_dimensions)] = self.active_dimensions.index(dim)
                new_active_dimensions.append(dim)
        # Build reordered properties by cubes
        res = ConnectivityProperties(new_all_dimensions_list)
        for cube in self:
            new_cube = self._reorder_list_by_map(cube, new_active_dims_map)
            res.add_cube(new_cube, new_active_dimensions)
        return res

    @staticmethod
    def _reorder_list_by_map(orig_list, new_to_old_map):
        """
        Reorder a given list by map from new to old indices.
        :param list orig_list: the original list
        :param list[int] new_to_old_map: the list mapping new to old indices
        :return: the resulting list
        """
        res = []
        for i in range(len(orig_list)):
            res.append(orig_list[new_to_old_map[i]])
        return res
