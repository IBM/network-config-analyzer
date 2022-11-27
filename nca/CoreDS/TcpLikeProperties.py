#
# Copyright 2020- IBM Inc. All rights reserved
# SPDX-License-Identifier: Apache2.0
#

from .CanonicalIntervalSet import CanonicalIntervalSet
from .CanonicalHyperCubeSet import CanonicalHyperCubeSet
from .DimensionsManager import DimensionsManager
from .PortSet import PortSet
from .MethodSet import MethodSet
from .ProtocolSet import ProtocolSet
from .Peer import PeerSet


class TcpLikeProperties(CanonicalHyperCubeSet):
    """
    A class for holding a set of cubes, each defined over dimensions from TcpLikeProperties.dimensions_list
    For UDP, SCTP protocols, the actual used dimensions are only [source ports, dest ports]
    for TCP, it may be any of the dimensions from dimensions_list.

    Also, including support for (included and excluded) named ports (relevant for dest ports only).

    The representation with named ports is considered a mid-representation, and is required due to the late binding
    of the named ports to real ports numbers.
    The method convert_named_ports is responsible for applying this late binding, and is called by a policy's method
    allowed_connections() to get policy's allowed connections, given <src, dest> peers and direction ingress/egress
    Given a specific dest-peer context, the pod's named ports mapping is known, and used for the named ports conversion.
    Some of the operators for TcpLikeProperties are not supported for objects with (included and excluded) named ports.
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

    dimensions_list = ["src_peers", "dst_peers", "protocols", "src_ports", "dst_ports", "methods", "paths", "hosts", ]

    # TODO: change constructor defaults? either all arguments in "allow all" by default, or "empty" by default
    def __init__(self, source_ports=PortSet(), dest_ports=PortSet(), protocols=ProtocolSet(True),
                 methods=MethodSet(True), paths=None, hosts=None, base_peer_set=None, src_peers=None, dst_peers=None):
        """
        This will create all cubes made of the input arguments ranges/regex values.
        :param PortSet source_ports: The set of source ports (as a set of intervals/ranges)
        :param PortSet dest_ports: The set of target ports (as a set of intervals/ranges)
        :param ProtocolSet protocols: the set of eligible protocols
        :param MethodSet methods: the set of http request methods
        :param MinDFA paths: The dfa of http request paths
        :param MinDFA hosts: The dfa of http request hosts
        :param PeerSet base_peer_set: the base peer set which is referenced by the indices in 'peers'
        :param CanonicalIntervalSet src_peers: the set of source peers
        :param CanonicalIntervalSet dst_peers: the set of target peers
        """
        super().__init__(TcpLikeProperties.dimensions_list)
        assert (not src_peers and not dst_peers) or base_peer_set

        self.named_ports = {}  # a mapping from dst named port (String) to src ports interval set
        self.excluded_named_ports = {}  # a mapping from dst named port (String) to src ports interval set
        self.base_peer_set = base_peer_set if base_peer_set else PeerSet()

        # create the cube from input arguments
        cube = []
        active_dims = []
        # The order of dimensions below should be the same as in self.dimensions_list
        if src_peers is not None:
            cube.append(src_peers)
            active_dims.append("src_peers")
        if dst_peers is not None:
            cube.append(dst_peers)
            active_dims.append("dst_peers")
        if protocols and not protocols.is_whole_range():
            cube.append(protocols)
            active_dims.append("protocols")
        if not source_ports.is_all():
            cube.append(source_ports.port_set)
            active_dims.append("src_ports")
        if not dest_ports.is_all():
            cube.append(dest_ports.port_set)
            active_dims.append("dst_ports")
        if methods and not methods.is_whole_range():
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
                ports_list = cube[0].get_interval_set_list_numbers_and_ranges()
                ports_str = ','.join(str(ports_interval) for ports_interval in ports_list)
                return ports_str

        cubes_dict_list = [self.get_cube_dict(cube, True) for cube in self]
        return ','.join(str(cube_dict) for cube_dict in cubes_dict_list)

    def __hash__(self):
        return super().__hash__()

    def get_cube_dict(self, cube, is_txt=False):
        """
        represent the properties cube as dict objet, for output generation as yaml/txt format
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
            if dim == 'protocols' or dim == 'methods':
                values_list = str(dim_values)
            elif dim == "src_peers" or dim == "dst_peers":
                values_list = self.base_peer_set.get_peer_set_by_indices(dim_values)
            elif dim_type == DimensionsManager.DimensionType.IntervalSet:
                values_list = dim_values.get_interval_set_list_numbers_and_ranges()
                if is_txt:
                    values_list = ','.join(str(interval) for interval in values_list)
            else:
                # TODO: should be a list of words for a finite len DFA?
                values_list = DimensionsManager().get_dim_values_str(dim_values, dim)
            cube_dict[dim] = values_list
        return cube_dict

    def get_cube_dict_with_orig_values(self, cube):
        """
        represent the properties cube as dict object, where the values are the original values
        with which the cube was built (i.e., MethodSet, PeerSet, etc.)
        :param list cube: the values of the input cube
        :return: the cube properties in dict representation
        :rtype: dict
        """
        cube_dict = {}
        for i, dim in enumerate(self.active_dimensions):
            dim_values = cube[i]
            dim_domain = DimensionsManager().get_dimension_domain_by_name(dim)
            if dim_domain == dim_values:
                continue  # skip dimensions with all values allowed in a cube
            if dim == 'src_ports' or dim == 'dst_ports':
                values = PortSet()
                values.port_set = dim_values.copy()
            elif dim == 'protocols':
                values = ProtocolSet()
                values.set_protocols(dim_values)
            elif dim == 'methods':
                values = MethodSet()
                values.set_methods(dim_values)
            elif dim == "src_peers" or dim == "dst_peers":
                values = self.base_peer_set.get_peer_set_by_indices(dim_values)
            else:
                values = dim_values
            cube_dict[dim] = values
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
        if isinstance(other, TcpLikeProperties):
            assert not self.base_peer_set or not other.base_peer_set or self.base_peer_set == other.base_peer_set
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
        assert not isinstance(other, TcpLikeProperties) or not self.base_peer_set or \
               not other.base_peer_set or self.base_peer_set == other.base_peer_set
        assert not self.has_named_ports()
        assert not isinstance(other, TcpLikeProperties) or not other.has_named_ports()
        if isinstance(other, TcpLikeProperties):
            self.base_peer_set |= other.base_peer_set
        super().__iand__(other)
        return self

    def __ior__(self, other):
        assert not isinstance(other, TcpLikeProperties) or not self.base_peer_set or \
               not other.base_peer_set or self.base_peer_set == other.base_peer_set
        assert not self.excluded_named_ports
        assert not isinstance(other, TcpLikeProperties) or not other.excluded_named_ports
        if isinstance(other, TcpLikeProperties):
            self.base_peer_set |= other.base_peer_set
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
        assert not isinstance(other, TcpLikeProperties) or not self.base_peer_set or \
               not other.base_peer_set or self.base_peer_set == other.base_peer_set
        assert not self.has_named_ports()
        assert not isinstance(other, TcpLikeProperties) or not other.has_named_ports()
#        if isinstance(other, TcpLikeProperties):
#            self.base_peer_set |= other.base_peer_set
        super().__isub__(other)
        return self

    def contained_in(self, other):
        """
        :param TcpLikeProperties other: Another PortSetPair
        :return: Whether all (source port, target port) pairs in self also appear in other
        :rtype: bool
        """
        assert not isinstance(other, TcpLikeProperties) or not self.base_peer_set or \
               not other.base_peer_set or self.base_peer_set == other.base_peer_set
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
                rectangle = [my_named_ports[port],
                             CanonicalIntervalSet.get_interval_set(real_port_number, real_port_number)]
                self.add_cube(rectangle)
        for port in my_excluded_named_ports:
            real_port = named_ports.get(port)
            if real_port and real_port[1] == protocol:
                real_port_number = real_port[0]
                rectangle = [my_excluded_named_ports[port],
                             CanonicalIntervalSet.get_interval_set(real_port_number, real_port_number)]
                self.add_hole(rectangle)

    def copy(self):
        res = TcpLikeProperties()
        # from CanonicalHyperCubeSet.copy():
        for layer in self.layers:
            res.layers[self._copy_layer_elem(layer)] = self.layers[layer].copy()
        res.active_dimensions = self.active_dimensions.copy()

        res.named_ports = self.named_ports.copy()
        res.excluded_named_ports = self.excluded_named_ports.copy()
        res.base_peer_set = self.base_peer_set.copy()
        return res

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
                dim_item = ProtocolSet.all_protocols_list[item[i]]
            elif dim_name == 'methods':
                dim_item = MethodSet.all_methods_list[item[i]]
            else:
                dim_item = item[i]
            res_list.append(f'{dim_name}={dim_item}')
        return '[' + ','.join(s for s in res_list) + ']'

    def project_on_one_dimension(self, dim_name):
        """
        Build the projection of self to the given dimension
        :param str dim_name: the given dimension
        :return: the projection on the given dimension, having that dimension type (either IntervalSet or DFA)
        """
        if dim_name not in self.active_dimensions:
            return None
        res = None
        for cube in self:
            cube_dict = self.get_cube_dict_with_orig_values(cube)
            values = cube_dict.get(dim_name)
            if values:
                res = (res | values) if res else values
        return res

    @staticmethod
    def make_tcp_like_properties(peer_container, dest_ports, protocols=None, src_peers=None, dst_peers=None,
                                 paths_dfa=None, hosts_dfa=None, methods=None):
        """
        get TcpLikeProperties with TCP allowed connections, corresponding to input properties cube.
        TcpLikeProperties should not contain named ports: substitute them with corresponding port numbers, per peer
        :param PeerContainer peer_container: The set of endpoints and their namespaces
        :param PortSet dest_ports: ports set for dest_ports dimension (possibly containing named ports)
        :param ProtocolSet protocols: CanonicalIntervalSet obj for protocols dimension
        :param PeerSet src_peers: the set of source peers
        :param PeerSet dst_peers: the set of target peers
        :param MinDFA paths_dfa: MinDFA obj for paths dimension
        :param MinDFA hosts_dfa: MinDFA obj for hosts dimension
        :param MethodSet methods: CanonicalIntervalSet obj for methods dimension
        :return: TcpLikeProperties with TCP allowed connections, corresponding to input properties cube
        """
        base_peer_set = peer_container.peer_set.copy()
        if src_peers:
            src_peers_interval = base_peer_set.get_peer_interval_of(src_peers)
        else:
            src_peers_interval = None
        if dst_peers:
            dst_peers_interval = base_peer_set.get_peer_interval_of(dst_peers)
        else:
            dst_peers_interval = None
        if not dest_ports.named_ports:
            return TcpLikeProperties(source_ports=PortSet(True), dest_ports=dest_ports,
                                     protocols=protocols, methods=methods,
                                     paths=paths_dfa, hosts=hosts_dfa, src_peers=src_peers_interval,
                                     dst_peers=dst_peers_interval, base_peer_set=base_peer_set)
        assert dst_peers
        assert not dest_ports.port_set
        assert len(dest_ports.named_ports) == 1
        port = list(dest_ports.named_ports)[0]
        tcp_properties = None
        tcp_protocol = ProtocolSet()
        tcp_protocol.add_protocol('TCP')
        for peer in dst_peers:
            named_ports = peer.get_named_ports()
            real_port = named_ports.get(port)
            if not real_port:
                print(f'Warning: Missing named port {port} in the pod {peer}. Ignoring the pod')
                continue
            if real_port[1] != 'TCP':
                print(f'Warning: Illegal protocol {real_port[1]} in the named port {port} of the target pod {peer}.'
                      f'Ignoring the pod')
                continue
            peer_in_set = PeerSet()
            peer_in_set.add(peer)
            ports = PortSet()
            ports.add_port(real_port[0])
            props = TcpLikeProperties(source_ports=PortSet(True), dest_ports=ports,
                                      protocols=protocols if protocols else tcp_protocol, methods=methods,
                                      paths=paths_dfa, hosts=hosts_dfa, src_peers=src_peers_interval,
                                      dst_peers=base_peer_set.get_peer_interval_of(peer_in_set),
                                      base_peer_set=base_peer_set)
            if tcp_properties:
                tcp_properties |= props
            else:
                tcp_properties = props

        return tcp_properties

    @staticmethod
    def make_tcp_like_properties_from_dict(peer_container, cube_dict):
        """
        Create TcpLikeProperties from the given cube
        :param PeerContainer peer_container: the set of all peers
        :param dict cube_dict: the given cube represented as a dictionary
        :return: TcpLikeProperties
        """
        cube_dict_copy = cube_dict.copy()
        dest_ports = cube_dict_copy.pop("dst_ports", PortSet(True))
        protocols = cube_dict_copy.pop("protocols", None)
        src_peers = cube_dict_copy.pop("src_peers", None)
        dst_peers = cube_dict_copy.pop("dst_peers", None)
        paths_dfa = cube_dict_copy.pop("paths", None)
        hosts_dfa = cube_dict_copy.pop("hosts", None)
        methods = cube_dict_copy.pop("methods", None)
        assert not cube_dict_copy
        return TcpLikeProperties.make_tcp_like_properties(peer_container, dest_ports, protocols,
                                                          src_peers, dst_peers, paths_dfa, hosts_dfa, methods)
