#
# Copyright 2020- IBM Inc. All rights reserved
# SPDX-License-Identifier: Apache2.0
#

from .CanonicalHyperCubeSet import CanonicalHyperCubeSet
from .DimensionsManager import DimensionsManager
from .PortSet import PortSet
from .MethodSet import MethodSet
from .Peer import PeerSet, BasePeerSet
from .ProtocolNameResolver import ProtocolNameResolver
from .ProtocolSet import ProtocolSet
from .MinDFA import MinDFA
from .ConnectivityCube import ConnectivityCube


class ConnectivityProperties(CanonicalHyperCubeSet):
    """
    A class for holding a set of cubes, each defined over dimensions from ConnectivityCube.dimensions_list
    For UDP, SCTP protocols, the actual used dimensions are only [src_peers, dst_peers, src_ports, dst_ports],
    for TCP, it may be any of the dimensions from dimensions_list, except for icmp_type and icmp_code,
    for icmp data the actual used dimensions are only [src_peers, dst_peers, icmp_type, icmp_code].

    ConnectivityProperties potentially hold all the dimensions, including sets of source peers and destination peers.
    The connectivity properties are built at the parse time for every policy.

    The src_peers and dst_peers dimensions are special dimensions,  they do not have constant domain. Their domain
    depends on the current set of peers in the system (as appears in BasePeerSet singleton). This set grows when
    adding more configurations. Thus, there is no unique 'all values' representation. In particular, those
    dimensions are never reduced to inactive.
    This might be a problem in comparison and inclusion operators of ConnectivityProperties. The possible solution
    may be to keep 'reference full domain value' for these dimensions (as another member in the BasePeerSet),
    and to set it to relevant values per query, and to make a special treatment of these dimensions
    in the above operators.

    Also, including support for (included and excluded) named ports (relevant for dest ports only), which are
    resolved during the construction of ConnectivityProperties.

    """

    def __init__(self, dimensions_list=None, create_all=False):
        """
        This will create empty or full connectivity properties, depending on create_all flag.
        :param create_all: whether to create full connectivity properties.
        """
        super().__init__(dimensions_list if dimensions_list else ConnectivityCube.all_dimensions_list)
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
        assert not dst_ports.named_ports and not dst_ports.excluded_named_ports
        return res

    def __str__(self):
        if self.is_all():
            return 'All connections'
        if not super().__bool__():
            return 'No connections'
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

    def __lt__(self, other):
        return len(self) < len(other) or str(self) < str(other)

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
        dimensions_manager = DimensionsManager()
        for i, dim in enumerate(self.active_dimensions):
            dim_values = cube[i]
            dim_type = dimensions_manager.get_dimension_type_by_name(dim)
            dim_domain = dimensions_manager.get_dimension_domain_by_name(dim)
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
                values_list = dimensions_manager.get_dim_values_str(dim_values, dim)
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
            return super().__eq__(other)
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

    def copy(self):
        """
        :rtype: ConnectivityProperties
        """
        res = ConnectivityProperties(self.all_dimensions_list)
        for layer in self.layers:
            res.layers[self._copy_layer_elem(layer)] = self.layers[layer].copy()
        res.active_dimensions = self.active_dimensions.copy()
        return res

    def print_diff(self, other, self_name, other_name):
        """
        :param ConnectivityProperties other: another connectivity properties object
        :param str self_name: A name for 'self'
        :param str other_name: A name for 'other'
        :return: If self!=other, return a string showing a (source, target) pair that appears in only one of them
        :rtype: str
        """
        if self.is_all() and not other.is_all():
            return self_name + ' allows all connections while ' + other_name + ' does not.'
        if not self.is_all() and other.is_all():
            return other_name + ' allows all connections while ' + self_name + ' does not.'
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
    def _resolve_named_ports(named_ports, peer, protocols, used_named_ports):
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
            used_named_ports.add(named_port)
        return real_ports

    @staticmethod
    def make_conn_props(conn_cube):
        """
        This will create connectivity properties made of the given connectivity cube.
        This includes tcp properties, non-tcp properties, icmp data properties.
        If possible (i.e., in the optimized solution, when dst_peers are supported in the given cube),
        the named ports will be resolved.

        The resulting ConnectivityProperties should not contain named ports:
            they are substituted with corresponding port numbers, per peer

        :param ConnectivityCube conn_cube: the input connectivity cube including all dimension values,
            whereas missing dimensions are represented by their default values (representing all possible values).
        """

        src_ports = conn_cube["src_ports"]
        dst_ports = conn_cube["dst_ports"]
        assert not src_ports.named_ports and not src_ports.excluded_named_ports
        if not dst_ports.named_ports and not dst_ports.excluded_named_ports:
            # No named ports
            return ConnectivityProperties._make_conn_props_no_named_ports_resolution(conn_cube)

        # Should resolve named ports
#        assert conn_cube.is_active_dim("dst_peers")
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
        used_named_ports = set()
        for peer in dst_peers:
            real_ports = ConnectivityProperties._resolve_named_ports(dst_ports.named_ports, peer, protocols,
                                                                     used_named_ports)
            if real_ports:
                conn_cube.update({"dst_ports": real_ports, "dst_peers": PeerSet({peer})})
                conn_properties |= ConnectivityProperties._make_conn_props_no_named_ports_resolution(conn_cube)
            excluded_real_ports = ConnectivityProperties._resolve_named_ports(dst_ports.excluded_named_ports, peer,
                                                                              protocols, used_named_ports)
            if excluded_real_ports:
                conn_cube.update({"dst_ports": excluded_real_ports, "dst_peers": PeerSet({peer})})
                conn_properties -= ConnectivityProperties._make_conn_props_no_named_ports_resolution(conn_cube)
        unresolved_named_ports = (dst_ports.named_ports.union(dst_ports.excluded_named_ports)).difference(used_named_ports)
        if unresolved_named_ports:
            print(f'Warning: Named ports {unresolved_named_ports} are not defined in any pod')
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
        # optimization: src_peers and dst_peers have the same domain
        peers = BasePeerSet().get_peer_set_by_indices(DimensionsManager().get_dimension_domain_by_name("src_peers"))
        return ConnectivityProperties.make_conn_props_from_dict({"src_peers": peers, "dst_peers": peers})

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

    @staticmethod
    def extract_src_dst_peers_from_cube(the_cube, peer_container, relevant_protocols=ProtocolSet(True)):
        """
        Remove src_peers and dst_peers from the given cube, and return those sets of peers
        and the resulting properties without the peers.
        :param ConnectivityCube the_cube: the given cube
        :param PeerContainer peer_container: the peer container
        :param relevant_protocols: the relevant protocols used to represent all protocols
        :return: tuple(ConnectivityProperties, PeerSet, PeerSet) - the resulting properties after removing
        src_peers and dst_peers, src_peers, dst_peers
        """
        all_peers = peer_container.get_all_peers_group(True)
        conn_cube = the_cube.copy()
        src_peers = conn_cube["src_peers"] or all_peers
        conn_cube.unset_dim("src_peers")
        dst_peers = conn_cube["dst_peers"] or all_peers
        conn_cube.unset_dim("dst_peers")
        protocols = conn_cube["protocols"]
        if protocols == relevant_protocols:
            conn_cube.unset_dim("protocols")
        props = ConnectivityProperties.make_conn_props(conn_cube)
        return props, src_peers, dst_peers

    def get_simplified_connections_representation(self, is_str, use_complement_simplification=True):
        """
        Get a simplified representation of the connectivity properties - choose shorter version between self
        and its complement.
        representation as str is a string representation, and not str is representation as list of objects.
        The representation is used at fw-rules representation of the connection.
        :param bool is_str: should get str representation (True) or list representation (False)
        :param bool use_complement_simplification: should choose shorter rep between self and complement
        :return: the required representation of the connection set
        :rtype Union[str, list]
        """
        if self.is_all():
            return "All connections" if is_str else ["All connections"]
        if not super().__bool__():
            return "No connections" if is_str else ["No connections"]

        compl = ConnectivityProperties.make_all_props() - self
        if len(self) > len(compl) and use_complement_simplification:
            compl_rep = compl._get_connections_representation(is_str)
            return f'All but {compl_rep}' if is_str else [{"All but": compl_rep}]
        else:
            return self._get_connections_representation(is_str)

    def _get_connections_representation(self, is_str):
        cubes_list = [self.get_cube_dict(cube, is_str) for cube in self]
        if is_str:
            return ','.join(self._get_cube_str_representation(cube) for cube in cubes_list)
        return cubes_list

    @staticmethod
    def _get_cube_str_representation(cube):
        return '{' + ','.join(f'{item[0]}:{item[1]}' for item in cube.items()) + '}'
