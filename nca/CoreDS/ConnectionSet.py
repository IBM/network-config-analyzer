#
# Copyright 2020- IBM Inc. All rights reserved
# SPDX-License-Identifier: Apache2.0
#

from collections import defaultdict
from .CanonicalIntervalSet import CanonicalIntervalSet
from .ConnectivityProperties import ConnectivityProperties
from .ProtocolNameResolver import ProtocolNameResolver
from .ProtocolSet import ProtocolSet
from .Peer import PeerSet, IpBlock
from nca.FWRules import FWRule


class ConnectionSet:
    """
    This class holds a set of connections and allows several manipulations on this set such as union, intersection, ...
    """
    _icmp_protocols = {1, 58}
    port_supporting_protocols = {6, 17, 132}
    _max_protocol_num = 255
    _min_protocol_num = 0

    def __init__(self, allow_all=False):
        self.allowed_protocols = {}  # a map from protocol number (0-255) to allowed properties (ports, icmp)
        self.allow_all = allow_all  # Shortcut to represent all connections, and then allowed_protocols is to be ignored

    def __bool__(self):
        return self.allow_all or bool(self.allowed_protocols)

    def __eq__(self, other):
        if isinstance(other, ConnectionSet):
            return self.allow_all == other.allow_all and self.allowed_protocols == other.allowed_protocols
        return False

    def __lt__(self, other):
        if self.allow_all:
            return False
        if other.allow_all:
            return True
        if len(self.allowed_protocols) != len(other.allowed_protocols):
            return len(self.allowed_protocols) < len(other.allowed_protocols)
        return str(self) < str(other)

    def __hash__(self):
        return hash((frozenset(self.allowed_protocols.keys()), self.allow_all))

    def get_simplified_connections_representation(self, is_str, use_complement_simplification=True):
        """
        Get a simplified representation of the connection set - choose shorter version between self and its complement.
        representation as str is a string representation, and not str is representation as list of objects.
        The representation is used at fw-rules representation of the connection.
        :param bool is_str: should get str representation (True) or list representation (False)
        :param bool use_complement_simplification: should choose shorter rep between self and complement
        :return: the required representation of the connection set
        :rtype Union[str, list]
        """
        if self.allow_all or not self.allowed_protocols:
            return self._get_connections_representation(is_str)
        self_rep = self._get_connections_representation(is_str)
        if not use_complement_simplification:
            return self_rep
        # check the alternative of the complement
        complement = ConnectionSet(True) - self
        complement_rep = complement._get_connections_representation(is_str)
        if len(complement_rep) < len(self_rep):
            return f'All but {complement_rep}' if is_str else [{"All but": complement_rep}]
        return self_rep

    def _get_connections_representation(self, is_str):
        """
        get the required representation of the connection set (str or list) for fw-rules output
        :param bool is_str: should get str representation (True) or list representation (False)
        :return: the required representation of the connection set
        :rtype Union[str, list]
        """
        if self.allow_all or not self.allowed_protocols:
            return str(self) if is_str else [str(self)]
        res = []
        protocols_ranges = CanonicalIntervalSet()
        protocols = self.allowed_protocols
        if is_str:
            # aggregate specific representations:
            protocols, aggregated_properties_txt = self._aggregate_connection_representation(self.allowed_protocols)
            if aggregated_properties_txt != '':
                res.append(aggregated_properties_txt)
        for protocol in sorted(protocols):
            if ProtocolNameResolver.is_standard_protocol(protocol):
                protocol_text = ProtocolNameResolver.get_protocol_name(protocol)
                properties = protocols[protocol]
                res.append(self._get_protocol_with_properties_representation(is_str, protocol_text, properties))
            else:
                # collect allowed protocols numbers into ranges
                # assuming no properties objects for protocols numbers
                protocols_ranges.add_interval(CanonicalIntervalSet.Interval(protocol, protocol))
        if protocols_ranges:
            res += self._get_protocols_ranges_representation(is_str, protocols_ranges)
        return ','.join(s for s in res) if is_str else res

    @staticmethod
    def _aggregate_connection_representation(protocols):
        """
        Aggregate shared properties of the protocols, for better human understanding.
        :param dict protocols: a map from protocol number (1-255) to allowed properties
        :return: dict protocols_not_aggregated: the rest of the protocol data that was not aggregated.
        :return: str aggregation_results: a string of the aggregated representation
        """
        protocols_not_aggregated = protocols
        aggregation_results = ''

        # handle TCP+UDP ports aggregation (do not handle range segmentation overlapping)
        tcp_protocol_number = ProtocolNameResolver.get_protocol_number('TCP')
        udp_protocol_number = ProtocolNameResolver.get_protocol_number('UDP')
        tcp_protocol = protocols_not_aggregated.get(tcp_protocol_number)
        udp_protocol = protocols_not_aggregated.get(udp_protocol_number)
        if tcp_protocol and udp_protocol and tcp_protocol.active_dimensions and \
                udp_protocol.active_dimensions == tcp_protocol.active_dimensions:
            aggregation_results, protocols_not_aggregated = ConnectionSet._aggregate_pair_protocols(protocols_not_aggregated,
                                                                                                    tcp_protocol_number,
                                                                                                    udp_protocol_number)
            if aggregation_results != '':  # can be empty when all properties are allowed for both protocols
                aggregation_results = 'TCP+UDP ' + aggregation_results

        # handle future aggregations here

        return protocols_not_aggregated, aggregation_results

    @staticmethod
    def _aggregate_pair_protocols(protocols, protocol_number1, protocol_number2):
        """
        Handles aggregation of 2 protocols' properties
        :param protocols: The protocol dictionary so we can remove empty protocols after aggregation
        :param protocol_number1: first protocol number to aggregate with the second
        :param protocol_number2: second protocol number to aggregate
        :return: str aggregated_properties: a string of the aggregated properties
        :return: dict protocols_not_aggregated: the rest of the protocol data that was not aggregated.
        """
        protocols_not_aggregated = protocols
        aggregated_properties = protocols_not_aggregated[protocol_number1] & protocols_not_aggregated[protocol_number2]
        if not aggregated_properties:
            return '', protocols_not_aggregated

        protocol1_dif = protocols_not_aggregated[protocol_number1] - protocols_not_aggregated[protocol_number2]
        protocol2_dif = protocols_not_aggregated[protocol_number2] - protocols_not_aggregated[protocol_number1]
        protocols_not_aggregated = protocols.copy()
        if protocol1_dif:
            protocols_not_aggregated[protocol_number1] = protocol1_dif
        else:
            del protocols_not_aggregated[protocol_number1]

        if protocol2_dif:
            protocols_not_aggregated[protocol_number2] = protocol2_dif
        else:
            del protocols_not_aggregated[protocol_number2]

        return str(aggregated_properties), protocols_not_aggregated

    @staticmethod
    def _get_protocol_with_properties_representation(is_str, protocol_text, properties):
        """
        :param bool is_str: should get str representation (True) or list representation (False)
        :param str protocol_text: str description of protocol
        :param Union[bool, ConnectivityProperties] properties: properties object of the protocol
        :return: representation required for a given pair of protocol and its properties
        :rtype: Union[dict, str]
        """
        if not is_str:
            protocol_obj = {'Protocol': protocol_text}
            if not isinstance(properties, bool):
                protocol_obj.update(properties.get_properties_obj())
            return protocol_obj
        # for str representation:
        return protocol_text if isinstance(properties, bool) else ' '.join(filter(None, [protocol_text, str(properties)]))

    @staticmethod
    def _get_protocols_ranges_representation(is_str, protocols_ranges):
        """
        :param bool is_str: should get str representation (True) or list representation (False)
        :param protocols_ranges:
        :return:
        :rtype: list
        """
        if is_str:
            return [f'protocols numbers: {protocols_ranges}']
        res = []
        for protocols_range in protocols_ranges.get_interval_set_list_numbers_and_ranges():
            res.append({'Protocol': protocols_range})
        return res

    def __str__(self):
        if self.allow_all:
            return "All connections"
        if not self.allowed_protocols:
            return 'No connections'

        if len(self.allowed_protocols) == 1:
            protocol_num = next(iter(self.allowed_protocols))
            protocol_text = 'Protocol: ' + ProtocolNameResolver.get_protocol_name(protocol_num)
            properties = self.allowed_protocols[protocol_num]
            properties_text = ''
            if not isinstance(properties, bool) and str(properties):
                properties_text = ', ' + str(properties)
            return protocol_text + properties_text

        protocol_text = 'Protocols: '
        for idx, protocol in enumerate(self.allowed_protocols.keys()):
            if idx > 0:
                protocol_text += ', '
            protocol_text += ProtocolNameResolver.get_protocol_name(protocol)

            # add properties:
            properties = self.allowed_protocols[protocol]
            properties_text = ''
            if not isinstance(properties, bool):
                properties_text = ', ' + str(properties)
            protocol_text += properties_text
        return protocol_text

    def __and__(self, other):
        if other.allow_all:
            return self.copy()
        if self.allow_all:
            return other.copy()

        res = ConnectionSet()
        for key, properties in self.allowed_protocols.items():
            if key in other.allowed_protocols:
                conjunction = properties & other.allowed_protocols[key]
                if conjunction:
                    res.allowed_protocols[key] = conjunction

        return res

    def __or__(self, other):
        res = ConnectionSet()
        if self.allow_all or other.allow_all:
            res.allow_all = True
            return res

        for key, properties in self.allowed_protocols.items():
            if key in other.allowed_protocols:
                res.allowed_protocols[key] = properties | other.allowed_protocols[key]
            else:
                res.allowed_protocols[key] = self.copy_properties(properties)

        for key, properties in other.allowed_protocols.items():
            if key not in res.allowed_protocols:
                res.allowed_protocols[key] = self.copy_properties(properties)

        res.check_if_all_connections()
        return res

    def __sub__(self, other):
        if other.allow_all:
            return ConnectionSet()
        if self.allow_all:
            res = self.copy()
            res -= other
            return res

        res = ConnectionSet()
        for key, properties in self.allowed_protocols.items():
            if key in other.allowed_protocols:
                if isinstance(properties, bool):
                    continue
                diff = properties - other.allowed_protocols[key]
                if diff:
                    res.allowed_protocols[key] = diff
            else:
                res.allowed_protocols[key] = self.copy_properties(properties)

        return res

    def __iand__(self, other):
        if other.allow_all:
            return self
        if self.allow_all:
            self.allow_all = False
            for protocol, properties in other.allowed_protocols.items():
                self.allowed_protocols[protocol] = self.copy_properties(properties)
            return self

        for key in list(self.allowed_protocols.keys()):  # we need a copy of the keys because we delete while iterating
            if key not in other.allowed_protocols:
                del self.allowed_protocols[key]
            else:
                self.allowed_protocols[key] &= other.allowed_protocols[key]
                if not self.allowed_protocols[key]:
                    del self.allowed_protocols[key]  # became empty
        return self

    def __ior__(self, other):
        if self.allow_all or not bool(other):
            return self
        if other.allow_all:
            self.allow_all = True
            self.allowed_protocols.clear()
            return self

        for key in self.allowed_protocols:
            if key in other.allowed_protocols:
                self.allowed_protocols[key] |= other.allowed_protocols[key]

        for key in other.allowed_protocols.keys():
            if key not in self.allowed_protocols:
                self.allowed_protocols[key] = self.copy_properties(other.allowed_protocols[key])

        self.check_if_all_connections()
        return self

    def __isub__(self, other):
        if not bool(other):
            return self  # nothing to subtract
        if other.allow_all:
            self.allowed_protocols.clear()  # subtract everything
            self.allow_all = False
            return self

        if self.allow_all:
            self.add_all_connections()
            self.allow_all = False  # We are about to subtract something

        for key in list(self.allowed_protocols.keys()):
            if key in other.allowed_protocols:
                other_features = other.allowed_protocols[key]
                if isinstance(other_features, bool):
                    del self.allowed_protocols[key]
                else:
                    self.allowed_protocols[key] -= other_features
                    if not self.allowed_protocols[key]:
                        del self.allowed_protocols[key]

        return self

    def contained_in(self, other):
        """
        Check whether the 'self' set of connections is contained in the 'other' set of connections
        :param ConnectionSet other: The other set of connections
        :return: True if it 'self' is contained in 'other', False otherwise
        :rtype: bool
        """
        if other.allow_all:
            return True
        if self.allow_all:  # BUGBUG: What if other allows all implicitly
            return False

        for protocol, properties in self.allowed_protocols.items():
            if protocol not in other.allowed_protocols:
                return False
            if isinstance(properties, bool):
                continue
            if not properties.contained_in(other.allowed_protocols[protocol]):
                return False

        return True

    @staticmethod
    def copy_properties(properties):
        """
        :param properties: protocol properties
        :return: A (deep) copy of the given properties
        """
        if isinstance(properties, bool):
            return properties
        return properties.copy()

    def copy(self):
        """
        :return: A deep copy of self
        :rtype: ConnectionSet
        """
        res = ConnectionSet(self.allow_all)
        for protocol, properties in self.allowed_protocols.items():
            res.allowed_protocols[protocol] = self.copy_properties(properties)
        return res

    @staticmethod
    def protocol_supports_ports(protocol):
        """
        :param protocol: Protocol number or name
        :return: Whether the given protocol has ports
        :rtype: bool
        """
        prot = protocol
        if isinstance(protocol, str):
            prot = ProtocolNameResolver.get_protocol_number(protocol)
        return prot in ConnectionSet.port_supporting_protocols

    @staticmethod
    def protocol_is_icmp(protocol):
        """
        :param protocol: Protocol number or name
        :return: Whether the protocol is icmp or icmpv6
        :rtype: bool
        """
        prot = protocol
        if isinstance(protocol, str):
            prot = ProtocolNameResolver.get_protocol_number(protocol)
        return prot in ConnectionSet._icmp_protocols

    def add_connections(self, protocol, properties=True):
        """
        Add connections to the set of connections
        :param int,str protocol: protocol number of the connections to add
        :param properties: an object with protocol properties (e.g., ports), if relevant
        :type properties: Union[bool, ConnectivityProperties]
        :return: None
        """
        if isinstance(protocol, str):
            protocol = ProtocolNameResolver.get_protocol_number(protocol)
        if not ProtocolNameResolver.is_valid_protocol(protocol):
            raise Exception('Protocol must be in the range 0-255')
        if not bool(properties):  # if properties are empty, there is nothing to add
            return
        if protocol in self.allowed_protocols:
            self.allowed_protocols[protocol] |= properties
        else:
            self.allowed_protocols[protocol] = properties if isinstance(properties, bool) else properties.copy()

    def remove_protocol(self, protocol):
        """
        Remove a protocol from the set of connections
        :param int,str protocol: The protocol to remove
        :return: None
        """
        if isinstance(protocol, str):
            protocol = ProtocolNameResolver.get_protocol_number(protocol)
        if not ProtocolNameResolver.is_valid_protocol(protocol):
            raise Exception('Protocol must be in the range 0-255')
        if protocol not in self.allowed_protocols:
            return
        del self.allowed_protocols[protocol]

    def _add_all_connections_of_protocol(self, protocol):
        """
        Add all possible connections to the connection set for a given protocol
        :param protocol: the given protocol number
        :return: None
        """
        if self.protocol_supports_ports(protocol) or self.protocol_is_icmp(protocol):
            self.allowed_protocols[protocol] = ConnectivityProperties.make_all_props()
        else:
            self.allowed_protocols[protocol] = True

    def add_all_connections(self, excluded_protocols=None):
        """
        Add all possible connections to the connection set
        :param list[int] excluded_protocols: (optional) list of protocol numbers to exclude
        :return: None
        """
        for protocol in range(ConnectionSet._min_protocol_num, ConnectionSet._max_protocol_num + 1):
            if excluded_protocols and protocol in excluded_protocols:
                continue
            self._add_all_connections_of_protocol(protocol)

    def check_if_all_connections(self):
        """
        update self if it allows all connections but not flagged with allow_all
        """
        if self.is_all_connections_without_allow_all():
            self.allow_all = True
            self.allowed_protocols.clear()

    def is_all_connections_without_allow_all(self):
        """
        check if self is not flagged with allow_all, but still allows all connections, and thus should
        be replaced with allow_all flag
        :rtype: bool
        """
        if self.allow_all:
            return False
        num_protocols = ConnectionSet._max_protocol_num - ConnectionSet._min_protocol_num + 1
        if len(self.allowed_protocols) < num_protocols:
            return False
        for protocol in ConnectionSet.port_supporting_protocols | ConnectionSet._icmp_protocols:
            if not self.allowed_protocols[protocol].is_all():
                return False
        return True

    def has_named_ports(self):
        """
        :return: True if any of the port-supporting protocols refers to a named port, False otherwise
        :rtype: bool
        """
        for protocol, properties in self.allowed_protocols.items():
            if self.protocol_supports_ports(protocol) and properties.has_named_ports():
                return True
        return False

    def get_named_ports(self):
        """
        :return: A list of (protocol, set-of-named-ports) pairs for every protocol that supports ports
        :rtype: list[(int, set[str])]
        """
        res = []
        for protocol, properties in self.allowed_protocols.items():
            if self.protocol_supports_ports(protocol) and properties.has_named_ports():
                res.append((protocol, properties.get_named_ports()))
        return res

    def convert_named_ports(self, named_ports):
        """
        Replaces all references to named ports with actual ports, given a mapping
        NOTE: that this function modifies self
        :param dict[str, (int, int)] named_ports: mapping from a named to port (str) to  actual port number + protocol
        :return: None
        """
        for protocol, properties in list(self.allowed_protocols.items()):
            if self.protocol_supports_ports(protocol):
                properties.convert_named_ports(named_ports, ProtocolNameResolver.get_protocol_name(protocol))
                if not properties:
                    del self.allowed_protocols[protocol]

    def print_diff(self, other, self_name, other_name):
        """
        Prints a single diff between two sets of connections ('self' and 'other')
        :param ConnectionSet other: The connections to compare against
        :param self_name: the name of 'self' connection set
        :param other_name: The name of 'other' connection set
        :return: A string with the diff details (if any)
        :rtype: str
        """
        if self.allow_all and other.allow_all:
            return 'No diff.'
        if self.allow_all and not other.allow_all:
            return self_name + ' allows all connections while ' + other_name + ' does not.'
        if not self.allow_all and other.allow_all:
            return other_name + ' allows all connections while ' + self_name + ' does not.'
        for protocol, properties in self.allowed_protocols.items():
            if protocol not in other.allowed_protocols:
                return self_name + ' allows communication using protocol ' + ProtocolNameResolver.get_protocol_name(protocol) \
                    + ' while ' + other_name + ' does not.'
            other_properties = other.allowed_protocols[protocol]
            if properties != other_properties:
                return ProtocolNameResolver.get_protocol_name(protocol) + ' protocol - ' + \
                    properties.print_diff(other_properties, self_name, other_name)

        for protocol in other.allowed_protocols:
            if protocol not in self.allowed_protocols:
                return other_name + ' allows communication using protocol ' + \
                    ProtocolNameResolver.get_protocol_name(protocol) + ' while ' + self_name + ' does not.'

        return 'No diff.'

    def convert_to_connectivity_properties(self):
        """
        Convert the current ConnectionSet to ConnectivityProperties format.
        This function is used for comparing fw-rules output between original and optimized implementation,
        when optimized_run == 'debug'
        :return: the connection set in ConnectivityProperties format
        """
        if self.allow_all:
            return ConnectivityProperties.make_all_props()

        res = ConnectivityProperties.make_empty_props()
        for protocol, properties in self.allowed_protocols.items():
            protocols = ProtocolSet.get_protocol_set_with_single_protocol(protocol)
            this_prop = ConnectivityProperties.make_conn_props_from_dict({"protocols": protocols})
            if isinstance(properties, bool):
                if properties:
                    res |= this_prop
            else:
                res |= (this_prop & properties)
        return res

    @staticmethod
    def get_all_tcp_connections():
        tcp_conns = ConnectionSet()
        tcp_conns.add_connections('TCP', ConnectivityProperties.make_all_props())
        return tcp_conns

    @staticmethod
    def get_non_tcp_connections():
        res = ConnectionSet()
        res.add_all_connections([ProtocolNameResolver.get_protocol_number('TCP')])
        return res
        # return ConnectionSet(True) - ConnectionSet.get_all_TCP_connections()

    # TODO - after moving to the optimized HC set implementation,
    #  get rid of ConnectionSet and move the code below to ConnectivityProperties.py
    @staticmethod
    def conn_props_to_fw_rules(conn_props, cluster_info, peer_container, ip_blocks_mask,
                               connectivity_restriction):
        """
        Build FWRules from the given ConnectivityProperties
        :param ConnectivityProperties conn_props: properties describing allowed connections
        :param ClusterInfo cluster_info: the cluster info
        :param PeerContainer peer_container: the peer container
        :param IpBlock ip_blocks_mask: IpBlock containing all allowed ip values,
         whereas all other values should be filtered out in the output
        :param Union[str,None] connectivity_restriction: specify if connectivity is restricted to
               TCP / non-TCP , or not
        :return: FWRules map
        """
        ignore_protocols = ProtocolSet()
        if connectivity_restriction:
            if connectivity_restriction == 'TCP':
                ignore_protocols.add_protocol('TCP')
            else:  # connectivity_restriction == 'non-TCP'
                ignore_protocols = ProtocolSet.get_non_tcp_protocols()

        fw_rules_map = defaultdict(list)
        for cube in conn_props:
            conn_cube = conn_props.get_connectivity_cube(cube)
            src_peers = conn_cube["src_peers"]
            if not src_peers:
                src_peers = peer_container.get_all_peers_group(True)
            conn_cube.unset_dim("src_peers")
            dst_peers = conn_cube["dst_peers"]
            if not dst_peers:
                dst_peers = peer_container.get_all_peers_group(True)
            conn_cube.unset_dim("dst_peers")
            if IpBlock.get_all_ips_block() != ip_blocks_mask:
                src_peers.filter_ipv6_blocks(ip_blocks_mask)
                dst_peers.filter_ipv6_blocks(ip_blocks_mask)
            protocols = conn_cube["protocols"]
            conn_cube.unset_dim("protocols")
            if not conn_cube.has_active_dim() and (protocols.is_whole_range() or protocols == ignore_protocols):
                conns = ConnectionSet(True)
            else:
                conns = ConnectionSet()
                protocol_names = ProtocolSet.get_protocol_names_from_interval_set(protocols) if protocols else ['TCP']
                for protocol in protocol_names:
                    if conn_cube.has_active_dim():
                        conns.add_connections(protocol, ConnectivityProperties.make_conn_props(conn_cube))
                    else:
                        if ConnectionSet.protocol_supports_ports(protocol):
                            conns.add_connections(protocol, ConnectivityProperties.make_all_props())
                        elif ConnectionSet.protocol_is_icmp(protocol):
                            conns.add_connections(protocol, ConnectivityProperties.make_all_props())
                        else:
                            conns.add_connections(protocol, True)
            # create FWRules for src_peers and dst_peers
            fw_rules_map[conns] += ConnectionSet.create_fw_rules_list_from_conns(conns, src_peers, dst_peers,
                                                                                 cluster_info)
        return fw_rules_map

    @staticmethod
    def create_fw_rules_list_from_conns(conns, src_peers, dst_peers, cluster_info):
        src_fw_elements = ConnectionSet.split_peer_set_to_fw_rule_elements(src_peers, cluster_info)
        dst_fw_elements = ConnectionSet.split_peer_set_to_fw_rule_elements(dst_peers, cluster_info)
        fw_rules_list = []
        for src_elem in src_fw_elements:
            for dst_elem in dst_fw_elements:
                fw_rules_list.append(FWRule.FWRule(src_elem, dst_elem, conns))
        return fw_rules_list

    @staticmethod
    def split_peer_set_to_fw_rule_elements(peer_set, cluster_info):
        res = []
        peer_set_copy = peer_set.copy()
        ns_set = set()
        # first, split by namespaces
        while peer_set_copy:
            peer = list(peer_set_copy)[0]
            if isinstance(peer, IpBlock):
                res.append(FWRule.IPBlockElement(peer))
                peer_set_copy.remove(peer)
                continue
            ns_peers = PeerSet(cluster_info.ns_dict[peer.namespace])
            if ns_peers.issubset(peer_set_copy):
                ns_set.add(peer.namespace)
            else:
                # TODO try to split the element below by labels
                res.append(FWRule.PeerSetElement(ns_peers & peer_set_copy))
            peer_set_copy -= ns_peers
        if ns_set:
            res.append(FWRule.FWRuleElement(ns_set))

        return res

    @staticmethod
    def fw_rules_to_conn_props(fw_rules):
        res = ConnectivityProperties.make_empty_props()
        for fw_rules_list in fw_rules.fw_rules_map.values():
            for fw_rule in fw_rules_list:
                conn_props = fw_rule.conn.convert_to_connectivity_properties()
                src_peers = PeerSet(fw_rule.src.get_peer_set(fw_rules.cluster_info))
                dst_peers = PeerSet(fw_rule.dst.get_peer_set(fw_rules.cluster_info))
                rule_props = ConnectivityProperties.make_conn_props_from_dict({"src_peers": src_peers,
                                                                               "dst_peers": dst_peers}) & conn_props
                res |= rule_props
        return res
