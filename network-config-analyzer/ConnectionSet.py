#
# Copyright 2020- IBM Inc. All rights reserved
# SPDX-License-Identifier: Apache2.0
#
from CanonicalIntervalSet import CanonicalIntervalSet
from PortSet import PortSet
from TcpLikeProperties import TcpLikeProperties
from ICMPDataSet import ICMPDataSet
from ProtocolNameResolver import ProtocolNameResolver


class ConnectionSet:
    """
    This class holds a set of connections and allows several manipulations on this set such as union, intersection, ...
    """
    _icmp_protocols = {1, 58}
    port_supporting_protocols = {6, 17, 132}
    _max_protocol_num = 255
    _min_protocol_num = 1

    def __init__(self, allow_all=False):
        self.allowed_protocols = {}  # a map from protocol number (1-255) to allowed properties (ports, icmp)
        self.allow_all = allow_all  # Shortcut to represent all connections, and then allowed_protocols is to be ignored

    def __bool__(self):
        return self.allow_all or bool(self.allowed_protocols)

    def __eq__(self, other):
        if isinstance(other, ConnectionSet):
            return self.allow_all == other.allow_all and self.allowed_protocols == other.allowed_protocols
        return NotImplemented

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
        for protocol in sorted(self.allowed_protocols):
            if ProtocolNameResolver.is_standard_protocol(protocol):
                protocol_text = ProtocolNameResolver.get_protocol_name(protocol)
                properties = self.allowed_protocols[protocol]
                res.append(self._get_protocol_with_properties_representation(is_str, protocol_text, properties))
            else:
                # collect allowed protocols numbers into ranges
                # assuming no properties objects for protocols numbers
                protocols_ranges.add_interval(CanonicalIntervalSet.Interval(protocol, protocol))
        if protocols_ranges:
            res += self._get_protocols_ranges_representation(is_str, protocols_ranges)
        return ','.join(s for s in res) if is_str else res

    @staticmethod
    def _get_protocol_with_properties_representation(is_str, protocol_text, properties):
        """
        :param bool is_str: should get str representation (True) or list representation (False)
        :param str protocol_text: str description of protocol
        :param Union[bool, TcpLikeProperties, ICMPDataSet] properties: properties object of the protocol
        :return: representation required for given pair of protocol and its properties
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
            if not isinstance(properties, bool):
                properties_text = ', ' + str(properties)
            return protocol_text + properties_text

        protocol_text = 'Protocols: '
        for idx, protocol in enumerate(self.allowed_protocols.keys()):
            if idx > 5:
                protocol_text += ', ...'
                break
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
        :param protocol: Protocol number
        :return: Whether the given protocol has ports
        :rtype: bool
        """
        return protocol in ConnectionSet.port_supporting_protocols

    @staticmethod
    def protocol_is_icmp(protocol):
        """
        :param protocol: Protocol number
        :return: Whether the protocol is icmp or icmpv6
        :rtype: bool
        """
        return protocol in ConnectionSet._icmp_protocols

    def add_connections(self, protocol, properties=True):
        """
        Add connections to the set of connections
        :param int,str protocol: protocol number of the connections to add
        :param properties: an object with protocol properties (e.g., ports), if relevant
        :type properties: Union[bool, TcpLikeProperties, ICMPDataSet]
        :return: None
        """
        if isinstance(protocol, str):
            protocol = ProtocolNameResolver.get_protocol_number(protocol)
        if protocol < 1 or protocol > 255:
            raise Exception('Protocol must be in the range 1-255')
        if not bool(properties):  # if properties are empty, there is nothing to add
            return
        if protocol in self.allowed_protocols:
            self.allowed_protocols[protocol] |= properties
        else:
            self.allowed_protocols[protocol] = properties

    def remove_protocol(self, protocol):
        """
        Remove a protocol from the set of connections
        :param int,str protocol: The protocol to remove
        :return: None
        """
        if isinstance(protocol, str):
            protocol = ProtocolNameResolver.get_protocol_number(protocol)
        if protocol < 1 or protocol > 255:
            raise Exception('Protocol must be in the range 1-255')
        if protocol not in self.allowed_protocols:
            return
        del self.allowed_protocols[protocol]

    def add_all_connections(self, excluded_protocols=None):
        """
        Add all possible connections to the connection set
        :param list[int] excluded_protocols: (optional) list of protocol numbers to exclude
        :return: None
        """
        for protocol in range(ConnectionSet._min_protocol_num, ConnectionSet._max_protocol_num + 1):
            if excluded_protocols and protocol in excluded_protocols:
                continue
            if self.protocol_supports_ports(protocol):
                self.allowed_protocols[protocol] = TcpLikeProperties(PortSet(True), PortSet(True))
            elif self.protocol_is_icmp(protocol):
                self.allowed_protocols[protocol] = ICMPDataSet(add_all=True)
            else:
                self.allowed_protocols[protocol] = True

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

    @staticmethod
    def get_all_tcp_connections():
        tcp_conns = ConnectionSet()
        tcp_conns.add_connections('TCP', TcpLikeProperties(PortSet(True), PortSet(True)))
        return tcp_conns

    @staticmethod
    def get_non_tcp_connections():
        res = ConnectionSet()
        res.add_all_connections([ProtocolNameResolver.get_protocol_number('TCP')])
        return res
        # return ConnectionSet(True) - ConnectionSet.get_all_TCP_connections()
