#
# Copyright 2020- IBM Inc. All rights reserved
# SPDX-License-Identifier: Apache2.0
#
from CanonicalIntervalSet import CanonicalIntervalSet
from PortSet import PortSet
from TcpLikeProperties import TcpLikeProperties
from ICMPDataSet import ICMPDataSet


class ConnectionSet:
    """
    This class holds a set of connections and allows several manipulations on this set such as union, intersection, ...
    """
    _protocol_number_to_name_dict = {1: 'ICMP', 6: 'TCP', 17: 'UDP', 58: 'ICMPv6', 132: 'SCTP', 135: 'UDPLite'}
    _protocol_name_to_number_dict = {'ICMP': 1, 'TCP': 6, 'UDP': 17, 'ICMPv6': 58, 'SCTP': 132, 'UDPLite': 135}
    _icmp_protocols = {1, 58}
    port_supporting_protocols = {6, 17, 132}

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

    # TODO: should consider shorter notation (complement- 'all but ...' ) for yaml representation as well?
    def get_connections_list(self, relevant_protocols):
        """
        allowed connections representation, restricted to protocols from relevant_protocols
        :param set[int] relevant_protocols:  a set of protocols numbers or None
        :return:  list with yaml representation of the connection set, to be used at fw-rules representation in yaml
        """
        res = []
        if self.allow_all:
            res.append(str(self))
            return res
        if not self.allowed_protocols:
            res.append(str(self))
            return res
        protocols_set = set(self.allowed_protocols.keys())
        # in k8s policy - restrict allowed protocols only to protocols supported by it
        if relevant_protocols is not None:
            protocols_set &= relevant_protocols
        for protocol in sorted(list(protocols_set)):
            protocol_text = protocol #self.protocol_number_to_name(protocol)
            if protocol in ConnectionSet._protocol_number_to_name_dict:
                protocol_text = ConnectionSet._protocol_number_to_name_dict[protocol]
            protocol_obj = {'Protocol': protocol_text}
            properties = self.allowed_protocols[protocol]
            if not isinstance(properties, bool):
                protocol_obj.update(properties.get_properties_obj())
            res.append(protocol_obj)
        return res

    def get_simplified_connections_str(self, relevant_protocols, use_complement_simplification):
        """
        Get a simplified representation of the connection set - choose shorter version between self and its complement.
        Restrict representation to relevant protocols, and use complement simplification when required.
        :param set[int] relevant_protocols:  a set of protocols numbers or None
        :param bool use_complement_simplification: should use complement simplification when possible or not
        :return: a string representation of the connection set, to be used at fw-rules representation in txt
        """
        if self.allow_all:
            return "All connections"
        if not self.allowed_protocols:
            return 'No connections'
        self_str = self.get_connections_str(relevant_protocols)
        if not use_complement_simplification:
            return self_str

        # check the alternative of the complement str
        complement = ConnectionSet(True) - self
        complement_str = complement.get_connections_str(relevant_protocols)
        # TODO: is there a better heuristic here?
        if len(complement_str) < len(self_str):
            return f'All but {complement_str}'
        return self_str

    def get_connections_str(self, relevant_protocols):
        """
        Get a string representation of the connection set
        :param set[int] relevant_protocols: a set of protocols numbers or None
        :return: a string representation of the connection set, to be used at fw-rules representation in txt
        """
        if self.allow_all:
            return "All connections"
        if not self.allowed_protocols:
            return 'No connections'
        res = ''
        protocols_set = set(self.allowed_protocols.keys())
        if relevant_protocols is not None:
            protocols_set &= relevant_protocols
        protocols_numbers = CanonicalIntervalSet()
        for protocol in sorted(list(protocols_set)):
            if protocol not in ConnectionSet._protocol_number_to_name_dict:
                interval = CanonicalIntervalSet.Interval(protocol, protocol)
                protocols_numbers.add_interval(interval)
            else:
                protocol_text = self.protocol_number_to_name(protocol)
                properties = self.allowed_protocols[protocol]
                if not isinstance(properties, bool):
                    res += protocol_text + ' ' + str(properties) + ','
                else:
                    res += protocol_text + ','
        if protocols_numbers:
            res += 'protocols numbers: ' + str(protocols_numbers)
        return res

    def __str__(self):
        if self.allow_all:
            return "All connections"
        if not self.allowed_protocols:
            return 'No connections'

        if len(self.allowed_protocols) == 1:
            protocol_num = next(iter(self.allowed_protocols))
            protocol_text = 'Protocol: ' + self.protocol_number_to_name(protocol_num)
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
            protocol_text += self.protocol_number_to_name(protocol)

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
    def protocol_name_to_number(name):
        """
        Convert protocol name to protocol number (for common protocols)
        Source: https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
        :param str name: protocol name
        :return: protocol number
        :rtype: int
        """
        if isinstance(name, int):
            return name

        protocol_num = ConnectionSet._protocol_name_to_number_dict.get(name)
        if not protocol_num:
            raise Exception('Unknown protocol name: ' + name)

        return protocol_num

    @staticmethod
    def protocol_number_to_name(number):
        """
        Convert protocol number to protocol name (for common protocols)
        :param int number: protocol number
        :return: protocol name
        :rtype: str
        """
        if number < 1 or number > 255:
            raise Exception('Protocol number must be in the range 1-255')

        return ConnectionSet._protocol_number_to_name_dict.get(number, str(number))

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
            protocol = self.protocol_name_to_number(protocol)
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
            protocol = self.protocol_name_to_number(protocol)
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
        for protocol in range(1, 256):
            if excluded_protocols and protocol in excluded_protocols:
                continue
            if self.protocol_supports_ports(protocol):
                self.allowed_protocols[protocol] = TcpLikeProperties(PortSet(True), PortSet(True))
            elif self.protocol_is_icmp(protocol):
                self.allowed_protocols[protocol] = ICMPDataSet(add_all=True)
            else:
                self.allowed_protocols[protocol] = True

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
                properties.convert_named_ports(named_ports, self.protocol_number_to_name(protocol))
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
                return self_name + ' allows communication using protocol ' + self.protocol_number_to_name(protocol) + \
                       ' while ' + other_name + ' does not.'
            other_properties = other.allowed_protocols[protocol]
            if properties != other_properties:
                return self.protocol_number_to_name(protocol) + ' protocol - ' + \
                       properties.print_diff(other_properties, self_name, other_name)

        for protocol in other.allowed_protocols:
            if protocol not in self.allowed_protocols:
                return other_name + ' allows communication using protocol ' + self.protocol_number_to_name(protocol) + \
                       ' while ' + self_name + ' does not.'

        return 'No diff.'

    @staticmethod
    def get_all_tcp_connections():
        tcp_conns = ConnectionSet()
        tcp_conns.add_connections('TCP', TcpLikeProperties(PortSet(True), PortSet(True)))
        return tcp_conns

    @staticmethod
    def get_non_tcp_connections():
        res = ConnectionSet()
        res.add_all_connections([ConnectionSet._protocol_name_to_number_dict['TCP']])
        return res
        #return ConnectionSet(True) - ConnectionSet.get_all_TCP_connections()
