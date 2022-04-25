#
# Copyright 2020- IBM Inc. All rights reserved
# SPDX-License-Identifier: Apache2.0
#
import copy
import ipaddress
from ipaddress import ip_network
from sys import stderr
from string import hexdigits
from CanonicalIntervalSet import CanonicalIntervalSet
from K8sNamespace import K8sNamespace


class Peer:
    """
    This is the base class for all network endpoints, both inside the relevant cluster and outside of it
    """

    def __init__(self, name, namespace):
        self.name = name
        self.namespace = namespace
        self.labels = {}  # Storing the endpoint's labels in a dict as key-value pairs
        self.extra_labels = {}  # for labels coming from 'labelsToApply' field in Profiles (Calico only)

    def set_label(self, key, value):
        """
        Add a label to the endpoint
        :param str key: label key
        :param str value: label value
        :return: None
        """
        self.labels[key] = value

    def set_extra_label(self, key, value):
        """
        Add a label which comes from one of the endpoint's profiles
        :param str key: label key
        :param str value: label value
        :return: None
        """
        self.extra_labels[key] = value

    def clear_extra_labels(self):
        self.extra_labels.clear()

    def has_profiles(self):
        return False

    def is_global_peer(self):
        return False

    @staticmethod
    def get_named_ports():
        return {}


class ClusterEP(Peer):
    """
    This is the base class for endpoints inside the given cluster
    """

    def __init__(self, name, namespace=None):
        super().__init__(name, namespace)
        self.named_ports = {}  # A map from port name to the port number and its protocol
        self.profiles = []  # The set of attached profiles (Calico only)

    def __eq__(self, other):
        if isinstance(other, type(self)):
            return self.full_name() == other.full_name()
        return NotImplemented

    def __str__(self):
        return self.full_name()

    def __hash__(self):
        return hash(self.full_name())

    def full_name(self):
        return self.name

    def add_named_port(self, name, port_num, protocol, warn=True):
        """
        Adds a named port which is defined for the endpoint
        :param str name: The name given to the named port
        :param int port_num: Port number
        :param str protocol: Port protocol
        :param bool warn: Whether to warn if the port is already being used
        :return: None
        """
        if not name:
            return
        if warn and name in self.named_ports:
            print('Warning: a port named', name, 'is multiply defined for pod', self.full_name(), file=stderr)
        self.named_ports[name] = (port_num, protocol)

    def get_named_ports(self):
        return self.named_ports

    def add_profile(self, profile_name):
        self.profiles.append(profile_name)

    def has_profiles(self):
        return len(self.profiles) > 0

    def get_first_profile_name(self):
        """
        :return str: The name of the first assigned profile, or None if ep has no profiles.
        """
        return self.profiles[0] if self.profiles else None

    def canonical_form(self):
        """
        Two eps are isomorphic (cannot be distinguished by selectors) if they have the same set of labels and profiles.
        This function returns a string which should be the same for any pair of isomorphic eps and should be different
        for any pair of non-isomorphic eps.
        :return str: A string which is unique for every ep up to isomorphism
        """
        ret = ''
        if self.profiles:
            ret += ',' + self.profiles[0]  # first profile is really important - it determines default ingress/egress
            if len(self.profiles) > 1:  # other profiles may only add labels using 'labelsToApply' field
                sorted_profiles = sorted(self.profiles[1:])
                for profile in sorted_profiles:
                    ret += ',' + profile

        labels = sorted(self.labels.items())
        for label in labels:
            ret += ',(' + label[0] + ',' + label[1] + ')'

        return ret


class Pod(ClusterEP):
    """
    This class represents either a K8s Pod resource or a Calico WorkloadEndpoint resource
    """

    def __init__(self, name, namespace, owner_name='', owner_kind=None, service_account_name=''):
        """
        :param str name: The name of the Pod
        :param K8sNamespace namespace: The namespace object for the Pod's namespace
        :param str owner_name: The name of the Pod's owner
        :param str owner_kind: The kind of the Pod's owner
        """
        super().__init__(name, namespace)
        self.owner_name = owner_name
        self.service_account_name = service_account_name

        if not owner_name:  # no owner
            self.workload_name = f'{namespace.name}/{name}(Pod)'
        elif owner_kind == 'ReplicaSet':
            # if owner name ends with hex-suffix, assume the pod is generated indirectly
            # by Deployment or StatefulSet; and remove the hex-suffix from workload name
            suffix = owner_name[owner_name.rfind('-') + 1:]
            if all(c in hexdigits for c in suffix):
                self.workload_name = f'{namespace.name}/{owner_name[:owner_name.rfind("-")]}(Deployment-StatefulSet)'
            else:  # else, assume the pod is generated directly by a ReplicaSet
                self.workload_name = f'{namespace.name}/{owner_name}(ReplicaSet)'
        else:  # all other kind of workloads that generate pods
            self.workload_name = f'{namespace.name}/{owner_name}({owner_kind})'

    def __str__(self):
        return self.full_name()

    def __repr__(self):
        return self.full_name()

    def full_name(self):
        return self.namespace.name + '/' + self.name

    def canonical_form(self):
        # two pods are isomorphic if they have the same namespace and have the same set of labels and profiles
        return self.namespace.name + '_' + self.workload_name + '_' + super().canonical_form()

    def add_named_port(self, name, port_num, protocol, warn=False):
        warn = self.namespace.name != 'kube-system'  # suppress warnings which the user cannot avoid
        super().add_named_port(name, port_num, protocol, warn)


class HostEP(ClusterEP):
    """
    This class represents Calico's HostEndpoint resource
    """

    def is_global_peer(self):
        return True


class IPNetworkAddress:
    """
    This class represents an arbitrary network address (either IPv4 or IPv6)
    """

    def __init__(self, address):
        if not isinstance(address, ipaddress.IPv4Address) and \
                not isinstance(address, ipaddress.IPv6Address):
            raise ValueError('%r does not appear to be an IPv4 or IPv6 network' % address)
        self.address = address

    def __int__(self):
        return int(self.address)

    def __eq__(self, other):
        return self.address == other.address

    def __lt__(self, other):
        if not isinstance(other, IPNetworkAddress):
            return NotImplemented
        if self.address._version == other.address._version:
            return self.address < other.address
        return self.address._version < other.address._version  # IPv4 < IPv6

    def __le__(self, other):
        if not isinstance(other, IPNetworkAddress):
            return NotImplemented
        if self.address._version == other.address._version:
            return self.address <= other.address
        return self.address._version < other.address._version  # IPv4 < IPv6

    def __gt__(self, other):
        if not isinstance(other, IPNetworkAddress):
            return NotImplemented
        if self.address._version == other.address._version:
            return self.address > other.address
        return self.address._version > other.address._version  # IPv6 > IPv4

    def __ge__(self, other):
        if not isinstance(other, IPNetworkAddress):
            return NotImplemented
        if self.address._version == other.address._version:
            return self.address >= other.address
        return self.address._version > other.address._version  # IPv6 > IPv4

    def __add__(self, other):
        if not isinstance(other, int):
            return NotImplemented
        try:
            res = self.__class__(self.address + other)
        except ipaddress.AddressValueError:
            res = self.__class__(self.address)
        return res

    def __sub__(self, other):
        if not isinstance(other, int):
            return NotImplemented
        try:
            res = self.__class__(self.address - other)
        except ipaddress.AddressValueError:
            res = self.__class__(self.address)
        return res

    def __repr__(self):
        return repr(self.address)

    def __str__(self):
        return str(self.address)

    def __hash__(self):
        return hash(self.address)

    def __format__(self, fmt):
        return format(self.address)


class IpBlock(Peer, CanonicalIntervalSet):
    """
    This class represents a set of ip ranges
    """

    def __init__(self, cidr=None, exceptions=None, interval=None, name=None, namespace=None, is_global=False):
        """
        Constructs an IpBlock object. Use either cidr+exceptions or interval
        :param str cidr: a cidr-formatted string representing a range of ips to include in the range
        :param list[str] exceptions: a list of cidr-formatted strings to exclude from the ip range
        :param CanonicalIntervalSet.Interval interval: A range of ip addresses as an interval
        """
        Peer.__init__(self, name, namespace)
        CanonicalIntervalSet.__init__(self)
        self.is_global = is_global
        if interval:
            self.interval_set.append(interval)
        elif cidr:
            self.add_cidr(cidr, exceptions)

    def is_global_peer(self):
        return self.is_global

    def canonical_form(self):
        if self.namespace is None:
            return self.name
        else:
            return self.namespace.name + '_' + self.name

    def copy(self):
        res = IpBlock(name=self.name, namespace=self.namespace, is_global=self.is_global)
        res.interval_set = self.interval_set.copy()
        return res

    def get_cidr_list(self):
        cidr_list = []
        for interval in self.interval_set:
            startip = interval.start.address.__class__(interval.start)  # either IPv4AAddress or IPv6Address
            endip = interval.end.address.__class__(interval.end)
            cidrs = [ipaddr for ipaddr in ipaddress.summarize_address_range(startip, endip)]
            cidr_list += [str(cidr) for cidr in cidrs]
        return cidr_list

    def get_cidr_list_str(self):
        cidr_list = self.get_cidr_list()
        return ','.join(str(cidr) for cidr in cidr_list)

    def get_ip_range_or_cidr_str(self):
        """
        Get str for self with shorter notation - either as ip range or as cidr
        :rtype str
        """
        num_cidrs = len(self.get_cidr_list())
        num_ranges = len(self.interval_set)
        if num_ranges * 2 <= num_cidrs:
            return str(self)
        return self.get_cidr_list_str()

    @staticmethod
    def get_all_ips_block():
        """
        :return: The full range of ipv4 and ipv6 addresses
        :rtype: IpBlock
        """
        res = IpBlock('0.0.0.0/0')
        res.add_cidr('::/0')
        return res

    @staticmethod
    def get_all_ips_block_peer_set():
        """
        :return: The full range of ipv4 and ipv6 addresses
        :rtype: PeerSet
        """
        res = PeerSet()
        res.add(IpBlock.get_all_ips_block())
        return res

    def split(self):
        """
        Splits self's set of ip ranges into multiple IpBlock objects, each containing a single range
        :return PeerSet: A set of IpBlock objects, each with a single range of ips
        """
        res = PeerSet()
        for ip_range in self:
            res.add(IpBlock(interval=ip_range))
        return res

    def ip_count(self):
        """
        Calculates the number of unique ip addresses in self's set of ranges
        :return int: Total number of ip addresses, represented by self
        """
        res = 0
        for ip_range in self:
            res += int(ip_range.end) - int(ip_range.start) + 1
        return res

    def add_cidr(self, cidr, exceptions=None):
        ipn = ip_network(cidr, False)  # strict is False as k8s API shows an example CIDR where host bits are set
        self.add_interval(CanonicalIntervalSet.Interval(IPNetworkAddress(ipn.network_address),
                                                        IPNetworkAddress(ipn.broadcast_address)))
        for exception in exceptions or []:
            exception_n = ip_network(exception, False)
            # the following line has no effect - only used to raise an exception when exception_n is not within cidr
            exception_n.subnet_of(ipn)
            hole = CanonicalIntervalSet.Interval(IPNetworkAddress(exception_n.network_address),
                                                 IPNetworkAddress(exception_n.broadcast_address))
            self.add_hole(hole)

    def get_peer_set(self):
        """
        :return: get PeerSet from IpBlock (empty set if IpBlock is empty)
        """
        return PeerSet({self}) if self else PeerSet()

    @staticmethod
    def _add_interval_to_list(interval, non_overlapping_interval_list):
        """
        Adding an interval to the list of non-overlapping blocks while maintaining the invariants
        :param IpBlock interval: The interval to add
        :param list[IpBlock] non_overlapping_interval_list: The existing list the interval should be added to
        :return: None
        """
        to_add = []
        for idx, ip_block in enumerate(non_overlapping_interval_list):
            if not ip_block.overlaps(interval):
                continue
            intersection = ip_block & interval
            interval -= intersection
            if ip_block != intersection:
                to_add.append(intersection)
                non_overlapping_interval_list[idx] -= intersection
            if not interval:
                break

        non_overlapping_interval_list += interval.split()
        non_overlapping_interval_list += to_add

    @staticmethod
    def disjoint_ip_blocks(ip_blocks1, ip_blocks2):
        """
        Takes all (atomic) ip-ranges in both ip-blocks and returns a new set of ip-ranges where
        each ip-range is:
        1. a subset of an ip-range in either ip-blocks AND
        2. cannot be partially intersected by an ip-range in either ip-blocks AND
        3. is maximal (extending the range to either side will violate either 1 or 2)
        :param ip_blocks1: A set of ip blocks
        :param ip_blocks2: A set of ip blocks
        :return: A set of ip ranges as specified above
        :rtype: PeerSet
        """
        # deepcopy is required since add_interval_to_list() changes the 'interval' argument
        ip_blocks_set = copy.deepcopy(ip_blocks1)
        ip_blocks_set |= copy.deepcopy(ip_blocks2)
        ip_blocks = sorted(ip_blocks_set, key=IpBlock.ip_count)

        # making sure the resulting list does not contain overlapping ipBlocks
        blocks_with_no_overlap = []
        for interval in ip_blocks:
            IpBlock._add_interval_to_list(interval, blocks_with_no_overlap)

        res = PeerSet()
        for ip_block in blocks_with_no_overlap:
            res.add(ip_block)

        if not res:
            res.add(IpBlock.get_all_ips_block())

        return res


class PeerSet(set):
    """
    A container to hold a set of Peer objects

    Note #1: objects of type IpBlock are not transformed into canonical form
    Note #2: __contains__ is implemented under the assumption that item arg is from disjoint_ip_blocks()
    """

    def __init__(self, peer_set=None):
        super().__init__(peer_set or set())

    def __contains__(self, item):
        if isinstance(item, IpBlock):  # a special check here because an IpBlock may be contained in another IpBlock
            for peer in self:
                if isinstance(peer, IpBlock) and item.contained_in(peer):
                    return True
            return False
        return super().__contains__(item)

    def __eq__(self, other):
        # set comparison
        if self.get_set_without_ip_block() != other.get_set_without_ip_block():
            return False
        # IpBlocks comparison
        self_ip_block = self.get_ip_block_canonical_form()
        other_ip_block = other.get_ip_block_canonical_form()
        return self_ip_block == other_ip_block

    def copy(self):
        # TODO: shallow copy or deep copy?
        # res = PeerSet(set(elem.copy() for elem in self))
        res = PeerSet(super().copy())
        return res

    # TODO: what is expected for ipblock name/namespace result on intersection?
    def __iand__(self, other):
        # intersection of IpBlocks (canonical interval set)
        self_ip_block = self.get_ip_block_canonical_form()
        other_ip_block = other.get_ip_block_canonical_form()
        res_peer_set_ip_block = (self_ip_block & other_ip_block).get_peer_set()
        # set intersection
        self_without_ip_block = self.get_set_without_ip_block()
        other_without_ip_block = other.get_set_without_ip_block()
        res_without_ip_block = self_without_ip_block & other_without_ip_block
        # combined result
        return PeerSet(res_without_ip_block) | res_peer_set_ip_block

    def __and__(self, other):
        res = self.copy()
        res &= other
        return res

    def __ior__(self, other):
        return PeerSet(super().__ior__(other))

    def __or__(self, other):
        return PeerSet(super().__or__(other))

    def __isub__(self, other):
        # subtraction on IpBlocks
        self_ip_block = self.get_ip_block_canonical_form()
        other_ip_block = other.get_ip_block_canonical_form()
        res_peer_set_ip_block = (self_ip_block - other_ip_block).get_peer_set()
        # set subtraction
        self_without_ip_block = self.get_set_without_ip_block()
        other_without_ip_block = other.get_set_without_ip_block()
        res_without_ip_block = self_without_ip_block - other_without_ip_block
        # combined result
        return PeerSet(res_without_ip_block) | res_peer_set_ip_block

    def __sub__(self, other):
        res = self.copy()
        res -= other
        return res

    def rep(self):
        """
        Returns a representing peer from the set of peers
        :return str: The name of the representing peer. An empty string if set is empty
        """
        if not bool(self):
            return ''
        for peer in self:
            return str(peer)

    def get_set_without_ip_block(self):
        """
        :return: a set with all elements from self which are not IpBlock
        """
        return set(elem for elem in self if not isinstance(elem, IpBlock))

    def get_ip_block_canonical_form(self):
        """
        :return: IpBlock element in canonical form for all elements from self which are IpBlock
        """
        res = IpBlock()
        for elem in self:
            if isinstance(elem, IpBlock):
                res |= elem
        return res
