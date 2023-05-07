#
# Copyright 2020- IBM Inc. All rights reserved
# SPDX-License-Identifier: Apache2.0
#
import copy
import ipaddress
import re
from ipaddress import ip_network
from sys import stderr
from string import hexdigits
from .CanonicalIntervalSet import CanonicalIntervalSet


class Peer:
    """
    This is the base class for all network endpoints, both inside the relevant cluster and outside of it
    """

    def __init__(self, name, namespace):
        self.name = name
        self.namespace = namespace
        self.labels = {}  # Storing the endpoint's labels in a dict as key-value pairs
        self.extra_labels = {}  # for labels coming from 'labelsToApply' field in Profiles (Calico only)

    def full_name(self):
        return self.namespace.name + '/' + self.name if self.namespace else self.name

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
        return False

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
            ret += f',({label[0]},{label[1]})'

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
        self.full_name_str = self.namespace.name + '/' + self.name
        self.replicaset_name = None
        if not owner_name:  # no owner
            self.workload_name = f'{namespace.name}/{name}(Pod)'
        elif owner_kind == 'ReplicaSet':
            self.replicaset_name = f'{namespace.name}/{owner_name}(ReplicaSet)'
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
        return self.full_name_str

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
            return False
        if self.address.version == other.address.version:
            return self.address < other.address
        return self.address.version < other.address.version  # IPv4 < IPv6

    def __le__(self, other):
        if not isinstance(other, IPNetworkAddress):
            return False
        if self.address.version == other.address.version:
            return self.address <= other.address
        return self.address.version < other.address.version  # IPv4 < IPv6

    def __gt__(self, other):
        if not isinstance(other, IPNetworkAddress):
            return True
        if self.address.version == other.address.version:
            return self.address > other.address
        return self.address.version > other.address.version  # IPv6 > IPv4

    def __ge__(self, other):
        if not isinstance(other, IPNetworkAddress):
            return True
        if self.address.version == other.address.version:
            return self.address >= other.address
        return self.address.version > other.address.version  # IPv6 > IPv4

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
        if not self.name:
            self.name = self.get_cidr_list_str()

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

    def get_ip_range_or_cidr_str(self, range_only=False):
        """
        Get str for self with shorter notation - either as ip range or as cidr
        :param bool range_only: indicates if to return the self str as ip range only
        :rtype str
        """
        num_cidrs = len(self.get_cidr_list())
        num_ranges = len(self.interval_set)
        if num_ranges * 2 <= num_cidrs or range_only:
            return str(self)
        return self.get_cidr_list_str()

    @staticmethod
    def get_all_ips_block(exclude_ipv6=False, exclude_ipv4=False):
        """
        :return: The full range of ipv4 and ipv6 addresses if exclude_ipv6 is False
        :param bool exclude_ipv6: indicates if to exclude the IPv6 addresses
        :param bool exclude_ipv4: indicates if to exclude the IPv4 addresses
        :rtype: IpBlock
        """
        assert not exclude_ipv6 or not exclude_ipv4
        res = IpBlock()
        if not exclude_ipv4:
            res.add_cidr('0.0.0.0/0')
        if not exclude_ipv6:
            res.add_cidr('::/0')
        return res

    @staticmethod
    def get_all_ips_block_peer_set(exclude_ipv6=False):
        """
        :return: The full range of ipv4 and ipv6 addresses (ipv6 if exclude_ipv6 is False)
        :param bool exclude_ipv6: indicates if to exclude the IPv6 addresses
        :rtype: PeerSet
        """
        res = PeerSet()
        res.add(IpBlock.get_all_ips_block(exclude_ipv6=exclude_ipv6))
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

    def remove_cidr(self, cidr):
        ipn = ip_network(cidr, False)  # strict is False as k8s API shows an example CIDR where host bits are set
        hole = CanonicalIntervalSet.Interval(IPNetworkAddress(ipn.network_address),
                                             IPNetworkAddress(ipn.broadcast_address))
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
    def disjoint_ip_blocks(ip_blocks1, ip_blocks2, exclude_ipv6=False):
        """
        Takes all (atomic) ip-ranges in both ip-blocks and returns a new set of ip-ranges where
        each ip-range is:
        1. a subset of an ip-range in either ip-blocks AND
        2. cannot be partially intersected by an ip-range in either ip-blocks AND
        3. is maximal (extending the range to either side will violate either 1 or 2)
        :param ip_blocks1: A set of ip blocks
        :param ip_blocks2: A set of ip blocks
        :param bool exclude_ipv6: indicates if to exclude the IPv6 addresses in case the result is all_ips_block
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
            res.add(IpBlock.get_all_ips_block(exclude_ipv6))

        return res

    def is_ipv4_block(self):
        """
        checks whether self IpBlock includes only IPv4 addresses
        :return: true if self includes only IPv4 addresses
        :rtype: bool
        """
        cnt = 0
        for interval in self.interval_set:
            ip_address = interval.start
            if isinstance(ip_address, IPNetworkAddress) and isinstance(ip_address.address, ipaddress.IPv4Address) or \
                    isinstance(ip_address, ipaddress.IPv4Address):
                cnt += 1
        return cnt == len(self.interval_set)


"""
The following class DNSEntry; represents another type of external peer which is produced from istio ServiceEntry objects.
Note: connectivity of DNSEntry peers is considered only for NetworkLayerName.Istio
a DNSEntry peer is created from a single host in the serviceEntry object

example: from this ServiceEntry yaml object:
    `
    apiVersion: networking.istio.io/v1alpha3
    kind: ServiceEntry
    metadata:
        name: external-svc-first-test
    spec:
        hosts:
            - www.slack.com
            - www.google.com
        location: MESH_EXTERNAL
        ports:
            - name: https-443
              number: 443
              protocol: HTTPS
        resolution: NONE
    `
two DNSEntry peers will be created :
1.DNSEntry(name=www.slack.com)
2.DNSEntry(name=www.google.com)
"""


class DNSEntry(Peer):
    """
    represents DNS entries, produced by istio ServiceEntry objects.
    A DNSEntry peer is created from single host in the service-entry hosts' list
    """
    # a dns entry pattern matches the following re-pattern
    dns_pattern = r"(([A-Za-z0-9][-A-Za-z0-9_.]*)?[A-Za-z0-9])?"

    def __init__(self, name=None, namespace=None):
        """
        Constructs a DNSEntry from the host name provided
        currently: each DNSEntry peer is exported to all namespaces
        """
        Peer.__init__(self, name, namespace)

    def __str__(self):
        return self.name

    def __repr__(self):
        return self.name

    def __hash__(self):
        return hash(self.name)

    def __eq__(self, other):
        if isinstance(other, type(self)):
            return self.name == other.name
        return False

    def canonical_form(self):
        if self.namespace is None:
            return self.name
        else:
            return self.namespace.name + '_' + self.name

    @staticmethod
    def compute_re_pattern_from_host_name(host_name):
        """
        translates the host name (dns) to a pattern that may be used with re library methods
         - "*" at the beginning of the host name will be replaced with an FQDN pattern
         - the "." in the host name may not be replaced by any other character
         :param str host_name: the host name
         :return: the re-pattern of the host name
         :rtype: str
        """
        if host_name.startswith('*'):
            name_suffix = re.escape(host_name[1:])
            return DNSEntry.dns_pattern + name_suffix
        return re.escape(host_name)


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
        """
        :rtype: PeerSet
        """
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
        res = PeerSet(super().__ior__(other))
        return res

    def __or__(self, other):
        res = PeerSet(super().__or__(other))
        return res

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

    def __hash__(self):
        """
        Note: PeerSet is a mutable type. Use with caution!
        :return: hash value for this object.
        """
        return hash(','.join(str(peer.full_name()) for peer in sorted(list(elem for elem in self), key=by_full_name)))

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

    def filter_ipv6_blocks(self, ip_blocks_mask):
        """
        Update ip blocks in the peer set by keeping only parts overlapping with the given mask.
        :param ip_blocks_mask: the mask according to which ip blocks should be updated
        """
        peers_to_remove = []
        peers_to_add = []
        for peer in self:
            if isinstance(peer, IpBlock):
                peers_to_remove.append(peer)
                if peer.overlaps(ip_blocks_mask):
                    new_peer = peer.copy()
                    new_peer &= ip_blocks_mask
                    peers_to_add.append(new_peer)

        for peer in peers_to_remove:
            self.remove(peer)
        for peer in peers_to_add:
            self.add(peer)


def by_full_name(elem):
    """
    Used for sorting peer list
    :param elem: Peer
    :return: Peer's name (the key being used by the sort)
    """
    return elem.full_name()


class BasePeerSet:
    """
    A singleton class that keeps the set of all possible pods in the system (from all configs),
    and translates PeerSets to CanonicalIntervalSets and vice versa.
    """

    # the inner class is needed to make the outer class a singleton
    class __BasePeerSet:

        ipv4_highest_number = int(ip_network('0.0.0.0/0').broadcast_address)
        ipv6_highest_number = int(ip_network('::/0').broadcast_address)
        max_num_of_pods = 10000
        gap_width = 5  # the gap is needed to avoid mixed-type intervals union
        min_ipv4_index = 0
        max_ipv4_index = min_ipv4_index + ipv4_highest_number
        min_ipv6_index = max_ipv4_index + gap_width
        max_ipv6_index = min_ipv6_index + ipv6_highest_number
        min_pod_index = max_ipv6_index + gap_width
        max_pod_index = min_pod_index + max_num_of_pods - 1

        def __init__(self):
            self.ordered_peer_list = []  # for converting PeerSet to CanonicalIntervalSet
            self.peer_to_index = dict()  # a map from peer name to index in self.ordered_peer_list

        def add_peer(self, peer):
            """
            Adds a given peer to self peers.
            :param peer: the peer to add.
            """
            if not isinstance(peer, IpBlock) and peer not in self.peer_to_index:
                assert len(self.ordered_peer_list) < self.max_num_of_pods
                self.peer_to_index[peer] = len(self.ordered_peer_list)
                self.ordered_peer_list.append(peer)

        def get_peer_interval_of(self, peer_set):
            """
            Translates the given peer_set to an interval set of indices
            :param PeerSet peer_set: the peer_set to be converted to the interval set
            :return: CanonicalIntervalSet for the peer_set
            """
            res = CanonicalIntervalSet()
            for peer in peer_set:
                if isinstance(peer, IpBlock):
                    for cidr in peer:
                        if isinstance(cidr.start.address, ipaddress.IPv4Address):
                            res.add_interval(CanonicalIntervalSet.Interval(self.min_ipv4_index + int(cidr.start),
                                                                           self.min_ipv4_index + int(cidr.end)))
                        elif isinstance(cidr.start.address, ipaddress.IPv6Address):
                            res.add_interval(CanonicalIntervalSet.Interval(self.min_ipv6_index + int(cidr.start),
                                                                           self.min_ipv6_index + int(cidr.end)))
                        else:
                            assert False
                else:
                    index = self.peer_to_index.get(peer)
                    assert index is not None
                    res.add_interval(CanonicalIntervalSet.Interval(self.min_pod_index + index,
                                                                   self.min_pod_index + index))
            return res

        def get_peer_set_by_indices(self, peer_interval_set):
            """
            Translates the given interval set of indices to a peer set.
            :param peer_interval_set: the interval set of indices
            :return: the PeerSet of peers referenced by the indices in the interval set
            """
            peer_set = PeerSet()
            for interval in peer_interval_set:
                if interval.end <= self.max_ipv4_index:
                    # this is IPv4Address
                    start = ipaddress.IPv4Address(interval.start - self.min_ipv4_index)
                    end = ipaddress.IPv4Address(interval.end - self.min_ipv4_index)
                    ipb = IpBlock(
                        interval=CanonicalIntervalSet.Interval(IPNetworkAddress(start), IPNetworkAddress(end)))
                    peer_set.add(ipb)
                elif interval.end <= self.max_ipv6_index:
                    # this is IPv6Address
                    start = ipaddress.IPv6Address(interval.start - self.min_ipv6_index)
                    end = ipaddress.IPv6Address(interval.end - self.min_ipv6_index)
                    ipb = IpBlock(
                        interval=CanonicalIntervalSet.Interval(IPNetworkAddress(start), IPNetworkAddress(end)))
                    peer_set.add(ipb)
                else:
                    # this is Pod
                    assert interval.end <= self.max_pod_index
                    curr_pods_max_ind = len(self.ordered_peer_list) - 1
                    for ind in range(min(interval.start - self.min_pod_index, curr_pods_max_ind),
                                     min(interval.end - self.min_pod_index, curr_pods_max_ind) + 1):
                        peer_set.add(self.ordered_peer_list[ind])
            return peer_set

    instance = None

    def __init__(self):
        if not BasePeerSet.instance:
            BasePeerSet.instance = BasePeerSet.__BasePeerSet()

    @staticmethod
    def reset():
        BasePeerSet.instance = None

    def __getattr__(self, name):
        return getattr(self.instance, name)

    @staticmethod
    def get_all_peers_and_ip_blocks_interval():
        res = CanonicalIntervalSet()
        res.add_interval(CanonicalIntervalSet.Interval(BasePeerSet.__BasePeerSet.min_ipv4_index,
                                                       BasePeerSet.__BasePeerSet.max_ipv4_index))
        res.add_interval(CanonicalIntervalSet.Interval(BasePeerSet.__BasePeerSet.min_ipv6_index,
                                                       BasePeerSet.__BasePeerSet.max_ipv6_index))
        res.add_interval(CanonicalIntervalSet.Interval(BasePeerSet.__BasePeerSet.min_pod_index,
                                                       BasePeerSet.__BasePeerSet.max_pod_index))
        return res
