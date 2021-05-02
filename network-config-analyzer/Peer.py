#
# Copyright 2020- IBM Inc. All rights reserved
# SPDX-License-Identifier: Apache2.0
#

from ipaddress import ip_network
from sys import stderr
from string import hexdigits
from CanonicalIntervalSet import CanonicalIntervalSet
from K8sNamespace import K8sNamespace


class Peer:
    """
    This is the base class for all network endpoints, both inside the relevant cluster and outside of it
    """
    @staticmethod
    def get_named_ports():
        return {}


class ClusterEP(Peer):
    """
    This is the base class for endpoints inside the given cluster
    """
    def __init__(self, name):
        self.name = name
        self.labels = {}  # Storing the endpoint's labels in a dict as key-value pairs
        self.extra_labels = {}  # for labels coming from 'labelsToApply' field in Profiles (Calico only)
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
    def __init__(self, name, namespace, owner_name='', owner_kind=None):
        """
        :param str name: The name of the Pod
        :param K8sNamespace namespace: The namespace object for the Pod's namespace
        :param str owner_name: The name of the Pod's owner
        :param str owner_kind: The kind of the Pod's owner
        """
        super().__init__(name)
        self.namespace = namespace

        if not owner_name:  # no owner
            self.workload_name = f'{namespace.name}/{name}(Pod)'
        elif owner_kind == 'ReplicaSet':
            # if owner name ends with hex-suffix, assume the pod is generated indirectly
            # by Deployment or StatefulSet; and remove the hex-suffix from workload name
            suffix = owner_name[owner_name.rfind('-')+1:]
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


class IpBlock(Peer, CanonicalIntervalSet):
    """
    This class represents a set of ip ranges
    """
    def __init__(self, cidr=None, exceptions=None, interval=None):
        """
        Constructs an IpBlock object. Use either cidr+exceptions or interval
        :param str cidr: a cidr-formatted string representing a range of ips to include in the range
        :param list[str] exceptions: a list of cidr-formatted strings to exclude from the ip range
        :param CanonicalIntervalSet.Interval interval: A range of ip addresses as an interval
        """
        super().__init__()
        if interval:
            self.interval_set.append(interval)
        elif cidr:
            ipn = ip_network(cidr, False)  # strict is False as k8s API shows an example CIDR where host bits are set
            self.interval_set.append(CanonicalIntervalSet.Interval(ipn.network_address, ipn.broadcast_address))
            for exception in exceptions or []:
                exception_n = ip_network(exception, False)
                # the following line has no effect - only used to raise an exception when exception_n is not within cidr
                ipn.address_exclude(exception_n)  # TODO: use exception_n.subnet_of(self.cidr) (Python 3.7 only)
                hole = CanonicalIntervalSet.Interval(exception_n.network_address, exception_n.broadcast_address)
                self.add_hole(hole)

    @staticmethod
    def get_all_ips_block():
        """
        :return: The full range of ipv4 addresses
        :rtype: IpBlock
        """
        return IpBlock('0.0.0.0/0')

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


class PeerSet(set):
    """
    A container to hold a set of Peer objects
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

    def __and__(self, other):
        return PeerSet(super().__and__(other))

    def __or__(self, other):
        return PeerSet(super().__or__(other))

    def __sub__(self, other):
        return PeerSet(super().__sub__(other))

    def rep(self):
        """
        Returns a representing peer from the set of peers
        :return str: The name of the representing peer. An empty string if set is empty
        """
        if not bool(self):
            return ''
        for peer in self:
            return str(peer)
