#
# Copyright 2020- IBM Inc. All rights reserved
# SPDX-License-Identifier: Apache2.0
#
from dataclasses import dataclass
from enum import Enum

from nca.CoreDS.ConnectionSet import ConnectionSet
from .NetworkPolicy import PolicyConnections, NetworkPolicy
from .IstioTrafficResources import istio_root_namespace
from ..CoreDS.Peer import DNSEntry, IpBlock
from ..CoreDS.PortSet import PortSet
from ..CoreDS.TcpLikeProperties import TcpLikeProperties


@dataclass
class IstioSidecarRule:
    """
    A class representing a single egress rule (IstioEgressListener) in an Istio Sidecar object
    """

    def __init__(self, peer_set=None, peers_for_ns_compare=None, allow_all=False):
        """
        Init the Egress rule of an Istio Sidecar
        :param Peer.PeerSet peer_set: The set of mesh internal peers this rule allows connection to
        :param Peer.PeerSet peers_for_ns_compare: The set of peers captured by a global sidecar with hosts
        having namespace equal to '.'
        :param bool allow_all: indicates if this sidecar rule allows all egress from sidecar's peers
        """
        self.egress_peer_set = peer_set
        self.special_egress_peer_set = peers_for_ns_compare  # set of peers captured by a global sidecar with hosts of
        # './<any>' form - then peers in this set will be in allowed connections
        # only if are in the same namespace of the source peer captured by the sidecar
        self.allow_all = allow_all  # will be true if sidecar's outboundMode is allow_any and hosts in this rule
        # are of the form */*  - in this case the above peer sets will be empty


class IstioSidecar(NetworkPolicy):
    """
    This class implements istio-specific logic for Sidecar
    """

    class OutboundMode(Enum):
        ALLOW_ANY = 0
        REGISTRY_ONLY = 1

    def __init__(self, name, namespace):
        super().__init__(name, namespace)
        self.default_sidecar = False  # a flag that indicates if the sidecar is selector-less (default) or not
        self.outbound_mode = self.OutboundMode.ALLOW_ANY  # default mode is allow_any

    def __eq__(self, other):
        return super().__eq__(other) and self.default_sidecar == other.default_sidecar

    def allowed_connections(self, from_peer, to_peer, is_ingress):
        """
        Evaluate the set of connections this policy allows/denies/passes between two peers
        :param Peer.Peer from_peer: The source peer
        :param Peer.Peer to_peer:  The target peer
        :param bool is_ingress: whether we evaluate ingress rules only or egress rules only
        :return: A PolicyConnections object containing sets of allowed/denied/pass connections
        :rtype: PolicyConnections
        """
        # currently not handling ingress
        if is_ingress:
            return PolicyConnections(False, ConnectionSet(True))

        captured = from_peer in self.selected_peers
        # if not captured, or captured but the sidecar is not in from_peer top priority, don't consider connections
        if not captured or (captured and not self._is_sidecar_prior(from_peer)):
            return PolicyConnections(False)

        # connections to IP-block is enabled only if the outbound mode is allow-any (disabled for registry only)
        if isinstance(to_peer, IpBlock) and self.outbound_mode == IstioSidecar.OutboundMode.ALLOW_ANY:
            return PolicyConnections(True, allowed_conns=ConnectionSet(True))

        # since sidecar rules include only peer sets for now, if a to_peer appears in any rule then connections allowed
        for rule in self.egress_rules:
            if rule.allow_all or to_peer in rule.egress_peer_set or \
                    (to_peer in rule.special_egress_peer_set and self.check_peers_in_same_namespace(from_peer, to_peer)):
                if isinstance(to_peer, DNSEntry):
                    return \
                        PolicyConnections(True, allowed_conns=self.update_ports_of_dns_entry_conns(to_peer,
                                                                                                   str(from_peer.namespace)))
                else:
                    return PolicyConnections(True, allowed_conns=ConnectionSet(True))

        # egress from from_peer to to_peer is not allowed : if to_peer not been captured in the rules' egress_peer_set,
        # or if the sidecar is global and to_peer is not in same namespace of from_peer while rule host's ns is '.'
        return PolicyConnections(True, allowed_conns=ConnectionSet())

    def has_empty_rules(self, config_name=''):
        """
        Checks whether the sidecar contains empty rules (rules that do not select any peers)
        :param str config_name: (optional) the name of the NetworkConfig object
        :return: A list of strings describing the emptiness + two sets of indexes of empty ingress/egress rules
        :rtype: list[str], set, set
        """
        emptiness_explanation = []
        empty_egress_rules = set()
        full_name = self.full_name(config_name)
        for rule_index, egress_rule in enumerate(self.egress_rules, start=1):
            if not egress_rule.allow_all and not egress_rule.egress_peer_set:
                emptiness = f'Rule no. {rule_index} in Sidecar {full_name} does not select any pods/services'
                emptiness_explanation.append(emptiness)
                empty_egress_rules.add(rule_index)

        return emptiness_explanation, set(), empty_egress_rules

    def clone_without_rule(self, rule_to_exclude, _ingress_rule):
        """
        Makes a copy of 'self' without a given policy rule
        :param IstioSidecarRule rule_to_exclude: The one rule not to include in the copy
        :param bool _ingress_rule: Whether the rule is an ingress or egress rule
        :return: A copy of 'self' without the provided rule
        :rtype: IstioSidecar
        """
        assert not _ingress_rule
        res = IstioSidecar(self.name, self.namespace)
        res.selected_peers = self.selected_peers
        res.affects_egress = self.affects_egress
        res.affects_ingress = self.affects_ingress
        res.default_sidecar = self.default_sidecar

        for rule in self.egress_rules:
            if rule != rule_to_exclude:
                res.add_egress_rule(rule)
        return res

    def _is_sidecar_prior(self, from_peer):
        """
        Check if the current sidecar is in the top priority of the captured from_peer
        to be considered in its connections or not
        :param Peer.Peer from_peer: the source peer captured by the current sidecar
        :return: True if the sidecar is in the peer's top priority to consider it in its connections, otherwise False
        computing the return value is according to following:
        1- for from_peer, preference will be given to the first injected sidecar with
        a workloadSelector that selected the peer.
        2- if the specific sidecar from (1) does not exist, preference will be given to the
        first injected selector-less sidecar in the peer's namespace
        3- if sidecars from (1) and (2) don't exist, the preference will be given to the first default
        sidecar of the istio root namespace
        :rtype: bool
        """
        if not self.default_sidecar:  # specific sidecar
            if from_peer.prior_sidecar and self == from_peer.prior_sidecar:
                return True
        else:  # selector-less sidecar
            if from_peer.prior_sidecar:
                return False
            if from_peer.namespace.prior_default_sidecar:
                if self == from_peer.namespace.prior_default_sidecar:
                    return True
            else:
                if str(self.namespace) == istio_root_namespace and \
                        self == self.namespace.prior_default_sidecar:
                    return True
        return False

    @staticmethod
    def check_peers_in_same_namespace(from_peer, to_peer):
        """
        checks if from_peer and to_peer are in the same namespace or if to_peer is exported to from_peer
        (in case to_peer is DNSEntry)
        :param Peer from_peer: the src peer
        :param Peer to_peer: the dst peer
        :rtype: bool
        """
        # a captured from_peer is always internal (having a specified namespace)
        from_ns = from_peer.namespace
        if to_peer.namespace:
            return from_ns == to_peer.namespace
        # else to_peer is a DNSEntry: it is exported to from_peer if it is exported to its namespace or to all namespaces
        assert isinstance(to_peer, DNSEntry)
        return '*' in to_peer.namespaces_ports.keys() or from_ns in to_peer.namespaces_ports.keys()

    @staticmethod
    def update_ports_of_dns_entry_conns(to_peer, from_ns):
        """
        computes the allowed connections to a DNSEntry peer considering its ports and the src namespace
        :param DNSEntry to_peer: the dst DNSEntry peer
        :param str from_ns : the namespace name of the src peer
        :rtype: ConnectionSet
        """
        if not from_ns:
            return ConnectionSet()  # if we get here means that the src peer is not internal (ClusterEP),
            # the connections will not be considered

        dst_ports = PortSet()
        res = ConnectionSet()
        # the ports that this src can connect with to to_peer, are ports that are exported to all namespaces and the
        # ports that are exported specifically to the src namespace
        if '*' in to_peer.namespaces_ports.keys():
            for port_num in to_peer.namespaces_ports['*']:
                dst_ports.add_port(port_num)
        if from_ns in to_peer.namespaces_ports.keys():
            for port_num in to_peer.namespaces_ports[from_ns]:
                dst_ports.add_port(port_num)

        # all allowed protocols of service-entry (source of dns-entries) are TCPLike
        # the allowed protocols are: 'HTTP', 'HTTPS', 'GRPC', 'HTTP2', 'MONGO', 'TCP', 'TLS'
        res.add_connections(protocol='TCP', properties=TcpLikeProperties(PortSet(True), dst_ports))
        return res
