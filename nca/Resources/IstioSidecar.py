#
# Copyright 2020- IBM Inc. All rights reserved
# SPDX-License-Identifier: Apache2.0
#
from dataclasses import dataclass
from enum import Enum

from nca.CoreDS.ConnectionSet import ConnectionSet
from nca.CoreDS.Peer import IpBlock, PeerSet, DNSEntry
from nca.CoreDS.ProtocolSet import ProtocolSet
from nca.CoreDS.ConnectivityProperties import ConnectivityProperties, ConnectivityCube
from .NetworkPolicy import PolicyConnections, OptimizedPolicyConnections, NetworkPolicy
from .IstioTrafficResources import istio_root_namespace


@dataclass
class IstioSidecarRule:
    """
    A class representing a single egress rule (IstioEgressListener) in an Istio Sidecar object
    """

    def __init__(self, peer_set=None, peers_for_ns_compare=None):
        """
        Init the Egress rule of an Istio Sidecar
        :param Peer.PeerSet peer_set: The set of mesh internal peers this rule allows connection to
        :param Peer.PeerSet peers_for_ns_compare: The set of peers captured by a global sidecar with hosts
        having namespace equal to '.'
        """
        self.egress_peer_set = peer_set
        self.special_egress_peer_set = peers_for_ns_compare  # set of peers captured by a global sidecar with hosts of
        # './<any>' form - then peers in this set will be in allowed connections only if are in the same namespace of the
        # source peer captured by the sidecar


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
        # if not captured or (captured and not self._is_sidecar_prior(from_peer)):
        if not captured:
            return PolicyConnections(False)

        # connections to IP-block is enabled only if the outbound mode is allow-any (disabled for registry only)
        if isinstance(to_peer, IpBlock) and self.outbound_mode == IstioSidecar.OutboundMode.ALLOW_ANY:
            return PolicyConnections(True, allowed_conns=ConnectionSet(True))

        # since sidecar rules include only peer sets for now, if a to_peer appears in any rule then connections allowed
        for rule in self.egress_rules:
            if isinstance(to_peer, DNSEntry) and \
                    (to_peer in rule.egress_peer_set or to_peer in rule.special_egress_peer_set):
                return PolicyConnections(True, allowed_conns=ConnectionSet.get_all_tcp_connections())
            if to_peer in rule.egress_peer_set or \
                    (to_peer in rule.special_egress_peer_set and from_peer.namespace == to_peer.namespace):
                return PolicyConnections(True, allowed_conns=ConnectionSet(True))

        # egress from from_peer to to_peer is not allowed : if to_peer not been captured in the rules' egress_peer_set,
        # or if the sidecar is global and to_peer is not in same namespace of from_peer while rule host's ns is '.'
        return PolicyConnections(True, allowed_conns=ConnectionSet())

    def allowed_connections_optimized(self, is_ingress):
        res_conns = OptimizedPolicyConnections()
        if is_ingress:
            res_conns.allowed_conns = self.optimized_allow_ingress_props.copy()
            res_conns.denied_conns = self.optimized_deny_ingress_props.copy()
            res_conns.captured = PeerSet()
        else:
            res_conns.allowed_conns = self.optimized_allow_egress_props.copy()
            res_conns.denied_conns = self.optimized_deny_egress_props.copy()
            res_conns.captured = self.selected_peers if self.affects_egress else PeerSet()
        return res_conns

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
            if not egress_rule.egress_peer_set:
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
        res.policy_kind = self.policy_kind

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
    def combine_peer_sets_by_ns(from_peer_set, to_peer_set, peer_container):
        res = []
        from_peer_set_copy = from_peer_set.copy()
        while from_peer_set_copy:
            peer = list(from_peer_set_copy)[0]
            if isinstance(peer, IpBlock):
                from_peer_set_copy.remove(peer)
                continue
            peers_in_curr_ns = peer_container.get_namespace_pods(peer.namespace)
            res.append((from_peer_set_copy & peers_in_curr_ns, to_peer_set & peers_in_curr_ns))
            from_peer_set_copy -= peers_in_curr_ns
        return res

    def create_opt_egress_props(self, peer_container):
        for rule in self.egress_rules:
            # connections to IP-block is enabled only if the outbound mode is allow-any (disabled for registry only)
            if self.outbound_mode == IstioSidecar.OutboundMode.ALLOW_ANY:
                ip_blocks = IpBlock.get_all_ips_block_peer_set()
                conn_cube = ConnectivityCube.make_from_dict({"src_peers": self.selected_peers, "dst_peers": ip_blocks})
                self.optimized_allow_egress_props |= ConnectivityProperties.make_conn_props(conn_cube)

            dns_entries = peer_container.get_all_dns_entries()
            dst_dns_entries = dns_entries & (rule.egress_peer_set | rule.special_egress_peer_set)
            if self.selected_peers and dst_dns_entries:
                protocols = ProtocolSet.get_protocol_set_with_single_protocol('TCP')
                conn_cube = ConnectivityCube.make_from_dict({"src_peers": self.selected_peers,
                                                             "dst_peers": dst_dns_entries, "protocols": protocols})
                self.optimized_allow_egress_props |= ConnectivityProperties.make_conn_props(conn_cube)

            if self.selected_peers and rule.egress_peer_set:
                conn_cube = ConnectivityCube.make_from_dict({"src_peers": self.selected_peers,
                                                             "dst_peers": rule.egress_peer_set})
                self.optimized_allow_egress_props |= ConnectivityProperties.make_conn_props(conn_cube)
            peers_sets_by_ns = self.combine_peer_sets_by_ns(self.selected_peers, rule.special_egress_peer_set,
                                                            peer_container)
            for (from_peers, to_peers) in peers_sets_by_ns:
                if from_peers and to_peers:
                    conn_cube = ConnectivityCube.make_from_dict({"src_peers": from_peers, "dst_peers": to_peers})
                    self.optimized_allow_egress_props |= ConnectivityProperties.make_conn_props(conn_cube)
