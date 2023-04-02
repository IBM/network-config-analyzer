#
# Copyright 2020- IBM Inc. All rights reserved
# SPDX-License-Identifier: Apache2.0
#

from nca.CoreDS.ConnectionSet import ConnectionSet
from nca.CoreDS.ConnectivityProperties import ConnectivityProperties
from nca.CoreDS.Peer import PeerSet
from .NetworkPolicy import PolicyConnections, OptimizedPolicyConnections, NetworkPolicy


class IngressPolicyRule:
    """
    A class representing a single ingress rule in an Ingress object
    """
    def __init__(self, peer_set, connections):
        """
        :param Peer.PeerSet peer_set: The set of peers this rule allows connection to
        :param ConnectionSet connections: The set of connections allowed by this rule
        """
        self.peer_set = peer_set
        self.connections = connections

    def __eq__(self, other):
        return self.peer_set == other.peer_set and self.connections == other.connections

    def contained_in(self, other):
        """
        :param IngressPolicyRule other: Another rule
        :return: whether the self rule is contained in the other rule (self doesn't allow anything that other does not)
        :type: bool
        """
        return self.peer_set.issubset(other.peer_set) and self.connections.contained_in(other.connections)


class IngressPolicy(NetworkPolicy):
    """
    This class implements ingress controller logic for incoming http(s) requests
    The logic is kept similarly to NetworkPolicy, where the selected_peers are the ingress controller peers,
    and the rules are egress_rules.
    """

    def __init__(self, name, namespace):
        """
        :param str name: Ingress name
        :param K8sNamespace namespace: the namespace containing this ingress
        """
        super().__init__(name, namespace)
        self.affects_ingress = False
        self.affects_egress = True

    def __eq__(self, other):
        return super().__eq__(other)

    def add_rules(self, rules):
        """
        Adding a given list of rules to the list of egress rules
        :param list rules: The list of rules to add
        :return: None
        """
        self.egress_rules.extend(rules)

    def allowed_connections(self, from_peer, to_peer, is_ingress):
        """
        Evaluate the set of connections this ingress resource allows between two peers
        :param Peer.Peer from_peer: The source peer
        :param Peer.Peer to_peer:  The target peer
        :param bool is_ingress: For compatibility with other policies.
         Will return the set of allowed connections only for is_ingress being False.
        :return: A PolicyConnections object containing sets of allowed connections
        :rtype: PolicyConnections
        """

        captured = from_peer in self.selected_peers
        if not captured:
            return PolicyConnections(False)
        if is_ingress:
            return PolicyConnections(False)

        allowed_conns = ConnectionSet()
        for rule in self.egress_rules:
            if to_peer in rule.peer_set:
                assert not rule.connections.has_named_ports()
                allowed_conns |= rule.connections

        return PolicyConnections(True, allowed_conns)

    def allowed_connections_optimized(self, is_ingress):
        """
        Evaluate the set of connections this ingress resource allows between any two peers
        :param bool is_ingress: For compatibility with other policies.
         Will return the set of allowed connections only for is_ingress being False.
        :return: A ConnectivityProperties object containing all allowed connections for any peers,
        ConnectivityProperties object containing all denied connections,
        and the peer set of captured peers by this policy.
        :rtype: tuple (ConnectivityProperties, ConnectivityProperties, PeerSet)
        """
        res_conns = OptimizedPolicyConnections()
        if is_ingress:
            res_conns.allowed_conns = ConnectivityProperties.make_empty_props()
            res_conns.captured = PeerSet()
        else:
            res_conns.allowed_conns = self.optimized_egress_props.copy()
            res_conns.captured = self.selected_peers if self.affects_egress else PeerSet()
        return res_conns

    def has_empty_rules(self, _config_name=''):
        """
        Checks whether the policy contains empty rules (rules that do not select any peers)
        :param str _config_name: is not used. Kept for compatibility with other policies.
        :return: A list of strings describing the emptiness + two sets of indexes of empty ingress/egress rules
        :rtype: list[str], set, set
        """
        emptiness_explanation = []
        empty_rules = set()
        full_name = self.full_name()
        for rule_index, egress_rule in enumerate(self.egress_rules, start=1):
            if not egress_rule.peer_set:
                emptiness = f'Rule no. {rule_index} in Ingress resource {full_name} does not select any pods'
                emptiness_explanation.append(emptiness)
                empty_rules.add(rule_index)

        return emptiness_explanation, set(), empty_rules

    def clone_without_rule(self, rule_to_exclude, ingress_rule):
        """
        Makes a copy of 'self' without a given policy rule
        :param IngressPolicyRule rule_to_exclude: The one rule not to include in the copy
        :param bool ingress_rule: Whether the rule is an ingress or egress rule
        (for compatibility with network policies)
        :return: A copy of 'self' without the provided rule
        :rtype: IngressPolicy
        """
        assert not ingress_rule
        res = IngressPolicy(self.name, self.namespace)
        res.selected_peers = self.selected_peers
        res.affects_egress = self.affects_egress
        res.affects_ingress = self.affects_ingress
        res.policy_kind = self.policy_kind
        for rule in self.egress_rules:
            if rule != rule_to_exclude:
                res.add_egress_rule(rule)
        return res

    def has_allow_rules(self):
        """
        :return: Whether the policy has rules that allow connections.
        :rtype: bool
        """
        for rule in self.egress_rules:
            if rule.peer_set:
                return True
        return False
