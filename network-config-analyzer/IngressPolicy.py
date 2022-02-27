#
# Copyright 2020- IBM Inc. All rights reserved
# SPDX-License-Identifier: Apache2.0
#

from NetworkPolicy import PolicyConnections, NetworkPolicy
from ConnectionSet import ConnectionSet


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
        super().__init__(name, namespace)
        self.affects_ingress = False
        self.affects_egress = True

    def __eq__(self, other):
        return super().__eq__(other)

    def __lt__(self, other):  # required so we can evaluate the policies according to their order
        if isinstance(other, IngressPolicy):
            return self.full_name() < other.full_name()
        return NotImplemented

    def add_rules(self, rules):
        """
        Adding a given list of rules to the list of egress rules
        :param list rules: The list of rules to add
        :return: None
        """
        self.egress_rules.extend(rules)

    def allowed_connections(self, from_peer, to_peer):
        """
        Evaluate the set of connections this ingress resource allows between two peers
        :param Peer.Peer from_peer: The source peer
        :param Peer.Peer to_peer:  The target peer
        :return: A PolicyConnections object containing sets of allowed connections
        :rtype: PolicyConnections
        """

        captured = from_peer in self.selected_peers
        if not captured:
            return PolicyConnections(False)

        allowed_conns = ConnectionSet()
        for rule in self.egress_rules:
            if to_peer in rule.peer_set:
                allowed_conns |= rule.connections

        return PolicyConnections(True, allowed_conns)

    def has_empty_rules(self):
        """
        Checks whether the policy contains empty rules (rules that do not select any peers)
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

    def clone_without_rule(self, rule_to_exclude):
        """
        Makes a copy of 'self' without a given policy rule
        :param IngressPolicyRule rule_to_exclude: The one rule not to include in the copy
        :return: A copy of 'self' without the provided rule
        :rtype: IngressPolicy
        """
        res = IngressPolicy(self.name, self.namespace)
        res.selected_peers = self.selected_peers
        res.affects_egress = self.affects_egress
        res.affects_ingress = self.affects_ingress
        for rule in self.egress_rules:
            if rule != rule_to_exclude:
                res.add_egress_rule(rule)
        return res
