#
# Copyright 2020- IBM Inc. All rights reserved
# SPDX-License-Identifier: Apache2.0
#
from NetworkPolicy import PolicyConnections, NetworkPolicy
from ConnectionSet import ConnectionSet


class IstioSidecarRule:
    """
    A class representing a single egress rule (IstioEgressListener) in an Istio Sidecar object
    """

    def __init__(self, peer_set):
        """
        Init the Egress rule of an Istio Sidecar
        :param Peer.PeerSet peer_set: The set of mesh internal peers this rule allows connection to
        """
        self.peer_set = peer_set


class IstioSidecar(NetworkPolicy):
    """
    This class implements istio-specific logic for Sidecar
    """
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
        if not captured:
            return PolicyConnections(False)

        conns = ConnectionSet(True)
        # since sidecar rules include only peer sets for now, if a to_peer appears in any rule then connections allowed
        for rule in self.egress_rules:
            if to_peer in rule.peer_set:
                return PolicyConnections(True, allowed_conns=conns)
        # if to_peer not been captured in the rules no egress from from_peer to to_peer is allowed
        return PolicyConnections(True, denied_conns=conns)

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
            if not egress_rule.peer_set:
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

        for rule in self.egress_rules:
            if rule != rule_to_exclude:
                res.add_egress_rule(rule)
        return res