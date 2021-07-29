#
# Copyright 2020- IBM Inc. All rights reserved
# SPDX-License-Identifier: Apache2.0
#

from enum import Enum
from NetworkPolicy import PolicyConnections, NetworkPolicy
from ConnectionSet import ConnectionSet
from Peer import PeerSet, IpBlock


class IstioPolicyRule:
    """
    A class representing a single ingress rule in a Istio AuthorizationPolicy object
    """

    def __init__(self, peer_set, connections):
        """
        :param Peer.PeerSet peer_set: The set of peers this rule allows connection from
        :param ConnectionSet connections: The set of connections allowed/denied by this rule (the action resides in the policy)
        """
        # TODO: extend connections (ConnectionSet) to represent HTTP/grpc requests attributes
        self.peer_set = peer_set
        self.connections = connections

    def __eq__(self, other):
        return self.peer_set == other.peer_set and self.connections == other.connections

    def contained_in(self, other):
        """
        :param IstioPolicyRule other: Another rule
        :return: whether the self rule is contained in the other rule (self doesn't allow anything that other does not)
        :type: bool
        """
        return self.peer_set.issubset(other.peer_set) and self.connections.contained_in(other.connections)


class IstioNetworkPolicy(NetworkPolicy):
    """
    This class implements istio-specific logic for AuthorizationPolicies
    A class to hold processed information about a single Istio network Authorization Policy
    """

    class ActionType(Enum):
        """
        Allowed actions for Istio's network authorization policy
        """
        # currently skipping CUSTOM and AUDIT
        # https://istio.io/latest/docs/reference/config/security/authorization-policy/#AuthorizationPolicy-Action
        Deny = 0
        Allow = 1

    def __init__(self, name, namespace):
        super().__init__(name, namespace)
        # default action type is Allow
        self.action = IstioNetworkPolicy.ActionType.Allow

    def __eq__(self, other):
        return super().__eq__(other) and self.action == other.action

    # 'deny' policies should be evaluated before 'allow' policies
    def __lt__(self, other):  # required so we can evaluate the policies according to their order
        if isinstance(other, IstioNetworkPolicy):
            return self.action == IstioNetworkPolicy.ActionType.Deny
        return NotImplemented

    def allowed_connections(self, from_peer, to_peer, is_ingress):
        """
        Evaluate the set of connections this policy allows/denies/passes between two peers
        :param Peer.Peer from_peer: The source peer
        :param Peer.Peer to_peer:  The target peer
        :param bool is_ingress: whether we evaluate ingress rules only or egress rules only
        :return: A PolicyConnections object containing sets of allowed/denied/pass connections
        :rtype: PolicyConnections
        """

        # TODO: currently not handling egress, istio authorization policies have no egress rules
        if not is_ingress:
            return PolicyConnections(False, ConnectionSet(True))

        captured = to_peer in self.selected_peers
        if not captured:
            return PolicyConnections(False)

        allowed_conns = ConnectionSet()
        denied_conns = ConnectionSet()

        collected_conns = allowed_conns if self.action == IstioNetworkPolicy.ActionType.Allow else denied_conns
        for rule in self.ingress_rules:
            if from_peer in rule.peer_set:
                collected_conns |= rule.connections

        return PolicyConnections(True, allowed_conns, denied_conns)

    def referenced_ip_blocks(self):
        """
        :return: A set of all ipblocks referenced in one of the policy rules (one Peer object per one ip range)
        :rtype: Peer.PeerSet
        """
        res = PeerSet()
        for rule in self.ingress_rules:
            for peer in rule.peer_set:
                if isinstance(peer, IpBlock):
                    res |= peer.split()
        return res

    def has_empty_rules(self, config_name=''):
        """
        Checks whether the policy contains empty rules (rules that do not select any peers)
        :param str config_name: (optional) the name of the NetworkConfig object
        :return: A list of strings describing the emptiness + two sets of indexes of empty ingress/egress rules
        :rtype: list[str], set, set
        """
        emptiness_explanation = []
        empty_ingress_rules = set()
        full_name = self.full_name(config_name)
        for rule_index, ingress_rule in enumerate(self.ingress_rules, start=1):
            if not ingress_rule.peer_set:
                emptiness = f'Rule no. {rule_index} in AuthorizationPolicy {full_name} does not select any pods'
                emptiness_explanation.append(emptiness)
                empty_ingress_rules.add(rule_index)

        return emptiness_explanation, empty_ingress_rules, set()

    def clone_without_rule(self, rule_to_exclude, _ingress_rule):
        """
        Makes a copy of 'self' without a given policy rule
        :param IstioPolicyRule rule_to_exclude: The one rule not to include in the copy
        :param bool _ingress_rule: Whether the rule is an ingress or egress rule
        :return: A copy of 'self' without the provided rule
        :rtype: IstioNetworkPolicy
        """
        # currently assuming this method isn't called with ingress_rule=False, since istio authorization policies
        # do not have egress rules
        res = IstioNetworkPolicy(self.name, self.namespace)
        res.selected_peers = self.selected_peers
        res.affects_egress = self.affects_egress
        res.affects_ingress = self.affects_ingress
        res.action = self.action
        for rule in self.ingress_rules:
            if rule != rule_to_exclude:
                res.add_ingress_rule(rule)
        return res

    def rule_containing(self, other_policy, other_rule, other_rule_index, self_rules):
        """
        Check whether a rule in another policy is contained in one of the rules is the 'self' policy
        :param IstioNetworkPolicy other_policy: The other policy in which the suspect rule resides (might equal 'self')
        :param IstioPolicyRule other_rule: The rule to check if contained in one of the policy's rules
        :param int other_rule_index: The index of other_rule in its policy
        :param list[IstioPolicyRule] self_rules: The set of rules in the current policy to check containment against
        :return: The index of a containing rule if exists (else None) + whether the actions of the two rules contradict
        :rtype: int, bool
        """
        if not other_policy.selected_peers.issubset(self.selected_peers):
            return None, None
        for rule_index, rule in enumerate(self_rules, start=1):
            if rule_index == other_rule_index and self == other_policy:
                continue
            if other_rule.contained_in(rule):
                return rule_index, self.action != other_policy.action
        return None, None

    def has_allow_rules(self):
        """
        :return: Whether the policy has rules that allow connections.
        :rtype: bool
        """
        if self.action == IstioNetworkPolicy.ActionType.Deny:
            return False
        for ingress_rule in self.ingress_rules:
            if ingress_rule.peer_set:
                return True
        return False

    def has_deny_rules(self):
        """
        :return: Whether the policy has deny rules
        :rtype: bool
        """
        if self.action == IstioNetworkPolicy.ActionType.Allow:
            return False
        for ingress_rule in self.ingress_rules:
            if ingress_rule.peer_set:
                return True
        return False
