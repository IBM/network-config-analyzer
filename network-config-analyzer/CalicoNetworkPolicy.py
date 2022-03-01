#
# Copyright 2020- IBM Inc. All rights reserved
# SPDX-License-Identifier: Apache2.0
#

from enum import Enum
from ConnectionSet import ConnectionSet
from NetworkPolicy import PolicyConnections, NetworkPolicy
import Peer


class CalicoPolicyRule:
    """
    A class representing a single ingress/egress rule in a Calico NetworkPolicy/Profile object
    """
    class ActionType(Enum):
        """
        Allowed actions for Calico's network policy rules
        """
        Deny = 0
        Allow = 1
        Log = 2
        Pass = 3

    def __init__(self, src_peers, dst_peers, connections, action):
        """
        :param Peer.PeerSet src_peers: The source peers this rule refers to
        :param Peer.PeerSet dst_peers:  The destination peers this rule refers to
        :param ConnectionSet connections: The connections allowed/denied/passed by this rule
        :param ActionType action: The rule action
        """
        self.src_peers = src_peers
        self.dst_peers = dst_peers
        self.connections = connections
        self.action = action

    def __eq__(self, other):
        return self.src_peers == other.src_peers and self.dst_peers == other.dst_peers and \
            self.connections == other.connections and self.action == other.action

    def contained_in(self, other):
        """
        :param CalicoPolicyRule other: Another rule
        :return: Whether all connections specified by 'self' are also specified by 'other' (regardless of action)
        :rtype: bool
        """
        return self.src_peers.issubset(other.src_peers) and self.dst_peers.issubset(other.dst_peers) and \
            self.connections.contained_in(other.connections)

    @staticmethod
    def action_str_to_action_type(action_str):
        """
        Convert an action given as a string to the matching enum value
        :param str action_str: A string with the action
        :return: The matching enum value
        :rtype: CalicoPolicyRule.ActionType
        """
        if action_str == 'Deny':
            return CalicoPolicyRule.ActionType.Deny
        if action_str == 'Allow':
            return CalicoPolicyRule.ActionType.Allow
        if action_str == 'Log':
            return CalicoPolicyRule.ActionType.Log
        if action_str == 'Pass':
            return CalicoPolicyRule.ActionType.Pass
        return None


class CalicoNetworkPolicy(NetworkPolicy):
    """
    A class to hold processed information about a single Calico network policy / profile
    """
    def __init__(self, name, namespace):
        super().__init__(name, namespace)
        self.order = None  # None means infinity here

    def __eq__(self, other):
        return super().__eq__(other) and self.order == other.order

    def __lt__(self, other):  # required so we can evaluate the policies according to their order
        if isinstance(other, CalicoNetworkPolicy):
            if self.order is None:
                return False
            if other.order is None:
                return True
            return self.order < other.order
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
        captured = is_ingress and self.affects_ingress and to_peer in self.selected_peers or \
            not is_ingress and self.affects_egress and from_peer in self.selected_peers
        if not captured:
            return PolicyConnections(False)

        allowed_conns = ConnectionSet()
        denied_conns = ConnectionSet()
        pass_conns = ConnectionSet()
        rules = self.ingress_rules if is_ingress else self.egress_rules
        for rule in rules:
            if from_peer in rule.src_peers and to_peer in rule.dst_peers:
                rule_conns = rule.connections.copy()  # we need a copy because convert_named_ports is destructive
                rule_conns.convert_named_ports(to_peer.get_named_ports())

                if rule.action == CalicoPolicyRule.ActionType.Allow:
                    rule_conns -= denied_conns
                    rule_conns -= pass_conns
                    allowed_conns |= rule_conns
                elif rule.action == CalicoPolicyRule.ActionType.Deny:
                    rule_conns -= allowed_conns
                    rule_conns -= pass_conns
                    denied_conns |= rule_conns
                elif rule.action == CalicoPolicyRule.ActionType.Pass:
                    rule_conns -= allowed_conns
                    rule_conns -= denied_conns
                    pass_conns |= rule_conns
                else:
                    pass  # Nothing to do for Log action - does not affect connectivity

        return PolicyConnections(True, allowed_conns, denied_conns, pass_conns)

    def clone_without_rule(self, rule_to_exclude, ingress_rule):
        """
        Makes a copy of 'self' without a given policy rule
        :param CalicoPolicyRule rule_to_exclude: The one rule not to include in the copy
        :param bool ingress_rule: Whether the rule is an ingress or egress rule
        :return: A copy of 'self' without the provided rule
        :rtype: CalicoNetworkPolicy
        """
        res = CalicoNetworkPolicy(self.name, self.namespace)
        res.order = self.order
        res.selected_peers = self.selected_peers
        res.affects_egress = self.affects_egress
        res.affects_ingress = self.affects_ingress
        for rule in self.egress_rules:
            if ingress_rule or rule != rule_to_exclude:
                res.add_egress_rule(rule)
        for rule in self.ingress_rules:
            if not ingress_rule or rule != rule_to_exclude:
                res.add_ingress_rule(rule)
        return res

    def referenced_ip_blocks(self):
        """
        :return: A set of all ipblocks referenced in one of the policy rules (one Peer object per one ip range)
        :rtype: Peer.PeerSet
        """
        res = Peer.PeerSet()
        for rule in self.egress_rules:
            for peer in rule.dst_peers:
                if isinstance(peer, Peer.IpBlock):
                    res |= peer.split()
        for rule in self.ingress_rules:
            for peer in rule.src_peers:
                if isinstance(peer, Peer.IpBlock):
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
        empty_egress_rules = set()
        full_name = self.full_name(config_name)
        for rule_index, ingress_rule in enumerate(self.ingress_rules, start=1):
            if not ingress_rule.src_peers:
                emptiness = f'Ingress rule no. {rule_index} in NetworkPolicy {full_name} selects no source pods'
                emptiness_explanation.append(emptiness)
                empty_ingress_rules.add(rule_index)
            if not ingress_rule.dst_peers:
                emptiness = f'Ingress rule no. {rule_index} in NetworkPolicy {full_name} selects no destination pods'
                emptiness_explanation.append(emptiness)
                empty_ingress_rules.add(rule_index)

        for rule_index, egress_rule in enumerate(self.egress_rules, start=1):
            if not egress_rule.src_peers:
                emptiness = f'Egress rule no. {rule_index} in NetworkPolicy {full_name} selects no source pods'
                emptiness_explanation.append(emptiness)
                empty_egress_rules.add(rule_index)
            if not egress_rule.dst_peers:
                emptiness = f'Egress rule no. {rule_index} in NetworkPolicy {full_name} selects no destination pods'
                emptiness_explanation.append(emptiness)
                empty_egress_rules.add(rule_index)

        return emptiness_explanation, empty_ingress_rules, empty_egress_rules

    @staticmethod
    def has_rules_with_action(rule_set, action):
        """
        :param list rule_set: A set of rules (either ingress rules or egress rules)
        :param CalicoPolicyRule.ActionType action: Rule action (allow/deny)
        :return: Whether the policy has (non-empty) rules with the specified action
        :rtype: bool
        """
        for rule in rule_set:
            if rule.src_peers and rule.dst_peers and rule.action == action:
                return True
        return False

    def has_deny_rules(self):
        """
        :return: Whether the policy has (non-empty) rules that deny connections.
        :rtype: bool
        """
        return self.has_rules_with_action(self.ingress_rules, CalicoPolicyRule.ActionType.Deny) or \
            self.has_rules_with_action(self.egress_rules, CalicoPolicyRule.ActionType.Deny)

    def has_allow_rules(self):
        """
        :return: Whether the policy has (non-empty) rules that allow connections.
        :rtype: bool
        """
        return self.has_rules_with_action(self.ingress_rules, CalicoPolicyRule.ActionType.Allow) or \
            self.has_rules_with_action(self.egress_rules, CalicoPolicyRule.ActionType.Allow)

    @staticmethod
    def _rules_contain_conflicting_actions(ruleset1, ruleset2):
        """
        :param list[CalicoPolicyRule] ruleset1: First set of rules
        :param list[CalicoPolicyRule] ruleset2: Second set of rules
        :return: Whether one rule set has a deny rule while the other has an allow rule
        :rtype: bool
        """
        if CalicoNetworkPolicy.has_rules_with_action(ruleset1, CalicoPolicyRule.ActionType.Allow) and \
                CalicoNetworkPolicy.has_rules_with_action(ruleset2, CalicoPolicyRule.ActionType.Deny):
            return True
        return CalicoNetworkPolicy.has_rules_with_action(ruleset1, CalicoPolicyRule.ActionType.Deny) and \
            CalicoNetworkPolicy.has_rules_with_action(ruleset2, CalicoPolicyRule.ActionType.Allow)

    def is_conflicting(self, other):
        """
        Check whether two policies conflict: they have the same order, capture common endpoints but have rules with
        contradicting actions (we are not 100% sure this is a conflict, but this is close enough).
        :param CalicoNetworkPolicy other: another policy to check if conflicts with 'self'
        :return: True if the two policies conflict, False otherwise
        :rtype: bool
        """
        if self.order != other.order:
            return False
        if not ((self.affects_ingress and other.affects_ingress) or (self.affects_egress and other.affects_egress)):
            return False
        if not self.selected_peers & other.selected_peers:
            return False
        if self.affects_ingress and other.affects_ingress and \
                self._rules_contain_conflicting_actions(self.ingress_rules, other.ingress_rules):
            return True
        if self.affects_egress and other.affects_egress and \
                self._rules_contain_conflicting_actions(self.egress_rules, other.egress_rules):
            return True

        return False

    def rule_containing(self, other_policy, other_rule, other_rule_index, self_rules):
        """
        Check whether a rule in another policy is contained in one of the rules is the 'self' policy
        :param CalicoNetworkPolicy other_policy: The other policy in which the suspect rule resides (might equal 'self')
        :param CalicoPolicyRule other_rule: The rule to check if contained in one of the policy's rules
        :param int other_rule_index: The index of other_rule in its policy
        :param list[CalicoPolicyRule] self_rules: The set of rules in the current policy to check containment against
        :return: The index of a containing rule if exists (else None) + whether the actions of the two rules contradict
        :rtype: int, bool
        """
        for rule_index, rule in enumerate(self_rules, start=1):
            if rule_index == other_rule_index and self == other_policy:
                return None, None
            if other_rule.contained_in(rule):
                return rule_index, rule.action != other_rule.action
        return None, None
