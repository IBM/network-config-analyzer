#
# Copyright 2020- IBM Inc. All rights reserved
# SPDX-License-Identifier: Apache2.0
#

from enum import Enum
from nca.CoreDS.ConnectivityProperties import ConnectivityProperties
from nca.CoreDS.Peer import PeerSet
from .NetworkPolicy import PolicyConnections, NetworkPolicy


class IstioPolicyRule:
    """
    A class representing a single ingress rule in a Istio AuthorizationPolicy object
    """

    def __init__(self, peer_set, props):
        """
        :param Peer.PeerSet peer_set: The set of peers this rule allows connection from
        :param ConnectivityProperties props: the connections
        """
        self.peer_set = peer_set
        self.props = props
        # copy of props (used by src_peers/dst_peers domain-updating mechanism)
        self.props_copy = ConnectivityProperties()

    def __eq__(self, other):
        return self.props == other.props

    def contained_in(self, other):
        """
        :param IstioPolicyRule other: Another rule
        :return: whether the self rule is contained in the other rule (self doesn't allow anything that other does not)
        :type: bool
        """
        return self.props.contained_in(other.props)


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

    def __lt__(self, other):  # required so we can evaluate the policies according to their order
        if isinstance(other, IstioNetworkPolicy):
            # 'deny' policies should be evaluated before 'allow' policies
            return self.action == IstioNetworkPolicy.ActionType.Deny
        return False

    def sync_props(self):
        """
        If props of the policy are not synchronized (self.props_in_sync is False),
        compute props of the policy according to the optimized props of its rules
        """
        if self.props_in_sync:
            return
        self._init_props()
        for rule in self.ingress_rules:
            if self.action == IstioNetworkPolicy.ActionType.Allow:
                self._allow_ingress_props |= rule.props
            elif self.action == IstioNetworkPolicy.ActionType.Deny:
                self._deny_ingress_props |= rule.props

        self._optimized_allow_egress_props = ConnectivityProperties.get_all_conns_props_per_domain_peers()
        self.props_in_sync = True

    def allowed_connections(self, is_ingress):
        """
        Evaluate the set of connections this policy allows/denied/passed between any two peers
        :param bool is_ingress: whether we evaluate ingress rules only or egress rules only
        :return: A ConnectivityProperties object containing all allowed connections for relevant peers,
        ConnectivityProperties object containing all denied connections,
        and the peer set of captured peers by this policy.
        :rtype: tuple (ConnectivityProperties, ConnectivityProperties, PeerSet)
        """
        res_conns = PolicyConnections()
        if is_ingress:
            res_conns.allowed_conns = self.allow_ingress_props().copy()
            res_conns.denied_conns = self.deny_ingress_props().copy()
            res_conns.captured = self.selected_peers
        else:
            res_conns.allowed_conns = self.allow_egress_props().copy()
            res_conns.denied_conns = self.deny_egress_props().copy()
            res_conns.captured = PeerSet()
        return res_conns

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
        res.policy_kind = self.policy_kind
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
