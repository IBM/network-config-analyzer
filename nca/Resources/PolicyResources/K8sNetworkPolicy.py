#
# Copyright 2020- IBM Inc. All rights reserved
# SPDX-License-Identifier: Apache2.0
#
from nca.CoreDS.ConnectivityProperties import ConnectivityProperties
from nca.CoreDS import Peer
from .NetworkPolicy import PolicyConnections, NetworkPolicy


class K8sPolicyRule:
    """
    A class representing a single ingress/egress rule in a K8s NetworkPolicy object
    """
    def __init__(self, peer_set, props):
        """
        :param Peer.PeerSet peer_set: The set of peers this rule allows connection to/from
        :param ConnectivityProperties props: the connections
        """
        self.peer_set = peer_set
        self.props = props
        # copy of props (used by src_peers/dst_peers domain-updating mechanism)
        self.props_copy = ConnectivityProperties()

    def __eq__(self, other):
        return self.peer_set == other.peer_set and self.props == other.props

    def contained_in(self, other):
        """
        :param K8sPolicyRule other: Another rule
        :return: whether the self rule is contained in the other rule (self doesn't allow anything that other does not)
        :type: bool
        """
        return self.peer_set.issubset(other.peer_set) and self.props.contained_in(other.props)


class K8sNetworkPolicy(NetworkPolicy):
    """
    This class implements K8s-specific logic for NetworkPolicies
    """
    def sync_props(self):
        """
        If props of the policy are not synchronized (self.props_in_sync is False),
        compute props of the policy according to the props of its rules
        """
        if self.props_in_sync:
            return
        self._init_props()
        for rule in self.ingress_rules:
            self._allow_ingress_props |= rule.props
        for rule in self.egress_rules:
            self._allow_egress_props |= rule.props
        self.props_in_sync = True

    def allowed_connections(self, is_ingress):
        """
        Return the set of connections this policy allows between any two peers
        (either ingress or egress).
        :param bool is_ingress: whether we evaluate ingress rules only or egress rules only
        :return: A ConnectivityProperties object containing all allowed connections for relevant peers,
        None for denied connections (K8s does not have denied),
        and the peer set of captured peers by this policy.
        :rtype: tuple (ConnectivityProperties, ConnectivityProperties, PeerSet)
        """
        res_conns = PolicyConnections()
        if is_ingress:
            res_conns.allowed_conns = self.allow_ingress_props().copy()
            res_conns.captured = self.selected_peers if self.affects_ingress else Peer.PeerSet()
        else:
            res_conns.allowed_conns = self.allow_egress_props().copy()
            res_conns.captured = self.selected_peers if self.affects_egress else Peer.PeerSet()
        return res_conns

    def clone_without_rule(self, rule_to_exclude, ingress_rule):
        """
        Makes a copy of 'self' without a given policy rule
        :param K8sPolicyRule rule_to_exclude: The one rule not to include in the copy
        :param bool ingress_rule: Whether the rule is an ingress or egress rule
        :return: A copy of 'self' without the provided rule
        :rtype: K8sNetworkPolicy
        """
        res = K8sNetworkPolicy(self.name, self.namespace)
        res.selected_peers = self.selected_peers
        res.affects_egress = self.affects_egress
        res.affects_ingress = self.affects_ingress
        res.policy_kind = self.policy_kind
        for rule in self.egress_rules:
            if ingress_rule or rule != rule_to_exclude:
                res.add_egress_rule(rule)
        for rule in self.ingress_rules:
            if not ingress_rule or rule != rule_to_exclude:
                res.add_ingress_rule(rule)
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
            if not ingress_rule.peer_set:
                emptiness = f'Ingress rule no. {rule_index} in NetworkPolicy {full_name} does not select any pods'
                emptiness_explanation.append(emptiness)
                empty_ingress_rules.add(rule_index)

        for rule_index, egress_rule in enumerate(self.egress_rules, start=1):
            if not egress_rule.peer_set:
                emptiness = f'Egress rule no. {rule_index} in NetworkPolicy {full_name} does not select any pods'
                emptiness_explanation.append(emptiness)
                empty_egress_rules.add(rule_index)

        return emptiness_explanation, empty_ingress_rules, empty_egress_rules

    @staticmethod
    def is_conflicting(_other):
        """
        :param NetworkPolicy _other: Another network policy
        :return: False, as policies in K8s cannot conflict each other (there are only allow rules)
        """
        return False

    def has_allow_rules(self):
        """
        :return: Whether the policy has rules that allow connections. In K8s this means the policy has non-empty rules.
        :rtype: bool
        """
        for ingress_rule in self.ingress_rules:
            if ingress_rule.peer_set:
                return True

        for egress_rule in self.egress_rules:
            if egress_rule.peer_set:
                return True

        return False

    def rule_containing(self, other_policy, other_rule, other_rule_index, self_rules):
        """
        Check whether a rule in another policy is contained in one of the rules is the 'self' policy
        :param K8sNetworkPolicy other_policy: The other policy in which the suspect rule resides (might equal 'self')
        :param K8sPolicyRule other_rule: The rule to check if contained in one of the policy's rules
        :param int other_rule_index: The index of other_rule in its policy
        :param list[K8sPolicyRule] self_rules: The set of rules in the current policy to check containment against
        :return: The index of a containing rule if exists (else None) + whether the actions of the two rules contradict
        :rtype: int, bool
        """
        if not other_policy.selected_peers.issubset(self.selected_peers):
            return None, None
        for rule_index, rule in enumerate(self_rules, start=1):
            if rule_index == other_rule_index and self == other_policy:
                continue
            if other_rule.contained_in(rule):
                return rule_index, False
        return None, None

    def get_order(self):
        """
        :return: The order of the policy
        :rtype: int
        """
        return 1000  # In Calico, all K8s NetworkPolicies are considered to have their order set to 1000
