#
# Copyright 2020- IBM Inc. All rights reserved
# SPDX-License-Identifier: Apache2.0
#

from enum import Enum
from dataclasses import dataclass
from ConnectionSet import ConnectionSet
from Peer import PeerSet


class NetworkPolicy:
    """
    The base class for all network policies.
    """

    class PolicyType(Enum):
        """
        The supported policy types
        """
        Unknown = 0
        K8sNetworkPolicy = 1
        CalicoNetworkPolicy = 2
        CalicoGlobalNetworkPolicy = 3
        CalicoProfile = 4
        IstioAuthorizationPolicy = 10
        List = 500

    def __init__(self, name, namespace):
        self.name = name
        self.namespace = namespace
        self.selected_peers = PeerSet()  # The peers affected by this policy
        self.ingress_rules = []
        self.egress_rules = []
        self.affects_ingress = False  # whether the policy affects the ingress of the selected peers
        self.affects_egress = False  # whether the policy affects the egress of the selected peers
        self.findings = []  # accumulated findings which are relevant only to this policy (emptiness and redundancy)
        self.referenced_labels = set()

    def __str__(self):
        return self.full_name()

    def __eq__(self, other):
        if type(self) == type(other):
            return \
                self.name == other.name and \
                self.namespace == other.namespace and \
                self.affects_egress == other.affects_egress and \
                self.affects_ingress == other.affects_ingress and \
                self.selected_peers == other.selected_peers and \
                self.ingress_rules == other.ingress_rules and \
                self.egress_rules == other.egress_rules
        return NotImplemented

    def full_name(self, config_name=None):
        """
        :param config_name: (optional) network config name
        :return: The fully-qualified name of the policy
        :rtype: str
        """
        res = self.name
        if self.namespace:
            res = str(self.namespace) + '/' + res
        if config_name:
            res = config_name + '/' + res
        return res

    def is_policy_empty(self):
        """
        :return: whether the policy captures any pods
        :rtype: bool
        """
        return not self.selected_peers

    def add_ingress_rule(self, rule):
        """
        Adding a rule to the list of ingress rules
        :param rule: The rule to add
        :return: None
        """
        self.ingress_rules.append(rule)

    def add_egress_rule(self, rule):
        """
        Adding a rule to the list of egress rules
        :param rule: The rule to add
        :return: None
        """
        self.egress_rules.append(rule)

    @staticmethod
    def get_policy_type(policy):
        """
        Given a policy/policy-list resource, determines the type of policy it describes/contains (based on its 'kind')
        :param dict policy: The resource to examine
        :return: The type of the policy(ies) this resource describes
        :rtype: NetworkPolicy.PolicyType
        """
        if not isinstance(policy, dict):
            return NetworkPolicy.PolicyType.Unknown

        kind = policy.get('kind')
        api_version = policy.get('apiVersion')
        if not kind or not api_version:
            return NetworkPolicy.PolicyType.Unknown
        if not isinstance(kind, str) or not isinstance(api_version, str):
            return NetworkPolicy.PolicyType.Unknown

        policy_type = NetworkPolicy.PolicyType.Unknown
        if kind.endswith('List'):
            policy_type = NetworkPolicy.PolicyType.List
        elif 'calico' in api_version:
            if kind == 'Profile':
                policy_type = NetworkPolicy.PolicyType.CalicoProfile
            elif kind == 'NetworkPolicy':
                policy_type = NetworkPolicy.PolicyType.CalicoNetworkPolicy
            elif kind == 'GlobalNetworkPolicy':
                policy_type = NetworkPolicy.PolicyType.CalicoGlobalNetworkPolicy
        elif 'istio' in api_version:
            if kind == 'AuthorizationPolicy':
                policy_type = NetworkPolicy.PolicyType.IstioAuthorizationPolicy
        elif kind == 'NetworkPolicy':
            policy_type = NetworkPolicy.PolicyType.K8sNetworkPolicy

        return policy_type

    def add_finding(self, finding):
        self.findings.append(finding)

    @staticmethod
    def has_allow_rules():
        """
        :return: Whether the policy has allow rules
        :rtype: bool
        """
        return False  # default value, can be overridden in derived classes

    @staticmethod
    def has_deny_rules():
        """
        :return: Whether the policy has deny rules
        :rtype: bool
        """
        return False  # default value, can be overridden in derived classes

    def rule_containing(self, other_policy, other_rule, other_rule_index, self_rules):
        """
        Check whether a rule in another policy is contained in one of the rules is the 'self' policy
        :param NetworkPolicy other_policy: The other policy in which the suspect rule resides (might equal 'self')
        :param other_rule: The rule to check if contained in one of the policy's rules
        :param int other_rule_index: The index of other_rule in its policy
        :param list self_rules: The set of rules in the current policy to check containment against
        :return: The index of a containing rule if exists (else None) + whether the actions of the two rules contradict
        :rtype: int, bool
        """
        return 0, False  # default values - override in derived classes

    def ingress_rule_containing(self, other_policy, other_ingress_rule_index):
        """
        Check if an ingress rule in self contains an ingress rule in other_policy
        :param NetworkPolicy other_policy: The other policy (might be the same as self)
        :param int other_ingress_rule_index: The index of the ingress rule to check containment against (1-based)
        :return: The index of a containing rule if exists (else None) + whether the actions of the two rules contradict
        :rtype: int, bool
        """
        return self.rule_containing(other_policy, other_policy.ingress_rules[other_ingress_rule_index - 1],
                                    other_ingress_rule_index, self.ingress_rules)

    def egress_rule_containing(self, other_policy, other_egress_rule_index):
        """
        Check if an egress rule in self contains an egress rule in other_policy
        :param NetworkPolicy other_policy: The other policy (might be the same as self)
        :param other_egress_rule_index: The index of the egress rule to check containment against (1-based)
        :return: The index of a containing rule if exists (else None) + whether the actions of the two rules contradict
        :rtype: int, bool
        """
        return self.rule_containing(other_policy, other_policy.egress_rules[other_egress_rule_index - 1],
                                    other_egress_rule_index, self.egress_rules)


@dataclass
class PolicyConnections:
    """
    A class to contain the effect of applying policies to a pair of peers
    """
    captured: bool  # Whether policy(ies) selectors captured relevant peers (can have empty allowed-conns with captured==True)
    allowed_conns: ConnectionSet = ConnectionSet()  # Connections allowed (and captured) by the policy(ies)
    denied_conns: ConnectionSet = ConnectionSet()  # Connections denied by the policy(ies)
    pass_conns: ConnectionSet = ConnectionSet()  # Connections specified as PASS by the policy(ies)
    all_allowed_conns: ConnectionSet = ConnectionSet()  # all (captured+ non-captured) Connections allowed by the policy(ies)
