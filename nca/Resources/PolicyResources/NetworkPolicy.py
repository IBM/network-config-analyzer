#
# Copyright 2020- IBM Inc. All rights reserved
# SPDX-License-Identifier: Apache2.0
#

from enum import Enum
from dataclasses import dataclass
from nca.CoreDS.Peer import PeerSet
from nca.CoreDS.ConnectivityProperties import ConnectivityProperties


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
        IstioSidecar = 11
        Ingress = 20
        Gateway = 30
        VirtualService = 31
        GatewayPolicy = 32
        List = 500

        @staticmethod
        def input_kind_name_str_to_policy_type(kind):
            if kind == "K8sNetworkPolicy":
                return NetworkPolicy.PolicyType.K8sNetworkPolicy
            elif kind == "CalicoNetworkPolicy":
                return NetworkPolicy.PolicyType.CalicoNetworkPolicy
            elif kind == "CalicoGlobalNetworkPolicy":
                return NetworkPolicy.PolicyType.CalicoGlobalNetworkPolicy
            elif kind == "IstioAuthorizationPolicy":
                return NetworkPolicy.PolicyType.IstioAuthorizationPolicy
            elif kind == "IstioSidecar":
                return NetworkPolicy.PolicyType.IstioSidecar
            elif kind == "K8sIngress":
                return NetworkPolicy.PolicyType.Ingress
            return None

    def __init__(self, name, namespace):
        self.name = name
        self.namespace = namespace
        self.selected_peers = PeerSet()  # The peers affected by this policy
        self.ingress_rules = []
        self.egress_rules = []

        # The flag below is used for lazy calculation of policy connections (as a union of rules connections)
        # The flag is set to False for new policies (including in redundancy query, when removing a rule from policy by
        # creating a new policy with a subset of rules), or after changing peers domains (per query).
        # When this flag is False, the sync_props function will (re)calculate policy connections.
        self.props_in_sync = False
        self._init_props()

        self.affects_ingress = False  # whether the policy affects the ingress of the selected peers
        self.affects_egress = False  # whether the policy affects the egress of the selected peers
        self.findings = []  # accumulated findings which are relevant only to this policy (emptiness and redundancy)
        self.referenced_labels = set()
        self.policy_kind = NetworkPolicy.PolicyType.Unknown
        self.has_ipv6_addresses = False  # whether the policy referenced ip addresses (by user)
        # if this flag is False, excluding ipv6 addresses from the query results will be enabled

    def _init_props(self):
        """
        The members below are used for lazy evaluation of policy connectivity properties.
        NOTE: THEY CANNOT BE ACCESSED DIRECTLY, ONLY BY 'GETTER' METHODS BELOW!
        """
        self._allow_ingress_props = ConnectivityProperties.make_empty_props()
        self._deny_ingress_props = ConnectivityProperties.make_empty_props()
        self._pass_ingress_props = ConnectivityProperties.make_empty_props()
        self._allow_egress_props = ConnectivityProperties.make_empty_props()
        self._deny_egress_props = ConnectivityProperties.make_empty_props()
        self._pass_egress_props = ConnectivityProperties.make_empty_props()

    def allow_ingress_props(self):
        self.sync_props()
        return self._allow_ingress_props

    def deny_ingress_props(self):
        self.sync_props()
        return self._deny_ingress_props

    def pass_ingress_props(self):
        self.sync_props()
        return self._pass_ingress_props

    def allow_egress_props(self):
        self.sync_props()
        return self._allow_egress_props

    def deny_egress_props(self):
        self.sync_props()
        return self._deny_egress_props

    def pass_egress_props(self):
        self.sync_props()
        return self._pass_egress_props

    def sync_props(self):
        """
        Implemented by derived policies to compute props of the policy according to the props
        of its rules, in case props are not currently synchronized.
        """
        return NotImplemented

    def __str__(self):
        return self.full_name()

    def __eq__(self, other):
        if isinstance(self, type(other)):
            self.sync_props()
            other.sync_props()
            return \
                self.name == other.name and \
                self.namespace == other.namespace and \
                self.affects_egress == other.affects_egress and \
                self.affects_ingress == other.affects_ingress and \
                self.selected_peers == other.selected_peers and \
                self.ingress_rules == other.ingress_rules and \
                self.egress_rules == other.egress_rules and \
                self._allow_ingress_props == other._allow_ingress_props and \
                self._deny_ingress_props == other._deny_ingress_props and \
                self._pass_ingress_props == other._pass_ingress_props and \
                self._allow_egress_props == other._allow_egress_props and \
                self._deny_egress_props == other._deny_egress_props and \
                self._pass_egress_props == other._pass_egress_props
        return False

    def __lt__(self, other):  # required so we can evaluate the policies according to their order
        if not isinstance(other, NetworkPolicy):
            return False
        # TODO - should add the condition below to make the comparison stable.
        # This makes some tests to fail because the order of output is different
        # if self.get_order() is None and other.get_order() is None:
        #     # to make the operator consistent
        #     return self.full_name() < other.full_name()
        # If not specified "order" defaults to infinity, so policies with unspecified "order" will be applied last.
        if self.get_order() is None:
            return False
        if other.get_order() is None:
            return True
        return self.get_order() < other.get_order()

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

    def reorganize_props_by_new_domains(self):
        """
        This method is called to allow reduction of src_peers/dst_peers to inactive dimensions
        in properties of every rule. It is called when running in a context of a certain query
        and after updating the domain accordingly in DimensionsManager.
        It also saves a copy of the connectivity properties before reduction, to allow restoring to
        these values after the query's run.
        Note: there is an assumption that rules of all derived policies have
        props and props_copy members
        """
        for rule in self.ingress_rules + self.egress_rules:
            if not rule.props_copy:
                # to avoid calling with the same rule multiple times
                rule.props_copy = rule.props.copy()
                rule.props.reduce_active_dimensions()
        self.props_in_sync = False

    def restore_props(self):
        """
        This method is called to restore connectivity properties of every rule to their original values,
        before the reduction of src_peers/dst_peers dimensions, s.t. the values of those dimensions will be
        with respect to the "full" default domain of these dimensions.
        Note: there is an assumption that rules of all derived policies have
        props and props_copy members
        """
        for rule in self.ingress_rules + self.egress_rules:
            if rule.props_copy:
                # to avoid calling with the same rule multiple times
                rule.props = rule.props_copy
                rule.props_copy = ConnectivityProperties()
        self.props_in_sync = False

    @staticmethod
    def get_policy_type_from_dict(policy):  # noqa: C901
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
            elif kind == 'Sidecar':
                policy_type = NetworkPolicy.PolicyType.IstioSidecar
            elif kind == 'Gateway':
                policy_type = NetworkPolicy.PolicyType.Gateway
            elif kind == 'VirtualService':
                policy_type = NetworkPolicy.PolicyType.VirtualService
        elif kind == 'NetworkPolicy':
            policy_type = NetworkPolicy.PolicyType.K8sNetworkPolicy
        elif kind == 'Ingress':
            policy_type = NetworkPolicy.PolicyType.Ingress

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

    def get_order(self):
        """
        :return: the order of the policy
        :rtype: int
        """
        return None  # default value, can be overridden in derived classes

    def clone_without_rule(self, rule_to_exclude, ingress_rule):
        """
        Implemented by derived classes to clone a policy without a specific rule
        """
        return NotImplemented

    def policy_type_str(self):
        if self.policy_kind == NetworkPolicy.PolicyType.Ingress:
            return "Ingress resource"
        elif self.policy_kind == NetworkPolicy.PolicyType.GatewayPolicy:
            return "Istio Gateway/VirtualService resource"
        else:
            return "NetworkPolicy"


# TODO - making PolicyConnections a dataclass does not work
# (probably because PeerSet and ConnectivityProperties are mutable)
class PolicyConnections:
    """
    A class to contain the effect of applying policies to all src and dst peers
    It also serves as a filter for lazy evaluations of connections:
    whenever any of allowed_conns/denied_conns/pass_conns/all_allowed_conns is None,
    those connections will not be calculated.
    """
    def __init__(self):
        self.captured = PeerSet()
        self.allowed_conns = ConnectivityProperties()
        self.denied_conns = ConnectivityProperties()
        self.pass_conns = ConnectivityProperties()
        self.all_allowed_conns = ConnectivityProperties()

    def and_by_filter(self, props, the_filter):
        """
        Update all properties (allowed, denied, etc.) by conjunction with a given expression,
        for the relevant properties from the input filter (which are set as True)
        :param ConnectivityProperties props: the given expression to conjunct with
        :param PolicyConnectionsFilter the_filter: contains True for all properties to update
        """
        if the_filter.calc_allowed:
            self.allowed_conns &= props
        if the_filter.calc_denied:
            self.denied_conns &= props
        if the_filter.calc_pass:
            self.pass_conns &= props
        if the_filter.calc_all_allowed:
            self.all_allowed_conns &= props

    def sub_by_filter(self, props, the_filter):
        """
        Update all properties (allowed, denied, etc.) by subtraction a given expression from them,
        for the relevant properties from the input filter (which are set as True)
        :param ConnectivityProperties props: the given expression to subtract
        :param PolicyConnectionsFilter the_filter: contains True for all properties to update
        """
        if the_filter.calc_allowed:
            self.allowed_conns -= props
        if the_filter.calc_denied:
            self.denied_conns -= props
        if the_filter.calc_pass:
            self.pass_conns -= props
        if the_filter.calc_all_allowed:
            self.all_allowed_conns -= props


@dataclass(frozen=True)
class PolicyConnectionsFilter:
    """
    A class that serves as a filter for lazy evaluations of connections:
    whether to calculate allowed_conns/denied_conns/pass_conns/all_allowed_conns (True) or not (False)
    """
    calc_allowed: bool = True
    calc_denied: bool = True
    calc_pass: bool = True
    calc_all_allowed: bool = True

    def __post_init__(self):
        # all_allowed_conns is needed for the calculation of allowed_conns
        object.__setattr__(self, 'calc_all_allowed', self.calc_all_allowed | self.calc_allowed)

    @staticmethod
    def only_allowed_connections():
        return PolicyConnectionsFilter(calc_allowed=True, calc_denied=False, calc_pass=False, calc_all_allowed=False)

    @staticmethod
    def only_denied_connections():
        return PolicyConnectionsFilter(calc_allowed=False, calc_denied=True, calc_pass=False, calc_all_allowed=False)

    @staticmethod
    def only_all_allowed_connections():
        return PolicyConnectionsFilter(calc_allowed=False, calc_denied=False, calc_pass=False, calc_all_allowed=True)
