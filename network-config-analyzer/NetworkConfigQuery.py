#
# Copyright 2020- IBM Inc. All rights reserved
# SPDX-License-Identifier: Apache2.0
#
from dataclasses import dataclass
import itertools
import os
from enum import Enum
from NetworkConfig import NetworkConfig
from NetworkPolicy import NetworkPolicy
from ConnectionSet import ConnectionSet
from ConnectivityGraph import ConnectivityGraph
from OutputConfiguration import OutputConfiguration
from Peer import PeerSet, IpBlock


class QueryType(Enum):
    SingleConfigQuery = 0
    ComparisonToBaseConfigQuery = 1
    PairComparisonQuery = 2
    PairwiseComparisonQuery = 3


@dataclass
class QueryAnswer:
    """
    A class for holding the answer to any one of the below queries
    """
    bool_result: bool = False
    output_result: str = ''
    output_explanation: str = ''
    numerical_result: int = 0


class BaseNetworkQuery:
    """
    A base class for NetworkConfigQuery and TwoNetworkConfigsQuery, with common output configuration logic:
    Per query in a scheme file, the field outputConfiguration is optional, and if exists should contain a dict
    with relevant fields and values
    Thus, every network query has a corresponding  output_config object of type OutputConfiguration
    """

    def __init__(self, output_config_obj):
        self.output_config = output_config_obj if output_config_obj is not None else OutputConfiguration()

    @staticmethod
    def get_supported_output_formats():
        return None


class NetworkConfigQuery(BaseNetworkQuery):
    """
    A base class for queries that inspect only a single network config
    """

    def __init__(self, config, output_config_obj=None):
        """
        :param NetworkConfig config: The config to query
        """
        super().__init__(output_config_obj)
        self.config = config

    @staticmethod
    def get_query_output(query_answer, only_explanation=False, add_explanation=False):
        res = query_answer.numerical_result
        if only_explanation:
            return res, query_answer.output_explanation
        query_output = query_answer.output_result
        if add_explanation:
            query_output += query_answer.output_explanation
        return res, query_output

    @staticmethod
    def get_query_type():
        return QueryType.SingleConfigQuery


class DisjointnessQuery(NetworkConfigQuery):
    """
    Check whether no two policy in the config capture the same peer
    """

    def exec(self):
        non_disjoint_explanation_list = []
        for policy1 in self.config.sorted_policies:
            if policy1.is_policy_empty():
                continue
            for policy2 in self.config.sorted_policies:
                if policy1 == policy2:
                    break
                intersection = policy1.selected_peers & policy2.selected_peers
                if intersection:
                    non_disjoint_explanation = f'The captured pods of NetworkPolicy {policy1.full_name()} ' \
                                               f'and NetworkPolicy {policy2.full_name()} ' \
                                               f'are overlapping. E.g., both capture {intersection.rep()}'
                    non_disjoint_explanation_list.append(non_disjoint_explanation)

        if not non_disjoint_explanation_list:
            return QueryAnswer(True, 'All policies are disjoint in ' + self.config.name, '', 0)
        full_explanation = '\n'.join(non_disjoint_explanation_list)
        return QueryAnswer(False,
                           'There are policies capturing the same pods in ' + self.config.name,
                           full_explanation, len(non_disjoint_explanation_list))

    def compute_query_output(self, query_answer):
        return self.get_query_output(query_answer, False, not query_answer.bool_result)


class EmptinessQuery(NetworkConfigQuery):
    """
    Check if any policy or one of its rules captures an empty set of peers
    """

    def exec(self):
        res = 0
        full_explanation_list = []
        for policy in self.config.policies.values():
            emptiness_list = []
            if policy.is_policy_empty():
                emptiness_list.append(f'NetworkPolicy {policy.full_name(self.config.name)} does not select any pods')
            empty_rules_explanation, _, _ = policy.has_empty_rules(self.config.name)
            emptiness_list.extend(empty_rules_explanation)
            res += len(emptiness_list)
            if emptiness_list:
                full_explanation_list.append('\n'.join(emptiness_list))
        if not res:
            return QueryAnswer(False, 'No empty NetworkPolicies and no empty rules in ' + self.config.name, res)
        full_explanation = '\n'.join(full_explanation_list)
        return QueryAnswer(res > 0,
                           'There are empty NetworkPolicies and/or empty ingress/egress rules in ' + self.config.name,
                           '\n' + full_explanation, res)

    def compute_query_output(self, query_answer):
        return self.get_query_output(query_answer, add_explanation=query_answer.bool_result)


class VacuityQuery(NetworkConfigQuery):
    """
    Check if the set of policies changes the cluster's default behavior
    """

    def exec(self):
        vacuous_config = self.config.clone_without_policies('vacuousConfig')
        vacuous_res = EquivalenceQuery(self.config, vacuous_config).exec()
        if not vacuous_res.bool_result:
            return QueryAnswer(vacuous_res.bool_result,
                               output_result=f'Network configuration {self.config.name} is not vacuous',
                               numerical_result=vacuous_res.bool_result)

        if self.config.type == NetworkConfig.ConfigType.Calico:
            output_result = f'Network configuration {self.config.name} is vacuous - only the default connections,' \
                            f' as defined by profiles, are allowed '
        else:
            output_result = f'Network configuration {self.config.name} is vacuous - it allows all connections'
        return QueryAnswer(bool_result=vacuous_res.bool_result, output_result=output_result,
                           numerical_result=vacuous_res.bool_result)

    def compute_query_output(self, query_answer):
        return self.get_query_output(query_answer)


class RedundancyQuery(NetworkConfigQuery):
    """
    Check if any of the policies can be removed without changing cluster connectivity. Same for each rule in each policy
    """

    def redundant_policies(self):
        res = 0
        redundancies = []
        redundant_policies = set()
        # Checking for redundant policies
        if len(self.config.policies) > 1:
            for policy in self.config.policies.values():
                config_without_policy = self.config.clone_without_policy(policy)
                if EquivalenceQuery(self.config, config_without_policy).exec().bool_result:
                    res += 1
                    redundant_policies.add(policy.full_name())
                    redundancy = f'NetworkPolicy {policy.full_name()} is redundant in {self.config.name}'
                    redundancies.append(redundancy)
        return redundant_policies, redundancies

    def find_redundant_rules(self, policy):
        # Checking for redundant ingress/egress rules
        redundancies = []
        redundant_ingress_rules = []
        redundant_egress_rules = []
        for rule_index, ingress_rule in enumerate(policy.ingress_rules, start=1):
            modified_policy = policy.clone_without_rule(ingress_rule, True)
            if len(modified_policy.ingress_rules) < len(policy.ingress_rules) - 1:
                redundancy = f'Ingress rule no. {rule_index} in NetworkPolicy {policy.full_name()} is redundant ' \
                             f'in {self.config.name}'
                redundancies.append(redundancy)
                redundant_ingress_rules.append(rule_index)
                continue
            config_with_modified_policy = self.config.clone_without_policy(policy)
            config_with_modified_policy.add_policy(modified_policy)
            equiv_result = EquivalenceQuery(self.config, config_with_modified_policy).exec()
            if equiv_result.bool_result:
                redundancy = f'Ingress rule no. {rule_index} in NetworkPolicy {policy.full_name()} is redundant ' \
                             f'in {self.config.name}'
                redundancies.append(redundancy)
                redundant_ingress_rules.append(rule_index)
        for rule_index, egress_rule in enumerate(policy.egress_rules, start=1):
            modified_policy = policy.clone_without_rule(egress_rule, False)
            if len(modified_policy.egress_rules) < len(policy.egress_rules) - 1:
                redundancy = f'Egress rule no. {rule_index} in NetworkPolicy {policy.full_name()} is redundant ' \
                             f'in {self.config.name}'
                redundancies.append(redundancy)
                redundant_egress_rules.append(rule_index)
                continue
            config_with_modified_policy = self.config.clone_without_policy(policy)
            config_with_modified_policy.add_policy(modified_policy)
            if EquivalenceQuery(self.config, config_with_modified_policy).exec().bool_result:
                redundancy = f'Egress rule no. {rule_index} in NetworkPolicy {policy.full_name()} is redundant ' \
                             f'in {self.config.name}'
                redundant_egress_rules.append(rule_index)
                redundancies.append(redundancy)
        return redundant_ingress_rules, redundant_egress_rules, redundancies

    def exec(self):
        redundant_policies, redundancies = self.redundant_policies()
        res = len(redundant_policies)

        # Checking for redundant ingress/egress rules
        for policy in self.config.policies.values():
            if policy.full_name() in redundant_policies:  # we skip checking rules if the whole policy is redundant
                continue
            _, _, rules_redundancy_explanation = \
                self.find_redundant_rules(policy)
            res += len(rules_redundancy_explanation)
            redundancies += rules_redundancy_explanation

        if res > 0:
            output_explanation = '\n'.join(redundancies)
            return QueryAnswer(True, 'Redundancies found in ' + self.config.name + '\n', output_explanation, res)
        return QueryAnswer(False, 'No redundancy found in ' + self.config.name)

    def compute_query_output(self, query_answer):
        return self.get_query_output(query_answer, add_explanation=query_answer.bool_result)


class SanityQuery(NetworkConfigQuery):
    """
    Perform various queries to check the network config sanity. Checks vacuity, redundancy and emptiness
    """

    def has_conflicting_policies_with_same_order(self):
        if self.config.type != NetworkConfig.ConfigType.Calico:
            return False, ''
        if len(self.config.sorted_policies) <= 1:
            return False, ''

        curr_set = []
        for policy in self.config.sorted_policies:
            if curr_set:
                policy_in_curr_set = next(iter(curr_set))
                if policy_in_curr_set < policy:
                    curr_set.clear()
                else:  # policy has same priority as policies in curr_set
                    for other_policy in curr_set:
                        if policy.is_conflicting(other_policy):
                            conflict_str = 'Policies {} and {} have same order but conflicting rules. Behavior is ' \
                                           'undefined.'.format(policy.full_name(), other_policy.full_name())
                            policy.add_finding(conflict_str)
                            other_policy.add_finding(conflict_str)
                            return True, conflict_str
            curr_set.append(policy)
        return False, ''

    def other_policy_containing_allow(self, self_policy, config_with_self_policy):
        """
        Search for a policy which contains all allowed connections specified by self_policy
        :param NetworkPolicy self_policy: The policy to check
        :param NetworkConfig config_with_self_policy: A network config with self_policy as its single policy
        :return: A policy containing self_policy's allowed connections if exist, None otherwise
        :rtype: NetworkPolicy
        """
        only_captured = self.config.type == NetworkConfig.ConfigType.K8s or self.config.type == NetworkConfig.ConfigType.Istio
        for other_policy in self.config.sorted_policies:
            if other_policy == self_policy:
                if self.config.type == NetworkConfig.ConfigType.Calico:
                    return None  # All other policies have a lower order and cannot contain self_policy
                continue
            if only_captured and not self_policy.selected_peers.issubset(other_policy.selected_peers):
                continue
            config_with_other_policy = self.config.clone_with_just_one_policy(other_policy.full_name())
            if ContainmentQuery(config_with_self_policy, config_with_other_policy).exec(only_captured).bool_result:
                return other_policy
        return None

    def other_policy_containing_deny(self, self_policy, config_with_self_policy):
        """
        Search for a policy which contains all denied connections specified by self_policy
        :param NetworkPolicy self_policy: The policy to check
        :param NetworkConfig config_with_self_policy: A network config with self_policy as its single policy
        :return: A policy containing self_policy's denied connections if exist, None otherwise
        :rtype: NetworkPolicy
        """
        for other_policy in self.config.sorted_policies:
            if other_policy == self_policy:
                if self.config.type == NetworkConfig.ConfigType.Calico:
                    return None  # not checking lower priority for Calico
                continue  # (istio: skip comparison of policy to itself)
            if not other_policy.has_deny_rules():
                continue
            config_with_other_policy = self.config.clone_with_just_one_policy(other_policy.full_name())
            pods_to_compare = self.config.peer_container.get_all_peers_group()
            pods_to_compare |= TwoNetworkConfigsQuery(self.config,
                                                      config_with_other_policy).disjoint_referenced_ip_blocks()
            for pod1 in pods_to_compare:
                for pod2 in pods_to_compare:
                    if isinstance(pod1, IpBlock) and isinstance(pod2, IpBlock):
                        continue
                    if pod1 == pod2:
                        continue  # no way to prevent a pod from communicating with itself
                    _, _, _, self_deny_conns = config_with_self_policy.allowed_connections(pod1, pod2)
                    _, _, _, other_deny_conns = config_with_other_policy.allowed_connections(pod1, pod2)
                    if not self_deny_conns:
                        continue
                    if not self_deny_conns.contained_in(other_deny_conns):
                        return None
            return other_policy
        return None

    def other_rule_containing(self, self_policy, self_rule_index, is_ingress):
        """
        Search whether a given policy rule is contained in another policy rule
        :param NetworkPolicy self_policy: The network policy containing the given rule
        :param int self_rule_index: The index of the rule in the policy (1-based)
        :param bool is_ingress: Whether this is an ingress rule or an egress rule
        :return: If a containing rule is found, return its policy, its index and whether it contradicts the input rule
        :rtype: NetworkPolicy, int, bool
        """
        for other_policy in self.config.sorted_policies:
            if is_ingress:
                found_index, contradict = other_policy.ingress_rule_containing(self_policy, self_rule_index)
            else:
                found_index, contradict = other_policy.egress_rule_containing(self_policy, self_rule_index)
            if found_index:
                return other_policy, found_index, contradict
            if other_policy == self_policy and self.config.type == NetworkConfig.ConfigType.Calico:
                return None, None, None  # All following policies have a lower order - containment is not interesting

        return None, None, None

    def redundant_rule_text(self, policy, rule_index, is_ingress):
        """
        Attempts to provide an explanation as to why a policy rule is redundant
        :param NetworkPolicy policy: A redundant policy
        :param int rule_index: The index of the rule in the policy (1-based)
        :param bool is_ingress: Whether this is an ingress rule or an egress rule
        :return: A text explaining why the policy is redundant
        :rtype: str
        """
        redundant_text = 'In' if is_ingress else 'E'
        redundant_text += f'gress rule no. {rule_index} in NetworkPolicy {policy.full_name()} ' \
                          f'is redundant in {self.config.name}'
        containing_policy, containing_index, containing_contradict = \
            self.other_rule_containing(policy, rule_index, is_ingress)
        if not containing_policy:
            return redundant_text + '\n'
        redundant_text += ' since it is contained in '
        redundant_text += 'in' if is_ingress else 'e'
        redundant_text += f'gress rule no. {containing_index}'
        if containing_policy == policy:
            redundant_text += ' of its NetworkPolicy'
        else:
            redundant_text += f' of NetworkPolicy {containing_policy.full_name()}'
        if containing_contradict:
            redundant_text += '\n\tNote that the action of the containing rule and the rule are different.'
        return redundant_text + '\n'

    def redundant_policy_text(self, policy):
        """
        Attempts to provide an explanation as to why a policy is redundant
        :param NetworkPolicy policy: A redundant policy
        :return: A text explaining why the policy is redundant
        :rtype: str
        """
        redundant_text = f'NetworkPolicy {policy.full_name()} is redundant'
        single_policy_config = self.config.clone_with_just_one_policy(policy.full_name())
        if VacuityQuery(single_policy_config).exec().bool_result:
            if self.config.type == NetworkConfig.ConfigType.Calico:
                redundant_text += '. Note that it allows only the default connections, as defined by profiles'
            else:
                redundant_text += '. Note that it allows all connections'
            return redundant_text + '\n'

        has_allow_rules = policy.has_allow_rules()
        has_deny_rules = policy.has_deny_rules()
        # TODO: check: only in calico - if all the rules are empty then the policy is redundant?
        # can find an example with istio here?
        if not has_deny_rules and not has_allow_rules:  # all rules are empty
            return redundant_text + '. Note that it contains no effective allow/deny rules\n'

        contain_allow_policy, contain_deny_policy = None, None
        if has_allow_rules:
            contain_allow_policy = self.other_policy_containing_allow(policy, single_policy_config)
        if has_deny_rules and (not has_allow_rules or contain_allow_policy is not None):
            contain_deny_policy = self.other_policy_containing_deny(policy, single_policy_config)
        if (has_allow_rules and contain_allow_policy is None) or (has_deny_rules and contain_deny_policy is None):
            return redundant_text + '\n'
        if not has_deny_rules:
            redundant_text += f': it is contained in NetworkPolicy {contain_allow_policy.full_name()}\n'
        elif not has_allow_rules:
            redundant_text += f': it is contained in NetworkPolicy {contain_deny_policy.full_name()}\n'
        else:
            if contain_deny_policy == contain_allow_policy:
                redundant_text += f': it is contained in NetworkPolicy {contain_allow_policy.full_name()}\n'
            else:
                redundant_text += f': its allow rules are covered by NetworkPolicy {contain_allow_policy.full_name()}' \
                                  f', its deny rules are covered by NetworkPolicy {contain_deny_policy.full_name()}\n'
        return redundant_text

    def exec(self):  # noqa: C901
        if not self.config:
            return QueryAnswer(False, f'No NetworkPolicies in {self.config.name}. Nothing to check sanity on.', '', 1)
        has_conflicting_policies, conflict_explanation = self.has_conflicting_policies_with_same_order()
        if has_conflicting_policies:
            return QueryAnswer(bool_result=False, output_result=conflict_explanation, output_explanation='',
                               numerical_result=1)
        issues_counter = 0
        policies_issue = ''
        rules_issues = ''
        is_config_vacuous_res = VacuityQuery(self.config).exec()
        if is_config_vacuous_res.bool_result:
            issues_counter = 1
            policies_issue += is_config_vacuous_res.output_result + '\n'
            if len(self.config.policies) == 1:
                policies_issue += '\tNote that it contains a single policy.\n'
        redundant_policies, _ = RedundancyQuery(self.config).redundant_policies()
        for policy in self.config.policies.values():
            if policy.is_policy_empty():
                issues_counter += 1
                empty_issue = f'NetworkPolicy {policy.full_name()} is empty - it does not select any pods\n'
                policies_issue += empty_issue
                policy.add_finding(empty_issue)
                continue

            empty_rules_explanation, empty_ingress_rules_list, empty_egress_rules_list = policy.has_empty_rules('')
            if empty_rules_explanation:
                issues_counter += len(empty_rules_explanation)
                rules_issues += '\n'.join(empty_rules_explanation) + '\n'
                policy.findings += empty_rules_explanation

            if is_config_vacuous_res.bool_result:
                continue

            if policy.full_name() in redundant_policies:
                issues_counter += 1
                redundancy_full_text = self.redundant_policy_text(policy)
                policies_issue += redundancy_full_text
                policy.add_finding(redundancy_full_text)
                continue

            redundant_ingress_rules, redundant_egress_rules, _ = \
                RedundancyQuery(self.config).find_redundant_rules(policy)
            for rule_index in range(1, len(policy.ingress_rules) + 1):
                if rule_index in empty_ingress_rules_list:
                    continue
                if rule_index in redundant_ingress_rules:
                    issues_counter += 1
                    redundancy_text = self.redundant_rule_text(policy, rule_index, True)
                    rules_issues += redundancy_text
                    policy.add_finding(redundancy_text)
            for rule_index in range(1, len(policy.egress_rules) + 1):
                if rule_index in empty_egress_rules_list:
                    continue
                if rule_index in redundant_egress_rules:
                    issues_counter += 1
                    redundancy_text = self.redundant_rule_text(policy, rule_index, False)
                    rules_issues += redundancy_text
                    policy.add_finding(redundancy_text)

        if issues_counter == 0:
            output_result = f'NetworkConfig {self.config.name} passed sanity check'
        else:
            output_result = f'NetworkConfig {self.config.name} failed sanity check:'
        return QueryAnswer(bool_result=(issues_counter == 0), output_result=output_result,
                           output_explanation=policies_issue + rules_issues, numerical_result=issues_counter)

    def compute_query_output(self, query_answer):
        return self.get_query_output(query_answer, False, (not query_answer.bool_result))


class ConnectivityMapQuery(NetworkConfigQuery):
    """
    Print the connectivity graph in the form of firewall rules
    """

    @staticmethod
    def get_supported_output_formats():
        return {'txt', 'yaml', 'csv', 'md', 'dot'}

    def exec(self):
        self.output_config.configName = os.path.basename(self.config.name) if self.config.name.startswith('./') else \
            self.config.name
        peers_to_compare = self.config.peer_container.get_all_peers_group()

        ref_ip_blocks = IpBlock.disjoint_ip_blocks(self.config.get_referenced_ip_blocks(),
                                                   IpBlock.get_all_ips_block_peer_set())

        peers_to_compare |= ref_ip_blocks

        conn_graph = ConnectivityGraph(peers_to_compare, self.config.allowed_labels, self.output_config,
                                       self.config.type)
        for peer1 in peers_to_compare:
            for peer2 in peers_to_compare:
                if isinstance(peer1, IpBlock) and isinstance(peer2, IpBlock):
                    continue  # skipping pairs with ip-blocks for both src and dst
                if peer1 == peer2:
                    conn_graph.add_edge(peer1, peer2, ConnectionSet(True))  # cannot restrict pod's connection to itself
                else:
                    conns, _, _, _ = self.config.allowed_connections(peer1, peer2)
                    if conns:
                        if self.config.type == NetworkConfig.ConfigType.Istio and \
                                self.output_config.connectivityFilterIstioEdges:
                            should_filter, modified_conns = self.filter_istio_edge(peer2, conns)
                            if not should_filter:
                                conn_graph.add_edge(peer1, peer2, modified_conns)
                        else:
                            conn_graph.add_edge(peer1, peer2, conns)

        res = QueryAnswer(True)
        if self.output_config.outputFormat == 'dot':
            res.output_explanation = conn_graph.get_connectivity_dot_format_str()
        else:
            fw_rules = conn_graph.get_minimized_firewall_rules()
            res.output_explanation = fw_rules.get_fw_rules_in_required_format()
        return res

    def compute_query_output(self, query_answer):
        return self.get_query_output(query_answer, only_explanation=query_answer.bool_result)

    @staticmethod
    def filter_istio_edge(peer2, conns):
        # currently only supporting authorization policies, that do not capture egress rules
        if isinstance(peer2, IpBlock):
            return True, None
        # remove allowed connections for non TCP protocols
        # https://istio.io/latest/docs/ops/configuration/traffic-management/protocol-selection/
        # Non-TCP based protocols, such as UDP, are not proxied. These protocols will continue to function as normal,
        # without any interception by the Istio proxy
        conns_new = conns - ConnectionSet.get_non_tcp_connections()
        return False, conns_new


class TwoNetworkConfigsQuery(BaseNetworkQuery):
    """
    A base class for queries that inspect two network configs
    """

    def __init__(self, config1, config2, output_config_obj=None):
        """
        :param NetworkConfig config1: First config to query
        :param NetworkConfig config2: Second config to query
        """
        super().__init__(output_config_obj)
        self.config1 = config1
        self.config2 = config2
        self.name1 = os.path.basename(config1.name) if config1.name.startswith('./') else config1.name
        self.name2 = os.path.basename(config2.name) if config2.name.startswith('./') else config2.name

    @staticmethod
    def get_query_type():
        return QueryType.ComparisonToBaseConfigQuery

    def is_identical_topologies(self, check_same_policies=False):
        if self.config1.peer_container != self.config2.peer_container:
            return QueryAnswer(False, 'The two configurations have different network topologies '
                                      'and thus are not comparable.\n')
        if check_same_policies and self.config1.policies == self.config2.policies and \
                self.config1.profiles == self.config2.profiles:
            return QueryAnswer(True, f'{self.name1} and {self.name2} have the same network '
                                     'topology and the same set of policies.\n')
        return QueryAnswer(True)

    def disjoint_referenced_ip_blocks(self):
        """
        Returns disjoint ip-blocks in the policies of both configs
        :return: A set of disjoint ip-blocks
        :rtype: PeerSet
        """
        return IpBlock.disjoint_ip_blocks(self.config1.get_referenced_ip_blocks(),
                                          self.config2.get_referenced_ip_blocks())


class EquivalenceQuery(TwoNetworkConfigsQuery):
    """
    Check whether config1 and config2 allow exactly the same set of connections.
    """

    @staticmethod
    def get_query_type():
        return QueryType.PairComparisonQuery

    def exec(self):
        query_answer = self.is_identical_topologies(True)
        if query_answer.output_result:
            return query_answer

        peers_to_compare = self.config1.peer_container.get_all_peers_group()
        peers_to_compare |= self.disjoint_referenced_ip_blocks()
        captured_pods = self.config1.get_captured_pods() | self.config2.get_captured_pods()
        for peer1 in peers_to_compare:
            for peer2 in peers_to_compare if peer1 in captured_pods else captured_pods:
                if peer1 == peer2:
                    continue
                conns1, _, _, _ = self.config1.allowed_connections(peer1, peer2)
                conns2, _, _, _ = self.config2.allowed_connections(peer1, peer2)
                if conns1 != conns2:
                    explanation = f'Allowed connections from {peer1} to {peer2} are different\n' + \
                                  conns1.print_diff(conns2, self.name1, self.name2)
                    return QueryAnswer(False, self.name1 + ' and ' + self.name2 + ' are not semantically equivalent.',
                                       explanation)
        return QueryAnswer(True, self.name1 + ' and ' + self.name2 + ' are semantically equivalent.')

    @staticmethod
    def compute_query_output(query_answer, _):
        query_output = query_answer.output_result
        if not query_answer.bool_result:
            query_output += query_answer.output_explanation + '\n'
        return not query_answer.bool_result, query_output


class SemanticDiffQuery(TwoNetworkConfigsQuery):
    """
    Produces a report of changed connections (also for the case of two configurations of different network topologies)
    """

    @staticmethod
    def get_query_type():
        return QueryType.PairComparisonQuery

    @staticmethod
    def get_supported_output_formats():
        return {'txt', 'yaml', 'csv', 'md'}

    def get_explanation_from_conn_graph(self, is_added, conn_graph, is_first_connectivity_result):
        """
        :param is_added: a bool flag indicating if connections are added or removed
        :param conn_graph:  a ConnectivityGraph with added/removed connections
        :param is_first_connectivity_result: bool flag indicating if this is the first connectivity fw-rules computation
               for the current semantic-diff query
        :return: explanation (str) with fw-rules summarizing added/removed connections
        """
        topology_config_name = self.name2 if is_added else self.name1
        line_header_txt = 'Added' if is_added else 'Removed'
        fw_rules = conn_graph.get_minimized_firewall_rules()
        # for csv format, adding the csv header only for the first connectivity fw-rules computation
        fw_rules_output = fw_rules.get_fw_rules_in_required_format(False, is_first_connectivity_result)
        if self.output_config.outputFormat == 'txt':
            explanation = f'{line_header_txt} connections (based on topology from config: {topology_config_name}) :\n' \
                          f'{fw_rules_output}\n'
        else:
            explanation = fw_rules_output
        return explanation

    def get_results_for_computed_fw_rules(self, keys_list, conn_graph_removed_per_key, conn_graph_added_per_key):
        """
        Compute accumulated explanation and res for all keys of changed connections categories
        :param keys_list: the list of keys
        :param conn_graph_removed_per_key: map from key to ConnectivityGraph of removed connections
        :param conn_graph_added_per_key: map from key to ConnectivityGraph of added connections
        :return:
        res (int): number of categories with diffs
        explanation (str): a diff message
        """
        explanation = ''
        add_explanation = self.output_config.outputFormat in SemanticDiffQuery.get_supported_output_formats()
        res = 0
        for key in keys_list:
            conn_graph_added_conns = conn_graph_added_per_key[key]
            conn_graph_removed_conns = conn_graph_removed_per_key[key]
            is_added = conn_graph_added_conns is not None and conn_graph_added_conns.conn_graph_has_fw_rules()
            is_removed = conn_graph_removed_conns is not None and conn_graph_removed_conns.conn_graph_has_fw_rules()

            if (is_added or is_removed) and self.output_config.outputFormat == 'txt':
                explanation += f'{key}:\n'

            if is_added:
                explanation += self.get_explanation_from_conn_graph(True, conn_graph_added_conns,
                                                                    res == 0) if add_explanation else ''
                res += 1

            if is_removed:
                explanation += self.get_explanation_from_conn_graph(False, conn_graph_removed_conns,
                                                                    res == 0) if add_explanation else ''
                res += 1

        return res, explanation

    def get_conn_graph_changed_conns(self, key, ip_blocks, is_added):
        """
        create a ConnectivityGraph for chnged (added/removed) connections per given key
        :param key: the key (category) of changed connections
        :param ip_blocks: a PeerSet of ip-blocks to be added for the topology peers
        :param is_added: a bool flag indicating if connections are added or removed
        :return: a ConnectivityGraph object
        """
        old_peers = self.config1.peer_container.get_all_peers_group()
        new_peers = self.config2.peer_container.get_all_peers_group()
        allowed_labels = self.config1.allowed_labels.union(self.config2.allowed_labels)
        topology_peers = new_peers | ip_blocks if is_added else old_peers | ip_blocks
        updated_key = key.replace("Changed", "Added") if is_added else key.replace("Changed", "Removed")
        if self.output_config.queryName:
            query_name = f'semantic_diff, config1: {self.config1.name}, config2: {self.config2.name}, key: {updated_key}'
        else:
            # omit the query name prefix if self.output_config.queryName is empty (single query from command line)
            query_name = updated_key
        output_config = OutputConfiguration(self.output_config, query_name)
        config_type = self.config1.type if self.config1.type != NetworkConfig.ConfigType.Unknown else self.config2.type
        return ConnectivityGraph(topology_peers, allowed_labels, output_config, config_type)

    def compute_diff(self):  # noqa: C901
        """
       Compute changed connections as following:

       1.1. lost connections between removed peers
       1.2. lost connections between removed peers and ipBlocks

       2.1. lost connections between removed peers and intersected peers

       3.1. lost/new connections between intersected peers due to changes in policies and labels of pods/namespaces
       3.2. lost/new connections between intersected peers and ipBlocks due to changes in policies and labels

       4.1. new connections between intersected peers and added peers

       5.1. new connections between added peers
       5.2. new connections between added peers and ipBlocks

       Some sections might be empty and can be dropped.

       :return:
        res (int): number of categories with diffs
        explanation (str): a diff message

       """
        old_peers = self.config1.peer_container.get_all_peers_group()
        new_peers = self.config2.peer_container.get_all_peers_group()
        intersected_peers = old_peers & new_peers
        removed_peers = old_peers - intersected_peers
        added_peers = new_peers - intersected_peers
        captured_pods = (self.config1.get_captured_pods() | self.config2.get_captured_pods()) & intersected_peers
        old_ip_blocks = IpBlock.disjoint_ip_blocks(self.config1.get_referenced_ip_blocks(),
                                                   IpBlock.get_all_ips_block_peer_set())
        new_ip_blocks = IpBlock.disjoint_ip_blocks(self.config2.get_referenced_ip_blocks(),
                                                   IpBlock.get_all_ips_block_peer_set())

        conn_graph_removed_per_key = dict()
        conn_graph_added_per_key = dict()
        keys_list = []

        # 1.1. lost connections between removed peers
        key = 'Lost connections between removed peers'
        keys_list.append(key)
        conn_graph_removed_per_key[key] = self.get_conn_graph_changed_conns(key, PeerSet(), False)
        conn_graph_added_per_key[key] = None
        for pair in itertools.permutations(removed_peers, 2):
            lost_conns, _, _, _ = self.config1.allowed_connections(pair[0], pair[1])
            if lost_conns:
                conn_graph_removed_per_key[key].add_edge(pair[0], pair[1], lost_conns)

        # 1.2. lost connections between removed peers and ipBlocks
        key = 'Lost connections between removed peers and ipBlocks'
        keys_list.append(key)
        conn_graph_removed_per_key[key] = self.get_conn_graph_changed_conns(key, old_ip_blocks, False)
        conn_graph_added_per_key[key] = None
        for pair in itertools.product(removed_peers, old_ip_blocks):
            lost_conns, _, _, _ = self.config1.allowed_connections(pair[0], pair[1])
            if lost_conns:
                conn_graph_removed_per_key[key].add_edge(pair[0], pair[1], lost_conns)

            lost_conns, _, _, _ = self.config1.allowed_connections(pair[1], pair[0])
            if lost_conns:
                conn_graph_removed_per_key[key].add_edge(pair[1], pair[0], lost_conns)

        # 2.1. lost connections between removed peers and intersected peers
        key = 'Lost connections between removed peers and persistent peers'
        keys_list.append(key)
        conn_graph_removed_per_key[key] = self.get_conn_graph_changed_conns(key, PeerSet(), False)
        conn_graph_added_per_key[key] = None
        for pair in itertools.product(removed_peers, intersected_peers):
            lost_conns, _, _, _ = self.config1.allowed_connections(pair[0], pair[1])
            if lost_conns:
                conn_graph_removed_per_key[key].add_edge(pair[0], pair[1], lost_conns)

            lost_conns, _, _, _ = self.config1.allowed_connections(pair[1], pair[0])
            if lost_conns:
                conn_graph_removed_per_key[key].add_edge(pair[1], pair[0], lost_conns)

        # 3.1. lost/new connections between intersected peers due to changes in policies and labels of pods/namespaces
        key = 'Changed connections between persistent peers'
        keys_list.append(key)
        conn_graph_removed_per_key[key] = self.get_conn_graph_changed_conns(key, PeerSet(), False)
        conn_graph_added_per_key[key] = self.get_conn_graph_changed_conns(key, PeerSet(), True)
        for pod1 in intersected_peers:
            for pod2 in intersected_peers if pod1 in captured_pods else captured_pods:
                if pod1 == pod2:
                    continue
                old_conns, _, _, _ = self.config1.allowed_connections(pod1, pod2)
                new_conns, _, _, _ = self.config2.allowed_connections(pod1, pod2)
                if new_conns != old_conns:
                    conn_graph_removed_per_key[key].add_edge(pod1, pod2, old_conns - new_conns)
                    conn_graph_added_per_key[key].add_edge(pod1, pod2, new_conns - old_conns)

        # 3.2. lost/new connections between intersected peers and ipBlocks due to changes in policies and labels
        key = 'Changed connections between persistent peers and ipBlocks'
        disjoint_ip_blocks = IpBlock.disjoint_ip_blocks(old_ip_blocks, new_ip_blocks)
        peers = captured_pods | disjoint_ip_blocks
        keys_list.append(key)
        conn_graph_removed_per_key[key] = self.get_conn_graph_changed_conns(key, disjoint_ip_blocks, False)
        conn_graph_added_per_key[key] = self.get_conn_graph_changed_conns(key, disjoint_ip_blocks, True)
        for pod1 in peers:
            for pod2 in disjoint_ip_blocks if pod1 in captured_pods else captured_pods:
                old_conns, _, _, _ = self.config1.allowed_connections(pod1, pod2)
                new_conns, _, _, _ = self.config2.allowed_connections(pod1, pod2)
                if new_conns != old_conns:
                    conn_graph_removed_per_key[key].add_edge(pod1, pod2, old_conns - new_conns)
                    conn_graph_added_per_key[key].add_edge(pod1, pod2, new_conns - old_conns)

        # 4.1. new connections between intersected peers and added peers
        key = 'New connections between persistent peers and added peers'
        keys_list.append(key)
        conn_graph_removed_per_key[key] = None
        conn_graph_added_per_key[key] = self.get_conn_graph_changed_conns(key, PeerSet(), True)
        for pair in itertools.product(intersected_peers, added_peers):
            new_conns, _, _, _ = self.config2.allowed_connections(pair[0], pair[1])
            if new_conns:
                conn_graph_added_per_key[key].add_edge(pair[0], pair[1], new_conns)

            new_conns, _, _, _ = self.config2.allowed_connections(pair[1], pair[0])
            if new_conns:
                conn_graph_added_per_key[key].add_edge(pair[1], pair[0], new_conns)

        # 5.1. new connections between added peers
        key = 'New connections between added peers'
        keys_list.append(key)
        conn_graph_removed_per_key[key] = None
        conn_graph_added_per_key[key] = self.get_conn_graph_changed_conns(key, PeerSet(), True)
        for pair in itertools.permutations(added_peers, 2):
            new_conns, _, _, _ = self.config2.allowed_connections(pair[0], pair[1])
            if new_conns:
                conn_graph_added_per_key[key].add_edge(pair[0], pair[1], new_conns)

        # 5.2. new connections between added peers and ipBlocks
        key = 'New connections between added peers and ipBlocks'
        keys_list.append(key)
        conn_graph_removed_per_key[key] = None
        conn_graph_added_per_key[key] = self.get_conn_graph_changed_conns(key, new_ip_blocks, True)

        for pair in itertools.product(added_peers, new_ip_blocks):
            new_conns, _, _, _ = self.config2.allowed_connections(pair[0], pair[1])
            if new_conns:
                conn_graph_added_per_key[key].add_edge(pair[0], pair[1], new_conns)

            new_conns, _, _, _ = self.config2.allowed_connections(pair[1], pair[0])
            if new_conns:
                conn_graph_added_per_key[key].add_edge(pair[1], pair[0], new_conns)

        return self.get_results_for_computed_fw_rules(keys_list, conn_graph_removed_per_key,
                                                      conn_graph_added_per_key)

    def exec(self):
        query_answer = self.is_identical_topologies(True)
        if query_answer.bool_result and query_answer.output_result:
            return query_answer
        res, explanation = self.compute_diff()
        if res > 0:
            return QueryAnswer(bool_result=False,
                               output_result=f'{self.name1} and {self.name2} are not semantically equivalent.\n',
                               output_explanation=explanation,
                               numerical_result=res)

        return QueryAnswer(bool_result=True,
                           output_result=f'{self.name1} and {self.name2} are semantically equivalent.\n',
                           output_explanation=explanation,
                           numerical_result=res)

    def compute_query_output(self, query_answer, cmd_line_flag=False):
        res = query_answer.numerical_result if not cmd_line_flag else not query_answer.bool_result
        query_output = ''
        if self.output_config.outputFormat == 'txt':
            query_output += query_answer.output_result
        query_output += query_answer.output_explanation
        return res, query_output


class StrongEquivalenceQuery(TwoNetworkConfigsQuery):
    """
    Checks whether the two configs have exactly the same set of policies (same names and same semantics)
    """

    @staticmethod
    def get_query_type():
        return QueryType.PairComparisonQuery

    def exec(self):
        query_answer = self.is_identical_topologies(True)
        if query_answer.output_result:
            return query_answer

        policies1 = set(self.config1.policies.keys())
        policies2 = set(self.config2.policies.keys())
        policies_1_minus_2 = policies1.difference(policies2)
        policies_2_minus_1 = policies2.difference(policies1)
        if policies_1_minus_2:
            output_result = f'{self.name1} contains a network policy named {policies_1_minus_2.pop()}, but ' \
                            f'{self.name2} does not'
            return QueryAnswer(False, output_result)
        if policies_2_minus_1:
            output_result = f'{self.name2} contains a network policy named {policies_2_minus_1.pop()}, but ' \
                            f'{self.name1} does not'
            return QueryAnswer(False, output_result)

        for policy in self.config1.policies.values():
            single_policy_config1 = self.config1.clone_with_just_one_policy(policy.full_name())
            single_policy_config2 = self.config2.clone_with_just_one_policy(policy.full_name())
            full_result = EquivalenceQuery(single_policy_config1, single_policy_config2).exec()
            if not full_result.bool_result:
                output_result = f'{policy.full_name()} is not equivalent in {self.name1} and in {self.name2}'
                return QueryAnswer(False, output_result, full_result.output_explanation)

        return QueryAnswer(True, self.name1 + ' and ' + self.name2 + ' are strongly equivalent.')

    @staticmethod
    def compute_query_output(query_answer, cmd_line_flag=False):
        return EquivalenceQuery.compute_query_output(query_answer, cmd_line_flag)


class ContainmentQuery(TwoNetworkConfigsQuery):
    """
    Checking whether the connections allowed by config1 are contained in those allowed by config2
    """

    def exec(self, only_captured=False):
        config1_peers = self.config1.peer_container.get_all_peers_group()
        peers_in_config1_not_in_config2 = config1_peers - self.config2.peer_container.get_all_peers_group()
        if peers_in_config1_not_in_config2:
            peers = ', '.join(str(e) for e in peers_in_config1_not_in_config2)
            return QueryAnswer(False, f'{self.name1} is not contained in {self.name2} '
                                      f'because the following pods in {self.name1} are not in {self.name2}: {peers}')

        peers_to_compare = config1_peers | self.disjoint_referenced_ip_blocks()
        captured_pods = self.config1.get_captured_pods() | self.config2.get_captured_pods()
        for peer1 in peers_to_compare:
            for peer2 in peers_to_compare if peer1 in captured_pods else captured_pods:
                if peer1 == peer2:
                    continue
                conns1_all, captured1_flag, conns1_captured, _ = self.config1.allowed_connections(peer1, peer2)
                if only_captured and not captured1_flag:
                    continue
                conns1 = conns1_captured if only_captured else conns1_all
                conns2, _, _, _ = self.config2.allowed_connections(peer1, peer2)
                if not conns1.contained_in(conns2):
                    output_result = f'{self.name1} is not contained in {self.name2}'
                    output_explanation = f'Allowed connections from {peer1} to {peer2} in {self.name1} ' \
                                         f'are not a subset of those in {self.name2}\n'
                    output_explanation += conns1.print_diff(conns2, self.name1, self.name2)
                    return QueryAnswer(False, output_result, output_explanation)

        output_result = self.name1 + ' is contained in ' + self.name2
        return QueryAnswer(True, output_result, numerical_result=1)

    @staticmethod
    def compute_query_output(query_answer, cmd_line_flag=False):
        res = query_answer.numerical_result if not cmd_line_flag else not query_answer.bool_result
        query_output = query_answer.output_result + query_answer.output_explanation + '\n'
        return res, query_output


class TwoWayContainmentQuery(TwoNetworkConfigsQuery):
    """
    Checks containment in both sides (whether config1 is contained in config2 and vice versa)
    """

    @staticmethod
    def get_query_type():
        return QueryType.PairComparisonQuery

    def exec(self):
        query_answer = self.is_identical_topologies(True)
        if query_answer.bool_result and query_answer.output_result:
            return query_answer  # identical configurations (contained)

        contained_1_in_2 = ContainmentQuery(self.config1, self.config2).exec()
        contained_2_in_1 = ContainmentQuery(self.config2, self.config1).exec()
        explanation_not_contained_self_other = \
            contained_1_in_2.output_result + ':\n\t' + contained_1_in_2.output_explanation
        explanation_not_contained_other_self = \
            contained_2_in_1.output_result + ':\n\t' + contained_2_in_1.output_explanation
        if contained_1_in_2.bool_result and contained_2_in_1.bool_result:
            return QueryAnswer(bool_result=True,
                               output_result=f'The two network configurations {self.name1} and {self.name2} '
                                             'are semantically equivalent.',
                               numerical_result=3)
        if not contained_1_in_2.bool_result and not contained_2_in_1.bool_result:
            output_explanation = explanation_not_contained_self_other + '\n' + explanation_not_contained_other_self
            return QueryAnswer(bool_result=False,
                               output_result=f'Neither network configuration {self.name1} and {self.name2} '
                                             'are contained in the other.',
                               output_explanation=output_explanation, numerical_result=0)
        if contained_1_in_2.bool_result:
            return QueryAnswer(bool_result=False,
                               output_result=f'Network configuration {self.name1} is a proper subset of {self.name2}.',
                               output_explanation=explanation_not_contained_other_self, numerical_result=2)
        # (contained_2_in_1)
        return QueryAnswer(bool_result=False,
                           output_result=f'Network configuration {self.name2} is a proper subset of {self.name1}.',
                           output_explanation=explanation_not_contained_self_other, numerical_result=1)

    @staticmethod
    def compute_query_output(query_answer, cmd_line_flag=False):
        return ContainmentQuery.compute_query_output(query_answer, cmd_line_flag)


class PermitsQuery(TwoNetworkConfigsQuery):
    """
    Checking whether the connections explicitly allowed by config1 are allowed by config2
    """

    def exec(self):
        if not self.config1:
            return QueryAnswer(False,
                               output_result='There are no NetworkPolicies in the given permits config. '
                                             'No traffic is specified as permitted.')
        query_answer = self.is_identical_topologies()
        if query_answer.output_result:
            return query_answer  # non-identical configurations are not comparable

        return ContainmentQuery(self.config1, self.config2).exec(True)

    def compute_query_output(self, query_answer, cmd_line_flag=False):
        res = 0
        if not query_answer.bool_result:
            if not query_answer.output_explanation:
                query_output = query_answer.output_result
            else:
                res = 1
                query_output = f'{self.config2.name} does not permit connections specified in {self.config1.name}:'
                query_output += query_answer.output_explanation
        else:
            query_output = f'{self.config2.name} permits all connections specified in {self.config1.name}'
        if cmd_line_flag:
            res = not query_answer.bool_result
        return res, query_output


class InterferesQuery(TwoNetworkConfigsQuery):
    """
    Checking whether config2 extends config1's allowed connection for Pods captured by policies in config1
    """

    def exec(self):
        query_answer = self.is_identical_topologies()
        if query_answer.output_result:
            return query_answer

        peers_to_compare = self.config2.peer_container.get_all_peers_group()
        peers_to_compare |= self.disjoint_referenced_ip_blocks()
        captured_pods = self.config2.get_captured_pods() | self.config1.get_captured_pods()
        for peer1 in peers_to_compare:
            for peer2 in peers_to_compare if peer1 in captured_pods else captured_pods:
                if peer1 == peer2:
                    continue

                _, captured1_flag, conns1_captured, _ = self.config2.allowed_connections(peer1, peer2)
                if not captured1_flag:
                    continue
                _, captured2_flag, conns2_captured, _ = self.config1.allowed_connections(peer1, peer2)
                if captured2_flag and not conns2_captured.contained_in(conns1_captured):
                    output_explanation = f'{self.name1} extends the allowed connections from {peer1} to {peer2}\n' + \
                                         conns2_captured.print_diff(conns1_captured, self.name1, self.name2)
                    return QueryAnswer(True, self.name1 + ' interferes with ' + self.name2, output_explanation)

        return QueryAnswer(False, self.name1 + ' does not interfere with ' + self.name2)

    @staticmethod
    def compute_query_output(query_answer, cmd_line_flag=False):
        res = query_answer.bool_result if not cmd_line_flag else not query_answer.bool_result
        query_output = query_answer.output_result
        if query_answer.bool_result:
            query_output += query_answer.output_explanation
        return res, query_output


class PairwiseInterferesQuery(TwoNetworkConfigsQuery):

    @staticmethod
    def get_query_type():
        return QueryType.PairwiseComparisonQuery

    def exec(self):
        return InterferesQuery(self.config1, self.config2).exec()

    @staticmethod
    def compute_query_output(query_answer, cmd_line_flag=False):
        return InterferesQuery.compute_query_output(query_answer, cmd_line_flag)


class IntersectsQuery(TwoNetworkConfigsQuery):
    """
    Checking whether both configs allow the same connection between any pair of peers
    """

    def exec(self, only_captured=True):
        query_answer = self.is_identical_topologies()
        if query_answer.output_result:
            return query_answer

        peers_to_compare = self.config1.peer_container.get_all_peers_group()
        peers_to_compare |= self.disjoint_referenced_ip_blocks()
        captured_pods = self.config1.get_captured_pods() | self.config2.get_captured_pods()
        for peer1 in peers_to_compare:
            for peer2 in peers_to_compare if peer1 in captured_pods else captured_pods:
                if peer1 == peer2:
                    continue
                conns1_all, captured1_flag, conns1_captured, _ = self.config1.allowed_connections(peer1, peer2)
                if only_captured and not captured1_flag:
                    continue
                conns1 = conns1_captured if only_captured else conns1_all
                conns2, _, _, _ = self.config2.allowed_connections(peer1, peer2)
                conns_in_both = conns2 & conns1
                if bool(conns_in_both):
                    output_explanation = f'Both {self.name1} and {self.name2} allow the following connection ' \
                                         f'from {peer1} to {peer2}\n'
                    output_explanation += str(conns_in_both)
                    return QueryAnswer(True, self.name2 + ' intersects with ' + self.name1, output_explanation)

        return QueryAnswer(False, f'The connections allowed by {self.name1}'
                                  f' do not intersect the connections allowed by {self.name2}', numerical_result=1)


class ForbidsQuery(TwoNetworkConfigsQuery):

    def exec(self):
        if not self.config1:
            return QueryAnswer(False, 'There are no NetworkPolicies in the given forbids config. '
                                      'No traffic is specified as forbidden.')
        return IntersectsQuery(self.config1, self.config2).exec(True)

    def compute_query_output(self, query_answer, cmd_line_flag=False):
        res = not query_answer.numerical_result if cmd_line_flag else query_answer.bool_result
        query_output = query_answer.output_result + '\n'
        if query_answer.bool_result:
            query_output += f'{self.config2.name} does not forbid connections specified in {self.config1.name}: ' \
                            f'{query_answer.output_explanation}'
        elif query_answer.numerical_result == 1:
            query_output += f'{self.config2.name} forbids connections specified in {self.config1.name}'
        return res, query_output


class AllCapturedQuery(NetworkConfigQuery):
    """
    Check that all pods are captured
    """

    def _get_pod_name(self, pod):
        """
        :param Pod pod: a pod object
        :rtype str
        """
        return pod.workload_name if self.output_config.outputEndpoints == 'deployments' else str(pod)

    def _get_uncaptured_resources_explanation(self, uncaptured_pods, is_ingress):
        """
        get numerical result + str explanation for ingress/egress uncaptured pods
        :param PeerSet uncaptured_pods: the set of uncaptured
        :param bool is_ingress: flag indicating if pods are not captured by any policy that affects ingress or egress
        :return: (int,str): (the number of uncaptured resources , explanation str)
        """
        if not uncaptured_pods:
            return 0, ''
        uncaptured_resources = set(self._get_pod_name(pod) for pod in uncaptured_pods)  # no duplicate resources in set
        resources_list_str = ', '.join(e for e in uncaptured_resources)
        xgress_str = 'ingress' if is_ingress else 'egress'
        explanation = f'These workload resources are not captured by any policy that affects {xgress_str}:' \
                      f'{resources_list_str}\n'
        return len(uncaptured_resources), explanation

    def exec(self):
        existing_pods = self.config.peer_container.get_all_peers_group()

        if not self.config:
            return QueryAnswer(bool_result=False,
                               output_result='Flat network in ' + self.config.name,
                               numerical_result=len(existing_pods))

        uncaptured_ingress_pods = existing_pods - self.config.get_affected_pods(is_ingress=True)
        uncaptured_egress_pods = existing_pods - self.config.get_affected_pods(is_ingress=False)

        if not uncaptured_ingress_pods and not uncaptured_egress_pods:
            return QueryAnswer(bool_result=True,
                               output_result='All pods are captured by at least one policy in ' + self.config.name,
                               numerical_result=0)

        res_ingress, explanation_ingress = self._get_uncaptured_resources_explanation(uncaptured_ingress_pods, True)
        res_egress, explanation_egress = self._get_uncaptured_resources_explanation(uncaptured_egress_pods, False)
        res = res_ingress + res_egress
        full_explanation = explanation_ingress + explanation_egress

        return QueryAnswer(bool_result=False,
                           output_result=f'There are workload resources not captured by any policy in {self.config.name}\n',
                           output_explanation=full_explanation, numerical_result=res)

    def compute_query_output(self, query_answer):
        return self.get_query_output(query_answer, False, not query_answer.bool_result)
