#
# Copyright 2020- IBM Inc. All rights reserved
# SPDX-License-Identifier: Apache2.0
#
import itertools
import os
import time
from abc import abstractmethod
from collections import defaultdict
from enum import Enum

from nca.CoreDS.ConnectionSet import ConnectionSet
from nca.CoreDS.Peer import PeerSet, IpBlock, Pod, Peer, DNSEntry
from nca.CoreDS.ProtocolSet import ProtocolSet
from nca.CoreDS.ConnectivityProperties import ConnectivityProperties
from nca.FWRules.ConnectivityGraph import ConnectivityGraph
from nca.FWRules.MinimizeFWRules import MinimizeFWRules
from nca.FWRules.ClusterInfo import ClusterInfo
from nca.Resources.CalicoNetworkPolicy import CalicoNetworkPolicy
from nca.Resources.IngressPolicy import IngressPolicy
from nca.Utils.OutputConfiguration import OutputConfiguration
from .QueryOutputHandler import QueryAnswer, DictOutputHandler, StringOutputHandler, \
    PoliciesAndRulesExplanations, PodsListsExplanations, ConnectionsDiffExplanation, IntersectPodsExplanation, \
    PoliciesWithCommonPods, PeersAndConnections, ComputedExplanation
from .NetworkLayer import NetworkLayerName
from nca.Utils.ExplTracker import ExplTracker


class QueryType(Enum):
    SingleConfigQuery = 0
    ComparisonToBaseConfigQuery = 1
    PairComparisonQuery = 2
    PairwiseComparisonQuery = 3


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
        return {'txt', 'yaml', 'json'}

    @staticmethod
    def policy_title(policy):
        """
        Return the title of the given policy, including the type name and the policy name
        :param policy: the given policy
        :return: the title of the policy
        """
        return f'{policy.policy_type_str()} {policy.full_name()}'

    def execute_and_compute_output_in_required_format(self, cmd_line_flag=False):
        """
        calls the exec def of the running query, computes its output to fit the required format and returns query
        results and output
        :param cmd_line_flag: indicates if the query is running from a cmd-line, since it affects computing the
        numerical result of some of TwoNetworkConfigsQuery queries
        :return: the numerical result of the query,
        the query output in form to be written in required format if supported (otherwise empty string),
        and bool indicator if the query was not executed
        :rtype: int, Union[dict, str], bool
        """
        for config in self.get_configs():
            if not config.peer_container.get_num_peers():
                error_msg = f'Error: Network configuration \'{config.name}\' does not have any peers. Can not run Query'
                query_answer = QueryAnswer(output_result=error_msg, query_not_executed=True)
                return query_answer.numerical_result, self._handle_output(query_answer), query_answer.query_not_executed
        if self.output_config.outputFormat not in self.get_supported_output_formats():
            query_answer = QueryAnswer(query_not_executed=True)
            return query_answer.numerical_result, '', query_answer.query_not_executed
        query_answer = self.execute(cmd_line_flag)
        return query_answer.numerical_result, self._handle_output(query_answer), query_answer.query_not_executed

    def _handle_output(self, query_answer):
        """
        handles returning the output of the running query in a form that matches writing required format
        Using the relevant OutputHandler class
        :param QueryAnswer query_answer: the query result of running its exec def
        :return: the output in required format
        :rtype: Union[str, dict] - dict when required format is json/ yaml, otherwise str
        """
        query_name = self.output_config.queryName or type(self).__name__
        configs = self.get_configs_names()
        if self.output_config.outputFormat in ['yaml', 'json']:
            return DictOutputHandler(configs, query_name).compute_query_output(query_answer)
        return StringOutputHandler(self.output_config.outputFormat == 'txt').compute_query_output(query_answer)

    @abstractmethod
    def execute(self, cmd_line_flag):
        """
        this method is a wrapper method for calling exec def, since exec does not need
        the cmd_line_flag param for classes derived from NetworkConfigQuery
        :rtype: QueryAnswer
        """
        raise NotImplementedError

    @abstractmethod
    def get_configs_names(self):
        raise NotImplementedError

    @abstractmethod
    def get_configs(self):
        raise NotImplementedError

    # this def contains conditions that should be checked every time before computing
    # allowed connections of two peers, so added it here to avoid duplications in the queries code
    @staticmethod
    def determine_whether_to_compute_allowed_conns_for_peer_types(peer1, peer2):
        """
        determines if to continue to compute allowed connections for the given
        pair of peers based on their types
        :param Peer peer1: the src peer
        :param Peer peer2: the dst peer
        :rtype: bool
        """
        if isinstance(peer1, DNSEntry):  # connections from DNSEntry are not relevant
            return False
        if isinstance(peer1, IpBlock) and isinstance(peer2, (IpBlock, DNSEntry)):
            return False  # connectivity between external peers is not relevant either
        return True


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

    def get_configs_names(self):
        """
        returns the config name of the query's config
        :rtype: list[str]
        """
        return [self.config.name]

    def get_configs(self):
        """
        returns the config
        :rtype: list[NetworksConfig]
        """
        return [self.config]

    @staticmethod
    def get_query_type():
        return QueryType.SingleConfigQuery

    def execute(self, cmd_line_flag):
        return self.exec()

    @abstractmethod
    def exec(self):
        raise NotImplementedError

    def filter_conns_by_peer_types(self, conns, all_peers):
        """
        Filter the given connections by removing several connection kinds that are never allowed
        (such as IpBlock to IpBlock connections, connections from DNSEntries, and more).
        :param ConnectivityProperties conns: the given connections.
        :param PeerSet all_peers: all peers in the system.
        :return The resulting connections.
        :rtype ConnectivityProperties
        """
        res = conns
        # avoid IpBlock -> {IpBlock, DNSEntry} connections
        all_ips = IpBlock.get_all_ips_block_peer_set()
        all_dns_entries = self.config.peer_container.get_all_dns_entries()
        ip_to_ip_or_dns_conns = ConnectivityProperties.make_conn_props_from_dict({"src_peers": all_ips,
                                                                                  "dst_peers": all_ips | all_dns_entries})
        res -= ip_to_ip_or_dns_conns
        # avoid DNSEntry->anything connections
        dns_to_any_conns = ConnectivityProperties.make_conn_props_from_dict({"src_peers": all_dns_entries,
                                                                             "dst_peers": all_peers})
        res -= dns_to_any_conns
        return res

    def filter_conns_by_peer_types(self, conns, all_peers):
        res = conns
        # avoid IpBlock -> {IpBlock, DNSEntry} connections
        all_ips = IpBlock.get_all_ips_block_peer_set()
        all_dns_entries = self.config.peer_container.get_all_dns_entries()
        ip_to_ip_or_dns_conns = ConnectivityProperties.make_conn_props_from_dict({"src_peers": all_ips,
                                                                                  "dst_peers": all_ips | all_dns_entries})
        res -= ip_to_ip_or_dns_conns
        # avoid DNSEntry->anything connections
        dns_to_any_conns = ConnectivityProperties.make_conn_props_from_dict({"src_peers": all_dns_entries,
                                                                             "dst_peers": all_peers})
        res -= dns_to_any_conns
        # avoid anything->DNSEntry connections if Istio layer does not exist
        if not self.config.policies_container.layers.does_contain_layer(NetworkLayerName.Istio):
            any_to_dns_conns = ConnectivityProperties.make_conn_props_from_dict({"src_peers": all_peers,
                                                                                 "dst_peers": all_dns_entries})
            res -= any_to_dns_conns
        return res


class DisjointnessQuery(NetworkConfigQuery):
    """
    Check whether no two policy in the config capture the same peer
    """

    def exec(self):
        # collecting non-disjoint policies per network layer
        non_disjoint_explanation_list = []
        for layer_name, layer in self.config.policies_container.layers.items():
            if layer_name == NetworkLayerName.Ingress:  # skip ingress layer
                continue
            policies_list = layer.policies_list
            for policy1 in policies_list:
                if policy1.is_policy_empty():
                    continue
                for policy2 in policies_list:
                    if policy1 == policy2:
                        break
                    intersection = policy1.selected_peers & policy2.selected_peers
                    if intersection:
                        common_pods = sorted([str(e) for e in intersection]) if self.output_config.fullExplanation \
                            else [intersection.rep()]
                        non_disjoint_explanation_list.append(PoliciesWithCommonPods(policy1.policy_type_str(),
                                                                                    policy1.full_name(),
                                                                                    policy2.policy_type_str(),
                                                                                    policy2.full_name(),
                                                                                    common_pods))

        if not non_disjoint_explanation_list:
            return QueryAnswer(True, output_result='All policies are disjoint in ' + self.config.name,
                               numerical_result=0)

        final_explanation = IntersectPodsExplanation(explanation_description='policies with overlapping captured pods',
                                                     policies_pods=sorted(non_disjoint_explanation_list))
        return QueryAnswer(False, output_result='There are policies capturing the same pods in ' + self.config.name,
                           output_explanation=[final_explanation], numerical_result=len(non_disjoint_explanation_list))


class EmptinessQuery(NetworkConfigQuery):
    """
    Check if any policy or one of its rules captures an empty set of peers
    """

    def exec(self):
        self.output_config.fullExplanation = True  # assign true for this query - it is always ok to compare its results
        all_policies_list = []
        for layer_name, layer in self.config.policies_container.layers.items():
            all_policies_list += layer.policies_list

        res = 0
        empty_policies = []
        empty_ingress_rules = {}
        empty_egress_rules = {}
        for policy in sorted(all_policies_list):
            cnt = 0
            if policy.is_policy_empty():
                cnt += 1
                empty_policies.append(self.policy_title(policy))
            _, ingress_rules, egress_rules = policy.has_empty_rules(self.config.name)
            if ingress_rules:
                cnt += len(ingress_rules)
                empty_ingress_rules.update({self.policy_title(policy): sorted(ingress_rules)})
            if egress_rules:
                cnt += len(egress_rules)
                empty_egress_rules.update({self.policy_title(policy): sorted(egress_rules)})
            if cnt:
                res += cnt
        if not res:
            return QueryAnswer(False, 'No empty NetworkPolicies and no empty rules in ' + self.config.name,
                               numerical_result=res)

        final_explanation = PoliciesAndRulesExplanations(explanation_description=' that does not select any pods',
                                                         policies_list=empty_policies,
                                                         policies_to_ingress_rules_dict=empty_ingress_rules,
                                                         policies_to_egress_rules_dict=empty_egress_rules)
        return QueryAnswer(res > 0,
                           'There are empty NetworkPolicies and/or empty ingress/egress rules in ' + self.config.name,
                           output_explanation=[final_explanation], numerical_result=res)


class VacuityQuery(NetworkConfigQuery):
    """
    Check if the set of policies changes the cluster's default behavior
    """

    def exec(self):
        # TODO: should handle 'ingress' layer or not? (ingress controller pod is not expected to have egress
        #  traffic without any Ingress resource)
        #  currently ignoring ingres layer, removing it from configs on this query
        self.output_config.fullExplanation = True  # assign true for this query - it is ok to compare its results
        vacuous_config = self.config.clone_without_policies('vacuousConfig')
        self_config = TwoNetworkConfigsQuery.clone_without_ingress(self.config)
        vacuous_res = EquivalenceQuery(self_config, vacuous_config).exec()
        if not vacuous_res.bool_result:
            return QueryAnswer(vacuous_res.bool_result,
                               output_result=f'Network configuration {self.config.name} is not vacuous',
                               numerical_result=vacuous_res.bool_result)

        output_result = f'Network configuration {self.config.name} is vacuous - it allows all default connections'
        return QueryAnswer(bool_result=vacuous_res.bool_result, output_result=output_result,
                           numerical_result=vacuous_res.bool_result)


class RedundancyQuery(NetworkConfigQuery):
    """
    Check if any of the policies can be removed without changing cluster connectivity. Same for each rule in each policy
    """

    def redundant_policies(self, policies_list, layer_name):
        """
        Assuming that the input policies list is within a single layer.
        Check if any of the policies in the given list can be removed without changing cluster connectivity.
        :param list[NetworkPolicy.NetworkPolicy] policies_list: the list of policies to check
        :param NetworkLayerName layer_name: the name of the layer the policies are in
        :return: set of redundant policy names
        :rtype: set[str]
        """
        res = 0
        redundant_policies = set()
        # Checking for redundant policies
        # TODO: should a config with 1 policy that is vacuous be considered redundant?
        if len(policies_list) > 1:
            for policy in policies_list:
                config_without_policy = self.config.clone_without_policy(policy)
                # limit the equivalence per relevant layer: one layer's policy should not be considered redundant
                # if its connectivity is contained in a different policy from another layer
                if EquivalenceQuery(self.config, config_without_policy).exec(layer_name=layer_name).bool_result:
                    res += 1
                    redundant_policies.add(policy.full_name())
        return redundant_policies

    def find_redundant_rules(self, policy, layer_name):
        """
        Find redundant rules in the given policy.
        Consider redundancy only with respect to connectivity of the given layer of the policy.
        :param NetworkPolicy.NetworkPolicy policy: the policy to check
        :param NetworkLayerName layer_name: the name of the layer the policies are in
        :return: A tuple of :
                (1) list of redundant ingress rules indexes
                (2) list of redundant egress rules indexes
        :rtype: (list[int], list[int])
        """
        # Checking for redundant ingress/egress rules
        redundant_ingress_rules = []
        redundant_egress_rules = []
        for rule_index, ingress_rule in enumerate(policy.ingress_rules, start=1):
            modified_policy = policy.clone_without_rule(ingress_rule, True)
            if len(modified_policy.ingress_rules) < len(policy.ingress_rules) - 1:
                redundant_ingress_rules.append(rule_index)
                continue
            config_with_modified_policy = self.config.clone_without_policy(policy)
            config_with_modified_policy.append_policy_to_config(modified_policy)
            equiv_result = EquivalenceQuery(self.config, config_with_modified_policy).exec(layer_name=layer_name)
            if equiv_result.bool_result:
                redundant_ingress_rules.append(rule_index)
        for rule_index, egress_rule in enumerate(policy.egress_rules, start=1):
            modified_policy = policy.clone_without_rule(egress_rule, False)
            if len(modified_policy.egress_rules) < len(policy.egress_rules) - 1:
                redundant_egress_rules.append(rule_index)
                continue
            config_with_modified_policy = self.config.clone_without_policy(policy)
            config_with_modified_policy.append_policy_to_config(modified_policy)
            if EquivalenceQuery(self.config, config_with_modified_policy).exec(layer_name=layer_name).bool_result:
                redundant_egress_rules.append(rule_index)
        return redundant_ingress_rules, redundant_egress_rules

    def exec(self):
        res = 0
        redundant_policies = []
        redundant_ingress_rules = {}
        redundant_egress_rules = {}
        self.output_config.fullExplanation = True  # assign true for this query - it is ok to compare its results
        for layer_name, layer in self.config.policies_container.layers.items():
            if layer_name == NetworkLayerName.Ingress:
                continue
            policies_list = layer.policies_list
            redundant_policies = sorted(list(self.redundant_policies(policies_list, layer_name)))
            res += len(redundant_policies)

            # Checking for redundant ingress/egress rules
            for policy in sorted(policies_list):
                if policy.full_name() in redundant_policies:  # we skip checking rules if the whole policy is redundant
                    continue
                ingress_rules, egress_rules = self.find_redundant_rules(policy, layer_name)
                if ingress_rules:
                    res += len(ingress_rules)
                    redundant_ingress_rules.update({self.policy_title(policy): sorted(ingress_rules)})
                if egress_rules:
                    res += len(egress_rules)
                    redundant_egress_rules.update({self.policy_title(policy): sorted(egress_rules)})

        if res > 0:
            final_explanation = \
                PoliciesAndRulesExplanations(explanation_description=f' that are redundant in {self.config.name}',
                                             policies_list=redundant_policies,
                                             policies_to_ingress_rules_dict=redundant_ingress_rules,
                                             policies_to_egress_rules_dict=redundant_egress_rules)
            return QueryAnswer(True, output_result='Redundancies found in ' + self.config.name,
                               output_explanation=[final_explanation], numerical_result=res)
        return QueryAnswer(False, 'No redundancy found in ' + self.config.name)


class SanityQuery(NetworkConfigQuery):
    """
    Perform various queries to check the network config sanity. Checks vacuity, redundancy and emptiness
    """

    @staticmethod
    def get_supported_output_formats():
        return {'txt'}

    def has_conflicting_policies_with_same_order(self):
        """
        Check if there are Calico policies with the same order but conflicting rules.
        :return: (bool result, conflict str)
        :rtype: (bool, str)
        """
        if NetworkLayerName.K8s_Calico not in self.config.policies_container.layers:
            return False, ''
        calico_policies = self.config.policies_container.layers[NetworkLayerName.K8s_Calico].policies_list
        calico_policies = [policy for policy in calico_policies if isinstance(policy, CalicoNetworkPolicy)]
        if len(calico_policies) <= 1:
            return False, ''

        curr_set = []
        for policy in calico_policies:
            if curr_set:
                policy_in_curr_set = next(iter(curr_set))
                if policy_in_curr_set < policy:
                    curr_set.clear()
                else:  # policy has same priority as policies in curr_set
                    for other_policy in curr_set:
                        # TODO: add support for finding conflicting policies between k8s and calico?
                        if policy.is_conflicting(other_policy):
                            conflict_str = '{} and {} have same order but conflicting rules. Behavior is ' \
                                           'undefined.'.format(self.policy_title(policy),
                                                               self.policy_title(other_policy))
                            policy.add_finding(conflict_str)
                            other_policy.add_finding(conflict_str)
                            return True, conflict_str
            curr_set.append(policy)
        return False, ''

    def other_policy_containing_allow(self, self_policy, config_with_self_policy, layer_name):
        """
        Search for a policy which contains all allowed connections specified by self_policy
        :param NetworkPolicy self_policy: The policy to check
        :param NetworkConfig config_with_self_policy: A network config with self_policy as its single policy
        :param NetworkLayerName layer_name: The layer name of the policy
        :return: A policy containing self_policy's allowed connections if exist, None otherwise
        :rtype: NetworkPolicy
        """
        policies_list = self.config.policies_container.layers[layer_name].policies_list
        for other_policy in policies_list:
            if other_policy.get_order() and self_policy.get_order() and \
                    other_policy.get_order() < self_policy.get_order():
                return None  # All other policies have a lower order and cannot contain self_policy
            if other_policy == self_policy:
                continue
            if not self_policy.selected_peers.issubset(other_policy.selected_peers):
                continue
            config_with_other_policy = self.config.clone_with_just_one_policy(other_policy.full_name())
            if ContainmentQuery(config_with_self_policy, config_with_other_policy).exec(only_captured=True).bool_result:
                return other_policy
        return None

    def other_policy_containing_deny(self, self_policy, config_with_self_policy, layer_name):
        """
        Search for a policy which contains all denied connections specified by self_policy
        :param NetworkPolicy self_policy: The policy to check
        :param NetworkConfig config_with_self_policy: A network config with self_policy as its single policy
        :param NetworkLayerName layer_name: The layer name of the policy
        :return: A policy containing self_policy's denied connections if exist, None otherwise
        :rtype: NetworkPolicy
        """
        policies_list = self.config.policies_container.layers[layer_name].policies_list
        for other_policy in policies_list:
            if other_policy.get_order() and self_policy.get_order() and \
                    other_policy.get_order() < self_policy.get_order():
                return None  # not checking lower priority for Calico
            if other_policy == self_policy:
                continue
            if not other_policy.has_deny_rules():
                continue
            config_with_other_policy = self.config.clone_with_just_one_policy(other_policy.full_name())
            # calling get_all_peers_group does not require getting dnsEntry peers, since they are not relevant when computing
            # deny connections
            pods_to_compare = self.config.peer_container.get_all_peers_group()
            pods_to_compare |= TwoNetworkConfigsQuery(self.config,
                                                      config_with_other_policy).disjoint_referenced_ip_blocks()
            for pod1 in pods_to_compare:
                for pod2 in pods_to_compare:
                    if isinstance(pod1, IpBlock) and isinstance(pod2, IpBlock):
                        continue
                    if pod1 == pod2:
                        continue  # no way to prevent a pod from communicating with itself
                    _, _, _, self_deny_conns = config_with_self_policy.allowed_connections(pod1, pod2, layer_name)
                    _, _, _, other_deny_conns = config_with_other_policy.allowed_connections(pod1, pod2, layer_name)
                    if not self_deny_conns:
                        continue
                    if not self_deny_conns.contained_in(other_deny_conns):
                        return None
            return other_policy
        return None

    def other_rule_containing(self, self_policy, self_rule_index, is_ingress, layer_name):
        """
        Search whether a given policy rule is contained in another policy rule
        :param NetworkPolicy self_policy: The network policy containing the given rule
        :param int self_rule_index: The index of the rule in the policy (1-based)
        :param bool is_ingress: Whether this is an ingress rule or an egress rule
        :param NetworkLayerName layer_name: The layer name of the policy
        :return: If a containing rule is found, return its policy, its index and whether it contradicts the input rule
        :rtype: NetworkPolicy, int, bool
        """
        policies_list = self.config.policies_container.layers[layer_name].policies_list
        for other_policy in policies_list:
            if other_policy.get_order() and self_policy.get_order() and \
                    other_policy.get_order() < self_policy.get_order():
                return None, None, None  # All following policies have a lower order - containment is not interesting
            if is_ingress:
                found_index, contradict = other_policy.ingress_rule_containing(self_policy, self_rule_index)
            else:
                found_index, contradict = other_policy.egress_rule_containing(self_policy, self_rule_index)
            if found_index:
                return other_policy, found_index, contradict
        return None, None, None

    def redundant_rule_text(self, policy, rule_index, is_ingress, layer_name):
        """
        Attempts to provide an explanation as to why a policy rule is redundant
        :param NetworkPolicy policy: A redundant policy
        :param int rule_index: The index of the rule in the policy (1-based)
        :param bool is_ingress: Whether this is an ingress rule or an egress rule
        :param NetworkLayerName layer_name: The layer name of the policy
        :return: A text explaining why the policy is redundant
        :rtype: str
        """
        redundant_text = 'In' if is_ingress else 'E'
        redundant_text += f'gress rule no. {rule_index} in {self.policy_title(policy)} ' \
                          f'is redundant in {self.config.name}'
        containing_policy, containing_index, containing_contradict = \
            self.other_rule_containing(policy, rule_index, is_ingress, layer_name)
        if not containing_policy:
            return redundant_text + '\n'
        redundant_text += ' since it is contained in '
        redundant_text += 'in' if is_ingress else 'e'
        redundant_text += f'gress rule no. {containing_index}'
        if containing_policy == policy:
            redundant_text += ' of its NetworkPolicy'
        else:
            redundant_text += f' of {self.policy_title(containing_policy)}'
        if containing_contradict:
            redundant_text += '\n\tNote that the action of the containing rule and the rule are different.'
        return redundant_text + '\n'

    def redundant_policy_text(self, policy, layer_name):
        """
        Attempts to provide an explanation as to why a policy is redundant
        :param NetworkPolicy policy: A redundant policy
        :param NetworkLayerName layer_name: The name of the layer the policy is in
        :return: A text explaining why the policy is redundant
        :rtype: str
        """
        redundant_text = f'{self.policy_title(policy)} is redundant'
        single_policy_config = self.config.clone_with_just_one_policy(policy.full_name())
        if VacuityQuery(single_policy_config).exec().bool_result:
            redundant_text += '. Note that it does not change default connectivity'
            return redundant_text + '\n'

        has_allow_rules = policy.has_allow_rules()
        has_deny_rules = policy.has_deny_rules()
        if not has_deny_rules and not has_allow_rules:  # all rules are empty
            return redundant_text + '. Note that it contains no effective allow/deny rules\n'

        contain_allow_policy, contain_deny_policy = None, None
        if has_allow_rules:
            contain_allow_policy = self.other_policy_containing_allow(policy, single_policy_config, layer_name)
        if has_deny_rules and (not has_allow_rules or contain_allow_policy is not None):
            contain_deny_policy = self.other_policy_containing_deny(policy, single_policy_config, layer_name)
        if (has_allow_rules and contain_allow_policy is None) or (has_deny_rules and contain_deny_policy is None):
            return redundant_text + '\n'
        if not has_deny_rules:
            redundant_text += f': it is contained in {self.policy_title(contain_allow_policy)}\n'
        elif not has_allow_rules:
            redundant_text += f': it is contained in {self.policy_title(contain_deny_policy)}\n'
        else:
            if contain_deny_policy == contain_allow_policy:
                redundant_text += f': it is contained in {self.policy_title(contain_allow_policy)}\n'
            else:
                redundant_text += f': its allow rules are covered by {self.policy_title(contain_allow_policy)}' \
                                  f', its deny rules are covered by {self.policy_title(contain_deny_policy)}\n'
        return redundant_text

    def exec(self):  # noqa: C901
        if not self.config:
            return QueryAnswer(False, f'No NetworkPolicies in {self.config.name}. Nothing to check sanity on.')

        # check for conflicting policies in calico layer
        has_conflicting_policies, conflict_explanation = self.has_conflicting_policies_with_same_order()
        if has_conflicting_policies:
            return QueryAnswer(bool_result=False, output_result=conflict_explanation, numerical_result=1)
        issues_counter = 0
        policies_issue = ''
        rules_issues = ''

        # vacuity check
        is_config_vacuous_res = VacuityQuery(self.config).exec()
        if is_config_vacuous_res.bool_result:
            issues_counter = 1
            policies_issue += is_config_vacuous_res.output_result + '\n'
            if len(self.config.policies_container.policies) == 1:
                policies_issue += '\tNote that it contains a single policy.\n'

        for layer_name, layer in self.config.policies_container.layers.items():
            if layer_name == NetworkLayerName.Ingress:
                continue
            policies_list = layer.policies_list
            # check for redundant policies in this layer
            redundant_policies = RedundancyQuery(self.config).redundant_policies(policies_list, layer_name)

            for policy in policies_list:

                # check for empty policies
                if policy.is_policy_empty():
                    issues_counter += 1
                    empty_issue = f'{self.policy_title(policy)} is empty - it does not select any pods\n'
                    policies_issue += empty_issue
                    policy.add_finding(empty_issue)
                    continue

                empty_rules_explanation, empty_ingress_rules_list, empty_egress_rules_list = policy.has_empty_rules()
                if empty_rules_explanation:
                    issues_counter += len(empty_rules_explanation)
                    rules_issues += '\n'.join(empty_rules_explanation) + '\n'
                    policy.findings += empty_rules_explanation

                if is_config_vacuous_res.bool_result:
                    continue

                if policy.full_name() in redundant_policies:
                    issues_counter += 1
                    redundancy_full_text = self.redundant_policy_text(policy, layer_name)
                    policies_issue += redundancy_full_text
                    policy.add_finding(redundancy_full_text)
                    continue

                redundant_ingress_rules, redundant_egress_rules = \
                    RedundancyQuery(self.config).find_redundant_rules(policy, layer_name)
                for rule_index in range(1, len(policy.ingress_rules) + 1):
                    if rule_index in empty_ingress_rules_list:
                        continue
                    if rule_index in redundant_ingress_rules:
                        issues_counter += 1
                        redundancy_text = self.redundant_rule_text(policy, rule_index, True, layer_name)
                        rules_issues += redundancy_text
                        policy.add_finding(redundancy_text)
                for rule_index in range(1, len(policy.egress_rules) + 1):
                    if rule_index in empty_egress_rules_list:
                        continue
                    if rule_index in redundant_egress_rules:
                        issues_counter += 1
                        redundancy_text = self.redundant_rule_text(policy, rule_index, False, layer_name)
                        rules_issues += redundancy_text
                        policy.add_finding(redundancy_text)

        if issues_counter == 0:
            output_result = f'NetworkConfig {self.config.name} passed sanity check'
        else:
            output_result = f'NetworkConfig {self.config.name} failed sanity check:'

        return QueryAnswer(bool_result=(issues_counter == 0), output_result=output_result,
                           output_explanation=[ComputedExplanation(str_explanation=policies_issue + rules_issues)],
                           numerical_result=issues_counter)


class ConnectivityMapQuery(NetworkConfigQuery):
    """
    Print the connectivity graph in the form of firewall rules
    """

    @staticmethod
    def get_supported_output_formats():
        return {'txt', 'yaml', 'csv', 'md', 'dot', 'json', 'jpg', 'txt_no_fw_rules'}

    def is_in_subset(self, peer):
        """
        returns indication if the peer element is in the defined subset
        Please note: Subset is a sort of a filter. It filters out elements which WERE DEFINED and do
        not match the settings.
        Thus, the function returns True if no subset was defined
        since, in this case, the subset is infinite and everything is "in the subset"
        :param peer: peer element to filter (currently supports only Pods)
        :return:
        """
        # if subset restrictions were not defined at all, everything is in the subset
        if not self.output_config.subset:
            return True

        subset = self.output_config.subset
        # filter by namespace
        if isinstance(peer, Peer) and subset.get('namespace_subset') \
                and str(peer.namespace) in str(subset['namespace_subset']).split(','):
            return True

        # filter by deployment
        if isinstance(peer, Pod) and subset.get('deployment_subset') and peer.owner_name:
            dep_names = str(subset.get('deployment_subset')).split(',')
            for dep_name in dep_names:
                if '/' in dep_name:
                    dep_name_for_comp = peer.workload_name
                else:
                    dep_name_for_comp = peer.owner_name
                if dep_name in dep_name_for_comp:
                    return True

        # filter by label
        if isinstance(peer, Peer) and subset.get('label_subset') and peer.labels:
            # go over the labels and see if all of them are defined
            for single_label_subset in list(subset['label_subset']):
                if self.are_labels_all_included(single_label_subset, peer.labels):
                    return True

        return False

    def compute_subset(self, peers):
        """
        Computes all peers that are in the defined subset out of the given peer set
        :param PeerSet peers: the given peer set
        :return: peers in the defined subset
        """
        if not self.output_config.subset:
            return peers
        res = PeerSet()
        for peer in peers:
            if self.is_in_subset(peer):
                res.add(peer)
        return res

    @staticmethod
    def are_labels_all_included(target_labels, pool_labels):
        for key, val in target_labels.items():
            if pool_labels.get(key) != val:
                return False
        return True

    def compute_connectivity_output_original(self):
        """
        Compute connectivity output with original implementation (running for every pair of peers).
        :return: a tuple of output result (in a required format), FwRules, tcp FWRules and non-tcp FWRules.
        :rtype ([Union[str, dict], MinimizeFWRules, MinimizeFWRules], MinimizeFWRules)
        """
        fw_rules = None
        fw_rules_tcp = None
        fw_rules_non_tcp = None
        exclude_ipv6 = self.output_config.excludeIPv6Range
        connections = defaultdict(list)
        # if dns entry peers exist but no istio policies are configured,
        # then actually istio layer exists implicitly, connections to these peers will be considered with the
        # default Istio outbound traffic mode - allow any
        peers_to_compare = self.config.peer_container.get_all_peers_group(include_dns_entries=True)
        ref_ip_blocks = IpBlock.disjoint_ip_blocks(self.config.get_referenced_ip_blocks(exclude_ipv6),
                                                   IpBlock.get_all_ips_block_peer_set(exclude_ipv6), exclude_ipv6)
        peers_to_compare |= ref_ip_blocks
        peers = PeerSet()
        for peer1 in peers_to_compare:
            for peer2 in peers_to_compare:
                if self.is_in_subset(peer1):
                    peers.add(peer1)
                elif not self.is_in_subset(peer2):
                    continue  # skipping pairs if none of them are in the given subset
                if not self.determine_whether_to_compute_allowed_conns_for_peer_types(peer1, peer2):
                    continue
                if peer1 == peer2:
                    # cannot restrict pod's connection to itself
                    connections[ConnectionSet(True)].append((peer1, peer2))
                else:
                    conns, _, _, _ = self.config.allowed_connections(peer1, peer2)
                    if conns:
                        connections[conns].append((peer1, peer2))
                        # collect both peers, even if one of them is not in the subset
                        peers.add(peer1)
                        peers.add(peer2)
        # if Istio is a layer in the network config - produce 2 maps, for TCP and for non-TCP
        # because Istio policies can only capture TCP connectivity
        if self.config.policies_container.layers.does_contain_layer(NetworkLayerName.Istio):
            output_res, fw_rules_tcp, fw_rules_non_tcp = \
                self.get_connectivity_output_split_by_tcp(connections, peers, peers_to_compare)
        else:
            output_res, fw_rules = self.get_connectivity_output_full(connections, peers, peers_to_compare)
        return output_res, fw_rules, fw_rules_tcp, fw_rules_non_tcp

    def compute_connectivity_output_optimized(self):
        """
        Compute connectivity output with optimized implementation.
        :return: a tuple of output result (in a required format), FwRules, tcp FWRules and non-tcp FWRules.
        :rtype: ([Union[str, dict], MinimizeFWRules, MinimizeFWRules, MinimizeFWRules)
        """
        opt_fw_rules = None
        opt_fw_rules_tcp = None
        opt_fw_rules_non_tcp = None
        exclude_ipv6 = self.output_config.excludeIPv6Range
        opt_conns = self.config.allowed_connections_optimized()
        all_conns_opt = opt_conns.all_allowed_conns
        opt_peers_to_compare = self.config.peer_container.get_all_peers_group(include_dns_entries=True)
        # add all relevant IpBlocks, used in connections
        opt_peers_to_compare |= all_conns_opt.project_on_one_dimension('src_peers') | \
            all_conns_opt.project_on_one_dimension('dst_peers')
        if exclude_ipv6:
            ip_blocks_mask = IpBlock.get_all_ips_block(exclude_ipv6=True)
            ref_ip_blocks = self.config.get_referenced_ip_blocks(exclude_ipv6)
            for ip_block in ref_ip_blocks:
                ip_blocks_mask |= ip_block
            opt_peers_to_compare.filter_ipv6_blocks(ip_blocks_mask)
            # remove connections where any of src_peers or dst_peers contains automatically-added IPv6 blocks,
            # while keeping connections with IPv6 blocks directly referenced in policies
            all_conns_opt &= ConnectivityProperties.make_conn_props_from_dict({"src_peers": opt_peers_to_compare,
                                                                               "dst_peers": opt_peers_to_compare})
        base_peers_num = len(opt_peers_to_compare)
        subset_peers = self.compute_subset(opt_peers_to_compare)
        if len(subset_peers) != base_peers_num:
            # remove connections where both of src_peers and dst_peers are out of the subset
            subset_conns = ConnectivityProperties.make_conn_props_from_dict({"src_peers": subset_peers}) | \
                           ConnectivityProperties.make_conn_props_from_dict({"dst_peers": subset_peers})
            all_conns_opt &= subset_conns
        all_conns_opt = self.filter_conns_by_peer_types(all_conns_opt, opt_peers_to_compare)
        if ExplTracker().is_active():
            ExplTracker().set_connections_and_peers(all_conns_opt, subset_peers)
        if self.config.policies_container.layers.does_contain_layer(NetworkLayerName.Istio):
            output_res, opt_fw_rules_tcp, opt_fw_rules_non_tcp = \
                self.get_props_output_split_by_tcp(all_conns_opt, opt_peers_to_compare)
        else:
            output_res, opt_fw_rules = self.get_props_output_full(all_conns_opt, opt_peers_to_compare,
                                                                  ip_blocks_mask)
        return output_res, opt_fw_rules, opt_fw_rules_tcp, opt_fw_rules_non_tcp

    def exec(self):
        self.output_config.fullExplanation = True  # assign true for this query - it is always ok to compare its results
        self.output_config.configName = os.path.basename(self.config.name) if self.config.name.startswith('./') else \
            self.config.name
        res = QueryAnswer(True)
        fw_rules = None
        fw_rules_tcp = None
        fw_rules_non_tcp = None
        if self.config.optimized_run != 'true':
            orig_start = time.time()
            output_res, fw_rules, fw_rules_tcp, fw_rules_non_tcp = self.compute_connectivity_output_original()
            orig_end = time.time()
            print(f'Original loop: time: {(orig_end - orig_start):6.2f} seconds')
            if self.output_config.outputFormat in ['json', 'yaml']:
                res.output_explanation = [ComputedExplanation(dict_explanation=output_res)]
            else:
                res.output_explanation = [ComputedExplanation(str_explanation=output_res)]

        if self.config.optimized_run != 'false':
            opt_start = time.time()
            output_res, opt_fw_rules, opt_fw_rules_tcp, opt_fw_rules_non_tcp = \
                self.compute_connectivity_output_optimized()
            opt_end = time.time()
            print(f'Opt time: {(opt_end - opt_start):6.2f} seconds')
            if self.config.optimized_run == 'debug':
                if fw_rules and fw_rules.fw_rules_map and opt_fw_rules and opt_fw_rules.fw_rules_map:
                    self.compare_fw_rules(fw_rules, opt_fw_rules)
                if fw_rules_tcp and fw_rules_tcp.fw_rules_map and \
                        opt_fw_rules_tcp and opt_fw_rules_tcp.fw_rules_map:
                    self.compare_fw_rules(fw_rules_tcp, opt_fw_rules_tcp)
                if fw_rules_non_tcp and fw_rules_non_tcp.fw_rules_map and \
                        opt_fw_rules_non_tcp and opt_fw_rules_non_tcp.fw_rules_map:
                    self.compare_fw_rules(fw_rules_non_tcp, opt_fw_rules_non_tcp)
            else:  # self.config.optimized_run == 'true':
                if self.output_config.outputFormat in ['json', 'yaml']:
                    res.output_explanation = [ComputedExplanation(dict_explanation=output_res)]
                else:
                    res.output_explanation = [ComputedExplanation(str_explanation=output_res)]
        return res

    def compare_fw_rules(self, fw_rules1, fw_rules2):
        conn_props1 = ConnectionSet.fw_rules_to_conn_props(fw_rules1, self.config.peer_container)
        conn_props2 = ConnectionSet.fw_rules_to_conn_props(fw_rules2, self.config.peer_container)
        if conn_props1 == conn_props2:
            print("Original and optimized fw-rules are semantically equivalent")
        else:
            diff_prop = (conn_props1 - conn_props2) | (conn_props2 - conn_props1)
            if diff_prop.are_auto_conns():
                print("Original and optimized fw-rules differ only in auto-connections")
            else:
                print("Error: original and optimized fw-rules are different")
                assert False

    def get_connectivity_output_full(self, connections, peers, peers_to_compare):
        """
        get the connectivity map output considering all connections in the output
        :param dict connections: the connections' dict (map from connection-set to peer pairs)
        :param PeerSet peers: the peers to consider for dot and txt_no_fw_rules output
        :param PeerSet peers_to_compare: the peers to consider for fw-rules output
        :rtype (Union[str,dict], MinimizeFWRules)
        """
        if self.output_config.outputFormat in ['dot', 'jpg']:
            dot_full = self.dot_format_from_connections_dict(connections, peers)
            return dot_full, None
        if self.output_config.outputFormat == 'txt_no_fw_rules':
            conns_wo_fw_rules = self._txt_no_fw_rules_format_from_connections_dict(connections, peers)
            return conns_wo_fw_rules, None
        # handle other formats
        formatted_rules, fw_rules = self.fw_rules_from_connections_dict(connections, peers_to_compare)
        return formatted_rules, fw_rules

    def get_props_output_full(self, props, peers_to_compare, ip_blocks_mask):
        """
        get the connectivity map output considering all connections in the output
        :param ConnectivityProperties props: properties describing allowed connections
        :param PeerSet peers_to_compare: the peers to consider for dot/fw-rules output
         whereas all other values should be filtered out in the output
        :rtype ([Union[str, dict], MinimizeFWRules])
        """
        if self.output_config.outputFormat in ['dot', 'jpg']:
            dot_full = self.dot_format_from_props(props, peers_to_compare)
            return dot_full, None
        if self.output_config.outputFormat == 'txt_no_fw_rules':
            conns_wo_fw_rules = self.txt_no_fw_rules_format_from_props(props, peers_to_compare, ip_blocks_mask)
            return conns_wo_fw_rules, None
        # handle other formats
        formatted_rules, fw_rules = self.fw_rules_from_props(props, peers_to_compare)
        return formatted_rules, fw_rules

    def get_connectivity_output_split_by_tcp(self, connections, peers, peers_to_compare):
        """
        get the connectivity map output as two parts: TCP and non-TCP
        :param dict connections: the connections' dict (map from connection-set to peer pairs)
        :param PeerSet peers: the peers to consider for dot output
        :param PeerSet peers_to_compare: the peers to consider for fw-rules output
        :rtype (Union[str, dict], MinimizeFWRules, MinimizeFWRules)
        """
        connectivity_tcp_str = 'TCP'
        connectivity_non_tcp_str = 'non-TCP'
        connections_tcp, connections_non_tcp = self.convert_connections_to_split_by_tcp(connections)
        if self.output_config.outputFormat in ['dot', 'jpg']:
            dot_tcp = self.dot_format_from_connections_dict(connections_tcp, peers, connectivity_tcp_str)
            dot_non_tcp = self.dot_format_from_connections_dict(connections_non_tcp, peers, connectivity_non_tcp_str)
            # concatenate the two graphs into one dot file
            res_str = dot_tcp + dot_non_tcp
            return res_str, None, None

        if self.output_config.outputFormat == 'txt_no_fw_rules':
            conns_msg_suffix = ' Connections:'
            tcp_conns_wo_fw_rules = \
                self._txt_no_fw_rules_format_from_connections_dict(connections_tcp, peers,
                                                                   connectivity_tcp_str + conns_msg_suffix)
            non_tcp_conns_wo_fw_rules = \
                self._txt_no_fw_rules_format_from_connections_dict(connections_non_tcp, peers,
                                                                   connectivity_non_tcp_str + conns_msg_suffix)
            return tcp_conns_wo_fw_rules + '\n\n' + non_tcp_conns_wo_fw_rules, None, None
        # handle formats other than dot and txt_no_fw_rules
        formatted_rules_tcp, fw_rules_tcp = \
            self.fw_rules_from_connections_dict(connections_tcp, peers_to_compare, connectivity_tcp_str)
        formatted_rules_non_tcp, fw_rules_non_tcp = \
            self.fw_rules_from_connections_dict(connections_non_tcp, peers_to_compare, connectivity_non_tcp_str)
        if self.output_config.outputFormat in ['json', 'yaml']:
            # get a dict object containing the two maps on different keys (TCP_rules and non-TCP_rules)
            rules = formatted_rules_tcp
            rules.update(formatted_rules_non_tcp)
            return rules, fw_rules_tcp, fw_rules_non_tcp
        # remaining formats: txt / csv / md : concatenate the two strings of the conn-maps
        if self.output_config.outputFormat == 'txt':
            res_str = f'{formatted_rules_tcp}\n{formatted_rules_non_tcp}'
        else:
            res_str = formatted_rules_tcp + formatted_rules_non_tcp
        return res_str, fw_rules_tcp, fw_rules_non_tcp

    def get_props_output_split_by_tcp(self, props, peers_to_compare, ip_blocks_mask):
        """
        get the connectivity map output as two parts: TCP and non-TCP
        :param ConnectivityProperties props: properties describing allowed connections
        :param PeerSet peers_to_compare: the peers to consider for dot/fw-rules output
         whereas all other values should be filtered out in the output
        :param IpBlock ip_blocks_mask:  IpBlock containing all allowed ip values,
        :rtype (Union[str, dict], MinimizeFWRules, MinimizeFWRules)
        """
        connectivity_tcp_str = 'TCP'
        connectivity_non_tcp_str = 'non-TCP'
        props_tcp, props_non_tcp = self.convert_props_to_split_by_tcp(props)
        if self.output_config.outputFormat in ['dot', 'jpg']:
            dot_tcp = self.dot_format_from_props(props_tcp, peers_to_compare, connectivity_tcp_str)
            dot_non_tcp = self.dot_format_from_props(props_non_tcp, peers_to_compare, connectivity_non_tcp_str)
            # concatenate the two graphs into one dot file
            res_str = dot_tcp + dot_non_tcp
            return res_str, None, None
        if self.output_config.outputFormat in ['txt_no_fw_rules']:
            txt_no_fw_rules_tcp = self.txt_no_fw_rules_format_from_props(props_tcp, peers_to_compare, ip_blocks_mask,
                                                                         connectivity_tcp_str)
            txt_no_fw_rules_non_tcp = self.txt_no_fw_rules_format_from_props(props_non_tcp, peers_to_compare, ip_blocks_mask,
                                                                             connectivity_non_tcp_str)
            # concatenate the two graphs into one dot file
            res_str = txt_no_fw_rules_tcp + txt_no_fw_rules_non_tcp
            return res_str, None, None
        # handle formats other than dot and txt_no_fw_rules
        formatted_rules_tcp, fw_rules_tcp = self.fw_rules_from_props(props_tcp, peers_to_compare, connectivity_tcp_str)
        formatted_rules_non_tcp, fw_rules_non_tcp = self.fw_rules_from_props(props_non_tcp, peers_to_compare,
                                                                             connectivity_non_tcp_str)
        if self.output_config.outputFormat in ['json', 'yaml']:
            # get a dict object containing the two maps on different keys (TCP_rules and non-TCP_rules)
            rules = formatted_rules_tcp
            rules.update(formatted_rules_non_tcp)
            return rules, fw_rules_tcp, fw_rules_non_tcp
        # remaining formats: txt / csv / md : concatenate the two strings of the conn-maps
        if self.output_config.outputFormat == 'txt':
            res_str = f'{formatted_rules_tcp}\n{formatted_rules_non_tcp}'
        else:
            res_str = formatted_rules_tcp + formatted_rules_non_tcp
        return res_str, fw_rules_tcp, fw_rules_non_tcp

    def _get_conn_graph(self, connections, peers):
        """
        :param dict connections: the connections' dict (map from connection-set to peer pairs)
        :param PeerSet peers: the peers to consider for building connectivity graph
        :rtype:  ConnectivityGraph
        :return the connectivity graph of the given connections and peers
        """
        conn_graph = ConnectivityGraph(peers, self.config.get_allowed_labels(), self.output_config)
        conn_graph.add_edges(connections)
        return conn_graph

    def _txt_no_fw_rules_format_from_connections_dict(self, connections, peers, connectivity_restriction=None):
        """
        :param dict connections: the connections' dict (map from connection-set to peer pairs)
        :param PeerSet peers: the peers to consider for dot output
        :param Union[str,None] connectivity_restriction: specify if connectivity is restricted to TCP / non-TCP , or not
        :rtype:  str
        :return the connectivity map in txt_no_fw_rules format, the connections between peers, excluding fw-rules
        and connections involving livesim peers
        """
        conn_graph = self._get_conn_graph(connections, peers)
        return conn_graph.get_connections_without_fw_rules_txt_format(connectivity_restriction)

    def dot_format_from_connections_dict(self, connections, peers, connectivity_restriction=None):
        """
        :param dict connections: the connections' dict (map from connection-set to peer pairs)
        :param PeerSet peers: the peers to consider for dot output
        :param Union[str,None] connectivity_restriction: specify if connectivity is restricted to
               TCP / non-TCP , or not
        :rtype str
        :return the connectivity map in dot-format, considering connectivity_restriction if required
        """
        conn_graph = self._get_conn_graph(connections, peers)
        return conn_graph.get_connectivity_dot_format_str(connectivity_restriction)

    def dot_format_from_props(self, props, peers, connectivity_restriction=None):
        """
        :param ConnectivityProperties props: properties describing allowed connections
        :param PeerSet peers: the peers to consider for dot output
         whereas all other values should be filtered out in the output
        :param Union[str,None] connectivity_restriction: specify if connectivity is restricted to
               TCP / non-TCP , or not
        :rtype str
        :return the connectivity map in dot-format, considering connectivity_restriction if required
        """
        conn_graph = ConnectivityGraph(peers, self.config.get_allowed_labels(), self.output_config)
        for cube in props:
            conn_graph.add_edges_from_cube_dict(props.get_connectivity_cube(cube), self.config.peer_container)
        return conn_graph.get_connectivity_dot_format_str(connectivity_restriction)

    def dot_format_from_props(self, props, peers, ip_blocks_mask, connectivity_restriction=None):
        """
        :param ConnectivityProperties props: properties describing allowed connections
        :param PeerSet peers: the peers to consider for dot output
        :param IpBlock ip_blocks_mask:  IpBlock containing all allowed ip values,
         whereas all other values should be filtered out in the output
        :param Union[str,None] connectivity_restriction: specify if connectivity is restricted to
               TCP / non-TCP , or not
        :rtype str
        :return the connectivity map in dot-format, considering connectivity_restriction if required
        """
        conn_graph = ConnectivityGraph(peers, self.config.get_allowed_labels(), self.output_config)
        for cube in props:
            conn_graph.add_edges_from_cube_dict(props.get_connectivity_cube(cube), self.config.peer_container,
                                                ip_blocks_mask)
        return conn_graph.get_connectivity_dot_format_str(connectivity_restriction)

    def txt_no_fw_rules_format_from_props(self, props, peers, ip_blocks_mask, connectivity_restriction=None):
        """
        :param ConnectivityProperties props: properties describing allowed connections
        :param PeerSet peers: the peers to consider for dot output
        :param IpBlock ip_blocks_mask:  IpBlock containing all allowed ip values,
         whereas all other values should be filtered out in the output
        :param Union[str,None] connectivity_restriction: specify if connectivity is restricted to
               TCP / non-TCP , or not
        :rtype str
        :return the connectivity map in dot-format, considering connectivity_restriction if required
        """
        conn_graph = ConnectivityGraph(peers, self.config.get_allowed_labels(), self.output_config)
        for cube in props:
            conn_graph.add_edges_from_cube_dict(props.get_connectivity_cube(cube), self.config.peer_container)
        return conn_graph.get_connections_without_fw_rules_txt_format(connectivity_restriction)

    def fw_rules_from_connections_dict(self, connections, peers_to_compare, connectivity_restriction=None):
        """
        :param dict connections: the connections' dict (map from connection-set to peer pairs)
        :param PeerSet peers_to_compare: the peers to consider for fw-rules output
        :param Union[str,None] connectivity_restriction: specify if connectivity is restricted to
               TCP / non-TCP , or not
        :return the connectivity map in fw-rules, considering connectivity_restriction if required
        :rtype: (Union[str, dict], MinimizeFWRules)
        """
        conn_graph = self._get_conn_graph(connections, peers_to_compare)
        fw_rules = conn_graph.get_minimized_firewall_rules()
        formatted_rules = fw_rules.get_fw_rules_in_required_format(connectivity_restriction=connectivity_restriction)
        return formatted_rules, fw_rules

    def fw_rules_from_props(self, props, peers_to_compare, connectivity_restriction=None):
        """
        :param ConnectivityProperties props: properties describing allowed connections
        :param PeerSet peers_to_compare: the peers to consider for fw-rules output
         whereas all other values should be filtered out in the output
        :param Union[str,None] connectivity_restriction: specify if connectivity is restricted to
               TCP / non-TCP , or not
        :return the connectivity map in fw-rules, considering connectivity_restriction if required
        :rtype: (Union[str, dict], MinimizeFWRules)
        """
        cluster_info = ClusterInfo(peers_to_compare, self.config.get_allowed_labels())
        fw_rules_map = ConnectionSet.conn_props_to_fw_rules(props, cluster_info, self.config.peer_container,
                                                            connectivity_restriction)
        fw_rules = MinimizeFWRules(fw_rules_map, cluster_info, self.output_config, {})
        formatted_rules = fw_rules.get_fw_rules_in_required_format(connectivity_restriction=connectivity_restriction)
        return formatted_rules, fw_rules

    def convert_connections_to_split_by_tcp(self, connections):
        """
        given the connections' dict , convert it to two connection maps, one for TCP only, and the other
        for non-TCP only.
        :param dict connections: the connections' dict (map from connection-set to peer pairs)
        :return: a tuple of the two connection maps : first for TCP, second for non-TCP
        :rtype: tuple(dict, dict)
        """
        connections_tcp = defaultdict(list)
        connections_non_tcp = defaultdict(list)
        for conn, peers_list in connections.items():
            tcp_conns, non_tcp_conns = self.split_to_tcp_and_non_tcp_conns(conn)
            connections_tcp[tcp_conns] += peers_list
            connections_non_tcp[non_tcp_conns] += peers_list

        return connections_tcp, connections_non_tcp

    @staticmethod
    def split_to_tcp_and_non_tcp_conns(conns):
        """
        split a ConnectionSet object to two objects: one within TCP only, the other within non-TCP protocols
        :param ConnectionSet conns: a  ConnectionSet object
        :return: a tuple of the two ConnectionSet objects: first for TCP, second for non-TCP
        :rtype: tuple(ConnectionSet, ConnectionSet)
        """
        tcp_conns = conns - ConnectionSet.get_non_tcp_connections()
        non_tcp_conns = conns - tcp_conns
        if non_tcp_conns == ConnectionSet.get_non_tcp_connections():
            non_tcp_conns = ConnectionSet(True)  # all connections in terms of non-TCP
        if tcp_conns == ConnectionSet.get_all_tcp_connections():
            tcp_conns = ConnectionSet(True)  # all connections in terms of TCP

        return tcp_conns, non_tcp_conns

    @staticmethod
    def convert_props_to_split_by_tcp(props):
        """
        given the ConnectivityProperties properties set, convert it to two properties sets, one for TCP only, and the other
        for non-TCP only.
        :param ConnectivityProperties props: properties describing allowed connections
        :return: a tuple of the two properties sets: first for TCP, second for non-TCP
        :rtype: tuple(ConnectivityProperties, ConnectivityProperties)
        """
        tcp_protocol = ProtocolSet.get_protocol_set_with_single_protocol('TCP')
        tcp_props = props & ConnectivityProperties.make_conn_props_from_dict({"protocols": tcp_protocol})
        non_tcp_props = props - tcp_props
        return tcp_props, non_tcp_props


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

    def get_configs_names(self):
        """
        returns list of the query's configs names
        :rtype: list[str]
        """
        return [self.name1, self.name2]

    def get_configs(self):
        """
        returns list of the query's configs
        :rtype: list[NetworksConfig]
        """
        return [self.config1, self.config2]

    @staticmethod
    def get_query_type():
        return QueryType.ComparisonToBaseConfigQuery

    def is_identical_topologies(self, check_same_policies=False):
        if not self.config1.peer_container.is_comparable_with_other_container(self.config2.peer_container):
            return QueryAnswer(False, 'The two configurations have different network '
                                      'topologies and thus are not comparable.', query_not_executed=True)
        if check_same_policies and self.config1.policies_container.policies == self.config2.policies_container.policies:
            return QueryAnswer(True, f'{self.name1} and {self.name2} have the same network '
                                     'topology and the same set of policies.')
        return QueryAnswer(True)

    def disjoint_referenced_ip_blocks(self):
        """
        Returns disjoint ip-blocks in the policies of both configs
        :return: A set of disjoint ip-blocks
        :rtype: PeerSet
        """
        exclude_ipv6 = self.output_config.excludeIPv6Range
        return IpBlock.disjoint_ip_blocks(self.config1.get_referenced_ip_blocks(exclude_ipv6),
                                          self.config2.get_referenced_ip_blocks(exclude_ipv6), exclude_ipv6)

    @staticmethod
    def clone_without_ingress(config):
        """
        Clone config without ingress policies
        :param NetworkConfig config: the config to clone
        :return: resulting config without ingress policies
        :rtype: NetworkConfig
        """
        if NetworkLayerName.Ingress not in config.policies_container.layers or not config.policies_container.layers[
                NetworkLayerName.Ingress].policies_list:
            return config  # no ingress policies in this config
        config_without_ingress = config.clone_without_policies(config.name)
        for policy in config.policies_container.policies.values():
            if not isinstance(policy, IngressPolicy):  # ignoring ingress policies
                config_without_ingress.append_policy_to_config(policy)
        return config_without_ingress

    def execute(self, cmd_line_flag):
        return self.exec(cmd_line_flag)

    @abstractmethod
    def exec(self, cmd_line_flag):
        raise NotImplementedError


class EquivalenceQuery(TwoNetworkConfigsQuery):
    """
    Check whether config1 and config2 allow exactly the same set of connections.
    """

    @staticmethod
    def get_query_type():
        return QueryType.PairComparisonQuery

    def exec(self, cmd_line_flag=False, layer_name=None):
        query_answer = self.is_identical_topologies(True)
        if query_answer.output_result:
            query_answer.numerical_result = not query_answer.bool_result
            return query_answer

        peers_to_compare = \
            self.config1.peer_container.get_all_peers_group(include_dns_entries=True)
        peers_to_compare |= self.disjoint_referenced_ip_blocks()
        captured_pods = self.config1.get_captured_pods(layer_name) | self.config2.get_captured_pods(layer_name)
        different_conns_list = []
        for peer1 in peers_to_compare:
            for peer2 in peers_to_compare if peer1 in captured_pods else captured_pods:
                if peer1 == peer2:
                    continue
                if not self.determine_whether_to_compute_allowed_conns_for_peer_types(peer1, peer2):
                    continue
                conns1, _, _, _ = self.config1.allowed_connections(peer1, peer2, layer_name)
                conns2, _, _, _ = self.config2.allowed_connections(peer1, peer2, layer_name)
                if conns1 != conns2:
                    different_conns_list.append(PeersAndConnections(str(peer1), str(peer2), conns1, conns2))
                    if not self.output_config.fullExplanation:
                        return self._query_answer_with_relevant_explanation(different_conns_list)

        if different_conns_list:
            return self._query_answer_with_relevant_explanation(sorted(different_conns_list))

        return QueryAnswer(True, self.name1 + ' and ' + self.name2 + ' are semantically equivalent.',
                           numerical_result=0)

    def _query_answer_with_relevant_explanation(self, explanation_list):
        output_result = self.name1 + ' and ' + self.name2 + ' are not semantically equivalent.'
        explanation_description = f'Connections allowed in {self.name1} which are different in {self.name2}'
        final_explanation = ConnectionsDiffExplanation(explanation_description=explanation_description,
                                                       peers_diff_connections_list=explanation_list,
                                                       configs=self.get_configs_names(), conns_diff=True)
        return QueryAnswer(False, output_result, output_explanation=[final_explanation], numerical_result=1)


class SemanticDiffQuery(TwoNetworkConfigsQuery):
    """
    Produces a report of changed connections (also for the case of two configurations of different network topologies)
    """

    @staticmethod
    def get_query_type():
        return QueryType.PairComparisonQuery

    @staticmethod
    def get_supported_output_formats():
        return {'txt', 'yaml', 'csv', 'md', 'json', 'txt_no_fw_rules'}

    @staticmethod
    def _get_updated_key(key, is_added):
        """
        updates given key if needed, by replacing Changed with Added/ Removed based on the is_added flag value
        :param str key: a key string describing connectivity changes
        :param bool is_added: a bool flag indicating if connections are added or removed
        :return updated key
        :rtype: str
        """
        return key.replace("Changed", "Added") if is_added else key.replace("Changed", "Removed")

    @staticmethod
    def get_explanation_from_conn_graph(conn_graph, is_first_connectivity_result):
        """
        :param conn_graph:  a ConnectivityGraph with added/removed connections
        :param is_first_connectivity_result: bool flag indicating if this is the first connectivity fw-rules computation
               for the current semantic-diff query
        :return: fw-rules summarizing added/removed connections
        :rtype: Union[str, dict] - dict if required format is yaml/json , str otherwise
        """
        fw_rules = conn_graph.get_minimized_firewall_rules()
        # for csv format, adding the csv header only for the first connectivity fw-rules computation
        fw_rules_output = fw_rules.get_fw_rules_in_required_format(False, is_first_connectivity_result)
        return fw_rules_output

    def compute_explanation_for_key(self, key, is_added, conn_graph, is_first_connectivity_result):
        """
        computes the explanation for given key and conn_graph with description and fw-rules results
        prepares the description and explanation
        description text is written for txt, yaml and json formats
        other formats description already included in the conn_graph data
        :param str key: the key describing the changes
        :param bool is_added: a bool flag indicating if connections are added or removed
        :param ConnectivityGraph conn_graph: a ConnectivityGraph with added/removed connections
        :param bool is_first_connectivity_result: flag indicating if this is the first connectivity fw-rules computation
               for the current semantic-diff query
        :return the computedExplanation of the current key and conn_graph considering the outputFormat
        :rtype: ComputedExplanation
        """
        updated_key = self._get_updated_key(key, is_added)
        topology_config_name = self.name2 if is_added else self.name1
        connectivity_changes_header = f'{updated_key} (based on topology from config: {topology_config_name}) :'
        if self.output_config.outputFormat == 'txt_no_fw_rules':
            conn_graph_explanation = conn_graph.get_connections_without_fw_rules_txt_format(connectivity_changes_header) + '\n'
        else:
            conn_graph_explanation = self.get_explanation_from_conn_graph(conn_graph, is_first_connectivity_result)

        if self.output_config.outputFormat in ['json', 'yaml']:
            explanation_dict = {'description': updated_key}
            explanation_dict.update(conn_graph_explanation)
            key_explanation = ComputedExplanation(dict_explanation=explanation_dict)
        else:
            str_explanation = f'\n{connectivity_changes_header}\n' if self.output_config.outputFormat == 'txt' else ''
            str_explanation += conn_graph_explanation
            key_explanation = ComputedExplanation(str_explanation=str_explanation)

        return key_explanation

    def get_results_for_computed_fw_rules(self, keys_list, conn_graph_removed_per_key, conn_graph_added_per_key):
        """
        Compute accumulated explanation and res for all keys of changed connections categories
        :param keys_list: the list of keys
        :param conn_graph_removed_per_key: map from key to ConnectivityGraph of removed connections
        :param conn_graph_added_per_key: map from key to ConnectivityGraph of added connections
        :return:
        res (int): number of categories with diffs
        explanation (list): list of ComputedExplanation, the diffs' explanations, one for each category
        :rtype: int, list[ComputedExplanation]
        """
        explanation = []
        add_explanation = self.output_config.outputFormat in SemanticDiffQuery.get_supported_output_formats()
        res = 0
        for key in keys_list:
            conn_graph_added_conns = conn_graph_added_per_key[key]
            conn_graph_removed_conns = conn_graph_removed_per_key[key]
            is_added = conn_graph_added_conns is not None and conn_graph_added_conns.conn_graph_has_fw_rules()
            is_removed = conn_graph_removed_conns is not None and conn_graph_removed_conns.conn_graph_has_fw_rules()
            if is_added:
                if add_explanation:
                    explanation.append(self.compute_explanation_for_key(key, True, conn_graph_added_conns, res == 0))
                res += 1

            if is_removed:
                if add_explanation:
                    explanation.append(self.compute_explanation_for_key(key, False, conn_graph_removed_conns, res == 0))
                res += 1

        return res, explanation

    def get_conn_graph_changed_conns(self, key, ip_blocks, is_added):
        """
        create a ConnectivityGraph for changed (added/removed) connections per given key
        :param key: the key (category) of changed connections
        :param ip_blocks: a PeerSet of ip-blocks to be added for the topology peers
        :param is_added: a bool flag indicating if connections are added or removed
        :return: a ConnectivityGraph object
        """
        old_peers = self.config1.peer_container.get_all_peers_group(include_dns_entries=True)
        new_peers = self.config2.peer_container.get_all_peers_group(include_dns_entries=True)
        allowed_labels = (self.config1.get_allowed_labels()).union(self.config2.get_allowed_labels())
        topology_peers = new_peers | ip_blocks if is_added else old_peers | ip_blocks
        # following query_name update is for adding query line descriptions for csv and md formats
        updated_key = self._get_updated_key(key, is_added)
        if self.output_config.queryName:
            query_name = f'semantic_diff, config1: {self.config1.name}, config2: {self.config2.name}, key: {updated_key}'
        else:
            # omit the query name prefix if self.output_config.queryName is empty (single query from command line)
            query_name = updated_key
        output_config = OutputConfiguration(self.output_config, query_name)
        return ConnectivityGraph(topology_peers, allowed_labels, output_config)

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
        explanation (list): list of diff explanations - one for each category
        :rtype: int, list[ComputedExplanation]
        """
        old_peers = self.config1.peer_container.get_all_peers_group(include_dns_entries=True)
        new_peers = self.config2.peer_container.get_all_peers_group(include_dns_entries=True)
        intersected_peers = old_peers & new_peers
        removed_peers = old_peers - intersected_peers
        added_peers = new_peers - intersected_peers
        captured_pods = (self.config1.get_captured_pods() | self.config2.get_captured_pods()) & intersected_peers
        exclude_ipv6 = self.output_config.excludeIPv6Range
        old_ip_blocks = IpBlock.disjoint_ip_blocks(self.config1.get_referenced_ip_blocks(exclude_ipv6),
                                                   IpBlock.get_all_ips_block_peer_set(exclude_ipv6),
                                                   exclude_ipv6)
        new_ip_blocks = IpBlock.disjoint_ip_blocks(self.config2.get_referenced_ip_blocks(exclude_ipv6),
                                                   IpBlock.get_all_ips_block_peer_set(exclude_ipv6),
                                                   exclude_ipv6)

        conn_graph_removed_per_key = dict()
        conn_graph_added_per_key = dict()
        keys_list = []

        # 1.1. lost connections between removed peers
        key = 'Lost connections between removed peers'
        keys_list.append(key)
        conn_graph_removed_per_key[key] = self.get_conn_graph_changed_conns(key, PeerSet(), False)
        conn_graph_added_per_key[key] = None
        for pair in itertools.permutations(removed_peers, 2):
            if not self.determine_whether_to_compute_allowed_conns_for_peer_types(pair[0], pair[1]):
                continue
            lost_conns, _, _, _ = self.config1.allowed_connections(pair[0], pair[1])
            if lost_conns:
                conn_graph_removed_per_key[key].add_edge(pair[0], pair[1], lost_conns)

        # 1.2. lost connections between removed peers and ipBlocks
        key = 'Lost connections between removed peers and ipBlocks'
        keys_list.append(key)
        conn_graph_removed_per_key[key] = self.get_conn_graph_changed_conns(key, old_ip_blocks, False)
        conn_graph_added_per_key[key] = None
        for pair in itertools.product(removed_peers, old_ip_blocks):
            if not self.determine_whether_to_compute_allowed_conns_for_peer_types(pair[0], pair[1]):
                continue
            lost_conns, _, _, _ = self.config1.allowed_connections(pair[0], pair[1])
            if lost_conns:
                conn_graph_removed_per_key[key].add_edge(pair[0], pair[1], lost_conns)

            if not self.determine_whether_to_compute_allowed_conns_for_peer_types(pair[1], pair[0]):
                continue
            lost_conns, _, _, _ = self.config1.allowed_connections(pair[1], pair[0])
            if lost_conns:
                conn_graph_removed_per_key[key].add_edge(pair[1], pair[0], lost_conns)

        # 2.1. lost connections between removed peers and intersected peers
        key = 'Lost connections between removed peers and persistent peers'
        keys_list.append(key)
        conn_graph_removed_per_key[key] = self.get_conn_graph_changed_conns(key, PeerSet(), False)
        conn_graph_added_per_key[key] = None
        for pair in itertools.product(removed_peers, intersected_peers):
            if not self.determine_whether_to_compute_allowed_conns_for_peer_types(pair[0], pair[1]):
                continue
            lost_conns, _, _, _ = self.config1.allowed_connections(pair[0], pair[1])
            if lost_conns:
                conn_graph_removed_per_key[key].add_edge(pair[0], pair[1], lost_conns)

            if not self.determine_whether_to_compute_allowed_conns_for_peer_types(pair[1], pair[0]):
                continue
            lost_conns, _, _, _ = self.config1.allowed_connections(pair[1], pair[0])
            if lost_conns:
                conn_graph_removed_per_key[key].add_edge(pair[1], pair[0], lost_conns)

        # 3.1. lost/new connections between intersected peers due to changes in policies and labels of pods/namespaces
        key = 'Changed connections between persistent peers'
        keys_list.append(key)
        conn_graph_removed_per_key[key] = self.get_conn_graph_changed_conns(key, PeerSet(), False)
        conn_graph_added_per_key[key] = self.get_conn_graph_changed_conns(key, PeerSet(), True)
        for peer1 in intersected_peers:
            for peer2 in intersected_peers if peer1 in captured_pods else captured_pods:
                if peer1 == peer2:
                    continue
                if not self.determine_whether_to_compute_allowed_conns_for_peer_types(peer1, peer2):
                    continue
                old_conns, _, _, _ = self.config1.allowed_connections(peer1, peer2)
                new_conns, _, _, _ = self.config2.allowed_connections(peer1, peer2)
                if new_conns != old_conns:
                    conn_graph_removed_per_key[key].add_edge(peer1, peer2, old_conns - new_conns)
                    conn_graph_added_per_key[key].add_edge(peer1, peer2, new_conns - old_conns)

        # 3.2. lost/new connections between intersected peers and ipBlocks due to changes in policies and labels
        key = 'Changed connections between persistent peers and ipBlocks'
        disjoint_ip_blocks = IpBlock.disjoint_ip_blocks(old_ip_blocks, new_ip_blocks, exclude_ipv6)
        peers = captured_pods | disjoint_ip_blocks
        keys_list.append(key)
        conn_graph_removed_per_key[key] = self.get_conn_graph_changed_conns(key, disjoint_ip_blocks, False)
        conn_graph_added_per_key[key] = self.get_conn_graph_changed_conns(key, disjoint_ip_blocks, True)
        for peer1 in peers:
            for peer2 in disjoint_ip_blocks if peer1 in captured_pods else captured_pods:
                if not self.determine_whether_to_compute_allowed_conns_for_peer_types(peer1, peer2):
                    continue
                old_conns, _, _, _ = self.config1.allowed_connections(peer1, peer2)
                new_conns, _, _, _ = self.config2.allowed_connections(peer1, peer2)
                if new_conns != old_conns:
                    conn_graph_removed_per_key[key].add_edge(peer1, peer2, old_conns - new_conns)
                    conn_graph_added_per_key[key].add_edge(peer1, peer2, new_conns - old_conns)

        # 4.1. new connections between intersected peers and added peers
        key = 'New connections between persistent peers and added peers'
        keys_list.append(key)
        conn_graph_removed_per_key[key] = None
        conn_graph_added_per_key[key] = self.get_conn_graph_changed_conns(key, PeerSet(), True)
        for pair in itertools.product(intersected_peers, added_peers):
            if not self.determine_whether_to_compute_allowed_conns_for_peer_types(pair[0], pair[1]):
                continue
            new_conns, _, _, _ = self.config2.allowed_connections(pair[0], pair[1])
            if new_conns:
                conn_graph_added_per_key[key].add_edge(pair[0], pair[1], new_conns)

            if not self.determine_whether_to_compute_allowed_conns_for_peer_types(pair[1], pair[0]):
                continue
            new_conns, _, _, _ = self.config2.allowed_connections(pair[1], pair[0])
            if new_conns:
                conn_graph_added_per_key[key].add_edge(pair[1], pair[0], new_conns)

        # 5.1. new connections between added peers
        key = 'New connections between added peers'
        keys_list.append(key)
        conn_graph_removed_per_key[key] = None
        conn_graph_added_per_key[key] = self.get_conn_graph_changed_conns(key, PeerSet(), True)
        for pair in itertools.permutations(added_peers, 2):
            if not self.determine_whether_to_compute_allowed_conns_for_peer_types(pair[0], pair[1]):
                continue
            new_conns, _, _, _ = self.config2.allowed_connections(pair[0], pair[1])
            if new_conns:
                conn_graph_added_per_key[key].add_edge(pair[0], pair[1], new_conns)

        # 5.2. new connections between added peers and ipBlocks
        key = 'New connections between added peers and ipBlocks'
        keys_list.append(key)
        conn_graph_removed_per_key[key] = None
        conn_graph_added_per_key[key] = self.get_conn_graph_changed_conns(key, new_ip_blocks, True)

        for pair in itertools.product(added_peers, new_ip_blocks):
            if not self.determine_whether_to_compute_allowed_conns_for_peer_types(pair[0], pair[1]):
                continue
            new_conns, _, _, _ = self.config2.allowed_connections(pair[0], pair[1])
            if new_conns:
                conn_graph_added_per_key[key].add_edge(pair[0], pair[1], new_conns)

            if not self.determine_whether_to_compute_allowed_conns_for_peer_types(pair[1], pair[0]):
                continue
            new_conns, _, _, _ = self.config2.allowed_connections(pair[1], pair[0])
            if new_conns:
                conn_graph_added_per_key[key].add_edge(pair[1], pair[0], new_conns)

        return self.get_results_for_computed_fw_rules(keys_list, conn_graph_removed_per_key,
                                                      conn_graph_added_per_key)

    def exec(self, cmd_line_flag):
        self.output_config.fullExplanation = True  # assign true for this query - it is always ok to compare its results
        query_answer = self.is_identical_topologies(True)
        if query_answer.bool_result and query_answer.output_result:
            return query_answer
        res, explanation = self.compute_diff()
        if res > 0:
            return QueryAnswer(bool_result=False,
                               output_result=f'{self.name1} and {self.name2} are not semantically equivalent.',
                               output_explanation=explanation,
                               numerical_result=res if not cmd_line_flag else 1)

        return QueryAnswer(bool_result=True,
                           output_result=f'{self.name1} and {self.name2} are semantically equivalent.',
                           output_explanation=explanation,
                           numerical_result=res)


class StrongEquivalenceQuery(TwoNetworkConfigsQuery):
    """
    Checks whether the two configs have exactly the same set of policies (same names and same semantics)
    """

    @staticmethod
    def get_query_type():
        return QueryType.PairComparisonQuery

    def exec(self, cmd_line_flag):
        query_answer = self.is_identical_topologies(True)
        if query_answer.output_result:
            query_answer.numerical_result = not query_answer.bool_result
            return query_answer

        policies1 = set(f'{policy_name}[{policy_type}]' for policy_name, policy_type in
                        self.config1.policies_container.policies.keys())
        policies2 = set(f'{policy_name}[{policy_type}]' for policy_name, policy_type in
                        self.config2.policies_container.policies.keys())
        policies_1_minus_2 = policies1.difference(policies2)
        policies_2_minus_1 = policies2.difference(policies1)
        if policies_1_minus_2:
            output_result = f'{self.name1} contains a network policy named {policies_1_minus_2.pop()}, but ' \
                            f'{self.name2} does not'
            return QueryAnswer(False, output_result, numerical_result=1)
        if policies_2_minus_1:
            output_result = f'{self.name2} contains a network policy named {policies_2_minus_1.pop()}, but ' \
                            f'{self.name1} does not'
            return QueryAnswer(False, output_result, numerical_result=1)

        for policy in self.config1.policies_container.policies.values():
            single_policy_config1 = self.config1.clone_with_just_one_policy(policy.full_name())
            single_policy_config2 = self.config2.clone_with_just_one_policy(policy.full_name())
            full_result = EquivalenceQuery(single_policy_config1, single_policy_config2, self.output_config).exec()
            if not full_result.bool_result:
                output_result = f'{self.policy_title(policy)} is not equivalent in {self.name1} and in {self.name2}'

                return QueryAnswer(False, output_result,
                                   output_explanation=full_result.output_explanation, numerical_result=1)

        return QueryAnswer(True, self.name1 + ' and ' + self.name2 + ' are strongly equivalent.', numerical_result=0)


class ContainmentQuery(TwoNetworkConfigsQuery):
    """
    Checking whether the connections allowed by config1 are contained in those allowed by config2
    """

    def exec(self, cmd_line_flag=False, only_captured=False):
        config1_peers = self.config1.peer_container.get_all_peers_group(include_dns_entries=True)
        peers_in_config1_not_in_config2 = config1_peers - \
            self.config2.peer_container.get_all_peers_group(include_dns_entries=True)
        if peers_in_config1_not_in_config2:
            peers_list = [str(e) for e in peers_in_config1_not_in_config2]
            final_explanation = \
                PodsListsExplanations(explanation_description=f'Peers in {self.name1} which are not in {self.name2}',
                                      pods_list=sorted(peers_list))
            return QueryAnswer(False, f'{self.name1} is not contained in {self.name2} ',
                               output_explanation=[final_explanation], numerical_result=0 if not cmd_line_flag else 1)

        peers_to_compare = config1_peers | self.disjoint_referenced_ip_blocks()
        captured_pods = self.config1.get_captured_pods() | self.config2.get_captured_pods()
        not_contained_list = []
        for peer1 in peers_to_compare:
            for peer2 in peers_to_compare if peer1 in captured_pods else captured_pods:
                if peer1 == peer2:
                    continue
                if not self.determine_whether_to_compute_allowed_conns_for_peer_types(peer1, peer2):
                    continue
                conns1_all, captured1_flag, conns1_captured, _ = self.config1.allowed_connections(peer1, peer2)
                if only_captured and not captured1_flag:
                    continue
                conns1 = conns1_captured if only_captured else conns1_all
                conns2, _, _, _ = self.config2.allowed_connections(peer1, peer2)
                if not conns1.contained_in(conns2):
                    not_contained_list.append(PeersAndConnections(str(peer1), str(peer2), conns1))
                    if not self.output_config.fullExplanation:
                        return self._query_answer_with_relevant_explanation(not_contained_list, cmd_line_flag)
        if not_contained_list:
            return self._query_answer_with_relevant_explanation(sorted(not_contained_list), cmd_line_flag)
        return QueryAnswer(True, self.name1 + ' is contained in ' + self.name2,
                           numerical_result=1 if not cmd_line_flag else 0)

    def _query_answer_with_relevant_explanation(self, explanation_list, cmd_line_flag):
        output_result = f'{self.name1} is not contained in {self.name2}'
        explanation_description = f'Connections allowed in {self.name1} which are not a subset of those in {self.name2}'
        final_explanation = ConnectionsDiffExplanation(explanation_description=explanation_description,
                                                       peers_diff_connections_list=explanation_list)
        return QueryAnswer(False, output_result, output_explanation=[final_explanation],
                           numerical_result=0 if not cmd_line_flag else 1)


class TwoWayContainmentQuery(TwoNetworkConfigsQuery):
    """
    Checks containment in both sides (whether config1 is contained in config2 and vice versa)
    """

    @staticmethod
    def get_query_type():
        return QueryType.PairComparisonQuery

    def exec(self, cmd_line_flag):
        query_answer = self.is_identical_topologies(True)
        if query_answer.bool_result and query_answer.output_result:
            return query_answer  # identical configurations (contained)

        contained_1_in_2 = \
            ContainmentQuery(self.config1, self.config2, self.output_config).exec(cmd_line_flag=cmd_line_flag)
        contained_2_in_1 = \
            ContainmentQuery(self.config2, self.config1, self.output_config).exec(cmd_line_flag=cmd_line_flag)
        if contained_1_in_2.bool_result and contained_2_in_1.bool_result:
            return QueryAnswer(bool_result=True,
                               output_result=f'The two network configurations {self.name1} and {self.name2} '
                                             'are semantically equivalent.',
                               numerical_result=3 if not cmd_line_flag else 0)

        if not contained_1_in_2.bool_result and not contained_2_in_1.bool_result:
            final_explanation = contained_2_in_1.output_explanation + contained_1_in_2.output_explanation
            return QueryAnswer(bool_result=False,
                               output_result=f'Neither network configuration {self.name1} and {self.name2} '
                                             f'are contained in the other',
                               output_explanation=final_explanation,
                               numerical_result=0 if not cmd_line_flag else 1)
        if contained_1_in_2.bool_result:
            return QueryAnswer(bool_result=False,
                               output_result=f'Network configuration {self.name1} is a proper'
                                             f' subset of {self.name2} but ' + contained_2_in_1.output_result,
                               output_explanation=contained_2_in_1.output_explanation,
                               numerical_result=2 if not cmd_line_flag else 1)
        # (contained_2_in_1)
        return QueryAnswer(bool_result=False,
                           output_result=f'Network configuration {self.name2} is a proper '
                                         f'subset of {self.name1} but ' + contained_1_in_2.output_result,
                           output_explanation=contained_1_in_2.output_explanation,
                           numerical_result=1)


class PermitsQuery(TwoNetworkConfigsQuery):
    """
    Checking whether the connections explicitly allowed by config1 are allowed by config2
    """

    def exec(self, cmd_line_flag):
        output_result_on_permit = f'{self.name2} permits all connections specified in {self.name1}'
        if not self.config1:
            return QueryAnswer(False,
                               output_result='There are no NetworkPolicies in the given permits config. '
                                             'No traffic is specified as permitted.', query_not_executed=True)
        query_answer = self.is_identical_topologies()
        if query_answer.output_result:
            query_answer.numerical_result = 0 if not cmd_line_flag else not query_answer.bool_result
            if query_answer.bool_result:  # same topologies and same policies
                query_answer.output_result = output_result_on_permit
            return query_answer

        if self.config1.policies_container.layers.does_contain_single_layer(NetworkLayerName.Ingress):
            return QueryAnswer(bool_result=False,
                               output_result='Permitted traffic cannot be specified using Ingress resources only',
                               query_not_executed=True)

        config1_without_ingress = self.clone_without_ingress(self.config1)
        query_answer = ContainmentQuery(config1_without_ingress, self.config2,
                                        self.output_config).exec(cmd_line_flag=cmd_line_flag, only_captured=True)
        if not cmd_line_flag:
            query_answer.numerical_result = 1 if query_answer.output_explanation else 0
        if query_answer.bool_result:
            query_answer.output_result = output_result_on_permit
        if query_answer.output_explanation:
            query_answer.output_result = f'{self.name2} does not permit connections specified in {self.name1}'
        return query_answer


class InterferesQuery(TwoNetworkConfigsQuery):
    """
    Checking whether config2 extends config1's allowed connection for Pods captured by policies in config1
    """

    def exec(self, cmd_line_flag):
        query_answer = self.is_identical_topologies()
        if query_answer.output_result:
            query_answer.numerical_result = query_answer.bool_result if not cmd_line_flag \
                else not query_answer.bool_result
            return query_answer

        peers_to_compare = \
            self.config2.peer_container.get_all_peers_group(include_dns_entries=True)
        peers_to_compare |= self.disjoint_referenced_ip_blocks()
        captured_pods = self.config2.get_captured_pods() | self.config1.get_captured_pods()
        extended_conns_list = []
        for peer1 in peers_to_compare:
            for peer2 in peers_to_compare if peer1 in captured_pods else captured_pods:
                if peer1 == peer2:
                    continue
                if not self.determine_whether_to_compute_allowed_conns_for_peer_types(peer1, peer2):
                    continue
                _, captured2_flag, conns2_captured, _ = self.config2.allowed_connections(peer1, peer2)
                if not captured2_flag:
                    continue
                _, captured1_flag, conns1_captured, _ = self.config1.allowed_connections(peer1, peer2)
                if captured1_flag and not conns1_captured.contained_in(conns2_captured):
                    extended_conns_list.append(PeersAndConnections(str(peer1), str(peer2), conns1_captured,
                                                                   conns2_captured))
                    if not self.output_config.fullExplanation:
                        return self._query_answer_with_relevant_explanation(extended_conns_list, cmd_line_flag)
        if extended_conns_list:
            return self._query_answer_with_relevant_explanation(sorted(extended_conns_list), cmd_line_flag)
        return QueryAnswer(False, self.name1 + ' does not interfere with ' + self.name2,
                           numerical_result=0 if not cmd_line_flag else 1)

    def _query_answer_with_relevant_explanation(self, explanation_list, cmd_line_flag):
        interfere_result_msg = self.name1 + ' interferes with ' + self.name2
        explanation_description = f'Allowed connections from {self.name2} which are extended in {self.name1}'
        final_explanation = ConnectionsDiffExplanation(explanation_description=explanation_description,
                                                       peers_diff_connections_list=explanation_list,
                                                       configs=self.get_configs_names(), conns_diff=True)
        return QueryAnswer(True, interfere_result_msg, output_explanation=[final_explanation],
                           numerical_result=1 if not cmd_line_flag else 0)


# Checks whether any two sets in the list interfere each other
class PairwiseInterferesQuery(TwoNetworkConfigsQuery):

    @staticmethod
    def get_query_type():
        return QueryType.PairwiseComparisonQuery

    def exec(self, cmd_line_flag):
        return InterferesQuery(self.config1, self.config2, self.output_config).exec(cmd_line_flag)


# Local class - helps with getting the results for ForbidsQuery
class IntersectsQuery(TwoNetworkConfigsQuery):
    """
    Checking whether both configs allow the same connection between any pair of peers
    """

    def exec(self, cmd_line_flag=False, only_captured=True):
        query_answer = self.is_identical_topologies()
        if query_answer.output_result:
            return query_answer

        peers_to_compare = \
            self.config1.peer_container.get_all_peers_group(include_dns_entries=True)
        peers_to_compare |= self.disjoint_referenced_ip_blocks()
        captured_pods = self.config1.get_captured_pods() | self.config2.get_captured_pods()
        intersect_connections_list = []
        for peer1 in peers_to_compare:
            for peer2 in peers_to_compare if peer1 in captured_pods else captured_pods:
                if peer1 == peer2:
                    continue
                if not self.determine_whether_to_compute_allowed_conns_for_peer_types(peer1, peer2):
                    continue
                conns1_all, captured1_flag, conns1_captured, _ = self.config1.allowed_connections(peer1, peer2)
                if only_captured and not captured1_flag:
                    continue
                conns1 = conns1_captured if only_captured else conns1_all
                conns2, _, _, _ = self.config2.allowed_connections(peer1, peer2)
                conns_in_both = conns2 & conns1
                if bool(conns_in_both):
                    intersect_connections_list.append(PeersAndConnections(str(peer1), str(peer2), conns_in_both))
                    if not self.output_config.fullExplanation:
                        return self._query_answer_with_relevant_explanation(intersect_connections_list)

        if intersect_connections_list:
            return self._query_answer_with_relevant_explanation(sorted(intersect_connections_list))

        return QueryAnswer(False, f'The connections allowed by {self.name1}'
                                  f' do not intersect the connections allowed by {self.name2}', numerical_result=1)

    def _query_answer_with_relevant_explanation(self, explanation_list):
        intersect_result_msg = self.name2 + ' intersects with ' + self.name1
        final_explanation = ConnectionsDiffExplanation(peers_diff_connections_list=explanation_list)
        return QueryAnswer(bool_result=True, output_result=intersect_result_msg,
                           output_explanation=[final_explanation])


class ForbidsQuery(TwoNetworkConfigsQuery):
    """
    Checking whether the connections explicitly allowed by config1 are denied by config2
    """

    def exec(self, cmd_line_flag):
        if not self.config1:
            return QueryAnswer(False, 'There are no NetworkPolicies in the given forbids config. '
                                      'No traffic is specified as forbidden.', query_not_executed=True)
        if self.config1.policies_container.layers.does_contain_single_layer(NetworkLayerName.Ingress):
            return QueryAnswer(bool_result=False,
                               output_result='Forbidden traffic cannot be specified using Ingress resources only',
                               query_not_executed=True)

        config1_without_ingress = self.clone_without_ingress(self.config1)

        query_answer = \
            IntersectsQuery(config1_without_ingress, self.config2, self.output_config).exec(only_captured=True)
        if query_answer.numerical_result == 1:
            query_answer.output_result += f'\n{self.name2} forbids connections specified in ' \
                                          f'{self.name1}'
        if query_answer.output_explanation:
            assert len(query_answer.output_explanation) == 1
            query_answer.output_result = f'{self.name2} does not forbid connections specified in {self.name1}'
            query_answer.output_explanation[0].explanation_description = f'Both {self.name1} and {self.name2} allow ' \
                                                                         f'the following connection(s)'
        query_answer.numerical_result = int(query_answer.bool_result)
        return query_answer


class AllCapturedQuery(NetworkConfigQuery):
    """
    Check that all pods are captured
    Applies for k8s/calico/istio policies (checks only ingress direction for istio)
    """

    def _get_pod_name(self, pod):
        """
        :param Pod pod: a pod object
        :rtype str
        """
        return pod.workload_name if self.output_config.outputEndpoints == 'deployments' else str(pod)

    def _get_uncaptured_xgress_pods(self, layer_name, is_ingress=True):
        """
        returns the uncaptured ingress/egress pods set and its length for the given layer
        :param NetworkLayerName layer_name: the layer to check uncaptured pods in
        :param bool is_ingress: indicates if to check pods affected by ingress/egress
        :return: - number of uncaptured pod
                 - set of the uncaptured pods
        :rtype: (int,set[str])
        """
        # get_all_peers_group() does not require getting dnsEntry peers, since they are not ClusterEP (pods)
        existing_pods = self.config.peer_container.get_all_peers_group()
        uncaptured_xgress_pods = existing_pods - self.config.get_affected_pods(is_ingress, layer_name)
        if not uncaptured_xgress_pods:
            return 0, set()
        uncaptured_resources = set(self._get_pod_name(pod) for pod in uncaptured_xgress_pods)  # no duplicate resources in set
        return len(uncaptured_resources), uncaptured_resources

    def _compute_uncaptured_pods_by_layer(self, layer_name, ingress_only=False):
        """
        computes and returns the result of allcaptured query on the given layer if it includes policies
        :param NetworkLayerName layer_name: the layer to check uncaptured pods in
        :param bool ingress_only: a flag to indicate if to check captured pods only for ingress affected policies
        :return: 1- if there are uncaptured pods then return an explanation containing them, else None
                 2- the number of uncaptured pods on the layer
        :rtype: (PodsListsExplanations, int)
        """
        if layer_name not in self.config.policies_container.layers:
            return None, 0  # not relevant to compute for non-existed layer
        if ingress_only:
            print(f'Warning: AllCaptured query is not considering uncaptured pods in {layer_name.name} egress direction')

        res_ingress, uncaptured_ingress_pods_set = self._get_uncaptured_xgress_pods(layer_name, is_ingress=True)
        res_egress = 0
        uncaptured_egress_pods_set = set()
        if not ingress_only:
            res_egress, uncaptured_egress_pods_set = self._get_uncaptured_xgress_pods(layer_name, is_ingress=False)

        layer_res = res_ingress + res_egress
        if layer_res == 0:  # no uncaptured pods in this layer, no explanation would be written
            return None, 0

        explanation_str = f'workload resources that are not captured by any {layer_name.name} policy that affects '
        layer_explanation = PodsListsExplanations(explanation_description=explanation_str,
                                                  pods_list=list(sorted(uncaptured_ingress_pods_set)),
                                                  egress_pods_list=list(sorted(uncaptured_egress_pods_set)),
                                                  add_xgress_suffix=True)
        return layer_explanation, layer_res

    def exec(self):
        self.output_config.fullExplanation = True  # assign true for this query - it is always ok to compare its results
        # get_all_peers_group() does not require getting dnsEntry peers, since they are not ClusterEP (pods)
        existing_pods = self.config.peer_container.get_all_peers_group()
        if not self.config:
            return QueryAnswer(bool_result=False,
                               output_result=f'There are no network policies in {self.config.name}. '
                                             f'All workload resources are non captured',
                               numerical_result=len(existing_pods))

        if self.config.policies_container.layers.does_contain_single_layer(NetworkLayerName.Ingress):
            return QueryAnswer(bool_result=False,
                               output_result='AllCapturedQuery cannot be applied using Ingress resources only',
                               query_not_executed=True)

        k8s_calico_pods_list_explanation, k8s_calico_res = self._compute_uncaptured_pods_by_layer(NetworkLayerName.K8s_Calico)
        istio_pods_list_explanation, istio_res = self._compute_uncaptured_pods_by_layer(NetworkLayerName.Istio, True)

        if k8s_calico_res == 0 and istio_res == 0:
            output_str = f'All pods are captured by at least one policy in {self.config.name}'
            return QueryAnswer(bool_result=True, output_result=output_str, numerical_result=0)

        final_explanation = []
        if k8s_calico_pods_list_explanation:
            final_explanation.append(k8s_calico_pods_list_explanation)
        if istio_pods_list_explanation:
            final_explanation.append(istio_pods_list_explanation)

        output_str = f'There are workload resources not captured by any policy in {self.config.name}'
        res = k8s_calico_res + istio_res
        return QueryAnswer(bool_result=False, output_result=output_str, output_explanation=final_explanation,
                           numerical_result=res)
