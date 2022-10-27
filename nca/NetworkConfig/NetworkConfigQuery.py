#
# Copyright 2020- IBM Inc. All rights reserved
# SPDX-License-Identifier: Apache2.0
#
import itertools
import os
from dataclasses import dataclass
from collections import defaultdict
from enum import Enum
from typing import Union
import yaml

from nca.Utils.OutputConfiguration import OutputConfiguration
from nca.CoreDS.ConnectionSet import ConnectionSet
from nca.CoreDS.Peer import PeerSet, IpBlock, Pod, Peer
from nca.Resources.CalicoNetworkPolicy import CalicoNetworkPolicy
from nca.Resources.IngressPolicy import IngressPolicy
from nca.FWRules.ConnectivityGraph import ConnectivityGraph
from .NetworkConfig import NetworkConfig
from .NetworkLayer import NetworkLayerName


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
    # output explanation type may vary according to the pattern of the query results
    output_explanation: Union[str, list, tuple] = None
    numerical_result: int = 0
    query_not_executed: bool = False


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
        return {'txt', 'yaml'}

    @staticmethod
    def policy_title(policy):
        """
        Return the title of the given policy, including the type name and the policy name
        :param policy: the given policy
        :return: the title of the policy
        """
        return f'{policy.policy_type_str()} {policy.full_name()}'

    # following methods for writing query output in the required format
    def write_query_output(self, query_answer, explanation_header='', yaml_explanation_descriptions=None, query_result=None):
        """
        calls the relevant method to write the query output in the required format
        :param QueryAnswer query_answer: the query answer
        :param str explanation_header: the txt message that describes the query's output explanation
        :param list yaml_explanation_descriptions: [optional] the txt messages of explanations for yaml format,
        relevant for TwoNetworkConfigsQuery classes
        :param int query_result: [optional] the numerical result of the query, relevant for TwoNetworkConfigsQuery classes
        """
        # compatibility for the called methods
        yaml_description = yaml_explanation_descriptions or explanation_header
        numerical_result = query_result if query_result is not None else int(query_answer.numerical_result)
        if self.output_config.outputFormat not in self.get_supported_output_formats():
            return ''

        if self.output_config.outputFormat == 'yaml':
            return self.write_yaml_output(query_answer, yaml_description, numerical_result)

        return self.write_txt_output(query_answer, explanation_header)

    def write_txt_output(self, query_answer, explanation_description):
        query_output = query_answer.output_result + '\n'
        if query_answer.output_explanation:
            query_output += self.compute_txt_explanation(query_answer, explanation_description) + '\n'
        return query_output

    def write_yaml_output(self, query_answer, descriptions, query_result):
        query_name = self.output_config.queryName or type(self).__name__
        configs_field = 'config' if isinstance(self, NetworkConfigQuery) else 'configs'
        yaml_content = {'query': query_name, configs_field: self.get_configs_names()}
        if query_answer.query_not_executed:
            yaml_content.update({'executed': 0, 'description': query_answer.output_result})
            return yaml.dump(yaml_content, None, default_flow_style=False, sort_keys=False) + '---\n'
        yaml_content.update({'numerical_result': query_result})
        yaml_content.update({'textual_result': query_answer.output_result})
        if query_answer.output_explanation:
            return self.compute_yaml_with_explanation(yaml_content, descriptions, query_answer.output_explanation)
        return yaml.dump(yaml_content, None, default_flow_style=False, sort_keys=False) + '---\n'

    def compute_txt_explanation(self, query_answer, explanation):  # virtual
        raise NotImplementedError


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
        self._update_output_config_object_with_config_name()

    @staticmethod
    def get_query_output(query_answer, only_explanation=False):
        """
        computes the query result and query output of SanityQuery and ConnectivityMapQuery
        SanityQuery supports only txt
        ConnectivityMapQuery has the output explanation in the required format (it is computed during the query exec)
        :param QueryAnswer query_answer: the query_answer of the query
        :param bool only_explanation: indicates if to consider only the output_explanation in the query
        output computation
        :return the query result, query output in required format, if the query was not executed
        :rtype: (int, str, bool)
        """
        res = query_answer.numerical_result
        query_output = query_answer.output_result
        if query_answer.output_explanation:
            assert isinstance(query_answer.output_explanation, str)
            if only_explanation:
                return res, query_answer.output_explanation, query_answer.query_not_executed
            query_output += query_answer.output_explanation
        return res, query_output, query_answer.query_not_executed

    @staticmethod
    def get_query_type():
        return QueryType.SingleConfigQuery

    def _update_output_config_object_with_config_name(self):
        self.output_config.configName = self.config.name

    # following methods help with writing the query output in the required format
    def compute_txt_explanation(self, query_answer, explanation_description):
        """
        returns the query's output explanation in a txt format
        :param QueryAnswer query_answer: the query answer of the query
        :param str explanation_description: the txt message that describes the query's output explanation
        :rtype: str
        """
        return self.convert_explanation_to_required_format(query_answer.output_explanation, explanation_description)

    def get_configs_names(self):
        return self.output_config.configName

    def compute_yaml_with_explanation(self, yaml_content, explanation_description, output_explanation):
        """
        returns the query's output explanation in a yaml format
        :param dict yaml_content: the already generated content of the yaml object
        :param str explanation_description: the txt message that describes the query's output explanation
        :param output_explanation: the query output explanation
        :rtype: str
        """
        yaml_format = self.convert_explanation_to_required_format(output_explanation, explanation_description)
        yaml_content.update({'explanation': yaml_format})
        return yaml.dump(yaml_content, None, default_flow_style=False, sort_keys=False) + '---\n'

    def convert_explanation_to_required_format(self, explanation_lists, explanation_description):
        """
        convert the query's output_explanation into the required format
        this function is applied for EmptinessQuery and RedundancyQuery since their output_explanations have the same
        pattern, other classes derived from NetworkConfigQuery override this method as needed
        :param tuple explanation_lists: the query output explanation
        :param str explanation_description: the description of the explanation
        :return: the explanation in the required format, str for txt format, list for yaml
        :rtype: Union[str, list]
        """
        assert isinstance(explanation_lists, tuple)  # tuple of (policies, ingress_rules, egress_rules)
        txt_res = ''
        yaml_result = []
        policies_list = explanation_lists[0]
        if policies_list:
            description = 'Policies' + explanation_description
            if self.output_config.outputFormat == 'txt':
                txt_res = description + ':\n' + ', '.join(policies_list) + '\n'
            else:  # yaml
                yaml_result.append({'description': description,
                                    'policies': [policy.split()[1] for policy in policies_list]})
        ingress_rules_map = explanation_lists[1]
        if ingress_rules_map:
            description = 'Ingress rules' + explanation_description
            if self.output_config.outputFormat == 'txt':
                txt_res += '\n' + description + ':\n'
                for key, value in ingress_rules_map.items():
                    txt_res += key + ', ingress rules indexes: ' + ', '.join(str(idx) for idx in value) + '\n'
            else:
                rules = []
                for key, value in ingress_rules_map.items():
                    rules.append({'policy': key.split()[1], 'ingress_rules_indexes': [str(idx) for idx in value]})
                yaml_result.append({'description': description, 'pairs': rules})
        egress_rules_map = explanation_lists[2]
        if egress_rules_map:
            description = 'Egress rules' + explanation_description
            if self.output_config.outputFormat == 'txt':
                txt_res += '\n' + description + ':\n'
                for key, value in egress_rules_map.items():
                    txt_res += key + ', egress rules indexes: ' + ', '.join(str(idx) for idx in value) + '\n'
            else:
                rules = []
                for key, value in egress_rules_map.items():
                    rules.append({'policy': key.split()[1], 'egress_rules_indexes': [str(idx) for idx in value]})
                yaml_result.append({'description': description, 'pairs': rules})
        if self.output_config.outputFormat == 'yaml':
            return yaml_result
        return txt_res


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
                        common_pods = intersection if self.output_config.fullExplanation else intersection.rep()
                        non_disjoint_explanation_list.append((self.policy_title(policy1), self.policy_title(policy2),
                                                              common_pods))

        if not non_disjoint_explanation_list:
            return QueryAnswer(True, 'All policies are disjoint in ' + self.config.name, numerical_result=0)
        return QueryAnswer(False,
                           output_result='There are policies capturing the same pods in ' + self.config.name,
                           output_explanation=sorted(non_disjoint_explanation_list),
                           numerical_result=len(non_disjoint_explanation_list))

    def execute_and_write_output_in_required_format(self):
        query_answer = self.exec()
        explanation_header = 'policies with overlapping captured pods'
        return query_answer.numerical_result, self.write_query_output(query_answer, explanation_header),\
            query_answer.query_not_executed

    def convert_explanation_to_required_format(self, explanation_list, explanation_description):
        assert isinstance(explanation_list, list)  # list of tuples (policy1, policy2, pods)
        result = []
        delimiter = ' '
        for item in explanation_list:
            if self.output_config.outputFormat == 'txt':
                result.append(f'{item[0].split(delimiter)[0]}_1: {item[0].split(delimiter)[1]}, '
                              f'{item[1].split(delimiter)[0]}_2: {item[1].split(delimiter)[1]}, pods: {item[2]}')
            else:
                result.append({'policies': [item[0].split(' ')[1], item[1].split(' ')[1]],
                               'pods': str(item[2]).split(', ')})
        if self.output_config.outputFormat == 'yaml':
            return {'description': explanation_description, 'examples': result}
        return explanation_description + ':\n' + '\n'.join(result)  # txt


class EmptinessQuery(NetworkConfigQuery):
    """
    Check if any policy or one of its rules captures an empty set of peers
    """

    def exec(self):
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
            return QueryAnswer(False, 'No empty NetworkPolicies and no empty rules in ' + self.config.name, res)

        full_explanation_list = (empty_policies, empty_ingress_rules, empty_egress_rules)
        return QueryAnswer(res > 0,
                           'There are empty NetworkPolicies and/or empty ingress/egress rules in ' + self.config.name,
                           full_explanation_list, res)

    def execute_and_write_output_in_required_format(self):
        query_answer = self.exec()
        self.output_config.fullExplanation = True  # always true for this query
        description_suffix = ' that does not select any pods'
        return query_answer.numerical_result, self.write_query_output(query_answer, description_suffix), \
            query_answer.query_not_executed


class VacuityQuery(NetworkConfigQuery):
    """
    Check if the set of policies changes the cluster's default behavior
    """

    def exec(self):
        # TODO: should handle 'ingress' layer or not? (ingress controller pod is not expected to have egress
        #  traffic without any Ingress resource)
        #  currently ignoring ingres layer, removing it from configs on this query
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

    def execute_and_write_output_in_required_format(self):
        query_answer = self.exec()
        self.output_config.fullExplanation = True  # it is always true for this query
        return query_answer.numerical_result, self.write_query_output(query_answer), query_answer.query_not_executed


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
                if EquivalenceQuery(self.config, config_without_policy).exec(layer_name).bool_result:
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
            equiv_result = EquivalenceQuery(self.config, config_with_modified_policy).exec(layer_name)
            if equiv_result.bool_result:
                redundant_ingress_rules.append(rule_index)
        for rule_index, egress_rule in enumerate(policy.egress_rules, start=1):
            modified_policy = policy.clone_without_rule(egress_rule, False)
            if len(modified_policy.egress_rules) < len(policy.egress_rules) - 1:
                redundant_egress_rules.append(rule_index)
                continue
            config_with_modified_policy = self.config.clone_without_policy(policy)
            config_with_modified_policy.append_policy_to_config(modified_policy)
            if EquivalenceQuery(self.config, config_with_modified_policy).exec(layer_name).bool_result:
                redundant_egress_rules.append(rule_index)
        return redundant_ingress_rules, redundant_egress_rules

    def exec(self):
        res = 0
        redundant_policies = []
        redundant_ingress_rules = {}
        redundant_egress_rules = {}
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
            full_explanation_list = (redundant_policies, redundant_ingress_rules, redundant_egress_rules)
            return QueryAnswer(True, 'Redundancies found in ' + self.config.name, full_explanation_list, res)
        return QueryAnswer(False, 'No redundancy found in ' + self.config.name)

    def execute_and_write_output_in_required_format(self):
        query_answer = self.exec()
        self.output_config.fullExplanation = True  # always true for this query
        description_suffix = f' that are redundant in {self.output_config.configName}'
        return query_answer.numerical_result, self.write_query_output(query_answer, description_suffix), \
            query_answer.query_not_executed


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
            if other_policy.get_order() and self_policy.get_order() and other_policy.get_order() < self_policy.get_order():
                return None  # All other policies have a lower order and cannot contain self_policy
            if other_policy == self_policy:
                continue
            if not self_policy.selected_peers.issubset(other_policy.selected_peers):
                continue
            config_with_other_policy = self.config.clone_with_just_one_policy(other_policy.full_name())
            if ContainmentQuery(config_with_self_policy, config_with_other_policy).exec(True).bool_result:
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
            if other_policy.get_order() and self_policy.get_order() and other_policy.get_order() < self_policy.get_order():
                return None  # not checking lower priority for Calico
            if other_policy == self_policy:
                continue
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
            if other_policy.get_order() and self_policy.get_order() and other_policy.get_order() < self_policy.get_order():
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
            return QueryAnswer(False, f'No NetworkPolicies in {self.config.name}. Nothing to check sanity on.', '')

        # check for conflicting policies in calico layer
        has_conflicting_policies, conflict_explanation = self.has_conflicting_policies_with_same_order()
        if has_conflicting_policies:
            return QueryAnswer(bool_result=False, output_result=conflict_explanation, output_explanation='',
                               numerical_result=1)
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
                           output_explanation=policies_issue + rules_issues, numerical_result=issues_counter)

    def execute_and_write_output_in_required_format(self):
        query_answer = self.exec()
        return self.get_query_output(query_answer)


class ConnectivityMapQuery(NetworkConfigQuery):
    """
    Print the connectivity graph in the form of firewall rules
    """

    @staticmethod
    def get_supported_output_formats():
        return {'txt', 'yaml', 'csv', 'md', 'dot'}

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

    @staticmethod
    def are_labels_all_included(target_labels, pool_labels):
        for key, val in target_labels.items():
            if pool_labels.get(key) != val:
                return False
        return True

    def exec(self):
        self.output_config.configName = os.path.basename(self.config.name) if self.config.name.startswith('./') else \
            self.config.name
        peers_to_compare = self.config.peer_container.get_all_peers_group()

        ref_ip_blocks = IpBlock.disjoint_ip_blocks(self.config.get_referenced_ip_blocks(),
                                                   IpBlock.get_all_ips_block_peer_set())
        connections = defaultdict(list)
        peers = PeerSet()
        peers_to_compare |= ref_ip_blocks

        for peer1 in peers_to_compare:
            for peer2 in peers_to_compare:
                if self.is_in_subset(peer1):
                    peers.add(peer1)
                elif not self.is_in_subset(peer2):
                    continue  # skipping pairs if none of them are in the given subset
                if isinstance(peer1, IpBlock) and isinstance(peer2, IpBlock):
                    continue  # skipping pairs with ip-blocks for both src and dst
                if peer1 == peer2:
                    # cannot restrict pod's connection to itself
                    connections[ConnectionSet(True)].append((peer1, peer2))
                else:
                    conns, _, _, _ = self.config.allowed_connections(peer1, peer2)
                    if conns:
                        # TODO: consider separate connectivity maps for config that involves istio -
                        #  one that handles non-TCP connections, and one for TCP
                        # TODO: consider avoid "hiding" egress allowed connections, even though they are
                        #  not covered by authorization policies
                        if self.config.policies_container.layers.does_contain_single_layer(NetworkLayerName.Istio) and \
                                self.output_config.connectivityFilterIstioEdges:
                            should_filter, modified_conns = self.filter_istio_edge(peer2, conns)
                            if not should_filter:
                                connections[modified_conns].append((peer1, peer2))
                                # collect both peers, even if one of them is not in the subset
                                peers.add(peer1)
                                peers.add(peer2)
                        else:
                            connections[conns].append((peer1, peer2))
                            # collect both peers, even if one of them is not in the subset
                            peers.add(peer1)
                            peers.add(peer2)

        res = QueryAnswer(True)
        if self.output_config.outputFormat == 'dot':
            conn_graph = ConnectivityGraph(peers, self.config.get_allowed_labels(), self.output_config)
            conn_graph.add_edges(connections)
            res.output_explanation = conn_graph.get_connectivity_dot_format_str()
        else:
            conn_graph = ConnectivityGraph(peers_to_compare, self.config.get_allowed_labels(), self.output_config)
            conn_graph.add_edges(connections)
            fw_rules = conn_graph.get_minimized_firewall_rules()
            res.output_explanation = fw_rules.get_fw_rules_in_required_format()
        return res

    def execute_and_write_output_in_required_format(self):
        query_answer = self.exec()
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
        self._update_output_config_object_with_config_names()

    @staticmethod
    def get_query_type():
        return QueryType.ComparisonToBaseConfigQuery

    def is_identical_topologies(self, check_same_policies=False):
        if not self.config1.peer_container.is_comparable_with_other_container(self.config2.peer_container):
            return QueryAnswer(False, 'The two configurations have different network '
                                      'topologies and thus are not comparable.', query_not_executed=True)
        if check_same_policies and self.config1.policies_container.policies == self.config2.policies_container.policies:
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

    def _update_output_config_object_with_config_names(self):
        self.output_config.configName = self.name1
        self.output_config.secondConfigName = self.name2

    # following methods help with writing the query output in the required format
    # these functions are applied to all classes derived from TwoNetworkConfigsQuery
    # except SemanticDiff (which is handled differently)
    def compute_txt_explanation(self, query_answer, explanation_header):
        """
        returns the query's output explanation in a txt format
        :param QueryAnswer query_answer: the query answer of the query
        :param str explanation_header: the txt message that describes the query's output explanation
        :rtype: str
        """
        assert isinstance(query_answer.output_explanation, list)
        txt_explanation_form, _ = \
            self.convert_explanation_to_required_format(explanation_list=query_answer.output_explanation,
                                                        conns_diff=(len(query_answer.output_explanation[0]) == 4))
        return explanation_header + ':\n' + txt_explanation_form

    def get_configs_names(self):
        """
        returns list of the query's configs names to be added to the yaml output
        :rtype: list[str]
        """
        return [self.output_config.configName, self.output_config.secondConfigName]

    def compute_yaml_with_explanation(self, yaml_content, explanation_descriptions, explanation_list):
        """
        adds the query's output explanation to the yaml object/s generated for the query output
        and returns the relevant yaml object/s
        :param dict yaml_content: the already generated content of the yaml object
        :param list[str] explanation_descriptions: the descriptions of the query output explanation
        if this list include 2 items, then two parallel yaml objects are generated for the query output (each describe
        connections from one config)
        special case: if it comes from the TwoWayContainmentQuery, then the 2 explanations should be concatenated
        into one object
        :param list explanation_list: the output explanation of the query - may be list[str] or list[tuples] or
        list[lists]
        when list[str] for the case of peers list in containment query
        list[lists] for the case of 2 configs which are not contained in each other (TwoWayContainmentQuery)
        otherwise list[tuples]
        :rtype: str
        """
        assert isinstance(explanation_list, list)
        if not isinstance(explanation_list[0], list):  # not list[lists]
            # handling the cases of one or 2 yaml objects
            yaml_form_1, yaml_form_2 = self.convert_explanation_to_required_format(
                explanation_list=explanation_list, conns_diff=(len(explanation_descriptions) == 2))
            list_of_peers = isinstance(explanation_list[0], str)
            return self._dump_one_or_two_yaml_objects_with_relevant_explanations(yaml_content, explanation_descriptions,
                                                                                 yaml_form_1, yaml_form_2, list_of_peers)

        # special case of twoWayContainment when both configs do not contain each other - list[lists]
        assert len(explanation_list) == 2
        yaml_form_1, _ = self.convert_explanation_to_required_format(explanation_list[0])
        yaml_form_2, _ = self.convert_explanation_to_required_format(explanation_list[1])
        return TwoWayContainmentQuery.dump_explanations_in_one_yaml_object(yaml_content, explanation_descriptions,
                                                                           yaml_form_1, yaml_form_2)

    @staticmethod
    def _dump_one_or_two_yaml_objects_with_relevant_explanations(yaml_content, explanation_descriptions, yaml_form_1,
                                                                 yaml_form_2, str_flag):
        # handles the case of one or two yaml objects for a query with same pair of configs.
        #  Queries that may produce two yaml objects for same pair of configs are : EquivalenceQuery,
        #          StrongEquivalenceQuery, InterferesQuery and PairwiseInterferesQuery
        yaml_content_1 = yaml_content
        if str_flag:  # the specific case of peers in containment
            yaml_content_1.update({'explanation': {'description': explanation_descriptions[0], 'peers': yaml_form_1}})
        else:
            yaml_content_1.update({'explanation': {'description': explanation_descriptions[0],
                                                   'connections': yaml_form_1}})
        res1 = yaml.dump(yaml_content_1, None, default_flow_style=False, sort_keys=False)
        if yaml_form_2:  # two parallel yaml objects since connections differ in the configs (e.g. in equivalence query)
            yaml_content_2 = yaml_content
            yaml_content_2.update({'explanation': {'description': explanation_descriptions[1],
                                                   'connections': yaml_form_2}})
            res2 = yaml.dump(yaml_content_2, None, default_flow_style=False, sort_keys=False)
            return res1 + '---\n' + res2 + '---\n'
        return res1 + '---\n'

    def convert_explanation_to_required_format(self, explanation_list, conns_diff=False):
        """
        convert the query's output_explanation into the required format
        :param list explanation_list : the output explanation of the query
        :param bool conns_diff: indicates if connections are different in the configs,
         if true, two yaml explanations lists are returned so two yaml objects may be created with different
         explanations of the different connections.
         :return: 1. if output format is txt then it returns tuple of:  - a string containing the textual explanation
                                                                        - empty string
         2. if output format is yaml : it returns a tuple of : - list of connections to be added to the explanation
                                - if conns diff is true, the other side of the connections, else an empty list
         :rtype: Union[(str, ''), (list[str], list[str] or [])]
        """
        # case of peers list (from containment query)
        if isinstance(explanation_list[0], str):
            if self.output_config.outputFormat == 'yaml':
                return explanation_list, []
            return ', '.join(explanation_list), ''  # txt

        # case of (src, dst, conns1, "conns2") list - conns2 is optional
        conns1 = []
        conns2 = []
        for peers_conn in explanation_list:
            if self.output_config.outputFormat == 'txt':
                if conns_diff:
                    conns1.append(f'src: {peers_conn[0]}, dst: {peers_conn[1]}, description: '
                                  f'{peers_conn[2].print_diff(peers_conn[3], self.output_config.configName, self.output_config.secondConfigName)}')  # noqa: E501
                else:
                    conns1.append(f'src: {peers_conn[0]}, dst: {peers_conn[1]}, conn: {peers_conn[2]}')
            else:  # yaml
                conns1.append({'src': peers_conn[0], 'dst': peers_conn[1], 'conn': str(peers_conn[2])})
                if conns_diff:
                    conns2.append({'src': peers_conn[0], 'dst': peers_conn[1], 'conn': str(peers_conn[3])})

        if self.output_config.outputFormat == 'yaml':
            return conns1, conns2

        return '\n'.join(conns1), ''  # txt

    def _handle_equivalence_outputs(self, query_answer):
        # this def is to avoid duplications in EquivalenceQuery and StrongEquivalenceQuery
        query_result = not query_answer.bool_result
        txt_explanation_header = f'Connections allowed in {self.output_config.configName} and' \
                                 f' {self.output_config.secondConfigName} are different as following'
        yaml_explanation_descriptions = [
            f'Connections in {self.output_config.configName} which are different in {self.output_config.secondConfigName}',
            f'Connections in {self.output_config.secondConfigName} which are different in {self.output_config.configName}']
        query_output = self.write_query_output(query_answer, txt_explanation_header,
                                               yaml_explanation_descriptions, int(query_result))
        return query_result, query_output, query_answer.query_not_executed


class EquivalenceQuery(TwoNetworkConfigsQuery):
    """
    Check whether config1 and config2 allow exactly the same set of connections.
    """

    @staticmethod
    def get_query_type():
        return QueryType.PairComparisonQuery

    def exec(self, layer_name=None):
        query_answer = self.is_identical_topologies(True)
        if query_answer.output_result:
            return query_answer

        peers_to_compare = self.config1.peer_container.get_all_peers_group()
        peers_to_compare |= self.disjoint_referenced_ip_blocks()
        captured_pods = self.config1.get_captured_pods(layer_name) | self.config2.get_captured_pods(layer_name)
        different_conns_list = []
        negative_output_result = self.name1 + ' and ' + self.name2 + ' are not semantically equivalent.'
        for peer1 in peers_to_compare:
            for peer2 in peers_to_compare if peer1 in captured_pods else captured_pods:
                if peer1 == peer2:
                    continue
                conns1, _, _, _ = self.config1.allowed_connections(peer1, peer2, layer_name)
                conns2, _, _, _ = self.config2.allowed_connections(peer1, peer2, layer_name)
                if conns1 != conns2:
                    different_conns_list.append((str(peer1), str(peer2), conns1, conns2))
                    if not self.output_config.fullExplanation:
                        return QueryAnswer(False, negative_output_result, different_conns_list)

        if different_conns_list:
            return QueryAnswer(False, negative_output_result, sorted(different_conns_list))

        return QueryAnswer(True, self.name1 + ' and ' + self.name2 + ' are semantically equivalent.')

    def execute_and_write_output_in_required_format(self, _):
        query_answer = self.exec()
        return self._handle_equivalence_outputs(query_answer)


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
        allowed_labels = (self.config1.get_allowed_labels()).union(self.config2.get_allowed_labels())
        topology_peers = new_peers | ip_blocks if is_added else old_peers | ip_blocks
        updated_key = key.replace("Changed", "Added") if is_added else key.replace("Changed", "Removed")
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

    def execute_and_write_output_in_required_format(self, cmd_line_flag=False):
        query_answer = self.exec()
        res = query_answer.numerical_result if not cmd_line_flag else not query_answer.bool_result
        query_output = ''
        if self.output_config.outputFormat == 'txt':
            query_output += query_answer.output_result
        if query_answer.output_explanation:
            assert isinstance(query_answer.output_explanation, str)
            query_output += query_answer.output_explanation
        return res, query_output, query_answer.query_not_executed


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

        policies1 = set(f'{policy_name}[{policy_type}]' for policy_name, policy_type in
                        self.config1.policies_container.policies.keys())
        policies2 = set(f'{policy_name}[{policy_type}]' for policy_name, policy_type in
                        self.config2.policies_container.policies.keys())
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

        for policy in self.config1.policies_container.policies.values():
            single_policy_config1 = self.config1.clone_with_just_one_policy(policy.full_name())
            single_policy_config2 = self.config2.clone_with_just_one_policy(policy.full_name())
            full_result = EquivalenceQuery(single_policy_config1, single_policy_config2, self.output_config).exec()
            if not full_result.bool_result:
                output_result = f'{self.policy_title(policy)} is not equivalent in {self.name1} and in {self.name2}'
                return QueryAnswer(False, output_result, full_result.output_explanation)

        return QueryAnswer(True, self.name1 + ' and ' + self.name2 + ' are strongly equivalent.')

    def execute_and_write_output_in_required_format(self, _):
        query_answer = self.exec()
        return self._handle_equivalence_outputs(query_answer)


class ContainmentQuery(TwoNetworkConfigsQuery):
    """
    Checking whether the connections allowed by config1 are contained in those allowed by config2
    """

    def exec(self, only_captured=False):
        config1_peers = self.config1.peer_container.get_all_peers_group()
        peers_in_config1_not_in_config2 = config1_peers - self.config2.peer_container.get_all_peers_group()
        if peers_in_config1_not_in_config2:
            peers_list = [str(e) for e in peers_in_config1_not_in_config2]
            return QueryAnswer(False, f'{self.name1} is not contained in {self.name2} ', peers_list)

        peers_to_compare = config1_peers | self.disjoint_referenced_ip_blocks()
        captured_pods = self.config1.get_captured_pods() | self.config2.get_captured_pods()
        not_contained_list = []
        negative_output_result = f'{self.name1} is not contained in {self.name2}'
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
                    not_contained_list.append((str(peer1), str(peer2), conns1))
                    if not self.output_config.fullExplanation:
                        return QueryAnswer(False, negative_output_result, not_contained_list)

        if not_contained_list:
            return QueryAnswer(False, negative_output_result, sorted(not_contained_list))

        return QueryAnswer(True, self.name1 + ' is contained in ' + self.name2, numerical_result=1)

    def execute_and_write_output_in_required_format(self, cmd_line_flag=False):
        query_answer = self.exec()
        query_result = query_answer.numerical_result if not cmd_line_flag else not query_answer.bool_result
        explanation_header = ''
        yaml_description = []
        if query_answer.output_explanation:
            assert isinstance(query_answer.output_explanation, list)
            explanation_header = \
                self.determine_explanation_header(self.output_config.configName, self.output_config.secondConfigName,
                                                  query_answer.output_explanation[0])
            yaml_description = [explanation_header]

        query_output = self.write_query_output(query_answer, explanation_header, yaml_description, int(query_result))
        return query_result, query_output, query_answer.query_not_executed

    @staticmethod
    def determine_explanation_header(config_name_1, config_name_2, first_elem):
        """
        determines the explanation header message according to the type of elements in
        the query_answer.output_explanation list
        The output explanation of the ContainmentQuery may be :
        (1) list[str] - when configs containment is not fulfilled because of different peers
        (2) list[tuple] - when configs containment is not fulfilled because of different connections between same peers
        :param str config_name_1: the name of the first config
        :param str config_name_2: the name of the second config
        :param first_elem: the first element of the output_explanation to determine its type
        :rtype: str
        """
        if isinstance(first_elem, str):
            return f'Pods in {config_name_1} which are not in {config_name_2}'
        else:
            return f'Connections allowed in {config_name_1} which are not a subset of those in {config_name_2}'


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
            return query_answer, None, None  # identical configurations (contained)

        contained_1_in_2 = ContainmentQuery(self.config1, self.config2, self.output_config).exec()
        contained_2_in_1 = ContainmentQuery(self.config2, self.config1, self.output_config).exec()
        if contained_1_in_2.bool_result and contained_2_in_1.bool_result:
            return QueryAnswer(bool_result=True,
                               output_result=f'The two network configurations {self.name1} and {self.name2} '
                                             'are semantically equivalent.',
                               numerical_result=3), None, None

        sub_query_answer1 = QueryAnswer(output_result=contained_1_in_2.output_result,
                                        output_explanation=contained_1_in_2.output_explanation)
        sub_query_answer2 = QueryAnswer(output_result=contained_2_in_1.output_result,
                                        output_explanation=contained_2_in_1.output_explanation)
        if not contained_1_in_2.bool_result and not contained_2_in_1.bool_result:
            return QueryAnswer(bool_result=False,
                               output_result=f'Neither network configuration {self.name1} and {self.name2} '
                                             f'are contained in the other', numerical_result=0), sub_query_answer1,\
                sub_query_answer2
        if contained_1_in_2.bool_result:
            return QueryAnswer(bool_result=False,
                               output_result=f'Network configuration {self.name1} is a proper'
                                             f' subset of {self.name2}', numerical_result=2), None, sub_query_answer2
        # (contained_2_in_1)
        return QueryAnswer(bool_result=False,
                           output_result=f'Network configuration {self.name2} is a proper subset of {self.name1}',
                           numerical_result=1), sub_query_answer1, None

    def execute_and_write_output_in_required_format(self, cmd_line_flag=False):
        # TwoWayContainmentQuery executes two Containment sub queries
        query_answer, sub_query_answer_1, sub_query_answer_2 = self.exec()
        query_result = query_answer.numerical_result if not cmd_line_flag else not query_answer.bool_result
        if sub_query_answer_1 is None and sub_query_answer_2 is None:
            return query_result, \
                self.write_query_output(query_answer, query_result=int(query_result)), query_answer.query_not_executed
        description_2 = ''
        description_1 = ''
        if sub_query_answer_2:  # second config is not contained in first config
            assert isinstance(sub_query_answer_2.output_explanation, list)
            description_2 = ContainmentQuery.determine_explanation_header(self.output_config.configName,
                                                                          self.output_config.secondConfigName,
                                                                          sub_query_answer_2.output_explanation[0])
            explanation_header_2 = sub_query_answer_2.output_result + '\n' + description_2
            if sub_query_answer_1 is None:  # only config2 is not contained in config1
                query_answer.output_explanation = sub_query_answer_2.output_explanation
                return query_result, \
                    self.write_query_output(query_answer, explanation_header_2, [description_2], int(query_result)),\
                    query_answer.query_not_executed
        if sub_query_answer_1:  # first config is not contained in second config
            description_1 = ContainmentQuery.determine_explanation_header(self.output_config.secondConfigName,
                                                                          self.output_config.configName,
                                                                          sub_query_answer_1.output_explanation[0])
            explanation_header_1 = sub_query_answer_1.output_result + '\n' + description_1
            if sub_query_answer_2 is None:  # only config1 is not contained in config2
                query_answer.output_explanation = sub_query_answer_1.output_explanation
                return query_result, \
                    self.write_query_output(query_answer, explanation_header_1, [description_1], int(query_result)),\
                    query_answer.query_not_executed
        # both configs are not contained in each other
        if self.output_config.outputFormat == 'txt':
            query_output = query_answer.output_result + '\n'
            query_output += self.write_txt_output(sub_query_answer_1, description_1)
            query_output += '\n' + self.write_txt_output(sub_query_answer_2, description_2)
            return query_result, query_output, query_answer.query_not_executed
        elif self.output_config.outputFormat == 'yaml':
            query_answer.output_explanation = [sub_query_answer_1.output_explanation,
                                               sub_query_answer_2.output_explanation]
            yaml_descriptions = [description_1, description_2]
            query_output = self.write_query_output(query_answer, '', yaml_descriptions, int(query_result))
            return query_result, query_output, query_answer.query_not_executed
        return query_result, '', query_answer.query_not_executed

    @staticmethod
    def dump_explanations_in_one_yaml_object(yaml_content, explanation_descriptions, yaml_form_1, yaml_form_2):
        yaml_content.update({'explanation': [{'description': explanation_descriptions[0], 'connections': yaml_form_1},
                                             {'description': explanation_descriptions[1], 'connections': yaml_form_2}]})
        return yaml.dump(yaml_content, None, default_flow_style=False, sort_keys=False) + '---\n'


class PermitsQuery(TwoNetworkConfigsQuery):
    """
    Checking whether the connections explicitly allowed by config1 are allowed by config2
    """

    def exec(self):
        if not self.config1:
            return QueryAnswer(False,
                               output_result='There are no NetworkPolicies in the given permits config. '
                                             'No traffic is specified as permitted.', query_not_executed=True)
        query_answer = self.is_identical_topologies()
        if query_answer.output_result:
            return query_answer  # non-identical configurations are not comparable

        if self.config1.policies_container.layers.does_contain_single_layer(NetworkLayerName.Ingress):
            return QueryAnswer(bool_result=False,
                               output_result='Permitted traffic cannot be specified using Ingress resources only',
                               query_not_executed=True)

        config1_without_ingress = self.clone_without_ingress(self.config1)
        return ContainmentQuery(config1_without_ingress, self.config2, self.output_config).exec(True)

    def execute_and_write_output_in_required_format(self, cmd_line_flag=False):
        query_answer = self.exec()
        query_result = not query_answer.bool_result if cmd_line_flag else 1 if query_answer.output_explanation else 0
        explanation_header = ''
        yaml_description = []
        if query_answer.bool_result:
            query_answer.output_result = f'{self.output_config.secondConfigName} permits all connections' \
                                         f' specified in {self.output_config.configName}'
        if query_answer.output_explanation:
            assert isinstance(query_answer.output_explanation, list)
            query_answer.output_result = f'{self.output_config.secondConfigName} does not permit ' \
                                         f'connections specified in {self.output_config.configName}'
            explanation_header = ContainmentQuery.determine_explanation_header(self.output_config.configName,
                                                                               self.output_config.secondConfigName,
                                                                               query_answer.output_explanation[0])
            yaml_description = [explanation_header]

        return query_result,\
            self.write_query_output(query_answer, explanation_header, yaml_description, int(query_result)),\
            query_answer.query_not_executed


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
        extended_conns_list = []
        interfere_result_msg = self.name1 + ' interferes with ' + self.name2
        for peer1 in peers_to_compare:
            for peer2 in peers_to_compare if peer1 in captured_pods else captured_pods:
                if peer1 == peer2:
                    continue

                _, captured1_flag, conns1_captured, _ = self.config2.allowed_connections(peer1, peer2)
                if not captured1_flag:
                    continue
                _, captured2_flag, conns2_captured, _ = self.config1.allowed_connections(peer1, peer2)
                if captured2_flag and not conns2_captured.contained_in(conns1_captured):
                    extended_conns_list.append((str(peer1), str(peer2), conns2_captured, conns1_captured))
                    if not self.output_config.fullExplanation:
                        return QueryAnswer(True, interfere_result_msg, extended_conns_list)

        if extended_conns_list:
            return QueryAnswer(True, interfere_result_msg, sorted(extended_conns_list))

        return QueryAnswer(False, self.name1 + ' does not interfere with ' + self.name2)

    def execute_and_write_output_in_required_format(self, cmd_line_flag=False):
        query_answer = self.exec()
        query_result = query_answer.bool_result if not cmd_line_flag else not query_answer.bool_result
        txt_explanation_header = f'Allowed connections from {self.output_config.secondConfigName} which' \
                                 f' are extended in {self.output_config.configName}'
        yaml_explanation_descriptions = [f'Connections in {self.output_config.configName} which extend '
                                         f'connections in {self.output_config.secondConfigName}',
                                         f'The narrow connections in {self.output_config.secondConfigName}']
        query_output = self.write_query_output(query_answer, txt_explanation_header,
                                               yaml_explanation_descriptions, int(query_result))
        return query_result, query_output, query_answer.query_not_executed


# Checks whether any two sets in the list interfere each other
class PairwiseInterferesQuery(TwoNetworkConfigsQuery):

    @staticmethod
    def get_query_type():
        return QueryType.PairwiseComparisonQuery

    def execute_and_write_output_in_required_format(self, cmd_line_flag=False):
        return InterferesQuery(self.config1, self.config2, self.output_config).\
            execute_and_write_output_in_required_format(cmd_line_flag)


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
        intersect_pairs_list = []
        intersect_result_msg = self.name2 + ' intersects with ' + self.name1
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
                    intersect_pairs_list.append((str(peer1), str(peer2), conns_in_both))
                    if not self.output_config.fullExplanation:
                        return QueryAnswer(True, intersect_result_msg, intersect_pairs_list)

        if intersect_pairs_list:
            return QueryAnswer(True, intersect_result_msg, sorted(intersect_pairs_list))

        return QueryAnswer(False, f'The connections allowed by {self.name1}'
                                  f' do not intersect the connections allowed by {self.name2}', numerical_result=1)


class ForbidsQuery(TwoNetworkConfigsQuery):
    """
    Checking whether the connections explicitly allowed by config1 are denied by config2
    """

    def exec(self):
        if not self.config1:
            return QueryAnswer(False, 'There are no NetworkPolicies in the given forbids config. '
                                      'No traffic is specified as forbidden.', query_not_executed=True)
        if self.config1.policies_container.layers.does_contain_single_layer(NetworkLayerName.Ingress):
            return QueryAnswer(bool_result=False,
                               output_result='Forbidden traffic cannot be specified using Ingress resources only',
                               query_not_executed=True)

        config1_without_ingress = self.clone_without_ingress(self.config1)

        return IntersectsQuery(config1_without_ingress, self.config2, self.output_config).exec(True)

    def execute_and_write_output_in_required_format(self, cmd_line_flag=False):
        query_answer = self.exec()
        query_result = not query_answer.numerical_result if cmd_line_flag else query_answer.bool_result
        if query_answer.numerical_result == 1:
            query_answer.output_result += f'\n{self.output_config.secondConfigName} forbids connections specified in ' \
                                          f'{self.output_config.configName}'
        if query_answer.output_explanation:
            query_answer.output_result = f'{self.output_config.secondConfigName} does not forbid connections specified ' \
                                         f'in {self.output_config.configName}'
        explanation_header = f'Both {self.output_config.configName} and ' \
                             f'{self.output_config.secondConfigName} allow the following connection(s)'
        return query_result,\
            self.write_query_output(query_answer, explanation_header, [explanation_header], int(query_result)), \
            query_answer.query_not_executed


class AllCapturedQuery(NetworkConfigQuery):
    """
    Check that all pods are captured
    Applies only for k8s/calico policies
    """

    def _get_pod_name(self, pod):
        """
        :param Pod pod: a pod object
        :rtype str
        """
        return pod.workload_name if self.output_config.outputEndpoints == 'deployments' else str(pod)

    def _get_uncaptured_resources_explanation(self, uncaptured_pods):
        """
        get numerical result + set of names of ingress/egress uncaptured pods
        :param PeerSet uncaptured_pods: the set of uncaptured
        :return: (int,set[str]): (the number of uncaptured resources , uncaptured pods names)
        """
        if not uncaptured_pods:
            return 0, ''
        uncaptured_resources = set(self._get_pod_name(pod) for pod in uncaptured_pods)  # no duplicate resources in set
        return len(uncaptured_resources), uncaptured_resources

    def exec(self):
        existing_pods = self.config.peer_container.get_all_peers_group()
        if not self.config:
            return QueryAnswer(bool_result=False,
                               output_result='Flat network in ' + self.config.name,
                               numerical_result=len(existing_pods))

        if NetworkLayerName.K8s_Calico not in self.config.policies_container.layers:
            return QueryAnswer(bool_result=False,
                               output_result='AllCapturedQuery applies only for k8s/calico network policies',
                               query_not_executed=True)

        uncaptured_ingress_pods = existing_pods - self.config.get_affected_pods(True, NetworkLayerName.K8s_Calico)
        uncaptured_egress_pods = existing_pods - self.config.get_affected_pods(False, NetworkLayerName.K8s_Calico)
        if not uncaptured_ingress_pods and not uncaptured_egress_pods:
            output_str = f'All pods are captured by at least one policy of k8s/calico in {self.config.name}'
            return QueryAnswer(bool_result=True, output_result=output_str, numerical_result=0)

        res_ingress, uncaptured_ingress_pods_set = self._get_uncaptured_resources_explanation(uncaptured_ingress_pods)
        res_egress, uncaptured_egress_pods_set = self._get_uncaptured_resources_explanation(uncaptured_egress_pods)
        res = res_ingress + res_egress
        full_explanation = (sorted(uncaptured_ingress_pods_set), sorted(uncaptured_egress_pods_set))
        output_str = f'There are workload resources not captured by any k8s/calico policy in {self.config.name}'
        return QueryAnswer(bool_result=False, output_result=output_str,
                           output_explanation=full_explanation, numerical_result=res)

    def execute_and_write_output_in_required_format(self):
        query_answer = self.exec()
        self.output_config.fullExplanation = True
        explanation_prefix = 'workload resources that are not captured by any policy that affects '
        return query_answer.numerical_result, self.write_query_output(query_answer, explanation_prefix), \
            query_answer.query_not_executed

    def convert_explanation_to_required_format(self, explanation_lists, explanation_prefix):
        assert isinstance(explanation_lists, tuple)
        assert len(explanation_lists) == 2
        txt_res = ''
        yaml_result = []
        ingress_pods = explanation_lists[0]
        if ingress_pods:
            description = explanation_prefix + 'ingress'
            if self.output_config.outputFormat == 'txt':
                txt_res += '\n' + description + ':\n' + ', '.join(e for e in ingress_pods) + '\n'
            else:  # yaml
                yaml_result.append({'description': description, 'uncaptured_pods': list(ingress_pods)})
        egress_pods = explanation_lists[1]
        if egress_pods:
            description = explanation_prefix + 'egress'
            if self.output_config.outputFormat == 'txt':
                txt_res += '\n' + description + ':\n' + ', '.join(e for e in egress_pods) + '\n'
            else:
                yaml_result.append({'description': description, 'uncaptured_pods': list(egress_pods)})

        if self.output_config.outputFormat == 'yaml':
            return yaml_result
        return txt_res
