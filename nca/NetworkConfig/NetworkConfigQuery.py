#
# Copyright 2020- IBM Inc. All rights reserved
# SPDX-License-Identifier: Apache2.0
#
import os
from abc import abstractmethod
from enum import Enum
from dataclasses import dataclass

from nca.CoreDS.Peer import PeerSet, IpBlock, Pod, Peer, DNSEntry, BasePeerSet
from nca.CoreDS.ProtocolSet import ProtocolSet
from nca.CoreDS.ConnectivityProperties import ConnectivityProperties
from nca.CoreDS.DimensionsManager import DimensionsManager
from nca.FWRules.ConnectivityGraph import ConnectivityGraph
from nca.FWRules.MinimizeFWRules import MinimizeFWRules
from nca.FWRules.ClusterInfo import ClusterInfo
from nca.Resources.PolicyResources.NetworkPolicy import PolicyConnectionsFilter
from nca.Resources.PolicyResources.CalicoNetworkPolicy import CalicoNetworkPolicy
from nca.Resources.PolicyResources.GatewayPolicy import GatewayPolicy
from nca.Utils.OutputConfiguration import OutputConfiguration
from .QueryOutputHandler import QueryAnswer, DictOutputHandler, StringOutputHandler, \
    PoliciesAndRulesExplanations, PodsListsExplanations, ConnectionsDiffExplanation, IntersectPodsExplanation, \
    PoliciesWithCommonPods, PeersAndConnectivityProperties, ComputedExplanation
from .NetworkLayer import NetworkLayerName
from nca.Utils.ExplTracker import ExplTracker
from nca.NetworkConfig import PeerContainer


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
        # peer_set collects the set of peers from the config(s) related to current query
        peer_set = PeerSet()
        for config in self.get_configs():
            if not config.peer_container.get_num_peers():
                error_msg = f'Error: Network configuration \'{config.name}\' does not have any peers. Can not run Query'
                query_answer = QueryAnswer(output_result=error_msg, query_not_executed=True)
                return query_answer.numerical_result, self._handle_output(query_answer), query_answer.query_not_executed
            peer_set |= config.peer_container.get_all_peers_group(True, True, True)
        if self.output_config.outputFormat not in self.get_supported_output_formats():
            query_answer = QueryAnswer(query_not_executed=True)
            return query_answer.numerical_result, '', query_answer.query_not_executed
        # update domains src_peers/dst_peers with domains specific to current peer_set of current query
        DimensionsManager().set_domain("src_peers", DimensionsManager.DimensionType.IntervalSet,
                                       BasePeerSet().get_peer_interval_of(peer_set))
        DimensionsManager().set_domain("dst_peers", DimensionsManager.DimensionType.IntervalSet,
                                       BasePeerSet().get_peer_interval_of(peer_set))
        # update all optimized connectivity properties by reducing full src_peers/dst_peers dimensions
        # according to their updated domains (above)
        for config in self.get_configs():
            for policy in config.policies_container.policies.values():
                policy.reorganize_props_by_new_domains()
        # run the query
        query_answer = self.execute(cmd_line_flag)
        # restore peers domains and connectivity properties original values
        DimensionsManager.reset()
        for config in self.get_configs():
            for policy in config.policies_container.policies.values():
                policy.restore_props()
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

    @staticmethod
    def compare_conn_props(props1, props2, text_prefix):
        if props1 == props2:
            print(f"{text_prefix} are semantically equivalent")
        else:
            diff_prop = (props1 - props2) | (props2 - props1)
            if diff_prop.are_auto_conns():
                print(f"{text_prefix} differ only in auto-connections")
            else:
                print(f"Error: {text_prefix} are different")
                assert False

    @staticmethod
    def compare_fw_rules_to_conn_props(fw_rules, props, connectivity_restriction=None):
        text_prefix = "Connectivity properties and fw-rules generated from them"
        props2 = MinimizeFWRules.fw_rules_to_conn_props(fw_rules, connectivity_restriction)
        BaseNetworkQuery.compare_conn_props(props, props2, text_prefix)


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


class DisjointnessQuery(NetworkConfigQuery):
    """
    Check whether no two policy in the config capture the same peer
    """

    def exec(self):
        # collecting non-disjoint policies per network layer
        non_disjoint_explanation_list = []
        for layer_name, layer in self.config.policies_container.layers.items():
            if layer_name in {NetworkLayerName.K8sGateway, NetworkLayerName.IstioGateway}:  # skip gateway layers
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
        # TODO: should handle 'gateway' layer or not? (ingress controller pod is not expected to have egress
        #  traffic without any Ingress resource)
        #  currently ignoring gateway layer, removing it from configs on this query
        self.output_config.fullExplanation = True  # assign true for this query - it is ok to compare its results
        vacuous_config = self.config.clone_without_policies('vacuousConfig')
        self_config = TwoNetworkConfigsQuery.clone_without_gateway_layers(self.config)
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
            if layer_name in {NetworkLayerName.K8sGateway, NetworkLayerName.IstioGateway}:  # skip gateway layers
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
        :return: A policy containing self_policy's denied connections if exists, None otherwise
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
            if self.check_deny_containment(config_with_self_policy, config_with_other_policy, layer_name):
                return other_policy
        return None

    @staticmethod
    def check_deny_containment(config_with_self_policy, config_with_other_policy, layer_name):
        res_conns_filter = PolicyConnectionsFilter.only_denied_connections()
        self_props = config_with_self_policy.allowed_connections(layer_name, res_conns_filter)
        other_props = config_with_other_policy.allowed_connections(layer_name, res_conns_filter)
        return self_props.denied_conns.contained_in(other_props.denied_conns)

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
            if layer_name in {NetworkLayerName.K8sGateway, NetworkLayerName.IstioGateway}:  # skip gateway layers
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
        return {'txt', 'yaml', 'csv', 'md', 'dot', 'json', 'jpg', 'html', 'txt_no_fw_rules'}

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

    def compute_connectivity_output(self):
        """
        Compute connectivity output with optimized implementation.
        :return: output result in a required format
        :rtype: Union[str, dict]
        """
        exclude_ipv6 = self.config.check_for_excluding_ipv6_addresses(self.output_config.excludeIPv6Range)
        res_conns_filter = PolicyConnectionsFilter.only_all_allowed_connections()
        conns = self.config.allowed_connections(res_conns_filter=res_conns_filter)
        all_conns = conns.all_allowed_conns
        peers_to_compare = self.config.peer_container.get_all_peers_group(include_dns_entries=True)
        # add all relevant IpBlocks, used in connections
        peers_to_compare |= all_conns.get_all_peers()
        if exclude_ipv6:
            # remove connections where any of src_peers or dst_peers contain automatically-added IPv6 blocks,
            # while keeping connections with IPv6 blocks directly referenced in policies
            peers_to_compare.filter_ip_blocks_by_mask(IpBlock.get_all_ips_block(exclude_ipv6=True))
            all_conns &= ConnectivityProperties.make_conn_props_from_dict({"src_peers": peers_to_compare,
                                                                           "dst_peers": peers_to_compare})
        base_peers_num = len(peers_to_compare)
        subset_peers = self.compute_subset(peers_to_compare)
        all_peers = subset_peers
        if len(subset_peers) != base_peers_num:
            # remove connections where both of src_peers and dst_peers are out of the subset
            subset_conns = ConnectivityProperties.make_conn_props_from_dict({"src_peers": subset_peers}) | \
                           ConnectivityProperties.make_conn_props_from_dict({"dst_peers": subset_peers})
            all_conns &= subset_conns
            src_peers, dst_peers = ExplTracker().extract_peers(all_conns)
            all_peers = src_peers | dst_peers
        all_conns = self.config.filter_conns_by_peer_types(all_conns)
        expl_conns = all_conns
        if self.config.policies_container.layers.does_contain_istio_layers():
            output_res = self.get_props_output_split_by_tcp(all_conns, peers_to_compare)
            expl_conns, _ = self.convert_props_to_split_by_tcp(all_conns)
        else:
            output_res = self.get_props_output_full(all_conns, peers_to_compare)
        if ExplTracker().is_active():
            ExplTracker().set_connections_and_peers(expl_conns, all_peers)
        return output_res

    def exec(self):
        self.output_config.fullExplanation = True  # assign true for this query - it is always ok to compare its results
        self.output_config.configName = os.path.basename(self.config.name) if self.config.name.startswith('./') else \
            self.config.name
        res = QueryAnswer(True)

        output_res = self.compute_connectivity_output()
        if self.output_config.outputFormat in ['json', 'yaml']:
            res.output_explanation = [ComputedExplanation(dict_explanation=output_res)]
        else:
            res.output_explanation = [ComputedExplanation(str_explanation=output_res)]
        return res

    def get_props_output_full(self, props, all_peers):
        """
        get the connectivity map output considering all connections in the output
        :param ConnectivityProperties props: properties describing allowed connections
        :param PeerSet all_peers: the peers to consider for dot/fw-rules output
         whereas all other values should be filtered out in the output
        :rtype Union[str, dict]
        """
        peers_to_compare = props.get_all_peers()
        if self.output_config.outputFormat in ['dot', 'jpg', 'html']:
            dot_full = self.dot_format_from_props(props, peers_to_compare)
            return dot_full
        if self.output_config.outputFormat == 'txt_no_fw_rules':
            conns_wo_fw_rules = self.txt_no_fw_rules_format_from_props(props, peers_to_compare)
            return conns_wo_fw_rules
        # handle other formats
        formatted_rules = self.fw_rules_from_props(props, all_peers)
        return formatted_rules

    def get_props_output_split_by_tcp(self, props, all_peers):
        """
        get the connectivity map output as two parts: TCP and non-TCP
        :param ConnectivityProperties props: properties describing allowed connections
        :param PeerSet all_peers: the peers to consider for dot/fw-rules output
         whereas all other values should be filtered out in the output
        :rtype Union[str, dict]
        """
        peers_to_compare = props.get_all_peers()
        connectivity_tcp_str = 'TCP'
        connectivity_non_tcp_str = 'non-TCP'
        props_tcp, props_non_tcp = self.convert_props_to_split_by_tcp(props)
        if self.output_config.outputFormat in ['dot', 'jpg', 'html']:
            dot_tcp = self.dot_format_from_props(props_tcp, peers_to_compare, connectivity_tcp_str)
            dot_non_tcp = self.dot_format_from_props(props_non_tcp, peers_to_compare, connectivity_non_tcp_str)
            # concatenate the two graphs into one dot file
            res_str = dot_tcp + dot_non_tcp
            return res_str
        if self.output_config.outputFormat in ['txt_no_fw_rules']:
            txt_no_fw_rules_tcp = self.txt_no_fw_rules_format_from_props(props_tcp, peers_to_compare, connectivity_tcp_str)
            txt_no_fw_rules_non_tcp = self.txt_no_fw_rules_format_from_props(props_non_tcp, peers_to_compare,
                                                                             connectivity_non_tcp_str)
            res_str = txt_no_fw_rules_tcp + '\n\n' + txt_no_fw_rules_non_tcp
            return res_str
        # handle formats other than dot and txt_no_fw_rules
        formatted_rules_tcp = self.fw_rules_from_props(props_tcp, all_peers, connectivity_tcp_str)
        formatted_rules_non_tcp = self.fw_rules_from_props(props_non_tcp, all_peers, connectivity_non_tcp_str)
        if self.output_config.outputFormat in ['json', 'yaml']:
            # get a dict object containing the two maps on different keys (TCP_rules and non-TCP_rules)
            rules = formatted_rules_tcp
            rules.update(formatted_rules_non_tcp)
            return rules
        # remaining formats: txt / csv / md : concatenate the two strings of the conn-maps
        if self.output_config.outputFormat == 'txt':
            res_str = f'{formatted_rules_tcp}\n{formatted_rules_non_tcp}'
        else:
            res_str = formatted_rules_tcp + formatted_rules_non_tcp
        return res_str

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
        conn_graph.add_props_to_graph(props, self.config.peer_container, connectivity_restriction)
        return conn_graph.get_connectivity_dot_format_str(connectivity_restriction)

    def txt_no_fw_rules_format_from_props(self, props, peers, connectivity_restriction=None):
        """
        :param ConnectivityProperties props: properties describing allowed connections
        :param PeerSet peers: the peers to consider for dot output
        :param Union[str,None] connectivity_restriction: specify if connectivity is restricted to
               TCP / non-TCP , or not
        :rtype str
        :return the connectivity map in txt_no_fw_rules format, considering connectivity_restriction if required
        """
        conn_graph = ConnectivityGraph(peers, self.config.get_allowed_labels(), self.output_config)
        conn_graph.add_props_to_graph(props, self.config.peer_container, connectivity_restriction)
        return conn_graph.get_connections_without_fw_rules_txt_format(connectivity_restriction + " Connections:"
                                                                      if connectivity_restriction else None)

    def fw_rules_from_props(self, props, peers_to_compare, connectivity_restriction=None):
        """
        :param ConnectivityProperties props: properties describing allowed connections
        :param PeerSet peers_to_compare: the peers to consider for fw-rules output
         whereas all other values should be filtered out in the output
        :param Union[str,None] connectivity_restriction: specify if connectivity is restricted to
               TCP / non-TCP , or not
        :return the connectivity map in fw-rules, considering connectivity_restriction if required
        :rtype: Union[str, dict]
        """
        if self.output_config.fwRulesOverrideAllowedLabels:
            allowed_labels = set(label for label in self.output_config.fwRulesOverrideAllowedLabels.split(','))
        else:
            allowed_labels = self.config.get_allowed_labels()
        cluster_info = ClusterInfo(peers_to_compare, allowed_labels)

        fw_rules = MinimizeFWRules.get_minimized_firewall_rules_from_props(props, cluster_info, self.output_config,
                                                                           self.config.peer_container,
                                                                           connectivity_restriction)
        if self.config.debug:
            self.compare_fw_rules_to_conn_props(fw_rules, props, connectivity_restriction=connectivity_restriction)
        formatted_rules = fw_rules.get_fw_rules_in_required_format(connectivity_restriction=connectivity_restriction)
        return formatted_rules

    @staticmethod
    def convert_props_to_split_by_tcp(props):
        """
        given the ConnectivityProperties properties set, convert it to two properties sets, one for TCP only,
        and the other for non-TCP only.
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

    def filter_conns_by_input_or_internal_constraints(self, conns1, conns2):
        """
        Given two allowed connections (in config1 and in config2 respectively), filter those connections
        according to required IP blocks (external constrain - excludeIPv6Range option) and
        peer types (internal constraints).
        :param conns1: the first config allowed connections
        :param conns2: the second config allowed connections
        :rtype: [ConnectivityProperties, ConnectivityProperties]
        :return: two resulting allowed connections
        """
        all_peers = conns1.get_all_peers() | conns2.get_all_peers()
        exclude_ipv6 = self.config1.check_for_excluding_ipv6_addresses(self.output_config.excludeIPv6Range) and \
            self.config2.check_for_excluding_ipv6_addresses(self.output_config.excludeIPv6Range)
        conns_filter = ConnectivityProperties.make_all_props()
        if exclude_ipv6:
            all_peers.filter_ip_blocks_by_mask(IpBlock.get_all_ips_block(exclude_ipv6=True))
            conns_filter = ConnectivityProperties.make_conn_props_from_dict({"src_peers": all_peers,
                                                                             "dst_peers": all_peers})
        res_conns1 = self.config1.filter_conns_by_peer_types(conns1) & conns_filter
        res_conns2 = self.config2.filter_conns_by_peer_types(conns2) & conns_filter
        return res_conns1, res_conns2

    def _append_different_conns_to_list(self, conn_diff_props, different_conns_list, props_based_on_config1=True):
        """
        Adds difference between config1 and config2 connectivities into the list of differences
        :param ConnectivityProperties conn_diff_props: connectivity properties representing a difference
         between config1 and config2 connections (or between config2 and config1 connections)
        :param list different_conns_list: the list to add differences to
        :param bool props_based_on_config1: whether conn_diff_props represent connections present in config1 but not in config2
        (the value True) or connections present in config2 but not in config1 (the value False)
        """
        no_props = ConnectivityProperties()
        for cube in conn_diff_props:
            conn_cube = conn_diff_props.get_connectivity_cube(cube)
            conns, src_peers, dst_peers = \
                ConnectivityProperties.extract_src_dst_peers_from_cube(conn_cube, self.config1.peer_container)
            conns1 = conns if props_based_on_config1 else no_props
            conns2 = no_props if props_based_on_config1 else conns
            if self.output_config.fullExplanation:
                src_peers_str_sorted = str(sorted([str(peer) for peer in src_peers]))
                dst_peers_str_sorted = str(sorted([str(peer) for peer in dst_peers]))
                different_conns_list.append(PeersAndConnectivityProperties(src_peers_str_sorted, dst_peers_str_sorted,
                                                                           conns1, conns2))
            else:
                different_conns_list.append(PeersAndConnectivityProperties(src_peers.rep(), dst_peers.rep(), conns1, conns2))
                return

    @staticmethod
    def clone_without_gateway_layers(config):
        """
        Clone config without gateway policies
        :param NetworkConfig config: the config to clone
        :return: resulting config without gateway policies
        :rtype: NetworkConfig
        """
        if (NetworkLayerName.K8sGateway in config.policies_container.layers and
            config.policies_container.layers[NetworkLayerName.K8sGateway].policies_list) or \
                (NetworkLayerName.IstioGateway in config.policies_container.layers and
                 config.policies_container.layers[NetworkLayerName.IstioGateway].policies_list):
            config_without_gateway = config.clone_without_policies(config.name)
            for policy in config.policies_container.policies.values():
                if not isinstance(policy, GatewayPolicy):  # ignoring gateway policies
                    config_without_gateway.append_policy_to_config(policy)
            return config_without_gateway

        return config  # no K8s/Istio gateway policies in this config

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
        return self.check_equivalence(layer_name)

    def check_equivalence(self, layer_name=None):
        res_conns_filter = PolicyConnectionsFilter.only_all_allowed_connections()
        conn_props1 = self.config1.allowed_connections(layer_name, res_conns_filter)
        conn_props2 = self.config2.allowed_connections(layer_name, res_conns_filter)
        all_conns1, all_conns2 = self.filter_conns_by_input_or_internal_constraints(conn_props1.all_allowed_conns,
                                                                                    conn_props2.all_allowed_conns)
        if all_conns1 == all_conns2:
            return QueryAnswer(True, self.name1 + ' and ' + self.name2 + ' are semantically equivalent.',
                               numerical_result=0)

        conns1_not_in_conns2 = all_conns1 - all_conns2
        conns2_not_in_conns1 = all_conns2 - all_conns1
        different_conns_list = []
        self._append_different_conns_to_list(conns1_not_in_conns2, different_conns_list, True)
        self._append_different_conns_to_list(conns2_not_in_conns1, different_conns_list, False)
        return self._query_answer_with_relevant_explanation(sorted(different_conns_list))

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

    @dataclass
    class PropsAndExplanationData:
        props: ConnectivityProperties
        cluster_info: ClusterInfo
        output_config: OutputConfiguration
        peer_container: PeerContainer

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

    def compute_explanation_for_key(self, key, is_added, props_data, is_first_connectivity_result):
        """
        computes the explanation for given key and conn_graph with description and fw-rules results
        prepares the description and explanation
        description text is written for txt, yaml and json formats
        other formats description already included in the conn_graph data
        :param str key: the key describing the changes
        :param bool is_added: a bool flag indicating if connections are added or removed
        :param PropsAndExplanationData props_data: a ConnectivityProperties with added/removed connections
        :param bool is_first_connectivity_result: flag indicating if this is the first connectivity fw-rules computation
               for the current semantic-diff query
        :return the computedExplanation of the current key and conn_graph considering the outputFormat,
        and fw_rules from which the explanation was computed
        :rtype: ComputedExplanation, Union[None, MinimizeFWRules]
        """
        updated_key = self._get_updated_key(key, is_added)
        topology_config_name = self.name2 if is_added else self.name1
        connectivity_changes_header = f'{updated_key} (based on topology from config: {topology_config_name}) :'
        fw_rules = None
        if self.output_config.outputFormat == 'txt_no_fw_rules':
            conn_graph = ConnectivityGraph(props_data.cluster_info.all_peers, props_data.cluster_info.allowed_labels,
                                           props_data.output_config)
            conn_graph.add_props_to_graph(props_data.props, props_data.peer_container)
            conn_graph_explanation = conn_graph.get_connections_without_fw_rules_txt_format(
                connectivity_changes_header, exclude_self_loop_conns=False) + '\n'
        else:
            fw_rules = MinimizeFWRules.get_minimized_firewall_rules_from_props(props_data.props, props_data.cluster_info,
                                                                               props_data.output_config,
                                                                               props_data.peer_container, None)
            if self.config1.debug:
                self.compare_fw_rules_to_conn_props(fw_rules, props_data.props)
            conn_graph_explanation = fw_rules.get_fw_rules_in_required_format(False, is_first_connectivity_result)

        if self.output_config.outputFormat in ['json', 'yaml']:
            explanation_dict = {'description': updated_key}
            explanation_dict.update(conn_graph_explanation)
            key_explanation = ComputedExplanation(dict_explanation=explanation_dict)
        else:
            str_explanation = f'\n{connectivity_changes_header}\n' if self.output_config.outputFormat == 'txt' else ''
            str_explanation += conn_graph_explanation
            key_explanation = ComputedExplanation(str_explanation=str_explanation)

        return key_explanation, fw_rules

    def get_results_for_computed_fw_rules(self, keys_list, removed_props_per_key, added_props_per_key):
        """
        Compute accumulated explanation and res for all keys of changed connections categories
        :param keys_list: the list of keys
        :param removed_props_per_key: map from key to PropsAndExplanationData of removed connections
        :param added_props_per_key: map from key to PropsAndExplanationData of added connections
        :return:
        res (int): number of categories with diffs
        explanation (list): list of ComputedExplanation, the diffs' explanations, one for each category
        :rtype: int, list[ComputedExplanation]
        """
        explanation = []
        add_explanation = self.output_config.outputFormat in SemanticDiffQuery.get_supported_output_formats()
        res = 0
        for key in keys_list:
            added_props = added_props_per_key[key]
            removed_props = removed_props_per_key[key]
            is_added = added_props is not None and added_props.props
            is_removed = removed_props is not None and removed_props.props
            if is_added:
                if add_explanation:
                    key_explanation, _ = self.compute_explanation_for_key(key, True, added_props, res == 0)
                    explanation.append(key_explanation)
                res += 1

            if is_removed:
                if add_explanation:
                    key_explanation, _ = self.compute_explanation_for_key(key, False, removed_props, res == 0)
                    explanation.append(key_explanation)
                res += 1

        return res, explanation

    def get_changed_props_expl_data(self, key, ip_blocks, is_added, props, peer_container):
        """
        create an explanation for changed (added/removed) connections per given key
        :param key: the key (category) of changed connections
        :param ip_blocks: a PeerSet of ip-blocks to be added for the topology peers
        :param is_added: a bool flag indicating if connections are added or removed
        :param ConnectivityProperties props: the explanation
        :param PeerContainer peer_container: a relevant peer container
        :return: a PropsAndExplanationData object
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
        return SemanticDiffQuery.PropsAndExplanationData(props, ClusterInfo(topology_peers, allowed_labels),
                                                         output_config, peer_container)

    def compute_diff(self):  # noqa: C901
        """
        Compute changed connections (by optimized implementation) as following:

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
        keys_list (list[str]): list of names of connection categories,
        being the keys in conn_graph_removed_per_key/conn_graph_added_per_key
        conn_graph_removed_per_key (dict): a dictionary of removed connections connectivity graphs per category
        conn_graph_added_per_key (dict): a dictionary of added connections connectivity graphs per category
        :rtype: list[str], dict, dict
        """

        old_peers = self.config1.peer_container.get_all_peers_group(include_dns_entries=True)
        new_peers = self.config2.peer_container.get_all_peers_group(include_dns_entries=True)
        intersected_peers = old_peers & new_peers
        removed_peers = old_peers - intersected_peers
        added_peers = new_peers - intersected_peers
        captured_pods = (self.config1.get_captured_pods() | self.config2.get_captured_pods()) & intersected_peers
        exclude_ipv6 = self.config1.check_for_excluding_ipv6_addresses(self.output_config.excludeIPv6Range) and \
            self.config2.check_for_excluding_ipv6_addresses(self.output_config.excludeIPv6Range)
        all_ip_blocks = IpBlock.get_all_ips_block_peer_set(exclude_ipv6)

        removed_props_per_key = dict()
        added_props_per_key = dict()
        keys_list = []
        res_conns_filter = PolicyConnectionsFilter.only_all_allowed_connections()
        old_conns = self.config1.allowed_connections(res_conns_filter=res_conns_filter)
        new_conns = self.config2.allowed_connections(res_conns_filter=res_conns_filter)
        old_props, new_props = self.filter_conns_by_input_or_internal_constraints(old_conns.all_allowed_conns,
                                                                                  new_conns.all_allowed_conns)
        old_minus_new_props = old_props - new_props
        new_minus_old_props = new_props - old_props

        # 1.1. lost connections between removed peers
        key = 'Lost connections between removed peers'
        keys_list.append(key)
        props = ConnectivityProperties.make_conn_props_from_dict({"src_peers": removed_peers,
                                                                  "dst_peers": removed_peers})
        props &= old_props
        props = props.props_without_auto_conns()
        removed_props_per_key[key] = self.get_changed_props_expl_data(key, PeerSet(), False, props,
                                                                      self.config1.peer_container)
        added_props_per_key[key] = None

        # 1.2. lost connections between removed peers and ipBlocks
        key = 'Lost connections between removed peers and ipBlocks'
        keys_list.append(key)
        props = ConnectivityProperties.make_conn_props_from_dict({"src_peers": removed_peers,
                                                                  "dst_peers": all_ip_blocks}) | \
            ConnectivityProperties.make_conn_props_from_dict({"src_peers": all_ip_blocks,
                                                              "dst_peers": removed_peers})
        props &= old_props
        removed_props_per_key[key] = self.get_changed_props_expl_data(key, all_ip_blocks, False, props,
                                                                      self.config1.peer_container)
        added_props_per_key[key] = None

        # 2.1. lost connections between removed peers and intersected peers
        key = 'Lost connections between removed peers and persistent peers'
        keys_list.append(key)
        props = ConnectivityProperties.make_conn_props_from_dict({"src_peers": removed_peers,
                                                                  "dst_peers": intersected_peers}) | \
            ConnectivityProperties.make_conn_props_from_dict({"src_peers": intersected_peers,
                                                              "dst_peers": removed_peers})
        props &= old_props
        props = props.props_without_auto_conns()
        removed_props_per_key[key] = self.get_changed_props_expl_data(key, PeerSet(), False, props,
                                                                      self.config1.peer_container)
        added_props_per_key[key] = None

        # 3.1. lost/new connections between intersected peers due to changes in policies and labels of pods/namespaces
        key = 'Changed connections between persistent peers'
        keys_list.append(key)
        props = ConnectivityProperties.make_conn_props_from_dict({"src_peers": captured_pods,
                                                                  "dst_peers": intersected_peers}) | \
            ConnectivityProperties.make_conn_props_from_dict({"src_peers": intersected_peers,
                                                              "dst_peers": captured_pods})
        removed_props = (old_minus_new_props & props).props_without_auto_conns()
        added_props = (new_minus_old_props & props).props_without_auto_conns()
        removed_props_per_key[key] = self.get_changed_props_expl_data(key, PeerSet(), False, removed_props,
                                                                      self.config1.peer_container)
        added_props_per_key[key] = self.get_changed_props_expl_data(key, PeerSet(), True, added_props,
                                                                    self.config2.peer_container)

        # 3.2. lost/new connections between intersected peers and ipBlocks due to changes in policies and labels
        key = 'Changed connections between persistent peers and ipBlocks'
        keys_list.append(key)
        props = ConnectivityProperties.make_conn_props_from_dict({"src_peers": captured_pods,
                                                                  "dst_peers": all_ip_blocks}) | \
            ConnectivityProperties.make_conn_props_from_dict({"src_peers": all_ip_blocks,
                                                              "dst_peers": captured_pods})
        removed_props = old_minus_new_props & props
        added_props = new_minus_old_props & props
        removed_props_per_key[key] = self.get_changed_props_expl_data(key, all_ip_blocks, False, removed_props,
                                                                      self.config1.peer_container)
        added_props_per_key[key] = self.get_changed_props_expl_data(key, all_ip_blocks, True, added_props,
                                                                    self.config2.peer_container)

        # 4.1. new connections between intersected peers and added peers
        key = 'New connections between persistent peers and added peers'
        keys_list.append(key)
        props = ConnectivityProperties.make_conn_props_from_dict({"src_peers": intersected_peers,
                                                                  "dst_peers": added_peers}) | \
            ConnectivityProperties.make_conn_props_from_dict({"src_peers": added_peers,
                                                              "dst_peers": intersected_peers})
        props &= new_props
        props = props.props_without_auto_conns()
        removed_props_per_key[key] = None
        added_props_per_key[key] = self.get_changed_props_expl_data(key, PeerSet(), True, props,
                                                                    self.config2.peer_container)

        # 5.1. new connections between added peers
        key = 'New connections between added peers'
        keys_list.append(key)
        props = ConnectivityProperties.make_conn_props_from_dict({"src_peers": added_peers,
                                                                  "dst_peers": added_peers})
        props &= new_props
        props = props.props_without_auto_conns()
        removed_props_per_key[key] = None
        added_props_per_key[key] = self.get_changed_props_expl_data(key, PeerSet(), True, props,
                                                                    self.config2.peer_container)

        # 5.2. new connections between added peers and ipBlocks
        key = 'New connections between added peers and ipBlocks'
        keys_list.append(key)
        props = ConnectivityProperties.make_conn_props_from_dict({"src_peers": added_peers,
                                                                  "dst_peers": all_ip_blocks}) | \
            ConnectivityProperties.make_conn_props_from_dict({"src_peers": all_ip_blocks,
                                                              "dst_peers": added_peers})
        props &= new_props
        removed_props_per_key[key] = None
        added_props_per_key[key] = self.get_changed_props_expl_data(key, all_ip_blocks, True, props,
                                                                    self.config2.peer_container)

        return keys_list, removed_props_per_key, added_props_per_key

    def exec(self, cmd_line_flag):
        self.output_config.fullExplanation = True  # assign true for this query - it is always ok to compare its results
        query_answer = self.is_identical_topologies(True)
        if query_answer.bool_result and query_answer.output_result:
            return query_answer
        keys_list, removed_props_per_key, added_props_per_key = self.compute_diff()
        res, explanation = self.get_results_for_computed_fw_rules(keys_list, removed_props_per_key,
                                                                  added_props_per_key)
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

        return self.check_containment(cmd_line_flag, only_captured)

    def check_containment(self, cmd_line_flag=False, only_captured=False):
        if only_captured:
            res_conns_filter1 = PolicyConnectionsFilter.only_allowed_connections()
        else:
            res_conns_filter1 = PolicyConnectionsFilter.only_all_allowed_connections()
        res_conns_filter2 = PolicyConnectionsFilter.only_all_allowed_connections()
        conn_props1 = self.config1.allowed_connections(res_conns_filter=res_conns_filter1)
        conn_props2 = self.config2.allowed_connections(res_conns_filter=res_conns_filter2)
        conns1, conns2 = self.filter_conns_by_input_or_internal_constraints(
            conn_props1.allowed_conns if only_captured else conn_props1.all_allowed_conns,
            conn_props2.all_allowed_conns)
        if conns1.contained_in(conns2):
            return QueryAnswer(True, self.name1 + ' is contained in ' + self.name2,
                               numerical_result=1 if not cmd_line_flag else 0)

        conns1_not_in_conns2 = conns1 - conns2
        different_conns_list = []
        self._append_different_conns_to_list(conns1_not_in_conns2, different_conns_list)
        return self._query_answer_with_relevant_explanation(sorted(different_conns_list), cmd_line_flag)

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

        if self.config1.policies_container.layers.does_contain_only_gateway_layers():
            return QueryAnswer(bool_result=False,
                               output_result='Permitted traffic cannot be specified using Ingress/Gateway resources only',
                               query_not_executed=True)

        config1_without_gateway = self.clone_without_gateway_layers(self.config1)
        query_answer = ContainmentQuery(config1_without_gateway, self.config2,
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

        return self.check_interferes(cmd_line_flag)

    def check_interferes(self, cmd_line_flag=False):
        res_conns_filter = PolicyConnectionsFilter.only_allowed_connections()

        conn_props1 = self.config1.allowed_connections(res_conns_filter=res_conns_filter)
        conn_props2 = self.config2.allowed_connections(res_conns_filter=res_conns_filter)
        conns1, conns2 = self.filter_conns_by_input_or_internal_constraints(conn_props1.allowed_conns,
                                                                            conn_props2.allowed_conns)
        if conns1.contained_in(conns2):
            return QueryAnswer(False, self.name1 + ' does not interfere with ' + self.name2,
                               numerical_result=0 if not cmd_line_flag else 1)

        conns1_not_in_conns2 = conns1 - conns2
        extended_conns_list = []
        self._append_different_conns_to_list(conns1_not_in_conns2, extended_conns_list, True)
        return self._query_answer_with_relevant_explanation(sorted(extended_conns_list), cmd_line_flag)

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
    Note: this query is only used by ForbidsQuery.
    It's not symmetrical: config1 is a "specification config", that explicitly defines things to be checked
    in the "implementation" config (config2), i.e., its captured connections are considered,
    while config2 is the "implementation" config to be checked, and all its connections are considered.
    """

    def exec(self, cmd_line_flag=False, only_captured=True):
        query_answer = self.is_identical_topologies()
        if query_answer.output_result:
            return query_answer

        return self.check_intersects()

    def check_intersects(self, only_captured=True):
        if only_captured:
            res_conns_filter1 = PolicyConnectionsFilter.only_allowed_connections()
        else:
            res_conns_filter1 = PolicyConnectionsFilter.only_all_allowed_connections()
        res_conns_filter2 = PolicyConnectionsFilter.only_all_allowed_connections()
        conn_props1 = self.config1.allowed_connections(res_conns_filter=res_conns_filter1)
        conn_props2 = self.config2.allowed_connections(res_conns_filter=res_conns_filter2)
        conns1, conns2 = self.filter_conns_by_input_or_internal_constraints(
            conn_props1.allowed_conns if only_captured else conn_props1.all_allowed_conns,
            conn_props2.all_allowed_conns)
        conns_in_both = conns1 & conns2
        if conns_in_both:
            intersect_connections_list = []
            self._append_different_conns_to_list(conns_in_both, intersect_connections_list)
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
        if self.config1.policies_container.layers.does_contain_only_gateway_layers():
            return QueryAnswer(bool_result=False,
                               output_result='Forbidden traffic cannot be specified using Ingress/Gateway resources only',
                               query_not_executed=True)

        config1_without_gateway = self.clone_without_gateway_layers(self.config1)

        query_answer = \
            IntersectsQuery(config1_without_gateway, self.config2, self.output_config).exec(only_captured=True)
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
        if not self.config or self.config.policies_container.layers.does_contain_only_gateway_layers():
            return QueryAnswer(bool_result=False,
                               output_result=f'There are no network policies in {self.config.name}. '
                                             f'All workload resources are non captured',
                               numerical_result=len(existing_pods))

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
