#
# Copyright 2020- IBM Inc. All rights reserved
# SPDX-License-Identifier: Apache2.0
#
from __future__ import annotations
from abc import abstractmethod
from dataclasses import dataclass
import yaml


@dataclass
class QueryAnswer:
    """
    A class for holding the answer to any one of the NetworkConfigQuery.py queries
    """
    bool_result: bool = False
    output_result: str = ''
    output_explanation: OutputExplanation = None
    numerical_result: int = 0
    query_not_executed: bool = False


@dataclass
class OutputExplanation:
    """
    A class that unifies the possible types of the QueryAnswer's output_explanation as it may vary according to
    the pattern of the query's result - an output_explanation may have only one of its fields at a time besides
    to explanation_description
    """
    explanation_description: str = ''
    policies_with_intersect_pods: list[tuple] = None  # used in DisjointnessQuery - list of pods intersect between
    # policies
    policies_and_rules: PoliciesAndRulesExplanations = None
    pods_lists: PodsListsExplanations = None
    connections_diff: ConnectionsDiffExplanation = None
    combined_explanation: CombinedExplanation = None
    str_explanation: str = None  # for queries that compute separately the output in the required format
    # (i.e. ConnectivityMapQuery, SanityQuery and SemanticDiffQuery)


# following classes describe the more possible OutputExplanation patterns, each class consists of the explanation
# fields that may appear together in one output_explanation and additional info for writing the explanation if required
@dataclass
class PoliciesAndRulesExplanations:
    # used in RedundancyQuery and EmptinessQuery: we may have lists of redundant/empty policies, ingress/egress rules
    policies_list: list[str] = None
    policies_to_ingress_rules_dict: dict = None
    policies_to_egress_rules_dict: dict = None


@dataclass
class PodsListsExplanations:
    # 2 use cases:
    # 1. used in ContainmentQuery when a reason that config is not contained in the other,
    # is pods list that appears only in one
    # 2. used in AllCapturedQuery - lists of pods that are not captured for ingress and/or egress
    pods_list: list[str] = None
    egress_pods_list: list[str] = None
    add_xgress_suffix: bool = False


@dataclass
class ConnectionsDiffExplanation:
    # used in TwoNetworkConfigs queries that compare connections of pairs of peers in both configs
    peers_diff_connections_list: list[tuple] = None
    additional_description: str = ''


@dataclass
class CombinedExplanation:
    # used in TwoWayContainment, when both configs do not contain each other -
    # the output_explanation is a combination of two explanation of different containment queries
    two_results_combined: list[OutputExplanation] = None


class QueryOutputHandler:
    """
    A class to handle the output of the query and create it in the correct form ,
    output explanation is handled by it type
    """
    def __init__(self, configs):
        """
        :param list[str] configs: list of config(s) name(s)
        """
        self.configs_names = configs

    def handle_explanation_by_type(self, explanation):
        """
        handles writing the output explanation according to its type
        :param OutputExplanation explanation: the query's output explanation
        """
        if explanation.policies_with_intersect_pods:
            self.write_policies_with_intersect_pods_explanation(explanation.explanation_description,
                                                                explanation.policies_with_intersect_pods)
        elif explanation.policies_and_rules:
            self.write_policies_and_rules_explanations(explanation.explanation_description,
                                                       explanation.policies_and_rules)
        elif explanation.pods_lists:
            self.write_pods_list_explanation(explanation.explanation_description, explanation.pods_lists)
        elif explanation.connections_diff:
            self.write_conns_diff_explanation(explanation.explanation_description, explanation.connections_diff)
        elif explanation.combined_explanation:
            self.handle_explanation_by_type(explanation.combined_explanation.two_results_combined[0])
            self.handle_explanation_by_type(explanation.combined_explanation.two_results_combined[1])

    def write_policies_and_rules_explanations(self, description, policies_and_rules_explanation):
        """
        updates the output explanation result of the PoliciesAndRulesExplanations field and its description in
        the required format
        :param str description: the relevant description of the output explanation in the query answer
        :param  PoliciesAndRulesExplanations policies_and_rules_explanation: the policies_and_rules field of
        OutputExplanation
        """
        if policies_and_rules_explanation.policies_list:
            policies_description = 'Policies' + description
            self._add_policies_to_explanation(policies_description, policies_and_rules_explanation.policies_list)
        if policies_and_rules_explanation.policies_to_ingress_rules_dict:
            ingress_description = 'Ingress rules' + description
            self._add_rules_to_explanation(ingress_description,
                                           policies_and_rules_explanation.policies_to_ingress_rules_dict)
        if policies_and_rules_explanation.policies_to_egress_rules_dict:
            egress_description = 'Egress rules' + description
            self._add_rules_to_explanation(egress_description,
                                           policies_and_rules_explanation.policies_to_egress_rules_dict, 'egress')

    def write_pods_list_explanation(self, description, pods_list_explanation):
        """
        updates the output explanation result of PodsListsExplanations and its description in the required format
        :param str description: the relevant description of the output explanation in the query answer
        :param  PodsListsExplanations pods_list_explanation: the pods_lists field of
        OutputExplanation
        """
        if not pods_list_explanation.add_xgress_suffix:
            self._add_pods_list_to_explanation(description, pods_list_explanation.pods_list)
        else:
            if pods_list_explanation.pods_list:
                ingress_description = description + 'ingress'
                self._add_pods_list_to_explanation(ingress_description, pods_list_explanation.pods_list)
            if pods_list_explanation.egress_pods_list:
                egress_description = description + 'egress'
                self._add_pods_list_to_explanation(egress_description, pods_list_explanation.egress_pods_list)

    @abstractmethod
    def write_policies_with_intersect_pods_explanation(self, description, explanation):
        raise NotImplementedError

    @abstractmethod
    def _add_policies_to_explanation(self, policies_description, policies_list):
        raise NotImplementedError

    @abstractmethod
    def _add_rules_to_explanation(self, xgress_description, policies_to_xgress_rules_dict, prefix='ingress'):
        raise NotImplementedError

    @abstractmethod
    def _add_pods_list_to_explanation(self, description, pods_list):
        raise NotImplementedError

    @abstractmethod
    def write_conns_diff_explanation(self, description, conns_diff_explanation):
        raise NotImplementedError


class YamlOutputHandler(QueryOutputHandler):
    """
    A class to form the query output in Yaml format
    """
    def __init__(self, configs):
        super().__init__(configs)
        self.explanation_result_1 = []
        self.explanation_result_2 = []

    def compute_query_output(self, query_answer, query_name):
        """
        computes the query output in Yaml format
        :param QueryAnswer query_answer: the query answer - the result of the running query
        :param str query_name: name of the running query
        :return yaml format of the query answer
        :rtype: str
        """
        query_name = query_name
        yaml_content = {'query': query_name, 'configs': self.configs_names}
        if query_answer.query_not_executed:
            yaml_content.update({'executed': 0, 'description': query_answer.output_result})
            return yaml.dump(yaml_content, None, default_flow_style=False, sort_keys=False) + '---\n'
        yaml_content.update({'numerical_result': int(query_answer.numerical_result)})
        yaml_content.update({'textual_result': query_answer.output_result})
        if query_answer.output_explanation:
            return self.compute_yaml_explanation(yaml_content, query_answer.output_explanation)
        return yaml.dump(yaml_content, None, default_flow_style=False, sort_keys=False) + '---\n'

    def compute_yaml_explanation(self, yaml_content, explanation):
        """
        computes the output_explanation of the query answer in Yaml format
        :param dict yaml_content: already generated yaml from fields of the query answer other than output_explanation
        :param OutputExplanation explanation: the output_explanation of the query answer
        :return: the yaml output of the query with its output explanation
        :rtype: str
        """
        self.handle_explanation_by_type(explanation)
        yaml_content_1 = yaml_content
        yaml_content_1.update({'explanation': self.explanation_result_1})
        res1 = yaml.dump(yaml_content_1, None, default_flow_style=False, sort_keys=False)
        if self.explanation_result_2:  # two parallel yaml objects when connections differ in the configs
            yaml_content_2 = yaml_content
            yaml_content_2.update({'explanation': self.explanation_result_2})
            res2 = yaml.dump(yaml_content_2, None, default_flow_style=False, sort_keys=False)
            return res1 + '---\n' + res2 + '---\n'
        return res1 + '---\n'

    def write_policies_with_intersect_pods_explanation(self, description, policies_intersect_pods_explanation):
        """
        updates the explanation_result with the yaml format of IntersectPodsExplanation and its description
        :param str description: the relevant description of this output explanation
        :param  list[tuple] policies_intersect_pods_explanation: the policies_with_intersect_pods field of
        OutputExplanation
        """
        result = []
        for item in policies_intersect_pods_explanation:
            result.append({'policies': [item[0].split(' ')[1], item[1].split(' ')[1]],
                           'pods': str(item[2]).split(', ')})
        self.explanation_result_1.append({'description': description, 'examples': result})

    def _add_policies_to_explanation(self, policies_description, policies_list):
        """
        updates the explanation result with the yaml format of policies list and its description
        :param str policies_description: the relevant description of this output_explanation field of
        PoliciesAndRulesExplanations
        :param list[str] policies_list: policies list
        """
        self.explanation_result_1.append({'description': policies_description,
                                          'policies': [policy.split()[1] for policy in policies_list]})

    def _add_rules_to_explanation(self, xgress_description, policies_to_xgress_rules_dict, prefix='ingress'):
        """
        updates the explanation result with the yaml format of policies to ingress/egress rules and its description
        :param str xgress_description: the relevant description of this output_explanation field of
        PoliciesAndRulesExplanations
        :param dict policies_to_xgress_rules_dict: policies to matching rules indexes
        :param str prefix: indicates if rules types are ingress or egress
        """
        rules = []
        for key, value in policies_to_xgress_rules_dict.items():
            rules.append({'policy': key.split()[1], prefix + '_rules_indexes': [str(idx) for idx in value]})
        self.explanation_result_1.append({'description': xgress_description, 'pairs': rules})

    def _add_pods_list_to_explanation(self, description, pods_list):
        """
        updates the explanation result with the yaml format of pods lists and its description
        :param str description: the relevant description of this output_explanation field of PodsListsExplanations
        :param list[str] pods_list: pods names list
        """
        self.explanation_result_1.append({'description': description, 'pods': pods_list})

    def write_conns_diff_explanation(self, description, conns_diff_explanation):
        """
        updates the explanation results with the yaml format of ConnectionsDiffExplanation and its description
        if an additional description is given in the conns_diff_explanation parameter, then this explanation may
         be formatted in two ways, thus two yaml results are produced for the query answer
        :param str description: the relevant description of this output explanation
        :param ConnectionsDiffExplanation conns_diff_explanation: the connections_diff field of OutputExplanation
        """
        conns1 = []
        two_results = conns_diff_explanation.additional_description
        conns2 = []
        for peers_conn in conns_diff_explanation.peers_diff_connections_list:
            conns1.append({'src': peers_conn[0], 'dst': peers_conn[1], 'conn': str(peers_conn[2])})
            if two_results:
                conns2.append({'src': peers_conn[0], 'dst': peers_conn[1], 'conn': str(peers_conn[3])})

        self.explanation_result_1.append({'description': description, 'connections': conns1})
        if two_results:
            self.explanation_result_2.append({'description': conns_diff_explanation.additional_description,
                                              'connections': conns2})


class TxtOutputHandler(QueryOutputHandler):
    """
    A class to form the query output in Txt format
    """
    def __init__(self, configs):
        super().__init__(configs)
        self.explanation_result = ''

    def compute_query_output(self, query_answer, _):
        """
        computes the query output in Txt format
        :param QueryAnswer query_answer: the query answer - the result of the running query
        :param Any _ : for compatibility call of this def of QueryOutputHandler
        :return txt format of the query answer
        :rtype: str
        """
        query_output = query_answer.output_result + '\n'
        if query_answer.output_explanation:
            self.handle_explanation_by_type(query_answer.output_explanation)
            query_output += self.explanation_result + '\n'
        return query_output

    def write_policies_with_intersect_pods_explanation(self, description, policies_intersect_pods_explanation):
        """
        updates the explanation_result with the txt format of IntersectPodsExplanation and its description
        :param str description: the relevant description of this output explanation
        :param  list[tuple] policies_intersect_pods_explanation: the policies_with_intersect_pods field of
        OutputExplanation
        """
        result = []
        delimiter = ' '
        for item in policies_intersect_pods_explanation:
            result.append(f'{item[0].split(delimiter)[0]}_1: {item[0].split(delimiter)[1]}, '
                          f'{item[1].split(delimiter)[0]}_2: {item[1].split(delimiter)[1]}, pods: {item[2]}')
        self.explanation_result += description + ':\n' + '\n'.join(result)

    def _add_policies_to_explanation(self, policies_description, policies_list):
        """
        updates the explanation result with the txt format of policies list and its description
        :param str policies_description: the relevant description of this output_explanation field of
        PoliciesAndRulesExplanations
        :param list[str] policies_list: policies list
        """
        self.explanation_result += policies_description + ':\n' + ', '.join(policies_list) + '\n'

    def _add_rules_to_explanation(self, xgress_description, policies_to_xgress_rules_dict, prefix='ingress'):
        """
        updates the explanation result with the txt format of policies to ingress/egress rules and its description
        :param str xgress_description: the relevant description of this output_explanation field of
        PoliciesAndRulesExplanations
        :param dict policies_to_xgress_rules_dict: policies to matching rules indexes
        :param str prefix: indicates if rules types are ingress or egress
        """
        self.explanation_result += '\n' + xgress_description + ':\n'
        for key, value in policies_to_xgress_rules_dict.items():
            self.explanation_result +=\
                key + ', ' + prefix + ' rules indexes: ' + ', '.join(str(idx) for idx in value) + '\n'

    def _add_pods_list_to_explanation(self, description, pods_list):
        """
        updates the explanation result with the txt format of pods lists and its description
        :param str description: the relevant description of this output_explanation field of PodsListsExplanations
        :param list[str] pods_list: pods names list
        """
        self.explanation_result += '\n' + description + ':\n' + ', '.join(pods_list) + '\n'

    def write_conns_diff_explanation(self, description, conns_diff_explanation):
        """
        updates the explanation result with the txt format of ConnectionsDiffExplanation and its description
        :param str description: the relevant description of this output explanation
        :param ConnectionsDiffExplanation conns_diff_explanation: the connections_diff field of OutputExplanation
        """
        conns = []
        conns_diff = conns_diff_explanation.additional_description
        for peers_conn in conns_diff_explanation.peers_diff_connections_list:
            if conns_diff:
                conns.append(f'src: {peers_conn[0]}, dst: {peers_conn[1]}, description: '
                             f'{peers_conn[2].print_diff(peers_conn[3], self.configs_names[0], self.configs_names[1])}')
            else:
                conns.append(f'src: {peers_conn[0]}, dst: {peers_conn[1]}, conn: {peers_conn[2]}')

        self.explanation_result += description + ':\n' + '\n'.join(conns) + '\n'
