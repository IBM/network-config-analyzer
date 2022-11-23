#
# Copyright 2020- IBM Inc. All rights reserved
# SPDX-License-Identifier: Apache2.0
#
from __future__ import annotations
from dataclasses import dataclass
import yaml

from nca.CoreDS.ConnectionSet import ConnectionSet


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
    policies_with_intersect_pods: IntersectPodsExplanation = None
    policies_and_rules: PoliciesAndRulesExplanations = None
    pods_lists: PodsListsExplanations = None
    connections_diff: ConnectionsDiffExplanation = None
    combined_explanation: CombinedExplanation = None
    str_explanation: str = None  # for queries that compute separately the output in the required format
    # (i.e. ConnectivityMapQuery, SanityQuery and SemanticDiffQuery)

    def get_explanation_in_txt(self):
        """
        computes and returns the output explanation is txt format.
        An OutputExplanation object may have only one field representing the explanation data besides to
         explanation_description, so the output is computed by calling the get_explanation_in_txt method of this field
         :return the explanation written with its description in txt format
         :rtype: str
        """
        for val in self.__dict__.values():
            if not isinstance(val, str) and val is not None:
                return val.get_explanation_in_txt(self.explanation_description)

    def get_explanation_in_yaml(self):
        """
        computes and returns the output explanation is yaml format.
        An OutputExplanation object may have only one field representing the explanation data besides to
        explanation_description, so the output is computed by calling the get_explanation_in_txt method of this field
        :return the explanation written with its description in a list of dict pattern that matches yaml dump later
        A ConnectionsDiffExplanation may create two parallel results for one explanation, so return value might
        consist of two explanation results or one with None as second result
         :rtype: Union[[list[dict], None], [list[dict], list[dict]]
        """
        for val in self.__dict__.values():
            if not isinstance(val, str) and val is not None:
                return val.get_explanation_in_yaml(self.explanation_description)


# following classes describe the more possible OutputExplanation patterns, each class consists of the explanation
# fields that may appear together in one output_explanation and additional info for writing the explanation if required
@dataclass
class PoliciesWithCommonPods:
    """
    A class for holding information of pairs of policies with common pods
    """
    first_policy: str = ''
    second_policy: str = ''
    common_pods: str = ''

    def __lt__(self, other):
        if self.first_policy == other.first_policy:
            return self.second_policy < other.second_policy
        return self.first_policy < other.first_policy


@dataclass
class IntersectPodsExplanation:
    # used in DisjointnessQuery
    policies_pods: list[PoliciesWithCommonPods] = None  # used in DisjointnessQuery

    def get_explanation_in_yaml(self, explanation_description):
        """
        returns yaml format of self type of OutputExplanation
        :param explanation_description: the relevant description of this output explanation
        :rtype: list[dict], None
        """
        examples = []
        for record in self.policies_pods:
            examples.append({'policies': [record.first_policy.split(' ')[1], record.second_policy.split(' ')[1]],
                             'pods': record.common_pods.split(', ')})
        return [{'description': explanation_description, 'examples': examples}], None

    def get_explanation_in_txt(self, explanation_description):
        """
        returns txt format of self type of OutputExplanation
        :param explanation_description: the relevant description of this output explanation
        :rtype: str
        """
        result = []
        delimiter = ' '
        for record in self.policies_pods:
            result.append(f'{record.first_policy.split(delimiter)[0]}_1: {record.first_policy.split(delimiter)[1]}, '
                          f'{record.second_policy.split(delimiter)[0]}_2: {record.second_policy.split(delimiter)[1]},'
                          f' pods: {record.common_pods}')
        return explanation_description + ':\n' + '\n'.join(result)


@dataclass
class PoliciesAndRulesExplanations:
    # used in RedundancyQuery and EmptinessQuery: we may have lists of redundant/empty policies or
    # maps of policies to redundant/empty ingress/egress rules indexes
    policies_list: list[str] = None
    policies_to_ingress_rules_dict: dict[str, list[int]] = None
    policies_to_egress_rules_dict: dict[str, list[int]] = None

    @staticmethod
    def _get_policies_description(explanation_description):
        return 'Policies' + explanation_description

    @staticmethod
    def _get_xgress_description(explanation_description, prefix='Ingress'):
        return prefix + ' rules' + explanation_description

    @staticmethod
    def _add_rules_to_yaml_explanation(xgress_description, xgress_rules_dict, prefix='ingress'):
        """
        adds yaml format of policies to ingress/egress rules and its description to explanation result
        :param str xgress_description: the relevant description of this oof the given rules' dict
        :param str prefix: indicates if rules types are ingress or egress
        :return the yaml format of the explanation in dict of description and pairs of policy and rules indexes
        :rtype dict
        """
        rules = []
        for key, value in xgress_rules_dict.items():
            rules.append({'policy': key.split()[1], prefix + '_rules_indexes': [str(idx) for idx in value]})
        return {'description': xgress_description, 'pairs': rules}

    def get_explanation_in_yaml(self, explanation_description):
        """
        returns yaml format of self type of OutputExplanation
        :param explanation_description: the relevant description of this output explanation
        :rtype: list[dict], None
        """
        result = []
        if self.policies_list:
            result.append({'description': self._get_policies_description(explanation_description),
                           'policies': [policy.split()[1] for policy in self.policies_list]})
        if self.policies_to_ingress_rules_dict:
            ingress_description = self._get_xgress_description(explanation_description)
            result.append(self._add_rules_to_yaml_explanation(ingress_description, self.policies_to_ingress_rules_dict))
        if self.policies_to_egress_rules_dict:
            egress_description = self._get_xgress_description(explanation_description, prefix='Egress')
            result.append(self._add_rules_to_yaml_explanation(egress_description, self.policies_to_egress_rules_dict,
                                                              'egress'))
        return result, None

    @staticmethod
    def _add_rules_to_txt_explanation(xgress_description, xgress_rules_dict, prefix='ingress'):
        """
        adds txt format of policies to ingress/egress rules and its description to the explanation result
        :param str xgress_description: the relevant description of the given rules' dict
        :param dict xgress_rules_dict: a dict of policies to matching rules indexes
        :param str prefix: indicates if rules types are ingress or egress
        :return the txt format of the explanation
        :rtype: str
        """
        res = '\n' + xgress_description + ':\n'
        for key, value in xgress_rules_dict.items():
            res += key + ', ' + prefix + ' rules indexes: ' + ', '.join(str(idx) for idx in value) + '\n'
        return res

    def get_explanation_in_txt(self, explanation_description):
        """
        returns txt format of self type of OutputExplanation
        :param explanation_description: the relevant description of this output explanation
        :rtype: str
        """
        result = ''
        if self.policies_list:
            result += self._get_policies_description(explanation_description) + ':\n' +\
                      ', '.join(self.policies_list) + '\n'
        if self.policies_to_ingress_rules_dict:
            ingress_description = self._get_xgress_description(explanation_description)
            result += self._add_rules_to_txt_explanation(ingress_description, self.policies_to_ingress_rules_dict)
        if self.policies_to_egress_rules_dict:
            egress_description = self._get_xgress_description(explanation_description, prefix='Egress')
            result += self._add_rules_to_txt_explanation(egress_description, self.policies_to_egress_rules_dict,
                                                         'egress')
        return result


@dataclass
class PodsListsExplanations:
    # 2 use cases:
    # 1. used in ContainmentQuery when a reason that config is not contained in the other,
    # is pods list that appears only in one
    # 2. used in AllCapturedQuery - lists of pods that are not captured for ingress and/or egress
    pods_list: list[str] = None
    egress_pods_list: list[str] = None
    add_xgress_suffix: bool = False

    @staticmethod
    def _get_xgress_description(explanation_description, suffix='ingress'):
        return explanation_description + suffix

    @staticmethod
    def _add_pods_list_to_yaml_explanation(description, pods_list):
        return {'description': description, 'pods': pods_list}

    def get_explanation_in_yaml(self, explanation_description):
        """
        returns yaml format of self type of OutputExplanation
        :param explanation_description: the relevant description of this output explanation
        :rtype: list[dict], None
        """
        if not self.add_xgress_suffix:
            return list(self._add_pods_list_to_yaml_explanation(explanation_description, self.pods_list))
        result = []
        if self.pods_list:
            result.append(self._add_pods_list_to_yaml_explanation(self._get_xgress_description(explanation_description),
                                                                  self.pods_list))
        if self.egress_pods_list:
            result.append(self._add_pods_list_to_yaml_explanation(self._get_xgress_description(explanation_description,
                                                                                               'egress'),
                                                                  self.egress_pods_list))
        return result, None

    @staticmethod
    def _add_pods_list_to_txt_explanation(description, pods_list):
        return '\n' + description + ':\n' + ', '.join(pods_list) + '\n'

    def get_explanation_in_txt(self, explanation_description):
        """
        returns txt format of self type of OutputExplanation
        :param explanation_description: the relevant description of this output explanation
        :rtype: str
        """
        if not self.add_xgress_suffix:
            return self._add_pods_list_to_txt_explanation(explanation_description, self.pods_list)
        result = ''
        if self.pods_list:
            result += self._add_pods_list_to_txt_explanation(self._get_xgress_description(explanation_description),
                                                             self.pods_list)
        if self.egress_pods_list:
            result += self._add_pods_list_to_txt_explanation(self._get_xgress_description(explanation_description,
                                                                                          'egress'),
                                                             self.egress_pods_list)
        return result


@dataclass
class PeersAndConnections:
    """
    A class for holding info on connections between same peers pairs in two different configs
    """
    src_peer: str = ''
    dst_peer: str = ''
    conns1: ConnectionSet = None  # connections from src to dst in first config
    conns2: ConnectionSet = None  # connections from src to dst in second config

    def __lt__(self, other):
        if self.src_peer == other.src_peer:
            return self.dst_peer < other.dst_peer
        return self.src_peer < other.src_peer


@dataclass
class ConnectionsDiffExplanation:
    # used in TwoNetworkConfigs queries that compare connections of pairs of peers in both configs
    peers_diff_connections_list: list[PeersAndConnections] = None
    additional_description: str = ''
    configs: list[str] = None  # configs names are relevant only when we have the conns1 and conns2 in
    # PeersAndConnections items , so we need them when calling ConnectionSet.print_diff in get_explanation_in_txt

    def get_explanation_in_yaml(self, explanation_description):
        """
         returns the explanation results in the yaml format of ConnectionsDiffExplanation and its description
        if the additional description is given, then this explanation may
         be formatted in two ways, thus two yaml results are produced for the query answer
        :param str explanation_description: the relevant description of this output explanation
        :rtype Union[[list[dict], list[dict]],[list[dict], None]]
        """
        conns1 = []
        two_results = self.additional_description
        conns2 = []
        result2 = None
        for peers_conn in self.peers_diff_connections_list:
            conns1.append({'src': peers_conn.src_peer, 'dst': peers_conn.dst_peer, 'conn': str(peers_conn.conns1)})
            if two_results:
                conns2.append({'src': peers_conn.src_peer, 'dst': peers_conn.dst_peer, 'conn': str(peers_conn.conns2)})

        result1 = [{'description': explanation_description, 'connections': conns1}]
        if two_results:
            result2 = [{'description': self.additional_description, 'connections': conns2}]
        return result1, result2

    def get_explanation_in_txt(self, explanation_description):
        """
        returns the explanation result with the txt format of ConnectionsDiffExplanation and its description
        :param str explanation_description: the relevant description of this output explanation
        :rtype str
        """
        conns = []
        conns_diff = self.additional_description
        for peers_conn in self.peers_diff_connections_list:
            if conns_diff:
                conns.append(f'src: {peers_conn.src_peer}, dst: {peers_conn.dst_peer}, description: '
                             f'{peers_conn.conns1.print_diff(peers_conn.conns2, self.configs[0], self.configs[1])}')
            else:
                conns.append(f'src: {peers_conn.src_peer}, dst: {peers_conn.dst_peer}, conn: {peers_conn.conns1}')

        return explanation_description + ':\n' + '\n'.join(conns) + '\n'


@dataclass
class CombinedExplanation:
    # used in TwoWayContainment, when both configs do not contain each other -
    # the output_explanation is a combination of two explanation of different containment queries
    two_results_combined: list[OutputExplanation] = None

    def get_explanation_in_yaml(self, _):
        # computes and returns the yaml format of each list in self.two_results_combined
        # and returns the results joined together
        result = []
        for explanation in self.two_results_combined:
            result += (explanation.get_explanation_in_yaml()[0])
        return result, None

    def get_explanation_in_txt(self, _):
        # computes and returns the txt format of each list in self.two_results_combined
        # and returns the results concatenated
        result = ''
        for explanation in self.two_results_combined:
            result += explanation.get_explanation_in_txt()
        return result


class YamlOutputHandler:
    """
    A class to form the query output in Yaml format
    """
    def __init__(self, configs):
        self.configs_names = configs

    def compute_query_output(self, query_answer, query_name):
        """
        computes the query output in Yaml format
        :param QueryAnswer query_answer: the query answer - the result of the running query
        :param str query_name: name of the running query
        :return yaml format of the query answer
        :rtype: str
        """
        query_name = query_name
        output_content = {'query': query_name, 'configs': self.configs_names}
        if query_answer.query_not_executed:
            output_content.update({'executed': 0, 'description': query_answer.output_result})
            return self.dump_content(output_content)

        output_content.update({'numerical_result': int(query_answer.numerical_result)})
        output_content.update({'textual_result': query_answer.output_result})
        if query_answer.output_explanation:
            return self.compute_yaml_explanation(output_content, query_answer.output_explanation)
        return self.dump_content(output_content)

    def compute_yaml_explanation(self, generated_content, explanation):
        """
        computes the output_explanation of the query answer in Yaml format
        :param dict generated_content: already generated yaml from fields of the query answer other than
        output_explanation
        :param OutputExplanation explanation: the output_explanation of the query answer
        :return: the yaml output of the query with its output explanation
        :rtype: str
        """
        explanation_result_1,  explanation_result_2 = explanation.get_explanation_in_yaml()
        output_content_1 = generated_content.copy()
        output_content_1.update({'explanation': explanation_result_1})
        res1 = self.dump_content(output_content_1)
        if explanation_result_2:  # two parallel yaml objects when connections differ in the configs
            output_content_2 = generated_content.copy()
            output_content_2.update({'explanation': explanation_result_2})
            res2 = self.dump_content(output_content_2)
            return res1 + res2
        return res1

    @staticmethod
    def dump_content(output_content):
        return yaml.dump(output_content, None, default_flow_style=False, sort_keys=False) + '---\n'


class TxtOutputHandler:
    """
    A class to form the query output in Txt format
    """

    @staticmethod
    def compute_query_output(query_answer, _):
        """
        computes the query output in Txt format
        :param QueryAnswer query_answer: the query answer - the result of the running query
        :param Any _ : for compatibility call of this def
        :return txt format of the query answer
        :rtype: str
        """
        query_output = query_answer.output_result + '\n'
        if query_answer.output_explanation:
            query_output += query_answer.output_explanation.get_explanation_in_txt()
        return query_output
