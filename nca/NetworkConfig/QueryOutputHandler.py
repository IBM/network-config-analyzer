#
# Copyright 2020- IBM Inc. All rights reserved
# SPDX-License-Identifier: Apache2.0
#
from __future__ import annotations
from dataclasses import dataclass, field
import yaml

from nca.CoreDS.ConnectionSet import ConnectionSet


# following classes describe the more possible OutputExplanation patterns, each class consists of the explanation
# fields that may appear together in one output_explanation and additional info for writing the explanation if required
@dataclass
class PoliciesWithCommonPods:
    """
    A class for holding information of pairs of policies with common pods
    """
    first_policy_type: str = ''  # the type of the first policy
    first_policy_name: str = ''  # the name of the first policy
    second_policy_type: str = ''  # the type of the second policy
    second_policy_name: str = ''  # the name of the second policy
    common_pods: list[str] = field(default_factory=list)

    def __lt__(self, other):
        if self.first_policy_type == other.first_policy_type:
            if self.first_policy_name == other.first_policy_name:
                return self.second_policy_name < other.second_policy_name
            return self.first_policy_name < other.first_policy_name
        return self.first_policy_type < other.first_policy_type


@dataclass
class IntersectPodsExplanation:
    # used in DisjointnessQuery
    policies_pods: list[PoliciesWithCommonPods] = field(default_factory=list)  # used in DisjointnessQuery

    def get_explanation_in_dict(self, explanation_description):
        """
        returns self type of OutputExplanation written in dict of description and policies_pods examples
        :param explanation_description: the relevant description of this output explanation
        :rtype: list[dict]
        """
        examples = []
        for record in self.policies_pods:
            examples.append({'policies': [record.first_policy_name, record.second_policy_name],
                             'pods': record.common_pods})
        return [{'description': explanation_description, 'examples': examples}]

    def get_explanation_in_str(self, explanation_description):
        """
        returns self type of OutputExplanation written as str
        :param explanation_description: the relevant description of this output explanation
        :rtype: str
        """
        result = []
        comma = ', '  # used for writing the list of pods joined by comma inline
        for record in self.policies_pods:
            result.append(f'{record.first_policy_type}_1: {record.first_policy_name}, '
                          f'{record.second_policy_type}_2: {record.second_policy_name},'
                          f' pods: {comma.join(record.common_pods)}')
        return explanation_description + ':\n' + '\n'.join(result)


@dataclass
class PoliciesAndRulesExplanations:
    # used in RedundancyQuery and EmptinessQuery: we may have lists of redundant/empty policies or
    # maps of policies to redundant/empty ingress/egress rules indexes
    policies_list: list[str] = field(default_factory=list)  # policy titles list, i.e. each element's form is:
    # <policy_type> <policy_full_name>
    policies_to_ingress_rules_dict: dict[str, list[int]] = field(default_factory=dict)
    policies_to_egress_rules_dict: dict[str, list[int]] = field(default_factory=dict)

    @staticmethod
    def _get_policies_description(explanation_description):
        return 'Policies' + explanation_description

    @staticmethod
    def _get_xgress_description(explanation_description, prefix='Ingress'):
        return prefix + ' rules' + explanation_description

    @staticmethod
    def _add_rules_to_dict_explanation(xgress_description, xgress_rules_dict, prefix='ingress'):
        """
        returns dict object of policies to ingress/egress rules and its description
        :param str xgress_description: the relevant description of this oof the given rules' dict
        :param str prefix: indicates if rules types are ingress or egress
        :return dict of description and pairs of policy and rules indexes
        :rtype dict
        """
        rules = []
        for key, value in xgress_rules_dict.items():
            rules.append({'policy': key.split()[1], prefix + '_rules_indexes': [str(idx) for idx in value]})
        return {'description': xgress_description, 'pairs': rules}

    def get_explanation_in_dict(self, explanation_description):
        """
        returns self type of OutputExplanation arranged in dict/s objects
        a dict for each item in self with its relevant description
        :param explanation_description: the relevant description of this output explanation
        :rtype: list[dict]
        """
        result = []
        if self.policies_list:
            result.append({'description': self._get_policies_description(explanation_description),
                           'policies': [policy.split()[1] for policy in self.policies_list]})
        if self.policies_to_ingress_rules_dict:
            ingress_description = self._get_xgress_description(explanation_description)
            result.append(self._add_rules_to_dict_explanation(ingress_description, self.policies_to_ingress_rules_dict))
        if self.policies_to_egress_rules_dict:
            egress_description = self._get_xgress_description(explanation_description, prefix='Egress')
            result.append(self._add_rules_to_dict_explanation(egress_description, self.policies_to_egress_rules_dict,
                                                              'egress'))
        return result

    @staticmethod
    def _add_rules_to_str_explanation(xgress_description, xgress_rules_dict, prefix='ingress'):
        """
        return str format of policies to ingress/egress rules and its description
        :param str xgress_description: the relevant description of the given rules' dict
        :param dict xgress_rules_dict: a dict of policies to matching rules indexes
        :param str prefix: indicates if rules types are ingress or egress
        :return the str form of the explanation dict
        :rtype: str
        """
        res = '\n' + xgress_description + ':\n'
        for key, value in xgress_rules_dict.items():
            res += key + ', ' + prefix + ' rules indexes: ' + ', '.join(str(idx) for idx in value) + '\n'
        return res

    def get_explanation_in_str(self, explanation_description):
        """
        returns self type of OutputExplanation written in str form
        :param explanation_description: the relevant description of this output explanation
        :rtype: str
        """
        result = ''
        if self.policies_list:
            result += self._get_policies_description(explanation_description) + ':\n' +\
                      ', '.join(self.policies_list) + '\n'
        if self.policies_to_ingress_rules_dict:
            ingress_description = self._get_xgress_description(explanation_description)
            result += self._add_rules_to_str_explanation(ingress_description, self.policies_to_ingress_rules_dict)
        if self.policies_to_egress_rules_dict:
            egress_description = self._get_xgress_description(explanation_description, prefix='Egress')
            result += self._add_rules_to_str_explanation(egress_description, self.policies_to_egress_rules_dict,
                                                         'egress')
        return result


@dataclass
class PodsListsExplanations:
    # 2 use cases:
    # 1. used in ContainmentQuery (and queries using it such as TwoWayContainmentQuery and PermitsQuery)
    # when a reason that config is not contained in the other is, pods list that appears only in one
    # 2. used in AllCapturedQuery - lists of pods that are not captured for ingress and/or egress
    pods_list: list[str] = field(default_factory=list)
    egress_pods_list: list[str] = field(default_factory=list)
    add_xgress_suffix: bool = False

    @staticmethod
    def _get_xgress_description(explanation_description, suffix='ingress'):
        return explanation_description + suffix

    @staticmethod
    def _add_pods_list_to_dict_explanation(description, pods_list):
        return {'description': description, 'pods': pods_list}

    def get_explanation_in_dict(self, explanation_description):
        """
        returns self type of OutputExplanation arranged in dict/s forms
        a dict for each pods_list in self with its relevant description
        :param explanation_description: the relevant description of this output explanation
        :rtype: list[dict]
        """
        if not self.add_xgress_suffix:
            return list(self._add_pods_list_to_dict_explanation(explanation_description, self.pods_list))
        result = []
        if self.pods_list:
            result.append(self._add_pods_list_to_dict_explanation(self._get_xgress_description(explanation_description),
                                                                  self.pods_list))
        if self.egress_pods_list:
            result.append(self._add_pods_list_to_dict_explanation(self._get_xgress_description(explanation_description,
                                                                                               'egress'),
                                                                  self.egress_pods_list))
        return result

    @staticmethod
    def _add_pods_list_to_str_explanation(description, pods_list):
        return '\n' + description + ':\n' + ', '.join(pods_list) + '\n'

    def get_explanation_in_str(self, explanation_description):
        """
        returns self type of OutputExplanation written in str
        :param explanation_description: the relevant description of this output explanation
        :rtype: str
        """
        if not self.add_xgress_suffix:
            return self._add_pods_list_to_str_explanation(explanation_description, self.pods_list)
        result = ''
        if self.pods_list:
            result += self._add_pods_list_to_str_explanation(self._get_xgress_description(explanation_description),
                                                             self.pods_list)
        if self.egress_pods_list:
            result += self._add_pods_list_to_str_explanation(self._get_xgress_description(explanation_description,
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
    conns1: ConnectionSet = field(default_factory=ConnectionSet)  # connections from src to dst in first config
    conns2: ConnectionSet = field(default_factory=ConnectionSet)  # connections from src to dst in second config

    def __lt__(self, other):
        if self.src_peer == other.src_peer:
            return self.dst_peer < other.dst_peer
        return self.src_peer < other.src_peer


@dataclass
class ConnectionsDiffExplanation:
    # used in following TwoNetworkConfigs queries that compare connections of pairs of peers in both configs:
    # EquivalenceQuery, StrongEquivalenceQuery, ContainmentQuery, TwoWayContainmentQuery, PermitsQuery, InterferesQuery,
    # PairwiseInterferesQuery, and ForbidsQuery
    peers_diff_connections_list: list[PeersAndConnections] = field(default_factory=list)
    configs: list[str] = field(default_factory=list)  # configs names are relevant only when we have the
    # conns1 and conns2 in
    # PeersAndConnections items , so we need them when calling ConnectionSet.print_diff in get_explanation_in_str
    conns_diff: bool = False

    def get_explanation_in_dict(self, explanation_description):
        """
         returns the explanation results of ConnectionsDiffExplanation and its description arranged in dict.
        if self.conns_diff is True, i.e. PeersAndConnections items contain two connections, then for each
        (src, dst) pair , connections from both configs will be presented to emphasize the differences
        :param str explanation_description: the relevant description of this output explanation
        :rtype list[dict]
        """
        conns_lists = []
        for peers_conn in self.peers_diff_connections_list:
            example_dict = {'src': peers_conn.src_peer, 'dst': peers_conn.dst_peer}
            if self.conns_diff:
                example_dict.update({'conns_config1': str(peers_conn.conns1), 'conns_config2': str(peers_conn.conns2)})
            else:
                example_dict.update({'conn': str(peers_conn.conns1)})
            conns_lists.append(example_dict)

        return [{'description': explanation_description, 'connections': conns_lists}]

    def get_explanation_in_str(self, explanation_description):
        """
        returns the explanation result of ConnectionsDiffExplanation and its description in str.
        When self.conns_diff is True, i.e. having conns1 and conns2 in PeersAndConnections items, the diff between
        connection of each pair is printed
        otherwise (having only conns1, connections from first config is printed)
        :param str explanation_description: the relevant description of this output explanation
        :rtype str
        """
        conns = []
        for peers_conn in self.peers_diff_connections_list:
            if self.conns_diff:
                conns.append(f'src: {peers_conn.src_peer}, dst: {peers_conn.dst_peer}, description: '
                             f'{peers_conn.conns1.print_diff(peers_conn.conns2, self.configs[0], self.configs[1])}')
            else:
                conns.append(f'src: {peers_conn.src_peer}, dst: {peers_conn.dst_peer}, conn: {peers_conn.conns1}')

        return explanation_description + ':\n' + '\n'.join(conns) + '\n'


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
    str_explanation: str = None  # for queries that compute separately the output in the required format
    # (i.e. ConnectivityMapQuery, SanityQuery and SemanticDiffQuery)

    def get_explanation_in_str(self):
        """
        computes and returns the output explanation is str, so it may be used to write the query answer in txt format.
        An OutputExplanation object may have only one field representing the explanation data besides to
         explanation_description, so the output is computed by calling the get_explanation_in_str method of this field
         :return the explanation written with its description in txt format
         :rtype: str
        """
        for val in self.__dict__.values():
            if not isinstance(val, str) and val is not None:
                return val.get_explanation_in_str(self.explanation_description)

    def get_explanation_in_dict(self):
        """
        computes and returns the output explanation arranged in dict/s, so it may be used for writing the query answer
        in specific formats like json and yaml.
        Each OutputExplanation object may have only one field representing the explanation data besides to
        explanation_description, so the output is computed by calling the get_explanation_in_dict method of this field
        :return the explanation written with its description in a list of dict objects pattern which matches yaml/json
        dump later.
        A single dict pattern is {'description' : <explanation_description_str> ,
        <key_name>: <list of examples matching the result> }
         :rtype: list[dict]
        """
        for val in self.__dict__.values():
            if not isinstance(val, str) and val is not None:
                return val.get_explanation_in_dict(self.explanation_description)


@dataclass
class QueryAnswer:
    """
    A class for holding the answer to any one of the NetworkConfigQuery.py queries
    """
    bool_result: bool = False
    output_result: str = ''
    output_explanation: list[OutputExplanation] = field(default_factory=list)
    numerical_result: int = 0
    query_not_executed: bool = False


class YamlOutputHandler:
    """
    A class to form the query output in Yaml format
    """
    def __init__(self, configs, query_name):
        self.configs_names = configs
        self.query_name = query_name

    def compute_query_output(self, query_answer):
        """
        computes the query output in Yaml format
        :param QueryAnswer query_answer: the query answer - the result of the running query
        :return yaml format of the query answer
        :rtype: str
        """
        output_content = {'query': self.query_name, 'configs': self.configs_names}
        if query_answer.query_not_executed:
            output_content.update({'executed': 0, 'description': query_answer.output_result})
            return self.dump_content(output_content)
        output_content.update({'numerical_result': int(query_answer.numerical_result)})
        output_content.update({'textual_result': query_answer.output_result})
        explanation_result = []
        if query_answer.output_explanation:
            for explanation in query_answer.output_explanation:
                explanation_result += explanation.get_explanation_in_dict()
            output_content.update({'explanation': explanation_result})
        return self.dump_content(output_content)

    @staticmethod
    def dump_content(output_content):
        return yaml.dump(output_content, None, default_flow_style=False, sort_keys=False) + '---\n'


class TxtOutputHandler:
    """
    A class to form the query output in Txt format
    """

    @staticmethod
    def compute_query_output(query_answer):
        """
        computes the query output in Txt format
        :param QueryAnswer query_answer: the query answer - the result of the running query
        :return txt format of the query answer
        :rtype: str
        """
        query_output = query_answer.output_result + '\n'
        if query_answer.output_explanation:
            for explanation in query_answer.output_explanation:
                query_output += explanation.get_explanation_in_str()
        return query_output
