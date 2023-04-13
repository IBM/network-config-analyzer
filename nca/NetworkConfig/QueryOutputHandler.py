#
# Copyright 2020- IBM Inc. All rights reserved
# SPDX-License-Identifier: Apache2.0
#
from abc import abstractmethod
from dataclasses import dataclass, field

from nca.CoreDS.ConnectionSet import ConnectionSet


@dataclass
class OutputExplanation:
    """
    A base class of possible types of the QueryAnswer's output_explanation as it may vary according to
    the pattern of the query's result.
    common field is the explanation_description: the relevant description of current output explanation
    """
    explanation_description: str = ''

    @abstractmethod
    def get_explanation_in_str(self):
        """
        computes and returns the output explanation is str, so it may be used to write the query answer in txt format
         :return the explanation written with its description in txt format
         :rtype: str
        """
        raise NotImplementedError

    @abstractmethod
    def get_explanation_in_dict(self):
        """
        computes and returns the output explanation arranged in dict/s, so it may be used for writing the query answer
        in specific formats like json and yaml
        :return the explanation written with its description in a list of dict objects pattern which matches yaml/json
        dump later.
        A single dict pattern is {'description' : <explanation_description_str> ,
        <key_name>: <list of examples matching the result> }
         :rtype: list[dict]
        """
        raise NotImplementedError


# following classes describe possible OutputExplanation patterns (derived from it), each class consists of the
# explanation fields that may appear together in one output_explanation and additional info for writing
# the explanation if required
# PoliciesWithCommonPods and PeersAndConnections classes are helping classes for storing info on some OutputExplanation
@dataclass
class PoliciesWithCommonPods:
    """
    A class for holding information of pairs of policies with common pods
    """
    first_policy_type: str = ''  # the type of the first policy
    first_policy_name: str = ''  # the name of the first policy
    second_policy_type: str = ''  # the type of the second policy
    second_policy_name: str = ''  # the name of the second policy
    common_pods: list = field(default_factory=list)  # list[str] : list of pods names

    def __lt__(self, other):
        if self.first_policy_type == other.first_policy_type:
            if self.first_policy_name == other.first_policy_name:
                return self.second_policy_name < other.second_policy_name
            return self.first_policy_name < other.first_policy_name
        return self.first_policy_type < other.first_policy_type


@dataclass
class IntersectPodsExplanation(OutputExplanation):
    # used in DisjointnessQuery
    policies_pods: list = field(default_factory=list)  # list of PoliciesWithCommonPods objects
    # (storing data on pairs of policies with common pods)

    def get_explanation_in_dict(self):
        """
        returns self type of OutputExplanation written in dict of description and policies_pods examples
        :rtype: list[dict]
        """
        examples = []
        for record in self.policies_pods:
            examples.append({'policies': [record.first_policy_name, record.second_policy_name],
                             'pods': record.common_pods})
        return [{'description': self.explanation_description, 'examples': examples}]

    def get_explanation_in_str(self):
        """
        returns self type of OutputExplanation written as str
        :rtype: str
        """
        result = []
        comma = ', '  # used for writing the list of pods joined by comma inline
        for record in self.policies_pods:
            result.append(f'{record.first_policy_type}_1: {record.first_policy_name}, '
                          f'{record.second_policy_type}_2: {record.second_policy_name},'
                          f' pods: {comma.join(record.common_pods)}')
        return self.explanation_description + ':\n' + '\n'.join(result)


@dataclass
class PoliciesAndRulesExplanations(OutputExplanation):
    # used in RedundancyQuery and EmptinessQuery: we may have lists of redundant/empty policies or
    # maps of policies to redundant/empty ingress/egress rules indexes
    policies_list: list = field(default_factory=list)  # policy titles list, i.e. each element's str form is:
    # <policy_type> <policy_full_name>
    policies_to_ingress_rules_dict: dict = field(default_factory=dict)  # dict[str, list[int]] :
    # elements pattern: {<policy_tite>, <ingress_rules_indexes>}
    policies_to_egress_rules_dict: dict = field(default_factory=dict)  # dict[str, list[int]] :
    # elements pattern: {<policy_tite>, <egress_rules_indexes>}

    def _get_policies_description(self):
        return 'Policies' + self.explanation_description

    def _get_xgress_description(self, prefix='ingress'):
        return prefix.capitalize() + ' rules' + self.explanation_description

    @staticmethod
    def _get_policy_name_from_title(policy_title):
        """
        extracts the policy name from it title
        :param str policy_title: a policy title in pattern <policy_type> <policy_full_name>
        :return the <policy_full_name> part from policy_title
        :rtype: str
        """
        return policy_title.split()[1]

    def _add_rules_to_dict_explanation(self, xgress_rules_dict, prefix='ingress'):
        """
        returns dict object of policies to ingress/egress rules and its description
        :param str prefix: indicates if rules types are ingress or egress
        :return dict of description and pairs of policy and rules indexes
        :rtype dict
        """
        rules = []
        for policy_title, rules_indexes_list in xgress_rules_dict.items():
            rules.append({'policy': self._get_policy_name_from_title(policy_title),
                          prefix + '_rules_indexes': [str(idx) for idx in rules_indexes_list]})
        return {'description': self._get_xgress_description(prefix), 'pairs': rules}

    def get_explanation_in_dict(self):
        """
        returns self type of OutputExplanation arranged in dict/s objects
        a dict for each item in self with its relevant description
        :rtype: list[dict]
        """
        result = []
        if self.policies_list:
            result.append({'description': self._get_policies_description(),
                           'policies': [self._get_policy_name_from_title(policy) for policy in self.policies_list]})
        if self.policies_to_ingress_rules_dict:
            result.append(self._add_rules_to_dict_explanation(self.policies_to_ingress_rules_dict))
        if self.policies_to_egress_rules_dict:
            result.append(self._add_rules_to_dict_explanation(self.policies_to_egress_rules_dict, 'egress'))
        return result

    def _add_rules_to_str_explanation(self, xgress_rules_dict, prefix='ingress'):
        """
        return str format of policies to ingress/egress rules and its description
        :param dict xgress_rules_dict: a dict of policies to matching rules indexes
        :param str prefix: indicates if rules types are ingress or egress
        :return the str form of the explanation dict
        :rtype: str
        """
        res = '\n' + self._get_xgress_description(prefix) + ':\n'
        for policy_title, rules_indexes_list in xgress_rules_dict.items():
            res += policy_title + ', ' + prefix + ' rules indexes: ' +\
                ', '.join(str(idx) for idx in rules_indexes_list) + '\n'
        return res

    def get_explanation_in_str(self):
        """
        returns self type of OutputExplanation written in str form
        :rtype: str
        """
        result = ''
        if self.policies_list:
            result += self._get_policies_description() + ':\n' +\
                ', '.join(self.policies_list) + '\n'
        if self.policies_to_ingress_rules_dict:
            result += self._add_rules_to_str_explanation(self.policies_to_ingress_rules_dict)
        if self.policies_to_egress_rules_dict:
            result += self._add_rules_to_str_explanation(self.policies_to_egress_rules_dict, 'egress')
        return result


@dataclass
class PodsListsExplanations(OutputExplanation):
    # 2 use cases:
    # 1. used in ContainmentQuery (and queries using it such as TwoWayContainmentQuery and PermitsQuery)
    # when a reason that config is not contained in the other is, pods list that appears only in one
    # 2. used in AllCapturedQuery - lists of pods that are not captured for ingress and/or egress
    pods_list: list = field(default_factory=list)  # list[str]: pods names list
    egress_pods_list: list = field(default_factory=list)  # list[str]: pods names list
    add_xgress_suffix: bool = False

    def _get_list_description(self, suffix):
        return self.explanation_description + suffix

    def _add_pods_list_to_dict_explanation(self, pods_list, suffix=''):
        return {'description': self._get_list_description(suffix), 'pods': pods_list}

    def get_explanation_in_dict(self):
        """
        returns self type of OutputExplanation arranged in dict/s forms
        a dict for each pods_list in self with its relevant description
        :rtype: list[dict]
        """
        if not self.add_xgress_suffix:
            return list(self._add_pods_list_to_dict_explanation(self.pods_list))
        result = []
        if self.pods_list:
            result.append(self._add_pods_list_to_dict_explanation(self.pods_list, 'ingress'))
        if self.egress_pods_list:
            result.append(self._add_pods_list_to_dict_explanation(self.egress_pods_list, 'egress'))
        return result

    def _add_pods_list_to_str_explanation(self, pods_list, suffix=''):
        return '\n' + self._get_list_description(suffix) + ':\n' + ', '.join(pods_list) + '\n'

    def get_explanation_in_str(self):
        """
        returns self type of OutputExplanation written in str
        :rtype: str
        """
        if not self.add_xgress_suffix:
            return self._add_pods_list_to_str_explanation(self.pods_list)
        result = ''
        if self.pods_list:
            result += self._add_pods_list_to_str_explanation(self.pods_list, 'ingress')
        if self.egress_pods_list:
            result += self._add_pods_list_to_str_explanation(self.egress_pods_list, 'egress')
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
class ConnectionsDiffExplanation(OutputExplanation):
    # used in following TwoNetworkConfigs queries that compare connections of pairs of peers in both configs:
    # EquivalenceQuery, StrongEquivalenceQuery, ContainmentQuery, TwoWayContainmentQuery, PermitsQuery, InterferesQuery,
    # PairwiseInterferesQuery, and ForbidsQuery
    peers_diff_connections_list: list = field(default_factory=list)  # list of PeersAndConnections objects,
    # storing info of pairs of peers and their connection in the config/s
    configs: list = field(default_factory=list)  # list[str]: configs names, relevant only when we have the
    # conns1 and conns2 in PeersAndConnections items , so we need them when calling ConnectionSet.print_diff
    # in get_explanation_in_str
    conns_diff: bool = False

    def get_explanation_in_dict(self):
        """
         returns the explanation results of ConnectionsDiffExplanation and its description arranged in dict.
        if self.conns_diff is True, i.e. PeersAndConnections items contain two connections, then for each
        (src, dst) pair , connections from both configs will be presented to emphasize the differences
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

        return [{'description': self.explanation_description, 'connections': conns_lists}]

    def get_explanation_in_str(self):
        """
        returns the explanation result of ConnectionsDiffExplanation and its description in str.
        When self.conns_diff is True, i.e. having conns1 and conns2 in PeersAndConnections items, the diff between
        connection of each pair is printed
        otherwise (having only conns1, connections from first config is printed)
        :rtype str
        """
        conns = []
        for peers_conn in self.peers_diff_connections_list:
            if self.conns_diff:
                conns.append(f'src: {peers_conn.src_peer}, dst: {peers_conn.dst_peer}, description: '
                             f'{peers_conn.conns1.print_diff(peers_conn.conns2, self.configs[0], self.configs[1])}')
            else:
                conns.append(f'src: {peers_conn.src_peer}, dst: {peers_conn.dst_peer}, conn: {peers_conn.conns1}')

        return self.explanation_description + ':\n' + '\n'.join(conns) + '\n'


@dataclass
class ComputedExplanation(OutputExplanation):
    # Used in queries that computes the output in the required form while execution, so we need to add it as is
    # Used in ConnectivityMapQuery, SanityQuery and SemanticDiffQuery
    str_explanation: str = None
    dict_explanation: dict = field(default_factory=dict)  # dict of description and rules list {str:list}

    def get_explanation_in_str(self):
        return self.str_explanation

    def get_explanation_in_dict(self):
        return [self.dict_explanation]


@dataclass
class QueryAnswer:
    """
    A class for holding the answer to any one of the NetworkConfigQuery.py queries
    """
    bool_result: bool = False
    output_result: str = ''
    output_explanation: list = field(default_factory=list)  # list of OutputExplanation objects
    numerical_result: int = 0
    query_not_executed: bool = False


class DictOutputHandler:
    """
    A class to form the query output in a dict to be dumped into a data serialization language format e.g. yaml / json
    """
    def __init__(self, configs, query_name):
        self.configs_names = configs
        self.query_name = query_name

    def compute_query_output(self, query_answer):
        """
        arranges the query output in dict to be dumped later in the relevant output format (json/yaml)
        :param QueryAnswer query_answer: the query answer - the result of the running query
        :return  query results in dict
        :rtype: dict
        """
        output_content = {'query': self.query_name, 'configs': self.configs_names}
        if query_answer.query_not_executed:
            output_content.update({'executed': 0, 'description': query_answer.output_result})
            return output_content
        output_content.update({'numerical_result': int(query_answer.numerical_result)})
        if query_answer.output_result:
            output_content.update({'textual_result': query_answer.output_result})
        explanation_result = []
        if query_answer.output_explanation:
            for explanation in query_answer.output_explanation:
                explanation_result += explanation.get_explanation_in_dict()
            output_content.update({'explanation': explanation_result})
        return output_content


class StringOutputHandler:
    """
    A class to form the query output in txt , csv, md or dot format (from a string explanation)
    """
    def __init__(self, is_txt_format):
        # the query_answer.output_result message is added to the query output only if required format is txt
        self.add_output_result = is_txt_format

    def compute_query_output(self, query_answer):
        """
        computes the query output in string form
        :param QueryAnswer query_answer: the query answer - the result of the running query
        :return string format of the query answer
        :rtype: str
        """
        query_output = ''
        if self.add_output_result and query_answer.output_result:
            query_output += query_answer.output_result + '\n'
        if query_answer.output_explanation:
            for explanation in query_answer.output_explanation:
                query_output += explanation.get_explanation_in_str()
        return query_output
