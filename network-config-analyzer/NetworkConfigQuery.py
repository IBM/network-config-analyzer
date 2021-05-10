#
# Copyright 2020- IBM Inc. All rights reserved
# SPDX-License-Identifier: Apache2.0
#

from dataclasses import dataclass
import itertools
from NetworkConfig import NetworkConfig
from NetworkPolicy import NetworkPolicy
from ConnectionSet import ConnectionSet
from Peer import PeerSet, IpBlock


@dataclass
class QueryAnswer:
    """
    A class for holding the answer to any one of the below queries
    """
    bool_result: bool = False
    output_result: str = ''
    output_explanation: str = ''
    numerical_result: int = 0


class NetworkConfigQuery:
    """
    A base class for queries that inspect only a single network config
    """
    def __init__(self, config):
        """
        :param NetworkConfig config: The config to query
        """
        self.config = config


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
                           full_explanation, res)


class VacuityQuery(NetworkConfigQuery):
    """
    Check if the set of policies changes the cluster's default behavior
    """
    def exec(self):
        vacuous_config = self.config.clone_without_policies('vacuousConfig')
        vacuous_res = SemanticEquivalenceQuery(self.config, vacuous_config).exec()
        if not vacuous_res.bool_result:
            return QueryAnswer(vacuous_res.bool_result,
                               output_result=f'Network configuration {self.config.name} is not vacuous')

        if self.config.type == NetworkConfig.ConfigType.Calico:
            output_result = f'Network configuration {self.config.name} is vacuous - only the default connections,' \
                            f' as defined by profiles, are allowed '
        else:
            output_result = f'Network configuration {self.config.name} is vacuous - it allows all connections'
        return QueryAnswer(bool_result=vacuous_res.bool_result, output_result=output_result)


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
                if SemanticEquivalenceQuery(self.config, config_without_policy).exec().bool_result:
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
            equiv_result = SemanticEquivalenceQuery(self.config, config_with_modified_policy).exec()
            if equiv_result.bool_result:
                redundancy = f'Ingress rule no. {rule_index} in NetworkPolicy {policy.full_name()} is redundant '\
                             f'in {self.config.name}'
                redundancies.append(redundancy)
                redundant_ingress_rules.append(rule_index)
        for rule_index, egress_rule in enumerate(policy.egress_rules, start=1):
            modified_policy = policy.clone_without_rule(egress_rule, False)
            if len(modified_policy.egress_rules) < len(policy.egress_rules) - 1:
                redundancy = f'Egress rule no. {rule_index} in NetworkPolicy {policy.full_name()} is redundant '\
                             f'in {self.config.name}'
                redundancies.append(redundancy)
                redundant_egress_rules.append(rule_index)
                continue
            config_with_modified_policy = self.config.clone_without_policy(policy)
            config_with_modified_policy.add_policy(modified_policy)
            if SemanticEquivalenceQuery(self.config, config_with_modified_policy).exec().bool_result:
                redundancy = f'Egress rule no. {rule_index} in NetworkPolicy {policy.full_name()} is redundant '\
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
            _, _,  rules_redundancy_explanation = \
                self.find_redundant_rules(policy)
            res += len(rules_redundancy_explanation)
            redundancies += rules_redundancy_explanation

        if res > 0:
            output_explanation = '\n'.join(redundancies)
            return QueryAnswer(True, 'Redundancies found in ' + self.config.name, output_explanation, res)
        return QueryAnswer(False, 'No redundancy found in ' + self.config.name)


class SanityQuery(NetworkConfigQuery):
    """
    Perform various queries to check the network config sanity. Checks vacuity, redundancy and emptiness
    """
    def has_conflicting_policies_with_same_order(self):
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
        only_captured = (self.config.type == NetworkConfig.ConfigType.K8s)
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
                return None  # not checking lower priority
            if not other_policy.has_deny_rules():
                continue
            config_with_other_policy = self.config.clone_with_just_one_policy(other_policy.full_name())
            pods_to_compare = self.config.peer_container.get_all_peers_group()
            pods_to_compare |= TwoNetworkConfigsQuery(self.config, config_with_other_policy).disjoint_ip_blocks()
            for pod1 in pods_to_compare:
                for pod2 in pods_to_compare:
                    if isinstance(pod1, IpBlock) and isinstance(pod2, IpBlock):
                        continue
                    if pod1 == pod2:
                        continue  # no way to prevent a pod from communicating with itself
                    _, _, self_deny_conns = config_with_self_policy.allowed_connections(pod1, pod2)
                    _, _, other_deny_conns = config_with_other_policy.allowed_connections(pod1, pod2)
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

    def exec(self):
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
                rules_issues += '\n'.join(empty_rules_explanation)+'\n'
                policy.findings += empty_rules_explanation

            if is_config_vacuous_res.bool_result:
                continue

            if policy.full_name() in redundant_policies:
                issues_counter += 1
                redundancy_full_text = self.redundant_policy_text(policy)
                policies_issue += redundancy_full_text
                policy.add_finding(redundancy_full_text)
                continue

            redundant_ingress_rules, redundant_egress_rules,  _ = \
                RedundancyQuery(self.config).find_redundant_rules(policy)
            for rule_index in range(1, len(policy.ingress_rules)+1):
                if rule_index in empty_ingress_rules_list:
                    continue
                if rule_index in redundant_ingress_rules:
                    issues_counter += 1
                    redundancy_text = self.redundant_rule_text(policy, rule_index, True)
                    rules_issues += redundancy_text
                    policy.add_finding(redundancy_text)
            for rule_index in range(1, len(policy.egress_rules)+1):
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


class TwoNetworkConfigsQuery:
    """
    A base class for queries that inspect two network configs
    """
    def __init__(self, config1, config2):
        """
        :param NetworkConfig config1: First config to query
        :param NetworkConfig config2: Second config to query
        """
        self.config1 = config1
        self.config2 = config2
        self.name1 = config1.name
        self.name2 = config2.name

    def is_identical_topologies(self, check_same_policies=False):
        if self.config1.peer_container != self.config2.peer_container:
            return QueryAnswer(False, 'The two NetworkPolicy sets are not defined over the same set of endpoints, '
                                      'and are thus not comparable.')
        if check_same_policies and self.config1.policies == self.config2.policies and \
                self.config1.profiles == self.config2.profiles:
            return QueryAnswer(True, f'{self.name1} and {self.name2} have exactly the same set of policies')
        return QueryAnswer(True)

    @staticmethod
    def add_interval_to_list(interval, non_overlapping_interval_list):
        """
        Adding an interval to the list of non-overlapping blocks while maintaining the invariants
        :param IpBlock interval: The interval to add
        :param list[IpBlock] non_overlapping_interval_list: The existing list the interval should be added to
        :return: None
        """
        to_add = []
        for idx, ip_block in enumerate(non_overlapping_interval_list):
            if not ip_block.overlaps(interval):
                continue
            intersection = ip_block & interval
            interval -= intersection
            if ip_block != intersection:
                to_add.append(intersection)
                non_overlapping_interval_list[idx] -= intersection
            if not interval:
                break

        non_overlapping_interval_list += interval.split()
        non_overlapping_interval_list += to_add

    def disjoint_ip_blocks(self):
        """
        Takes all (atomic) ip-ranges in the policies of both configs and returns a new set of ip-ranges where
        each ip-range is:
        1. a subset of an ip-range in either config AND
        2. cannot be partially intersected by an ip-range in either config AND
        3. is maximal (extending the range to either side will violate either 1 or 2)
        :return: A set of ip ranges as specified above
        :rtype: PeerSet
        """
        ip_blocks_set = self.config1.get_referenced_ip_blocks()
        ip_blocks_set |= self.config2.get_referenced_ip_blocks()
        ip_blocks = sorted(ip_blocks_set, key=IpBlock.ip_count)

        # making sure the resulting list does not contain overlapping ipBlocks
        blocks_with_no_overlap = []
        for interval in ip_blocks:
            self.add_interval_to_list(interval, blocks_with_no_overlap)

        res = PeerSet()
        for ip_block in blocks_with_no_overlap:
            res.add(ip_block)

        if not res:
            res.add(IpBlock.get_all_ips_block())

        return res


class SemanticEquivalenceQuery(TwoNetworkConfigsQuery):
    """
    Check whether config1 and config2 allow exactly the same set of connections.
    """
    def exec(self):
        query_answer = self.is_identical_topologies(True)
        if query_answer.output_result:
            return query_answer

        peers_to_compare = self.config1.peer_container.get_all_peers_group()
        peers_to_compare |= self.disjoint_ip_blocks()
        captured_pods = self.config1.get_captured_pods() | self.config2.get_captured_pods()
        for peer1 in peers_to_compare:
            for peer2 in peers_to_compare if peer1 in captured_pods else captured_pods:
                if peer1 == peer2:
                    continue
                _, conns1, _ = self.config1.allowed_connections(peer1, peer2)
                _, conns2, _ = self.config2.allowed_connections(peer1, peer2)
                if conns1 != conns2:
                    explanation = f'Allowed connections from {peer1} to {peer2} are different\n' +\
                                  conns1.print_diff(conns2, self.name1, self.name2)
                    return QueryAnswer(False, self.name1 + ' and ' + self.name2 + ' are not semantically equivalent.',
                                       explanation)
        return QueryAnswer(True, self.name1 + ' and ' + self.name2 + ' are semantically equivalent.')


class SemanticDiffQuery(TwoNetworkConfigsQuery):
    """
    Produces a report of changed connections (also for the case of two configurations of different network topologies):
    1. lost connections between removed peers
    2. lost connections between removed peers and intersected peers
    3. lost/new connections between intersected peers (due to changes in policies and labels of pods/namespaces)
    4. new connections between intersected peers and added peers
    5. new connections between added peers
    """
    class SingleDiff:
        """
        Representing a single diff between a pair of eps
        """
        def __init__(self, from_ep, to_ep, removed, added):
            self.from_ep = from_ep
            self.to_ep = to_ep
            self.removed = removed
            self.added = added

        def __str__(self):
            res = "\n" + str(self.from_ep) + " -> " + str(self.to_ep) + ":\n"
            res += "\tRemoved: " + str(self.removed) + "\n"
            res += "\tAdded: " + str(self.added)
            return res

    @staticmethod
    def pretty_print_diff(diff_list):
        """
        pretty printing the results of semantic diff
        :param diff_list:
        :return:
        """
        result = ""
        for single in diff_list:
            if diff_list[single]:
                result += "- " + single + str(diff_list[single]) + "\n"
                result = result.replace('{', ' ').replace('}', ' ').replace('\'', '')
        return result

    def compute_diff(self):
        all_diff = {}
        #  TODO: is the line below required?
        # peers_to_compare |= self.disjoint_ip_blocks()
        old_peers = self.config1.peer_container.get_all_peers_group()
        new_peers = self.config2.peer_container.get_all_peers_group()
        intersected_peers = old_peers & new_peers
        removed_peers = old_peers - intersected_peers
        added_peers = new_peers - intersected_peers

        key = 'Lost connections between removed peers'
        all_diff[key] = []
        for pair in itertools.permutations(removed_peers, 2):
            _, lost_conns, _ = self.config1.allowed_connections(pair[0], pair[1])
            all_diff[key].append(
                SemanticDiffQuery.SingleDiff(pair[0], pair[1], lost_conns, None))

        key = 'Lost connections between removed peers and intersected peers'
        all_diff[key] = []
        for pair in itertools.product(removed_peers, intersected_peers):
            _, lost_conns, _ = self.config1.allowed_connections(pair[0], pair[1])
            all_diff[key].append(
                SemanticDiffQuery.SingleDiff(pair[0], pair[1], lost_conns, None))

            _, lost_conns, _ = self.config1.allowed_connections(pair[1], pair[0])
            all_diff[key].append(
                SemanticDiffQuery.SingleDiff(pair[1], pair[0], lost_conns, None))

        # lost/new connections between intersected peers due to changes in policies and labels of pods/namespaces
        key = 'Changed connections between intersected peers'
        captured_pods = self.config1.get_captured_pods() | self.config2.get_captured_pods()
        captured_pods &= intersected_peers
        all_diff[key] = []
        for pod1 in intersected_peers:
            for pod2 in intersected_peers if pod1 in captured_pods else captured_pods:
                if pod1 == pod2:
                    continue
                _, old_conns, _ = self.config1.allowed_connections(pod1, pod2)
                _, new_conns, _ = self.config2.allowed_connections(pod1, pod2)
                if new_conns != old_conns:
                    all_diff[key].append(
                        SemanticDiffQuery.SingleDiff(pod1, pod2, old_conns - new_conns, new_conns - old_conns))

        key = 'New connections between intersected peers and added peers'
        all_diff[key] = []
        for pair in itertools.product(intersected_peers, added_peers):
            _, new_conns, _ = self.config2.allowed_connections(pair[0], pair[1])
            all_diff[key].append(
                SemanticDiffQuery.SingleDiff(pair[0], pair[1], None, new_conns))

            _, new_conns, _ = self.config2.allowed_connections(pair[1], pair[0])
            all_diff[key].append(
                SemanticDiffQuery.SingleDiff(pair[1], pair[0], None, new_conns))

        key = 'New connections between added peers'
        all_diff[key] = []
        for pair in itertools.permutations(added_peers, 2):
            _, new_conns, _ = self.config2.allowed_connections(pair[0], pair[1])
            all_diff[key].append(
                SemanticDiffQuery.SingleDiff(pair[0], pair[1], None, new_conns))

        return all_diff

    def produce_diff_message(self, all_diff):
        explanation = ''
        for key in all_diff.keys():
            if len(all_diff[key]) > 0:
                explanation += f'{key}:\n'
                # Initialized with the 3 protocols supported by k8s
                # This implementation is not suitable for Calico!
                added = {}
                removed = {}
                for protocol in [6, 17, 132]:
                    added[ConnectionSet.protocol_number_to_name(protocol)] = {}
                    removed[ConnectionSet.protocol_number_to_name(protocol)] = {}
                added['All connections'] = []
                removed['All connections'] = []
                is_added = False
                is_removed = False
                # Hash diffs: protocol-> port ranges-> list of (from endpoint, to endpoint) tuples
                for entry in all_diff[key]:
                    if entry.added:
                        is_added = True
                        if entry.added.allow_all:
                            added['All connections'].append((entry.from_ep, entry.to_ep))
                        else:
                            for protocol in entry.added.allowed_protocols:
                                if not ConnectionSet.protocol_supports_ports(protocol):
                                    continue
                                protocol_name = ConnectionSet.protocol_number_to_name(protocol)
                                port_range = str(entry.added.allowed_protocols[protocol])
                                if port_range not in added[protocol_name]:
                                    added[protocol_name][port_range] = []
                                added[protocol_name][port_range].append((entry.from_ep, entry.to_ep))

                    if entry.removed:
                        is_removed = True
                        if entry.removed.allow_all:
                            removed['All connections'].append((entry.from_ep, entry.to_ep))
                        else:
                            for protocol in entry.removed.allowed_protocols:
                                if not ConnectionSet.protocol_supports_ports(protocol):
                                    continue
                                protocol_name = ConnectionSet.protocol_number_to_name(protocol)
                                port_range = str(entry.removed.allowed_protocols[protocol])
                                if port_range not in removed[protocol_name]:
                                    removed[protocol_name][port_range] = []
                                removed[protocol_name][port_range].append((entry.from_ep, entry.to_ep))
                if is_added:
                    explanation += f'Added connections:\n{self.pretty_print_diff(added)}\n'
                if is_removed:
                    explanation += f'Removed connections:\n{self.pretty_print_diff(removed)}\n'

        return explanation

    def exec(self):
        query_answer = self.is_identical_topologies(True)
        if query_answer.bool_result and query_answer.output_result:
            return query_answer  # nothing to do - identical configurations (same topologies and policies)

        all_diff = self.compute_diff()

        explanation = self.produce_diff_message(all_diff)
        if explanation:
            return QueryAnswer(False, f'{self.name1} and {self.name2} are not semantically equivalent.', explanation)

        return QueryAnswer(True, f'{self.name1} and {self.name2} are semantically equivalent.')


class StrongEquivalenceQuery(TwoNetworkConfigsQuery):
    """
    Checks whether the two configs have exactly the same set of policies (same names and same semantics)
    """
    def exec(self):
        query_answer = self.is_identical_topologies(True)
        if query_answer.output_result:
            return query_answer

        policies1 = set(self.config1.policies.keys())
        policies2 = set(self.config2.policies.keys())
        policies_1_minus_2 = policies1.difference(policies2)
        policies_2_minus_1 = policies2.difference(policies1)
        if policies_1_minus_2:
            output_result = self.name1 + ' contains a network policy named ' + policies_1_minus_2.pop() + ', but '\
                            + self.name2 + ' does not'
            return QueryAnswer(False, output_result)
        if policies_2_minus_1:
            output_result = self.name2 + ' contains a network policy named ' + policies_2_minus_1.pop() + ', but '\
                            + self.name1 + ' does not'
            return QueryAnswer(False, output_result)

        for policy in self.config1.policies.values():
            single_policy_config1 = self.config1.clone_with_just_one_policy(policy.full_name())
            single_policy_config2 = self.config2.clone_with_just_one_policy(policy.full_name())
            full_result = SemanticEquivalenceQuery(single_policy_config1, single_policy_config2).exec()
            if not full_result.bool_result:
                output_result = policy.full_name() + ' is not equivalent in ' + self.name1 +\
                                ' and in ' + self.name2
                return QueryAnswer(False, output_result, full_result.output_explanation)

        return QueryAnswer(True, self.name1 + ' and ' + self.name2 + ' are strongly equivalent.')


class ContainmentQuery(TwoNetworkConfigsQuery):
    """
    Checking whether the connections allowed by config1 are contained in those allowed by config2
    """
    def exec(self, only_captured=False):
        query_answer = self.is_identical_topologies(True)
        if query_answer.output_result:
            return query_answer

        peers_to_compare = self.config1.peer_container.get_all_peers_group()
        peers_to_compare |= self.disjoint_ip_blocks()
        captured_pods = self.config1.get_captured_pods() | self.config2.get_captured_pods()
        for peer1 in peers_to_compare:
            for peer2 in peers_to_compare if peer1 in captured_pods else captured_pods:
                if peer1 == peer2:
                    continue
                captured1, conns1, _ = self.config1.allowed_connections(peer1, peer2, only_captured)
                if only_captured and not captured1:
                    continue
                _, conns2, _ = self.config2.allowed_connections(peer1, peer2)
                if not conns1.contained_in(conns2):
                    output_result = f'{self.name1} is not contained in {self.name2}'
                    output_explanation = f'Allowed connections from {peer1} to {peer2} in {self.name1} ' \
                                         f'are not a subset of those in {self.name2}\n'
                    output_explanation += conns1.print_diff(conns2, self.name1, self.name2)
                    return QueryAnswer(False, output_result, output_explanation)

        output_result = self.name1 + ' is contained in ' + self.name2
        return QueryAnswer(True, output_result)


class TwoWayContainmentQuery(TwoNetworkConfigsQuery):
    """
    Checks containment in both sides (whether config1 is contained in config2 and vice versa)
    """
    def exec(self):
        query_answer = self.is_identical_topologies()
        if query_answer.output_result:
            return query_answer

        contained_1_in_2 = ContainmentQuery(self.config1, self.config2).exec()
        contained_2_in_1 = ContainmentQuery(self.config2, self.config1).exec()
        explanation_not_contained_self_other = \
            contained_1_in_2.output_result + ':\n\t' + contained_1_in_2.output_explanation
        explanation_not_contained_other_self = \
            contained_2_in_1.output_result + ':\n\t' + contained_2_in_1.output_explanation
        if contained_1_in_2.bool_result and contained_2_in_1.bool_result:
            return QueryAnswer(bool_result=False,
                               output_result=f'The two sets of NetworkPolicies {self.name1} and {self.name2}'
                                             'are semantically equivalent.',
                               numerical_result=3)
        if not contained_1_in_2.bool_result and not contained_2_in_1.bool_result:
            output_explanation = explanation_not_contained_self_other + '\n' + explanation_not_contained_other_self
            return QueryAnswer(bool_result=False,
                               output_result=f'Neither set of NetworkPolicies {self.name1} and {self.name2}'
                                             'is contained in the other.',
                               output_explanation=output_explanation, numerical_result=0)
        if contained_1_in_2.bool_result:
            return QueryAnswer(bool_result=False,
                               output_result=f'NetworkPolicy set {self.name1} is a proper subset of {self.name2}.',
                               output_explanation=explanation_not_contained_other_self, numerical_result=2)
        # (contained_2_in_1)
        return QueryAnswer(bool_result=False,
                           output_result=f'NetworkPolicy set {self.name2} is a proper subset of {self.name1}.',
                           output_explanation=explanation_not_contained_self_other, numerical_result=1)


class InterferesQuery(TwoNetworkConfigsQuery):
    """
    Checking whether config2 extends config1's allowed connection for Pods captured by policies in config1
    """
    def exec(self):
        query_answer = self.is_identical_topologies()
        if query_answer.output_result:
            return query_answer

        peers_to_compare = self.config1.peer_container.get_all_peers_group()
        peers_to_compare |= self.disjoint_ip_blocks()
        captured_pods = self.config1.get_captured_pods() | self.config2.get_captured_pods()
        for peer1 in peers_to_compare:
            for peer2 in peers_to_compare if peer1 in captured_pods else captured_pods:
                if peer1 == peer2:
                    continue
                captured1, conns1, _ = self.config1.allowed_connections(peer1, peer2, True)
                if not captured1:
                    continue
                captured2, conns2, _ = self.config2.allowed_connections(peer1, peer2, True)
                if captured2 and not conns2.contained_in(conns1):
                    output_explanation = f'{self.name2} extends the allowed connections from {peer1} to {peer2}\n' + \
                        conns2.print_diff(conns1, self.name2, self.name1)
                    return QueryAnswer(True, self.name2 + ' interferes with ' + self.name1, output_explanation)

        return QueryAnswer(False, self.name2 + ' does not interfere with ' + self.name1)


class IntersectsQuery(TwoNetworkConfigsQuery):
    """
    Checking whether both configs allow the same connection between any pair of peers
    """
    def exec(self, only_captured):
        query_answer = self.is_identical_topologies()
        if query_answer.output_result:
            return query_answer

        peers_to_compare = self.config1.peer_container.get_all_peers_group()
        peers_to_compare |= self.disjoint_ip_blocks()
        captured_pods = self.config1.get_captured_pods() | self.config2.get_captured_pods()
        for peer1 in peers_to_compare:
            for peer2 in peers_to_compare if peer1 in captured_pods else captured_pods:
                if peer1 == peer2:
                    continue
                captured1, conns1, _ = self.config1.allowed_connections(peer1, peer2, only_captured)
                if only_captured and not captured1:
                    continue
                _, conns2, _ = self.config2.allowed_connections(peer1, peer2)
                conns_in_both = conns2 & conns1
                if bool(conns_in_both):
                    output_explanation = f'Both {self.name1} and {self.name2} allow the following connection ' \
                                         f'from {peer1} to {peer2}\n'
                    output_explanation += str(conns_in_both)
                    return QueryAnswer(True, self.name2 + ' intersects with ' + self.name1, output_explanation)

        return QueryAnswer(False, 'The connections allowed by ' + self.name1 +
                           ' do not intersect the connections allowed by ' + self.name2)


class AllCapturedQuery(NetworkConfigQuery):
    """
    Check that all pods are captured
    """
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

        full_explanation = ''
        res = 0
        if uncaptured_ingress_pods:
            uncaptured_ingress_resources = set(pod.workload_name for pod in uncaptured_ingress_pods)  # no duplicate resources in the set
            res += len(uncaptured_ingress_resources)
            resources = ', '.join(e for e in uncaptured_ingress_resources)
            full_explanation += f'These workload resources are not captured by any policy that affects ingress: {resources}\n'
        if uncaptured_egress_pods:
            uncaptured_egress_resources = set(pod.workload_name for pod in uncaptured_egress_pods)  # no duplicate resources in the set
            res += len(uncaptured_egress_resources)
            resources = ', '.join(e for e in uncaptured_egress_resources)
            full_explanation += f'These workload resources are not captured by any policy that affects egress: {resources}\n'

        return QueryAnswer(bool_result=False,
                           output_result=f'There are workload resources not captured by any policy in {self.config.name}',
                           output_explanation=full_explanation, numerical_result=res)
