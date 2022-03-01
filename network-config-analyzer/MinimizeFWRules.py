#
# Copyright 2020- IBM Inc. All rights reserved
# SPDX-License-Identifier: Apache2.0
#

import yaml
from ConnectionSet import ConnectionSet
from FWRule import FWRuleElement, FWRule, PodElement, LabelExpr, PodLabelsElement, IPBlockElement
from Peer import IpBlock, ClusterEP, Pod, HostEP


class MinimizeCsFwRules:
    """
    This is a class for minimizing fw-rules within a specific connection-set
    """

    def __init__(self, cluster_info, allowed_labels, output_config):
        """
        create an object of MinimizeCsFwRules
        :param cluster_info:  an object of type ClusterInfo, with relevant cluster topology info
        :param allowed_labels: a set of label keys (set[str]) that appear in one of the policy yaml files.
                          using this set to determine which label can be used for grouping pods in fw-rules computation
        :param output_config: an OutputConfiguration object

        """

        self.cluster_info = cluster_info
        self.allowed_labels = allowed_labels
        self.output_config = output_config

        self.peer_pairs = set()
        self.connections = ConnectionSet()
        self.peer_pairs_in_containing_connections = set()
        self.ns_pairs = set()
        self.peer_pairs_with_partial_ns_expr = set()
        self.peer_pairs_without_ns_expr = set()
        self.covered_peer_pairs_union = set()
        self.results_info_per_option = dict()
        self.minimized_fw_rules = []  # holds the computation result of minimized fw-rules

    def compute_minimized_fw_rules_per_connection(self, connections, peer_pairs, peer_pairs_in_containing_connections):
        """
        The main function for creating the minimized set of fw-rules for a given connection set

        :param connections: the allowed connections for the given peer pairs, of type ConnectionSet
        :param peer_pairs: (set) pairs of peers (src,dst) for which communication is allowed over the given connections
        :param peer_pairs_in_containing_connections: (set) pairs of peers in connections that contain the current
               connection set

        class members used in computation of fw-rules:
        self.ns_pairs : pairs of namespaces, grouped from peer_pairs and peer_pairs_in_containing_connections
        self.peer_pairs_with_partial_ns_expr: pairs of (pod,ns) or (ns,pod), with ns-grouping for one dimension
        self.peer_pairs_without_ns_expr: pairs of pods, with no possible ns-grouping
        self.covered_peer_pairs_union: union (set) of all peer pairs for which communication is allowed in current
                                      connection-set (but not necessarily only limited to current connection set)

        :return:
        minimized_fw_rules: a list of fw-rules (of type list[FWRule])
        (results_info_per_option: for debugging, dict with some info about the computation)
        """
        self.peer_pairs = peer_pairs
        self.connections = connections
        self.peer_pairs_in_containing_connections = peer_pairs_in_containing_connections
        self.ns_pairs = set()
        self.peer_pairs_with_partial_ns_expr = set()
        self.peer_pairs_without_ns_expr = set()
        self.covered_peer_pairs_union = set()
        self.results_info_per_option = dict()
        self.minimized_fw_rules = []  # holds the computation result of minimized fw-rules

        self._create_fw_rules()
        if self.output_config.fwRulesRunInTestMode:
            self._print_firewall_rules(self.minimized_fw_rules)
            self._print_results_info()

        return self.minimized_fw_rules, self.results_info_per_option

    def _create_fw_rules(self):
        """
        The main function for creating the minimized set of fw-rules for a given connection set
        :return: None
        """
        # partition peer_pairs to ns_pairs, peer_pairs_with_partial_ns_expr, peer_pairs_without_ns_expr
        self._compute_basic_namespace_grouping()

        # add all fw-rules:
        self._add_all_fw_rules()

    def _compute_basic_namespace_grouping(self):
        """
        computation of peer_pairs with possible grouping by namespaces.
        Results are at: ns_pairs, peer_pairs_with_partial_ns_expr, peer_pairs_without_ns_expr
        :return: None
        """
        self._compute_covered_peer_pairs_union()
        # only Pod elements have namespaces (skipping IpBlocks and HostEPs)
        src_namespaces_set = set(src.namespace for (src, dest) in self.peer_pairs if isinstance(src, Pod))
        dst_namespaces_set = set(dest.namespace for (src, dest) in self.peer_pairs if isinstance(dest, Pod))
        # per relevant namespaces, compute which pairs of src-ns and dst-ns are covered by given peer-pairs
        for src_ns in src_namespaces_set:
            for dst_ns in dst_namespaces_set:
                ns_product_pairs = set((src, dst) for src in self.cluster_info.ns_dict[src_ns] for dst in
                                       self.cluster_info.ns_dict[dst_ns])
                if ns_product_pairs.issubset(self.covered_peer_pairs_union):
                    self.ns_pairs |= {(src_ns, dst_ns)}
                else:
                    self.peer_pairs_without_ns_expr |= ns_product_pairs & self.peer_pairs

        # TODO: what about peer pairs with ip blocks from containing connections, not only peer_pairs for this connection?
        pairs_with_elems_without_ns = set((src, dst) for (src, dst) in self.peer_pairs
                                          if isinstance(src, (IpBlock, HostEP)) or isinstance(dst, (IpBlock, HostEP)))
        self.peer_pairs_without_ns_expr |= pairs_with_elems_without_ns
        # compute pairs with src as pod/ip-block and dest as namespace
        self._compute_ns_pairs_with_partial_ns_expr(False)
        # compute pairs with src as pod/ip-block namespace dest as pod
        self._compute_ns_pairs_with_partial_ns_expr(True)
        # remove pairs of (pod,pod) for trivial cases of communication from pod to itself
        self._remove_trivial_rules_from_peer_pairs_without_ns_expr()

    def _compute_covered_peer_pairs_union(self):
        """
        compute the union (set) of all peer pairs for which communication is allowed in current connection-set (but
        not necessarily only limited to current connection set)
        :return: None
        """
        covered_peer_pairs_union = self.peer_pairs | self.peer_pairs_in_containing_connections

        all_pods_set = set(src for (src, dst) in self.peer_pairs if isinstance(src, ClusterEP)) | \
            set(dst for (src, dst) in self.peer_pairs if isinstance(dst, ClusterEP))
        for pod in all_pods_set:
            covered_peer_pairs_union |= {(pod, pod)}
        self.covered_peer_pairs_union = covered_peer_pairs_union

    @staticmethod
    def _get_pods_set_per_fixed_elem_from_peer_pairs(is_src_fixed, fixed_elem, peer_pairs_set):
        """

        :param is_src_fixed: bool flag indicating if fixed elem is src (True) or dst (False)
        :param fixed_elem: the fixed element
        :param peer_pairs_set: set of peer pairs
        :return:set of pods that are paired with fixed_elem ( as src/dst according to flag is_src_fixed)
                in peer_pairs_set
        """
        if is_src_fixed:
            return set(dest for (src, dest) in peer_pairs_set if src == fixed_elem and isinstance(dest, Pod))
        return set(src for (src, dest) in peer_pairs_set if dest == fixed_elem and isinstance(src, Pod))

    def _get_peer_pairs_product_for_ns_and_fixed_elem(self, is_pod_in_src, pod, ns):
        """
        compute all peer pairs represented by a pair of a pod with entire namespace
        :param is_pod_in_src: flag indicating if pod is src (True) or dst (False)
        :param pod: the fixed element
        :param ns: the entire namespace
        :return: a set of peer pairs
        """
        if is_pod_in_src:
            return set((pod, dst_pod) for dst_pod in self.cluster_info.ns_dict[ns])
        return set((src_pod, pod) for src_pod in self.cluster_info.ns_dict[ns])

    def _get_ns_covered_in_one_dimension(self, is_src_fixed, fixed_elem):
        """
        compute if a fixed elem (src or dst) can be paired with entire namespace (dst or src)
        :param is_src_fixed: a bool flag indicating if fixed_elem is a src elem (True) of dst (False)
        :param fixed_elem: a fixed elem (of type Pod/IpBlock)
        :return:
        covered_ns_set: set of namespaces for which fixed_elem can be paired with
         (connection is allowed between fixed_elem and each ns in this set [direction depends on is_src_fixed],
          according to current connection set and the containing connections as well).
        peer_pairs_product_union: set of peer pairs represented by each pair of fixed_elem with ns in covered_ns_set
        """
        pods_set = self._get_pods_set_per_fixed_elem_from_peer_pairs(is_src_fixed, fixed_elem,
                                                                     self.peer_pairs_without_ns_expr)
        # ns_set is a set with the potential namespaces for grouping
        ns_set = set(e.namespace for e in pods_set)
        covered_ns_set = set()
        peer_pairs_product_union = set()
        for ns in ns_set:
            peer_pairs_product = self._get_peer_pairs_product_for_ns_and_fixed_elem(is_src_fixed, fixed_elem, ns)
            # if the connections between entire ns and fixed_elem is allowed - add ns to covered_ns_set
            if peer_pairs_product.issubset(self.covered_peer_pairs_union):
                covered_ns_set |= {ns}
                peer_pairs_product_union |= peer_pairs_product
        return covered_ns_set, peer_pairs_product_union

    def _compute_ns_pairs_with_partial_ns_expr(self, is_src_ns):
        """
        computes and updates self.peer_pairs_with_partial_ns_expr with pairs where only one elem (src/dst)
        can be grouped to an entire namespace
        :param is_src_ns: a bool flag to indicate if computing pairs with src elem grouped as ns (True) or dst (False)
        :return: None
        """
        # pod_set is the set of pods in pairs of peer_pairs_without_ns_expr, within elem type (src/dst) which is not
        # in the grouping computation
        pod_set = set(src for (src, _) in self.peer_pairs_without_ns_expr) if not is_src_ns else \
            set(dst for (_, dst) in self.peer_pairs_without_ns_expr)
        # loop on fixed elements (not in the grouping computation)
        for pod in pod_set:
            covered_ns_set, peer_pairs_product_union = self._get_ns_covered_in_one_dimension(not is_src_ns, pod)
            for ns in covered_ns_set:
                partial_ns_expr_pair = (pod, ns) if not is_src_ns else (ns, pod)
                self.peer_pairs_with_partial_ns_expr |= {partial_ns_expr_pair}
            self.peer_pairs_without_ns_expr -= peer_pairs_product_union

    # remove trivial pairs to avoid creating them a fw-rule directly
    def _remove_trivial_rules_from_peer_pairs_without_ns_expr(self):
        """
        update peer_pairs_without_ns_expr by removing pairs with identical src and dst elements.
        a communication from a pod to itself is trivial, thus we should avoid creating fw-rules for such pairs.
        Note that these pairs are contained in self.covered_peer_pairs_union, thus can be used for grouping if needed.
        :return: None
        """
        trivial_pairs = set((src, dst) for (src, dst) in self.peer_pairs_without_ns_expr if src == dst)
        self.peer_pairs_without_ns_expr -= trivial_pairs

    def get_ns_fw_rules_grouped_by_common_elem(self, is_src_fixed, ns_set, fixed_elem):
        """
        create a  fw-rule from a fixed-elem and  a set of namespaces
        :param is_src_fixed: a flag indicating if the fixed elem is src (True) or dst (False)
        :param ns_set:  a set of namespaces
        :param fixed_elem: the fixed element
        :return: a list with created FWRule
        """
        # currently no grouping of ns-list by labels of namespaces
        grouped_elem = FWRuleElement(ns_set)
        if is_src_fixed:
            fw_rule = FWRule(fixed_elem, grouped_elem, self.connections)
        else:
            fw_rule = FWRule(grouped_elem, fixed_elem, self.connections)
        return [fw_rule]

    def _get_pods_grouping_by_labels_main(self, pods_set, extra_pods_set):
        """
        The main function to implement pods grouping by labels.
        This function splits the pods into namespaces, and per ns calls  get_pods_grouping_by_labels().
        :param pods_set: the pods for grouping
        :param extra_pods_set: additional pods that can be used for grouping
        :return:
        res_chosen_rep: a list of tuples (key,values,ns) -- as the chosen representation for grouping the pods.
        res_remaining_pods: set of pods from pods_set that are not included in the grouping result (could not be grouped).
        """
        ns_context_options = set(pod.namespace for pod in pods_set)
        res_chosen_rep = []
        res_remaining_pods = set()
        # grouping by pod-labels per each namespace separately
        for ns in ns_context_options:
            pods_set_per_ns = pods_set & self.cluster_info.ns_dict[ns]
            extra_pods_set_per_ns = extra_pods_set & self.cluster_info.ns_dict[ns]
            chosen_rep, remaining_pods = self._get_pods_grouping_by_labels(pods_set_per_ns, ns, extra_pods_set_per_ns)
            res_chosen_rep.extend(chosen_rep)
            res_remaining_pods |= remaining_pods
        return res_chosen_rep, res_remaining_pods

    def _get_pods_grouping_by_labels(self, pods_set, ns, extra_pods_set):
        """
        Implements pods grouping by labels in a single namespace.
        :param pods_set: the set of pods for grouping.
        :param ns: the namespace
        :param extra_pods_set: additional pods that can be used for completing the grouping
                               (originated in containing connections).
        :return:
        chosen_rep:  a list of tuples (key,values,ns) -- as the chosen representation for grouping the pods.
        remaining_pods: set of pods from pods_list that are not included in the grouping result
        """
        if self.output_config.fwRulesDebug:
            print('get_pods_grouping_by_labels:')
            print('pods_list: ' + ','.join([str(pod) for pod in pods_set]))
            print('extra_pods_list: ' + ','.join([str(pod) for pod in extra_pods_set]))
        all_pods_set = pods_set | extra_pods_set
        allowed_labels = self.cluster_info.allowed_labels
        pods_per_ns = self.cluster_info.ns_dict[ns]
        # labels_rep_options is a list of tuples (key, (values, pods-set)), where each tuple in this list is a valid
        # grouping of pods-set by "key in values"
        labels_rep_options = []
        for key in allowed_labels:
            values_for_key = self.cluster_info.get_all_values_set_for_key_per_namespace(key, {ns})
            fully_covered_label_values = set()
            pods_with_fully_covered_label_values = set()
            for v in values_for_key:
                all_pods_per_label_val = self.cluster_info.pods_labels_map[(key, v)] & pods_per_ns
                if not all_pods_per_label_val:
                    continue
                pods_with_label_val_from_pods_list = all_pods_per_label_val & all_pods_set
                pods_with_label_val_from_original_pods_list = all_pods_per_label_val & pods_set
                # allow to "borrow" from extra_pods_set only if at least one pod is also in original pods_set
                if all_pods_per_label_val == pods_with_label_val_from_pods_list and \
                        pods_with_label_val_from_original_pods_list:
                    fully_covered_label_values |= {v}
                    pods_with_fully_covered_label_values |= pods_with_label_val_from_pods_list
            # TODO: is it OK to ignore label-grouping if only one pod is involved?
            if self.output_config.fwRulesGroupByLabelSinglePod:
                if fully_covered_label_values and len(
                        pods_with_fully_covered_label_values) >= 1:  # don't ignore label-grouping if only one pod is involved
                    labels_rep_options.append((key, (fully_covered_label_values, pods_with_fully_covered_label_values)))
            else:
                if fully_covered_label_values and len(
                        pods_with_fully_covered_label_values) > 1:  # ignore label-grouping if only one pod is involved
                    labels_rep_options.append((key, (fully_covered_label_values, pods_with_fully_covered_label_values)))

        chosen_rep = []
        remaining_pods = pods_set.copy()
        # sort labels_rep_options by length of pods_with_fully_covered_label_values, to prefer label-grouping that
        # covers more pods
        sorted_rep_options = sorted(labels_rep_options, key=lambda x: len(x[1][1]), reverse=True)
        if self.output_config.fwRulesDebug:
            print('sorted rep options:')
            for (key, (label_vals, pods)) in sorted_rep_options:
                print(key, label_vals, len(pods))
        ns_info = {ns}
        for (k, (vals, pods)) in sorted_rep_options:
            if (pods & pods_set).issubset(remaining_pods):
                chosen_rep.append((k, vals, ns_info))
                remaining_pods -= pods
            if not remaining_pods:
                break
        return chosen_rep, remaining_pods

    def _get_pod_level_fw_rules_grouped_by_common_labels(self, is_src_fixed, pods_set, fixed_elem, extra_pods_set):
        """
        Implements grouping in the level of pods labels.
        :param is_src_fixed: a bool flag to indicate if fixed_elem is at src or dst.
        :param pods_set: the set of pods to be grouped
        :param fixed_elem: the fixed element of the original fw-rules
        :param extra_pods_set: an additional pods set from containing connections (with same fixed_elem) that can be
        used for grouping (completing for a set of pods to cover some label grouping).
        :return: a set of fw-rules result after grouping
        """
        res = []
        # (1) try grouping by pods-labels:
        chosen_rep, remaining_pods = self._get_pods_grouping_by_labels_main(pods_set, extra_pods_set)
        for (key, values, ns_info) in chosen_rep:
            map_simple_keys_to_all_values = self.cluster_info.get_map_of_simple_keys_to_all_values(key, ns_info)
            all_key_values = self.cluster_info.get_all_values_set_for_key_per_namespace(key, ns_info)
            pod_label_expr = LabelExpr(key, set(values), map_simple_keys_to_all_values, all_key_values)
            grouped_elem = PodLabelsElement(pod_label_expr, ns_info)
            if is_src_fixed:
                fw_rule = FWRule(fixed_elem, grouped_elem, self.connections)
            else:
                fw_rule = FWRule(grouped_elem, fixed_elem, self.connections)
            res.append(fw_rule)

        # TODO: should avoid having single pods remaining without labels grouping
        # (2) add rules for remaining single pods:
        for pod in remaining_pods:
            single_pod_elem = PodElement(pod, self.output_config.outputEndpoints == 'deployments')
            if is_src_fixed:
                fw_rule = FWRule(fixed_elem, single_pod_elem, self.connections)
            else:
                fw_rule = FWRule(single_pod_elem, fixed_elem, self.connections)
            res.append(fw_rule)
        return res

    def _create_initial_fw_rules_from_base_elements_list(self, base_elems_pairs):
        """
        creating initial fw-rules from base elements
        :param base_elems_pairs: a set of pairs (src,dst) , each of type: Pod/K8sNamespace/IpBlock
        :return: list with created fw-rules
        :rtype list[FWRule]
        """
        res = []
        for (src, dst) in base_elems_pairs:
            res.extend(FWRule.create_fw_rules_from_base_elements(src, dst, self.connections))
        return res

    def _create_all_initial_fw_rules(self):
        """
        Creating initial fw-rules from base-elements pairs (pod/ns/ip-block)
        :return: a list of initial fw-rules of type FWRule
        :rtype list[FWRule]
        """
        initial_fw_rules = []
        initial_fw_rules.extend(self._create_initial_fw_rules_from_base_elements_list(self.ns_pairs))
        initial_fw_rules.extend(self._create_initial_fw_rules_from_base_elements_list(self.peer_pairs_without_ns_expr))
        initial_fw_rules.extend(
            self._create_initial_fw_rules_from_base_elements_list(self.peer_pairs_with_partial_ns_expr))
        return initial_fw_rules

    def _add_all_fw_rules(self):
        """
        Computation of fw-rules, following the ns-grouping of peer_pairs.
        Results are at: self.minimized_rules_set
        :return: None
        """
        # create initial fw-rules from ns_pairs, peer_pairs_with_partial_ns_expr, peer_pairs_without_ns_expr
        initial_fw_rules = self._create_all_initial_fw_rules()
        # TODO: consider a higher resolution decision between option1 and option2 (per src,dst pair rather than per
        #  all ConnectionSet pairs)

        # option1 - start computation when src is fixed at first iteration, and merge applies to dst
        option1, convergence_iteration_1 = self._create_merged_rules_set(True, initial_fw_rules)
        # option2 - start computation when dst is fixed at first iteration, and merge applies to src
        option2, convergence_iteration_2 = self._create_merged_rules_set(False, initial_fw_rules)

        # self.post_processing_fw_rules(option1)
        # self.post_processing_fw_rules(option2)

        if self.output_config.fwRulesRunInTestMode:
            equiv1 = self.check_peer_pairs_equivalence(option1)
            equiv2 = self.check_peer_pairs_equivalence(option2)
            assert equiv1
            assert equiv2
            # add info for documentation about computation results
            self.results_info_per_option['option1_len'] = len(option1)
            self.results_info_per_option['option2_len'] = len(option2)
            self.results_info_per_option['convergence_iteration_1'] = convergence_iteration_1
            self.results_info_per_option['convergence_iteration_2'] = convergence_iteration_2
            self.results_info_per_option['equiv1'] = equiv1
            self.results_info_per_option['equiv2'] = equiv2

        if self.output_config.fwRulesDebug:
            print('option 1 rules:')
            self._print_firewall_rules(option1)
            print('option 2 rules: ')
            self._print_firewall_rules(option2)

        # choose the option with less fw-rules
        if len(option1) < len(option2):
            self.minimized_fw_rules = option1
            return
        self.minimized_fw_rules = option2

    def _get_grouping_result(self, fixed_elem, set_for_grouping_elems, src_first):
        """
        Apply grouping for a set of elements to create grouped fw-rules
        :param fixed_elem: the fixed elements from the original fw-rules
        :param set_for_grouping_elems: the set of elements to be grouped
        :param src_first: a bool flag to indicate if fixed_elem is src or dst
        :return: A list of fw-rules after possible grouping operations
        """
        res = []
        # partition set_for_grouping_elems into: (1) ns_elems, (2) pod_and_pod_labels_elems, (3) ip_block_elems
        pod_and_pod_labels_elems = set(elem for elem in set_for_grouping_elems if
                                       isinstance(elem, (PodElement, PodLabelsElement)))
        ip_block_elems = set(elem for elem in set_for_grouping_elems if isinstance(elem, IPBlockElement))
        ns_elems = set_for_grouping_elems - (pod_and_pod_labels_elems | ip_block_elems)

        if ns_elems:
            # grouping of ns elements is straight-forward
            ns_set = set.union(*(f.ns_info for f in ns_elems))
            res.extend(self.get_ns_fw_rules_grouped_by_common_elem(src_first, ns_set, fixed_elem))

        if pod_and_pod_labels_elems:
            # grouping of pod and pod-labels elements
            # TODO: currently adding this due to example in test24: a single pod-labels elem is replaced by another grouping
            if len(pod_and_pod_labels_elems) == 1 and isinstance(list(pod_and_pod_labels_elems)[0], PodLabelsElement):
                elem = list(pod_and_pod_labels_elems)[0]
                fw_rule = FWRule(fixed_elem, elem, self.connections) if src_first else FWRule(elem, fixed_elem,
                                                                                              self.connections)
                res.append(fw_rule)
            else:
                # set_for_grouping_pods is the set of all pods originated in pods and pod-labels elements, to be grouped
                set_for_grouping_pods = set()
                for e in pod_and_pod_labels_elems:
                    set_for_grouping_pods |= e.get_pods_set(self.cluster_info)

                # allow borrowing pods for labels-grouping from covered_peer_pairs_union
                fixed_elem_pods = fixed_elem.get_pods_set(self.cluster_info)
                # extra_pods_list is a list of pods sets that are paired with pods in fixed_elem_pods within
                # covered_peer_pairs_union
                extra_pods_list = []
                for p in fixed_elem_pods:
                    if src_first:
                        pods_to_add = set(dst for (src, dst) in self.covered_peer_pairs_union if src == p)
                    else:
                        pods_to_add = set(src for (src, dst) in self.covered_peer_pairs_union if dst == p)
                    extra_pods_list.append(pods_to_add)
                # extra_pods_list_common is a set of pods that are paired with all pods in fixed_elem_pods within
                # covered_peer_pairs_union
                extra_pods_list_common = set()
                if extra_pods_list:
                    extra_pods_list_common = set.intersection(*extra_pods_list)

                res.extend(self._get_pod_level_fw_rules_grouped_by_common_labels(src_first, set_for_grouping_pods,
                                                                                 fixed_elem, extra_pods_list_common))

        if ip_block_elems:
            # currently no grouping for ip blocks
            for elem in ip_block_elems:
                if src_first:
                    res.append(FWRule(fixed_elem, elem, self.connections))
                else:
                    res.append(FWRule(elem, fixed_elem, self.connections))

        return res

    def _create_merged_rules_set(self, is_src_first, fw_rules):
        """
        Computing a minimized set of fw-rules by merging src/dst elements iteratively
        :param is_src_first: a bool flag to indicate if merge process starts with src or dest
        :param fw_rules: a list of initial fw-rules
        :return: a list of minimized fw-rules after merge process
        """
        initial_fw_rules = fw_rules.copy()
        if not initial_fw_rules:
            return [], 0
        count_fw_rules = dict()  # map number of fw-rules per iteration number
        max_iter = self.output_config.fwRulesMaxIter
        convergence_iteration = max_iter
        for i in range(0, max_iter):
            fw_rules_after_merge = []
            count_fw_rules[i] = len(initial_fw_rules)
            if i > 1 and count_fw_rules[i] == count_fw_rules[i - 1]:
                convergence_iteration = i
                break
            if i > 1 and self.output_config.fwRulesRunInTestMode:
                assert count_fw_rules[i - 1] > count_fw_rules[i], "Expecting fewer fw_rules after each merge iteration."
            # change the grouping target (src/dst) on each iteration
            src_first = (i % 2 == 0) if is_src_first else (i % 2 == 1)
            first_elem_set = set(f.src for f in initial_fw_rules) if src_first else set(f.dst for f in initial_fw_rules)
            for elem in first_elem_set:
                if src_first:
                    # TODO: equals or contained in?
                    set_for_grouping_elems = set(f.dst for f in initial_fw_rules if f.src == elem)
                else:
                    set_for_grouping_elems = set(f.src for f in initial_fw_rules if f.dst == elem)
                res = self._get_grouping_result(elem, set_for_grouping_elems, src_first)
                fw_rules_after_merge.extend(res)
            # prepare for next iteration
            initial_fw_rules = fw_rules_after_merge
            if self.output_config.fwRulesDebug:
                print('fw rules after iteration: ' + str(i))
                self._print_firewall_rules(initial_fw_rules)

        return initial_fw_rules, convergence_iteration

    # ---------------------------------------------------------------------------------------------------------
    # below functions are for debugging :

    def _print_results_info(self):
        print('----------------')
        print('results_info_per_option: ')
        for key in self.results_info_per_option:
            val = self.results_info_per_option[key]
            print(str(key) + ':' + str(val))
        print('----------------')

    def _print_firewall_rules(self, rules):
        print('-------------------')
        print('rules for connections: ' + str(self.connections))
        for rule in rules:
            # filter out rule of a pod to itslef
            # if rule.is_rule_trivial():
            #    continue
            print(rule)

    def get_src_dest_pairs_from_fw_rules(self, rules):
        src_dest_pairs = []
        for rule in rules:
            # compute set of pods derived from rule src and rule dest
            if not isinstance(rule.src, IPBlockElement) and not isinstance(rule.dst, IPBlockElement):
                src_set = rule.src.get_pods_set(self.cluster_info)
                dest_set = rule.dst.get_pods_set(self.cluster_info)

                for src in src_set:
                    for dst in dest_set:
                        src_dest_pairs.append((src, dst))

            elif isinstance(rule.src, IPBlockElement) and not isinstance(rule.dst, IPBlockElement):
                dest_set = rule.dst.get_pods_set(self.cluster_info)
                for dst in dest_set:
                    src_dest_pairs.append((rule.src.element, dst))

            elif not isinstance(rule.src, IPBlockElement) and isinstance(rule.dst, IPBlockElement):
                src_set = rule.src.get_pods_set(self.cluster_info)
                for src in src_set:
                    src_dest_pairs.append((src, rule.dst.element))

        for (src, dst) in src_dest_pairs:
            if isinstance(src, IpBlock) and isinstance(dst, IpBlock):
                src_dest_pairs.remove((src, dst))

        return set(src_dest_pairs)

    @staticmethod
    def validate_ip_blocks(ips_list_1, ips_list_2):
        ip_block_1 = IpBlock()
        ip_block_2 = IpBlock()
        for ip in ips_list_1:
            ip_block_1 |= ip
        for ip in ips_list_2:
            ip_block_2 |= ip
        return ip_block_1.contained_in(ip_block_2)

    # for testing- make sure set of peer pairs derived from fw-rules is equivalent to the input peer pairs
    def check_peer_pairs_equivalence(self, rules):
        orig_set = set(self.peer_pairs)
        allowed_extra_set = set(self.covered_peer_pairs_union)  # set(self.peer_pairs_in_containing_connections)
        union_allowed_set = orig_set.union(allowed_extra_set)
        results_set_orig = self.get_src_dest_pairs_from_fw_rules(rules)

        # direction 1: find justification for every pair in the result
        for (src, dst) in results_set_orig:
            if isinstance(src, ClusterEP) and isinstance(dst, ClusterEP) and not (src, dst) in union_allowed_set:
                return False
            elif isinstance(dst, IpBlock):
                allowed_ips_from_res = [dst for (src1, dst) in results_set_orig if
                                        src1 == src and isinstance(dst, IpBlock)]
                allowed_ips_from_orig = [dst for (src1, dst) in union_allowed_set if
                                         src1 == src and isinstance(dst, IpBlock)]
                if not self.validate_ip_blocks(allowed_ips_from_res, allowed_ips_from_orig):
                    return False
            elif isinstance(src, IpBlock):
                allowed_ips_from_res = [src for (src, dst1) in results_set_orig if
                                        dst1 == dst and isinstance(src, IpBlock)]
                allowed_ips_from_orig = [src for (src, dst1) in union_allowed_set if
                                         dst1 == dst and isinstance(src, IpBlock)]
                if not self.validate_ip_blocks(allowed_ips_from_res, allowed_ips_from_orig):
                    return False

        # direction 2: make sure that any pair in the orig_set is covered in the result
        for (src, dst) in orig_set:
            if isinstance(src, ClusterEP) and isinstance(dst, ClusterEP) and not (src, dst) in results_set_orig:
                if src != dst:  # ignore trivial pairs
                    print('pair ' + str((src, dst)) + ' in orig_set but not in results_set_orig ')
                    return False
            elif isinstance(dst, IpBlock):
                allowed_ips_from_res = [dst for (src1, dst) in results_set_orig if
                                        src1 == src and isinstance(dst, IpBlock)]
                allowed_ips_from_orig = [dst for (src1, dst) in orig_set if src1 == src and isinstance(dst, IpBlock)]
                if not self.validate_ip_blocks(allowed_ips_from_orig, allowed_ips_from_res):
                    print('src: ' + str(src) + ' ip block from orig not covered in res ')
                    print(' orig ip block: ' + ','.join(str(ip) for ip in allowed_ips_from_orig))
                    print(' res ip block: ' + ','.join(str(ip) for ip in allowed_ips_from_res))
                    return False
            elif isinstance(src, IpBlock):
                allowed_ips_from_res = [src for (src, dst1) in results_set_orig if
                                        dst1 == dst and isinstance(src, IpBlock)]
                allowed_ips_from_orig = [src for (src, dst1) in orig_set if
                                         dst1 == dst and isinstance(src, IpBlock)]
                if not self.validate_ip_blocks(allowed_ips_from_orig, allowed_ips_from_res):
                    print('dst: ' + str(dst) + ' ip block from orig not covered in res ')
                    print(' orig ip block: ' + ','.join(str(ip) for ip in allowed_ips_from_orig))
                    print(' res ip block: ' + ','.join(str(ip) for ip in allowed_ips_from_res))
                    return False

        return True


# ==================================================================================================================

class MinimizeFWRules:
    """
    This is a class for minimizing and handling fw-rules globally for all connection sets
    """

    def __init__(self, fw_rules_map, cluster_info, output_config, results_map):
        """
        create n object of MinimizeFWRules
        :param fw_rules_map: a map from ConnectionSet to list[FWRule] - the list of minimized fw-rules per connection
        :param cluster_info: an object of type ClusterInfo
        :param output_config: an object of type OutputConiguration
        :param results_map: (temp, for debugging) a map from connection to results info
        """
        self.fw_rules_map = fw_rules_map
        self.cluster_info = cluster_info
        self.output_config = output_config
        self.results_map = results_map

    def get_fw_rules_in_required_format(self, add_txt_header=True, add_csv_header=True):
        """
        :param add_txt_header: bool flag to indicate if header of fw-rules query should be added in txt format
        :param add_csv_header: bool flag to indicate if header csv should be added in csv format
        :return: a string representing the computed minimized fw-rules (in a supported format txt/yaml/csv)
        """
        query_name = self.output_config.queryName
        if self.output_config.configName:
            query_name += ', config: ' + self.output_config.configName
        output_format = self.output_config.outputFormat
        if output_format not in FWRule.supported_formats:
            print(f'error: unexpected outputFormat in output configuration value [should be txt/yaml/csv],  '
                  f'value is: {output_format}')
        return self._get_fw_rules_content_str(query_name, output_format, add_txt_header, add_csv_header)

    def _get_fw_rules_content_str(self, query_name, req_format, add_txt_header, add_csv_header):
        """
        :param query_name: a string of the query name
        :param req_format: a string of the required format, should be in FWRule.supported_formats
        :param add_txt_header:  bool flag to indicate if header of fw-rules query should be added in txt format
        :param add_csv_header: bool flag to indicate if header csv should be added in csv format
        :return: a string of the query name + fw-rules in the required format
        """
        rules_list = self._get_all_rules_list_in_req_format(req_format)

        if req_format == 'txt':
            res = ''.join(line for line in sorted(rules_list))
            if add_txt_header:
                res = f'final fw rules for query: {query_name}:\n' + res
            return res

        elif req_format == 'yaml':
            yaml_query_content = [{'query': query_name, 'rules': rules_list}]
            res = yaml.dump(yaml_query_content, None, default_flow_style=False, sort_keys=False)
            return res

        elif req_format in ['csv', 'md']:
            is_csv = req_format == 'csv'
            res = ''
            header_lines = [[query_name] + [''] * (len(FWRule.rule_csv_header) - 1)]
            if add_csv_header:
                if is_csv:
                    header_lines = [FWRule.rule_csv_header] + header_lines
                else:
                    header_lines = [FWRule.rule_csv_header, ['---'] * len(FWRule.rule_csv_header)] + header_lines
            rules_list = header_lines + rules_list
            for row in rules_list:
                row_str = '' if is_csv else '|'
                for elem in row:
                    row_str += f'\"{elem}\",' if is_csv else f'{elem}|'
                res += row_str + '\n'
            return res

        return ''

    def _get_all_rules_list_in_req_format(self, req_format):
        """
        Get a sorted list of rules in required format:
        txt -> list of str objects
        yaml -> list of dict objects
        csv/md -> list of list objects
        :param str req_format: the required format, should be in FWRule.supported_formats
        :return: a list of objects representing the fw-rules in the required format
        :rtype: Union[list[str], list[dict], list[list]]

        The removal of duplicates is relevant for the case where output is in level of deployments, and creating
        duplications in rules where single pods are mapped to the same deployment name.
        This may happen when a deployment has more than one pod, and the grouping by label is not applied to it.
        (for example, when the pods are selected by named ports and not by podSelector with label, there may not be
        'allowed' relevant input labels available).
        # TODO: remove duplicate rules earlier? (rules with different pods mapped to the same pod owner)
        # current issue is that we use topologies with pods of the same owner but different labels, so cannot consider
        # fw-rules elements of pod with same owner as identical
        """
        rules_list = []
        all_connections = sorted(self.fw_rules_map.keys())
        for connection in all_connections:
            connection_rules = sorted(self.fw_rules_map[connection])
            rules_dict = dict()  # use to avoid duplicates
            for rule in connection_rules:
                if self.output_config.fwRulesFilterSystemNs and rule.should_rule_be_filtered_out():
                    continue
                rule_obj = rule.get_rule_in_req_format(req_format, self.cluster_info.config_type)
                if (self.output_config.outputEndpoints == 'deployments' and str(rule_obj) not in rules_dict) or (
                        self.output_config.outputEndpoints == 'pods'):
                    rules_list.append(rule_obj)
                    rules_dict[str(rule_obj)] = 1
        return rules_list
