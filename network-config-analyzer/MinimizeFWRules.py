import os
import yaml
from K8sNamespace import K8sNamespace
from ConnectionSet import ConnectionSet
from FWRule import FWRuleElement, FWRule, PodElement, LabelExpr, PodLabelsElement, IPBlockElement
from Peer import IpBlock, Pod
from pathlib import Path


# TODO: rename file or split to two files..
class MinimizeCsFwRules:
    """
    This is a class for minimizing fw-rules within a specific connection set
    """

    def __init__(self, peer_pairs, connections: ConnectionSet,
                 peer_pairs_in_containing_connections,
                 cluster_info,
                 allowed_labels,
                 output_config):
        self.peer_pairs = peer_pairs
        self.connections = connections
        self.peer_pairs_in_containing_connections = peer_pairs_in_containing_connections
        self.cluster_info = cluster_info
        self.allowed_labels = allowed_labels
        self.output_config = output_config
        self.ns_pairs = []
        self.peer_pairs_with_partial_ns_expr = []
        self.peer_pairs_without_ns_expr = []
        self.covered_peer_pairs_union = set()
        self.results_info_per_option = dict()
        self.minimized_rules_set = []
        # create the fw rules per given connection and its peer_pairs
        self.create_fw_rules()
        if self.output_config.fwRulesRunInTestMode:
            self.print_firewall_rules(self.minimized_rules_set)
            self.print_results_info()

    def create_fw_rules(self):
        """
        The main function for creating the set of fw-rules for a given connection set
        :return: None
        """
        # partition peer_pairs to ns_pairs, peer_pairs_with_partial_ns_expr, peer_pairs_without_ns_expr
        self.compute_basic_namespace_grouping()

        # add all fw-rules:
        self.add_all_fw_rules()

    def compute_covered_peer_pairs_union(self):
        covered_peer_pairs_union = set(self.peer_pairs).union(set(self.peer_pairs_in_containing_connections))

        all_pods_set = set([src for (src, dst) in self.peer_pairs if isinstance(src, Pod)]).union(
            set([dst for (src, dst) in self.peer_pairs if isinstance(dst, Pod)]))
        for pod in all_pods_set:
            covered_peer_pairs_union.add((pod, pod))
        self.covered_peer_pairs_union = covered_peer_pairs_union
        return

    def compute_basic_namespace_grouping(self):
        """
        computation of peer_pairs with possible grouping by namespaces.
        Results are at:
        self.ns_pairs : pairs of namespaces, grouped from peer_pairs and peer_pairs_in_containing_connections
        self.peer_pairs_with_partial_ns_expr: pairs of (pod,ns) or (ns,pod), with ns-grouping for one dimension
        self.peer_pairs_without_ns_expr: pairs of pods, with no possible ns-grouping
        :return: None
        """
        self.compute_covered_peer_pairs_union()
        src_namespaces_set = set([src.namespace for (src, dest) in self.peer_pairs if isinstance(src, Pod)])
        dst_namespaces_set = set([dest.namespace for (src, dest) in self.peer_pairs if isinstance(dest, Pod)])
        # per relevant namespaces, compute which pairs of src-ns and dst-ns are covered by given peer-pairs
        for src_ns in src_namespaces_set:
            for dst_ns in dst_namespaces_set:
                ns_product_pairs = set(self.get_ns_product_peer_pairs(src_ns, dst_ns))
                if ns_product_pairs.issubset(self.covered_peer_pairs_union):
                    self.ns_pairs.append((src_ns, dst_ns))
                else:
                    self.peer_pairs_without_ns_expr.extend(ns_product_pairs.intersection(set(self.peer_pairs)))

        # TODO: what about peer pairs with ip blocks from containing connections, not only peer_pairs for this connection?
        self.peer_pairs_without_ns_expr.extend(self.get_peer_pairs_with_ip_blocks(self.peer_pairs))
        # compute pairs with src as pod and dest as namespace
        self.compute_ns_pairs_with_partial_ns_expr(False)
        # compute pairs with src as pod namespace dest as pod
        self.compute_ns_pairs_with_partial_ns_expr(True)
        # remove pairs of (pod,pod) for trivial cases of communication from pod to itself
        self.remove_trivial_rules_from_peer_pairs_without_ns_expr()

    @staticmethod
    def get_peer_pairs_with_ip_blocks(peer_pairs_list):
        return [(src, dst) for (src, dst) in peer_pairs_list if isinstance(src, IpBlock) or isinstance(dst, IpBlock)]

    def print_results_info(self):
        print('----------------')
        print('results_info_per_option: ')
        for key in self.results_info_per_option:
            val = self.results_info_per_option[key]
            print(str(key) + ':' + str(val))
        print('----------------')
        return

    def print_firewall_rules(self, rules):
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
            if isinstance(src, Pod) and isinstance(dst, Pod) and not (src, dst) in union_allowed_set:
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
            if isinstance(src, Pod) and isinstance(dst, Pod) and not (src, dst) in results_set_orig:
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

    def get_ns_product_peer_pairs(self, src_ns, dst_ns):
        return [(src, dst) for src in self.cluster_info.ns_dict[src_ns] for dst in self.cluster_info.ns_dict[dst_ns]]

    def get_pods_set_per_fixed_elem_from_peer_pairs(self, is_src_fixed, fixed_elem, peer_pairs_list):
        if is_src_fixed:
            return [dest for (src, dest) in peer_pairs_list if src == fixed_elem and isinstance(dest, Pod)]
        return [src for (src, dest) in peer_pairs_list if dest == fixed_elem and isinstance(src, Pod)]

    def get_peer_pairs_product_for_ns_and_fixed_elem(self, is_pod_in_src, pod, ns):
        if is_pod_in_src:
            return set([(pod, dst_pod) for dst_pod in self.cluster_info.ns_dict[ns]])
        return set([(src_pod, pod) for src_pod in self.cluster_info.ns_dict[ns]])

    def get_ns_covered_in_one_dimension(self, is_src_fixed, fixed_elem):
        pods_set = self.get_pods_set_per_fixed_elem_from_peer_pairs(is_src_fixed, fixed_elem,
                                                                    self.peer_pairs_without_ns_expr)
        ns_set = set([e.namespace for e in pods_set])
        covered_ns_set = set()
        peer_pairs_product_union = set()
        for ns in ns_set:
            peer_pairs_product = self.get_peer_pairs_product_for_ns_and_fixed_elem(is_src_fixed, fixed_elem, ns)
            if peer_pairs_product.issubset(self.covered_peer_pairs_union):
                covered_ns_set.add(ns)
                peer_pairs_product_union.update(peer_pairs_product)
            # else:
            #    print('get_ns_covered_in_one_dimension could not group by ns following:')
            #    print('pod: ' + str(fixed_elem) + ' ns: ' + str(ns))
            #    missing_pods = [pod for pod in peer_pairs_product if pod not in self.covered_peer_pairs_union  ]
            #    print('missing pairs: ' + ','.join(str(pod) for pod in  missing_pods))
        return covered_ns_set, peer_pairs_product_union

    def compute_ns_pairs_with_partial_ns_expr(self, is_src_ns):
        pod_set = set([src for (src, _) in self.peer_pairs_without_ns_expr]) if not is_src_ns else set(
            [dst for (_, dst) in self.peer_pairs_without_ns_expr])
        for pod in pod_set:
            covered_ns_set, peer_pairs_product_union = self.get_ns_covered_in_one_dimension(not is_src_ns, pod)
            for ns in covered_ns_set:
                partial_ns_expr_pair = (pod, ns) if not is_src_ns else (ns, pod)
                self.peer_pairs_with_partial_ns_expr.append(partial_ns_expr_pair)
            self.peer_pairs_without_ns_expr = set(self.peer_pairs_without_ns_expr) - peer_pairs_product_union
        return

    # remove trivial pairs to avoid creating them a fw-rule directly
    def remove_trivial_rules_from_peer_pairs_without_ns_expr(self):
        trivial_pairs = set([(src, dst) for (src, dst) in self.peer_pairs_without_ns_expr if src == dst])
        self.peer_pairs_without_ns_expr = set(self.peer_pairs_without_ns_expr) - trivial_pairs
        return

    def get_ns_fw_rules_grouped_by_common_elem(self, is_src_fixed, ns_list, fixed_elem):
        # currently no grouping of ns-list by labels of namespaces
        grouped_elem = FWRuleElement(set(ns_list))
        if is_src_fixed:
            fw_rule = FWRule(fixed_elem, grouped_elem, self.connections)
        else:
            fw_rule = FWRule(grouped_elem, fixed_elem, self.connections)
        return [fw_rule]

    def get_pods_grouping_by_labels_main(self, pods_list, extra_pods_list):
        """
        The main function to implement pods grouping by labels.
        This function splits the pods into namespaces, anc per ns calls  get_pods_grouping_by_labels().
        :param pods_list: the pods for grouping
        :param extra_pods_list: additional pods that can be used for grouping
        :return:
        res_chosen_rep: a list of tuples (key,values,ns) -- as the chosen representation for grouping the pods.
        res_remaining_pods: set of pods from pods_list that are not included in the grouping result (could not be grouped).
        """
        ns_context_options = set([pod.namespace for pod in pods_list])
        res_chosen_rep = []
        res_remaining_pods = set()
        # grouping by pod-labels per each namespace separately
        for ns in ns_context_options:
            pods_list_per_ns = set(pods_list).intersection(set(self.cluster_info.ns_dict[ns]))
            extra_pods_list_per_ns = set(extra_pods_list).intersection(set(self.cluster_info.ns_dict[ns]))
            chosen_rep, remaining_pods = self.get_pods_grouping_by_labels(pods_list_per_ns, ns, extra_pods_list_per_ns)
            res_chosen_rep.extend(chosen_rep)
            res_remaining_pods.update(remaining_pods)
        return res_chosen_rep, res_remaining_pods

    def get_pods_grouping_by_labels(self, pods_list, ns, extra_pods_list):
        """
        Implements pods grouping by labels in a single namespace.
        :param pods_list: the list pod pods for grouping.
        :param ns: the namespace
        :param extra_pods_list: additional pods that can be used for completing the grouping (originated in containing connections).
        :return:
        chosen_rep:  a list of tuples (key,values,ns) -- as the chosen representation for grouping the pods.
        remaining_pods: set of pods from pods_list that are not included in the grouping result
        """
        if self.output_config.fwRulesDebug:
            print('get_pods_grouping_by_labels:')
            print('pods_list: ' + ','.join([str(pod) for pod in pods_list]))
            print('extra_pods_list: ' + ','.join([str(pod) for pod in extra_pods_list]))
        all_pods_list = set(pods_list).union(set(extra_pods_list))
        allowed_labels = self.cluster_info.allowed_labels
        labels_rep_options = []
        for key in allowed_labels:
            values_for_key = self.cluster_info.get_values_set_for_key(key)
            fully_covered_label_values = []
            pods_with_fully_covered_label_values = set()
            for v in values_for_key:
                all_pods_per_label_val = set(self.cluster_info.pods_labels_map[(key, v)]).intersection(
                    set(self.cluster_info.ns_dict[ns]))
                if len(all_pods_per_label_val) == 0:
                    continue
                pods_with_label_val_from_pods_list = all_pods_per_label_val.intersection(set(all_pods_list))
                pods_with_label_val_from_original_pods_list = all_pods_per_label_val.intersection(set(pods_list))
                if all_pods_per_label_val == pods_with_label_val_from_pods_list and len(
                        pods_with_label_val_from_original_pods_list) > 0:
                    fully_covered_label_values.append(v)
                    pods_with_fully_covered_label_values.update(pods_with_label_val_from_pods_list)
            # TODO: is it OK to ignore label-grouping if only one pod is involved?
            if self.output_config.fwRulesGroupByLabelSinglePod:
                if len(fully_covered_label_values) > 0 and len(
                        pods_with_fully_covered_label_values) >= 1:  # don't ignore label-grouping if only one pod is involved
                    labels_rep_options.append((key, (fully_covered_label_values, pods_with_fully_covered_label_values)))
            else:
                if len(fully_covered_label_values) > 0 and len(
                        pods_with_fully_covered_label_values) > 1:  # ignore label-grouping if only one pod is involved
                    labels_rep_options.append((key, (fully_covered_label_values, pods_with_fully_covered_label_values)))

        chosen_rep = []
        remaining_pods = set(pods_list).copy()
        sorted_rep_options = sorted(labels_rep_options, key=lambda x: len(x[1][1]), reverse=True)
        if self.output_config.fwRulesDebug:
            print('sorted rep options:')
            for index in range(0, len(sorted_rep_options)):
                (key, (label_vals, pods)) = sorted_rep_options[index]
                print(key, label_vals)
        ns_info = {ns}
        # ns_info.add(ns)
        for (k, (vals, pods)) in sorted_rep_options:
            # if len(set(pods).intersection(remaining_pods)) > 0:  # set(pods).issubset(remaining_pods):
            if (set(pods).intersection(pods_list)).issubset(remaining_pods):
                chosen_rep.append((k, vals, ns_info))
                remaining_pods -= pods
            if len(remaining_pods) == 0:
                break
        return chosen_rep, remaining_pods

    def get_pod_level_fw_rules_grouped_by_common_labels(self, is_src_fixed, pods_list, fixed_elem, extra_pods_list):
        """
        Implements grouping in the level of pods labels.
        :param is_src_fixed: a bool flag to indicate if fixed_elem is at src or dst.
        :param pods_list: the list of pods to be grouped
        :param fixed_elem: the fixed element of the original fw-rules
        :param extra_pods_list: an additional pods list from containing connections (with same fixed_elem) that can be
        used for grouping (completing for a set of pods to cover some label grouping).
        :return: a set of fw-rules result after grouping
        """
        res = []
        # (1) try grouping by pods-labels:
        chosen_rep, remaining_pods = self.get_pods_grouping_by_labels_main(pods_list, extra_pods_list)
        for (key, values, ns_info) in chosen_rep:
            pod_label_expr = LabelExpr(key, values)
            grouped_elem = PodLabelsElement(pod_label_expr, ns_info)
            if is_src_fixed:
                fw_rule = FWRule(fixed_elem, grouped_elem, self.connections)
            else:
                fw_rule = FWRule(grouped_elem, fixed_elem, self.connections)
            res.append(fw_rule)

        # TODO: should avoid having single pods remaining without labels grouping
        # (2) add rules for remaining single pods:
        for pod in remaining_pods:
            single_pod_elem = PodElement(pod)
            if is_src_fixed:
                fw_rule = FWRule(fixed_elem, single_pod_elem, self.connections)
            else:
                fw_rule = FWRule(single_pod_elem, fixed_elem, self.connections)
            res.append(fw_rule)
        return res

    @staticmethod
    def create_fw_elem(base_elem):
        if isinstance(base_elem, Pod):
            return PodElement(base_elem)
        elif isinstance(base_elem, IpBlock):
            ip_blocks_list = base_elem.split()
            if len(ip_blocks_list) == 1:
                return IPBlockElement(base_elem)
            else:
                return [IPBlockElement(ip) for ip in ip_blocks_list]
        # a K8sNamespace instance
        elif isinstance(base_elem, K8sNamespace):
            return FWRuleElement([base_elem])
        # unknown base-elem type
        return None

    def create_initial_fw_rule(self, src, dst):
        src_elem = self.create_fw_elem(src)
        dst_elem = self.create_fw_elem(dst)
        if self.output_config.fwRulesRunInTestMode:
            assert src_elem is not None and dst_elem is not None
        if isinstance(src_elem, list):
            return [FWRule(src, dst_elem, self.connections) for src in src_elem]
        if isinstance(dst_elem, list):
            return [FWRule(src_elem, dst, self.connections) for dst in dst_elem]
        return [FWRule(src_elem, dst_elem, self.connections)]

    # elems_list is a list of pairs (src,dst) , each of type: Pod/K8sNamespace/IpBlock
    def create_initial_fw_rules_from_base_elements_list(self, elems_list):
        res = []
        for (src, dst) in elems_list:
            res.extend(self.create_initial_fw_rule(src, dst))
        return res

    def create_all_initial_fw_rules(self):
        """
        Creating initial fw-rules from base-elements pairs (pod/ns/ip-block)
        :return: a list of initial fw-rules of type FWRule
        """
        initial_fw_rules = []
        initial_fw_rules.extend(self.create_initial_fw_rules_from_base_elements_list(self.ns_pairs))
        initial_fw_rules.extend(self.create_initial_fw_rules_from_base_elements_list(self.peer_pairs_without_ns_expr))
        initial_fw_rules.extend(
            self.create_initial_fw_rules_from_base_elements_list(self.peer_pairs_with_partial_ns_expr))
        return initial_fw_rules

    '''
    def simplify_fw_rule(self, rule, is_src_label_exp):
        pod = rule.dst.element if is_src_label_exp else rule.src.element
        pod_keys = set([key for (key, val) in pod.labels.items()])
        label_exp = rule.src.element if is_src_label_exp else rule.dst.element
        # TODO: handle _AND_ labels
        if label_exp.key in pod_keys:
            pod_val = pod.labels[label_exp.key]
            pods_with_val = self.cluster_info.pods_labels_map[(label_exp.key, pod_val)]
            if len(pods_with_val) == 1:
                label_exp.values = set(label_exp.values) - {pod_val}

    def post_processing_fw_rules(self, rules):
        # simplify rules between one pod to a label-expr: remove label-val of pod to itself if possible
        for rule in rules:
            if isinstance(rule.src, PodElement) and isinstance(rule.dst, PodLabelsElement):
                self.simplify_fw_rule(rule, False)
            elif isinstance(rule.dst, PodElement) and isinstance(rule.src, PodLabelsElement):
                self.simplify_fw_rule(rule, True)
    '''

    def add_all_fw_rules(self):
        """
        Computation of fw-rules, following the ns-grouping of peer_pairs.
        Results are at: self.minimized_rules_set
        :return: None
        """
        # create initial fw-rules from ns_pairs, peer_pairs_with_partial_ns_expr, peer_pairs_without_ns_expr
        initial_fw_rules = self.create_all_initial_fw_rules()
        # option1 - start computation when src is fixed at first iteration, and merge applies to dst
        option1, convergence_iteration_1 = self.create_merged_rules_set(True, initial_fw_rules)
        # option2 - start computation when dst is fixed at first iteration, and merge applies to src
        option2, convergence_iteration_2 = self.create_merged_rules_set(False, initial_fw_rules)

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
            self.print_firewall_rules(option1)
            print('option 2 rules: ')
            self.print_firewall_rules(option2)

        # choose the option with less fw-rules
        if len(option1) < len(option2):
            self.minimized_rules_set.extend(option1)
            return
        self.minimized_rules_set.extend(option2)

    def get_ns_set_from_elements_list(self, elems_list):
        ns_set_list = [f.ns_info for f in elems_list]
        return set([ns for ns_set in ns_set_list for ns in ns_set])

    def get_grouping_result(self, fixed_elem, set_for_grouping_elems, src_first):
        """
        Apply grouping for a set of elements to create grouped fw-rules
        :param fixed_elem: the fixed elements from the original fw-rules
        :param set_for_grouping_elems: the set of elements to be grouped
        :param src_first: a bool flag to indicate if fixed_elem is src or dst
        :return: A list of fw-rules after possible grouping operations
        """
        res = []
        fw_rule_elem_type = type(FWRuleElement([]))
        # partition set_for_grouping_elems into: (1) ns_elems, (2) pod_and_pod_labels_elems, (3) ip_block_elems
        ns_elems = set([elem for elem in set_for_grouping_elems if type(elem) == fw_rule_elem_type])
        pod_and_pod_labels_elems = [elem for elem in set_for_grouping_elems if
                                    isinstance(elem, PodElement) or isinstance(elem, PodLabelsElement)]

        ip_block_elems = [elem for elem in set_for_grouping_elems if isinstance(elem, IPBlockElement)]

        if len(ns_elems) > 0:
            ns_list = self.get_ns_set_from_elements_list(ns_elems)
            res.extend(self.get_ns_fw_rules_grouped_by_common_elem(src_first, ns_list, fixed_elem))

        if len(pod_and_pod_labels_elems) > 0:
            # TODO: currently adding this due to example in test24, where single pod-labels elem is replaced by another grouping
            if len(pod_and_pod_labels_elems) == 1 and isinstance(pod_and_pod_labels_elems[0], PodLabelsElement):
                elem = pod_and_pod_labels_elems[0]
                fw_rule = FWRule(fixed_elem, elem, self.connections) if src_first else FWRule(elem, fixed_elem,
                                                                                              self.connections)
                res.append(fw_rule)
            else:
                set_for_grouping_pods = []
                for e in pod_and_pod_labels_elems:
                    set_for_grouping_pods.extend(set(e.get_pods_set(self.cluster_info)))

                # allow borrowing pods for labels-grouping from covered_peer_pairs_union
                fixed_elem_pods = fixed_elem.get_pods_set(self.cluster_info)
                extra_pods_list = []
                for p in fixed_elem_pods:
                    if src_first:
                        pods_to_add = set([dst for (src, dst) in self.covered_peer_pairs_union if src == p])
                    else:
                        pods_to_add = set([src for (src, dst) in self.covered_peer_pairs_union if dst == p])
                    extra_pods_list.append(pods_to_add)
                extra_pods_list_common = []
                if len(extra_pods_list) > 0:
                    extra_pods_list_common = set.intersection(*extra_pods_list)

                res.extend(self.get_pod_level_fw_rules_grouped_by_common_labels(src_first, set_for_grouping_pods,
                                                                                fixed_elem, extra_pods_list_common))

        if len(ip_block_elems) > 0:
            ip_block_union = ip_block_elems[0].element.copy()
            # merged_ip_block = ip_block_elems[0]
            for ip in ip_block_elems:
                ip_block_union |= ip.element
            ip_intervals_list = ip_block_union.split()
            for ip in ip_intervals_list:
                elem = IPBlockElement(ip)
                if src_first:
                    res.append(FWRule(fixed_elem, elem, self.connections))
                else:
                    res.append(FWRule(elem, fixed_elem, self.connections))

            # currently no grouping for ip blocks
            # for elem in ip_block_elems:
            #    if src_first:
            #        res.append(FWRule(fixed_elem, elem, self.connections))
            #    else:
            #        res.append(FWRule(elem, fixed_elem, self.connections))

        return res

    def create_merged_rules_set(self, is_src_first, fw_rules):
        """
        Computing a minimized set of fw-rules by merging at src/dst
        :param is_src_first: a bool flag to indicate if mere process starts with src or dest
        :param fw_rules: a list of initial fw-rules
        :return: a list of minimized fw-rules after merge process
        """
        initial_fw_rules = fw_rules.copy()
        if len(initial_fw_rules) == 0:
            return [], 0
        fw_rules_after_merge = []
        count_fw_rules = dict()  # map number of fw-rules per iteration number
        max_iter = self.output_config.fwRulesMaxIter
        convergence_iteration = max_iter
        for i in range(0, max_iter):
            count_fw_rules[i] = len(initial_fw_rules)
            if i > 1 and count_fw_rules[i] == count_fw_rules[i - 1]:
                convergence_iteration = i
                break
            if i > 1 and self.output_config.fwRulesRunInTestMode:
                assert count_fw_rules[i - 1] > count_fw_rules[i], "Expecting fewer fw_rules after each merge iteration."
            src_first = (i % 2 == 0) if is_src_first else (i % 2 == 1)
            first_elem_set = set([f.src for f in initial_fw_rules]) if src_first else set(
                [f.dst for f in initial_fw_rules])
            for elem in first_elem_set:
                if src_first:
                    # TODO: equals or contained in?
                    set_for_grouping_elems = set([f.dst for f in initial_fw_rules if f.src == elem])
                else:
                    set_for_grouping_elems = set([f.src for f in initial_fw_rules if f.dst == elem])
                res = self.get_grouping_result(elem, set_for_grouping_elems, src_first)
                fw_rules_after_merge.extend(res)
            # prepare for next iteration
            initial_fw_rules = fw_rules_after_merge
            fw_rules_after_merge = []
            if self.output_config.fwRulesDebug:
                print('fw rules after iteration: ' + str(i))
                self.print_firewall_rules(initial_fw_rules)

        return initial_fw_rules, convergence_iteration


# ==================================================================================================================

class MinimizeFWRules:
    """
    This is a class for minimizing and handling fw-rules globally for all connection sets
    """

    def __init__(self, fw_rules_map, query_name, cluster_info, output_config, results_map):
        self.fw_rules_map = fw_rules_map
        self.query_name = query_name
        self.cluster_info = cluster_info
        self.output_config = output_config
        self.results_map = results_map

    # print to stdout the final fw rules (in txt format)
    def print_final_fw_rules(self):
        print('----------------------------------------------------------')
        header = 'final fw rules'
        if len(self.query_name) > 0:
            header += ' for: ' + self.query_name
        print(header + ':')
        output_rules = sorted(list(self.get_rules_str_values()))
        print(''.join(line for line in output_rules))

        '''
        if self.run_in_test_mode:
            comparison_to_ref = self.compare_final_rules_with_ref_file()
            print('comparison_to_ref: ' + str(comparison_to_ref))
            self.write_rules_to_yaml()
            self.write_results_to_file()
        '''

    def create_output_yaml_file(self):
        actual_content = self._get_all_rules_yaml_obj()
        file_name = self.output_config.fwRulesYamlOutputPath
        query_content = [{'query': self.query_name, 'rules': actual_content}]
        self._write_yaml_res_file(file_name, query_content)

    def get_rules_str_values(self):
        res = []
        all_connections = set(self.fw_rules_map.keys())
        for connection in all_connections:
            connection_rules = self.fw_rules_map[connection]
            for rule in connection_rules:
                # if rule.is_rule_trivial():
                #    continue
                if self.output_config.fwRulesFilterSystemNs and rule.should_rule_be_filtered_out():
                    continue
                rule_str = str(rule) + '\n'
                res.append(rule_str)
        # several rules can be mapped to the same str, since pods are mapped to owner name (example: semantic_diff_named_ports)
        return set(res)

    @staticmethod
    def _write_yaml_res_file(file_name, content):
        with open(file_name, 'a') as f:
            yaml.dump(content, f, default_flow_style=False, sort_keys=False)

    def _get_all_rules_yaml_obj(self):
        rules = []
        all_connections = set(self.fw_rules_map.keys())
        for connection in all_connections:
            connection_rules = self.fw_rules_map[connection]
            for rule in connection_rules:
                if self.output_config.fwRulesFilterSystemNs and rule.should_rule_be_filtered_out():
                    continue
                rule_obj = self._get_rule_yaml_obj(rule)
                rules.append(rule_obj)
        return rules

    @staticmethod
    def _get_rule_yaml_obj(rule):
        src_ns_list = [str(ns) for ns in rule.src.ns_info]
        dst_ns_list = [str(ns) for ns in rule.dst.ns_info]
        src_pods_list = rule.src.get_pods_yaml_obj() if not isinstance(rule.src, IPBlockElement) else None
        dst_pods_list = rule.dst.get_pods_yaml_obj() if not isinstance(rule.dst, IPBlockElement) else None
        src_ip_block_list = rule.src.get_ip_cidr_list() if isinstance(rule.src, IPBlockElement) else None
        dst_ip_block_list = rule.dst.get_ip_cidr_list() if isinstance(rule.dst, IPBlockElement) else None
        conn_list = rule.conn.get_connections_list()

        rule_obj = {}
        if src_ip_block_list is None and dst_ip_block_list is None:
            rule_obj = {'src_ns': src_ns_list,
                        'src_pods': src_pods_list,
                        'dst_ns': dst_ns_list,
                        'dst_pods': dst_pods_list,
                        'connection': conn_list}
        elif src_ip_block_list is not None:
            rule_obj = {'src_ip_block': src_ip_block_list,
                        'dst_ns': dst_ns_list,
                        'dst_pods': dst_pods_list,
                        'connection': conn_list}

        elif dst_ip_block_list is not None:
            rule_obj = {'src_ns': src_ns_list,
                        'src_pods': src_pods_list,
                        'dst_ip_block': dst_ip_block_list,
                        'connection': conn_list}
        return rule_obj



    '''
    @staticmethod
    def convert_rule_obj_to_str(rule_obj):
        res = ''
        if 'src_ns' in rule_obj:
            res += 'src_ns: ' + ','.join(ns for ns in sorted(rule_obj['src_ns'])) + ';'
        if 'src_pods' in rule_obj:
            res += 'src_pods: ' + ','.join(pod for pod in sorted(rule_obj['src_pods'])) + ';'
        if 'src_ip_block' in rule_obj:
            res += 'src_ip_block: ' + ','.join(ip for ip in sorted(rule_obj['src_ip_block'])) + ';'
        if 'dst_ns' in rule_obj:
            res += 'dst_ns: ' + ','.join(ns for ns in sorted(rule_obj['dst_ns'])) + ';'
        if 'dst_pods' in rule_obj:
            res += 'dst_pods: ' + ','.join(pod for pod in sorted(rule_obj['dst_pods'])) + ';'
        if 'dst_ip_block' in rule_obj:
            res += 'dst_ip_block: ' + ','.join(ip for ip in sorted(rule_obj['dst_ip_block'])) + ';'

        if 'connection' in rule_obj:
            res += 'connection: '
            if rule_obj['connection'][0] == 'All connections':
                res += 'All connections' + ';'
            else:
                for conn_obj in rule_obj['connection']:
                    conn_str = ''
                    if 'Protocol' in conn_obj:
                        conn_str += 'Protocol: ' + conn_obj['Protocol'] + ';'
                    if 'Ports' in conn_obj:
                        conn_str += 'Ports: ' + ','.join(str(ports) for ports in conn_obj['Ports']) + ';'
                    res += conn_str
        return res
    
    def compare_yaml_output_rules(self, expected, actual):
        # create for each yaml obj rule its str. sort array entries
        expected_str_list = []
        actual_str_list = []
        for rule_obj in expected:
            res = self.convert_rule_obj_to_str(rule_obj)
            expected_str_list.append(res)
        for rule_obj in actual:
            res = self.convert_rule_obj_to_str(rule_obj)
            actual_str_list.append(res)
        res = (set(expected_str_list) == set(actual_str_list))
        # TODO: verify len of set equals to list (no two different objects mapped to the same str)
        return res
    
    @staticmethod
    def write_txt_res_file(file_name, content):
        with open(file_name, 'a') as f:
            for r in content:
                f.write(r)
        return

    def get_yaml_comparison_result(self):
        actual_content = self.get_all_rules_yaml_obj()

        # file_name = self.config.expected_results_files['yaml']
        file_name = self.config.expected_fw_rules_yaml
        if len(file_name) == 0 or not os.path.isfile(file_name):
            # no comparison
            print('warning: no comparison of yaml results, file name is: ' + file_name)
            if self.config.create_output_files:
                self.create_default_results_file(actual_content, 'yaml')
            return True

        with open(file_name) as f:
            expected_content = yaml.safe_load(f)

        res = self.compare_yaml_output_rules(expected_content, actual_content)
        # if not res and self.config.override_result_file:
        #    print('warning: overridden file with new results at: ' + str(file_name))
        #    self.write_yaml_res_file(file_name, actual_content)
        print('------------------------------------')
        print('comparison result of yaml output: ' + str(res))

        return res

    def get_txt_comparison_result(self):
        actual_content = self.get_rules_str_values()

        file_name = self.config.expected_results_files['txt']
        if len(file_name) == 0 or not os.path.isfile(file_name):
            # no comparison
            print('warning: no comparison of txt results, file name is: ' + file_name)
            if self.config.create_output_files:
                self.create_default_results_file(actual_content, 'txt')
            return True

        with open(file_name) as f:
            expected_content = f.readlines()

        res = set(actual_content) == set(expected_content)
        if not res and self.config.override_result_file:
            print('warning: overridden file with new results at: ' + str(file_name))
            os.remove(file_name)
            self.write_txt_res_file(file_name, actual_content)
        return res

    def get_comparison_results(self):
        # txt_res = self.get_txt_comparison_result()
        yaml_res = self.get_yaml_comparison_result()
        return yaml_res

    
    # in case there is no results file for comparison, creating a default results file
    def create_default_results_file(self, content, file_type):
        Path(self.config.default_results_dir).mkdir(parents=True, exist_ok=True)
        file_name = os.path.join(self.config.default_results_dir, self.config.default_res_file_name + "." + file_type)
        if file_type == "txt":
            self.write_txt_res_file(file_name, content)
        elif file_type == "yaml":
            self.write_yaml_res_file(file_name, content)
        print('created default results file at: ' + file_name)
    
    def get_output_file_name(self, file_type):
        if file_type == 'txt' or file_type == 'yaml':
            return os.path.join('fw_rules_output', self.config_name + "." + file_type)
        # return empty string for unknown file_type
        return ''
    
    # for debug : text-based comparison of expected rules with actual rules
    def compare_final_rules_with_ref_file(self):
        file_name = self.get_output_file_name("txt")
        if not os.path.isfile(file_name):
            self.write_final_rules_to_file()

        with open(file_name) as f:
            content = f.readlines()
        expected_content = self.get_rules_str_values()
        res = set(content) == set(expected_content)
        if not res:
            # override file with new/current results:
            os.remove(file_name)
            self.write_final_rules_to_file()
            print('warning: overridden file with new results at: ' + str(file_name))

        return res
    
    def write_final_rules_to_file(self):
        file_name = self.get_output_file_name("txt")
        rules_str_values = self.get_rules_str_values()
        with open(file_name, 'a') as the_file:
            for r in rules_str_values:
                the_file.write(r)
        return
    
    def write_rules_to_yaml(self):
        rules = self.get_all_rules_yaml_obj()

        output_file = self.get_output_file_name("yaml")
        if len(output_file) > 0:
            with open(output_file, 'w') as f:
                # yaml.dump(rules, f, default_flow_style=False)
                yaml.dump(rules, f, default_flow_style=False, sort_keys=False)
                print(f'\nFirewall rules were successfully written to {output_file}')
        else:
            print(yaml.dump_all(rules))

    def write_results_to_file(self):
        res_file_name = os.path.join('fw_rules_output', self.config_name + "_res.txt")
        f = open(res_file_name, "w")
        for conn in self.results_map.keys():
            conn_obj = self.results_map[conn]
            conn_obj_str_list = []
            for key in conn_obj:
                conn_obj_str_list.append(str(key) + ':' + str(conn_obj[key]))
            f.write('\nconnection: ' + str(conn) + '\n')
            f.write('\n'.join(l for l in conn_obj_str_list))
        f.close()
        return
    '''
