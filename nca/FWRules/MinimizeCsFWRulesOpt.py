#
# Copyright 2020- IBM Inc. All rights reserved
# SPDX-License-Identifier: Apache2.0
#

from collections import defaultdict
from nca.CoreDS.ConnectionSet import ConnectionSet
from nca.CoreDS.ConnectivityProperties import ConnectivityProperties
from nca.CoreDS.Peer import IpBlock, ClusterEP, HostEP, DNSEntry, PeerSet, Pod
from nca.Resources.OtherResources.K8sNamespace import K8sNamespace
from .FWRule import FWRuleElement, FWRule, PodElement, PeerSetElement, LabelExpr, PodLabelsElement, IPBlockElement, \
    DNSElement
from .MinimizeBasic import MinimizeBasic


class MinimizeCsFwRulesOpt(MinimizeBasic):
    """
    This is a class for minimizing fw-rules within a specific connection-set
    """

    def __init__(self, cluster_info, output_config):
        """
        create an object of MinimizeCsFwRules
        :param cluster_info:  an object of type ClusterInfo, with relevant cluster topology info
        :param output_config: an OutputConfiguration object

        """
        super().__init__(cluster_info, output_config)
        self.peer_props = ConnectivityProperties()
        self.connections = ConnectionSet()
        self.peer_props_in_containing_connections = ConnectivityProperties()
        self.ns_set_pairs = set()
        self.peer_pairs_with_partial_ns_expr = set()
        self.peer_props_without_ns_expr = ConnectivityProperties()
        self.covered_peer_props = ConnectivityProperties()
        self.results_info_per_option = dict()
        self.minimized_fw_rules = []  # holds the computation result of minimized fw-rules

    def compute_minimized_fw_rules_per_connection(self, connections, peer_props,
                                                  peer_props_in_containing_connections):
        """
        The main function for creating the minimized set of fw-rules for a given connection set

        :param connections: the allowed connections for the given peer pairs, of type ConnectionSet
        :param ConnectivityProperties peer_props: peers (src,dst) for which communication is allowed over the given connections
        :param ConnectivityProperties peer_props_in_containing_connections: peers in connections that contain the current
               connection set

        class members used in computation of fw-rules:
        self.ns_set_pairs : pairs of sets of namespaces, grouped together
        self.peer_pairs_with_partial_ns_expr: pairs of (peer,ns) or (ns,peer), with ns-grouping for one dimension
        self.peer_pairs_without_ns_expr: pairs of pods, with no possible ns-grouping
        self.covered_peer_pairs_union: union (set) of all peer pairs for which communication is allowed in current
                                      connection-set (but not necessarily only limited to current connection set)

        :return:
        minimized_fw_rules: a list of fw-rules (of type list[FWRule])
        (results_info_per_option: for debugging, dict with some info about the computation)
        """
        self.peer_props = peer_props
        self.connections = connections
        self.peer_props_in_containing_connections = peer_props_in_containing_connections
        self.ns_set_pairs = set()
        self.peer_pairs_with_partial_ns_expr = set()
        self.peer_props_without_ns_expr = ConnectivityProperties()
        self.covered_peer_props = ConnectivityProperties()
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
        # partition peer_props to ns_set_pairs, peer_pairs_with_partial_ns_expr, peer_props_without_ns_expr
        self._compute_basic_namespace_grouping()

        # add all fw-rules:
        self._add_all_fw_rules()

    def _compute_basic_namespace_grouping(self):
        """
        computation of peer_pairs with possible grouping by namespaces.
        Results are at: ns_set_pairs, peer_pairs_with_partial_ns_expr, peer_pairs_without_ns_expr
        :return: None
        """
        self._compute_covered_peer_props()
        # only Pod elements have namespaces (skipping IpBlocks and HostEPs)
        all_src_ns_set = set(src.namespace for src in self.covered_peer_props.project_on_one_dimension("src_peers")
                             if isinstance(src, Pod))
        all_dst_ns_set = set(dst.namespace for dst in self.covered_peer_props.project_on_one_dimension("dst_peers")
                             if isinstance(dst, Pod))
        # per relevant namespaces, compute which pairs of src-ns and dst-ns are covered by given peer-pairs
        src_ns_to_dst_ns = defaultdict(set)
        for src_ns in all_src_ns_set:
            for dst_ns in all_dst_ns_set:
                ns_product_props = \
                    ConnectivityProperties.make_conn_props_from_dict({"src_peers": PeerSet(self.cluster_info.ns_dict[src_ns]),
                                                                      "dst_peers": PeerSet(self.cluster_info.ns_dict[dst_ns])})
                if ns_product_props.contained_in(self.covered_peer_props):
                    self.covered_peer_props -= ns_product_props
                    if ns_product_props & self.peer_props:
                        # ensure that the found ns-pair is at least partially included in the current connections' properties
                        # (rather than being wholly contained in containing connections' properties)
                        src_ns_to_dst_ns[src_ns].add(dst_ns)
                else:
                    self.peer_props_without_ns_expr |= ns_product_props & self.peer_props
        dst_ns_to_src_ns = defaultdict(set)
        for src_ns, dst_ns_set in src_ns_to_dst_ns.items():
            dst_ns_to_src_ns[frozenset(dst_ns_set)].add(src_ns)
        for dst_ns_set, src_ns_set in dst_ns_to_src_ns.items():
            self.ns_set_pairs.add((frozenset(src_ns_set), dst_ns_set))

        # TODO: what about peer pairs with ip blocks from containing connections, not only peer_pairs for this connection?
        src_peers_without_ns = PeerSet(set(src for src in self.peer_props.project_on_one_dimension("src_peers")
                                           if isinstance(src, (IpBlock, HostEP, DNSEntry))))
        dst_peers_without_ns = PeerSet(set(dst for dst in self.peer_props.project_on_one_dimension("dst_peers")
                                           if isinstance(dst, (IpBlock, HostEP, DNSEntry))))
        props_with_elems_without_ns = \
            ConnectivityProperties.make_conn_props_from_dict({"src_peers": src_peers_without_ns}) |\
            ConnectivityProperties.make_conn_props_from_dict({"dst_peers": dst_peers_without_ns})
        self.peer_props_without_ns_expr |= props_with_elems_without_ns & self.peer_props
        # compute pairs with src as pod/ip-block and dest as namespace
        self._compute_peer_pairs_with_partial_ns_expr(all_dst_ns_set, False)
        # compute pairs with src as pod/ip-block namespace dest as pod
        if self.peer_props_without_ns_expr:
            self._compute_peer_pairs_with_partial_ns_expr(all_src_ns_set, True)

    def _compute_covered_peer_props(self):
        """
        compute the union (set) of all peer pairs for which communication is allowed in current connection-set (but
        not necessarily only limited to current connection set)
        :return: None
        """
        covered_peer_props = self.peer_props | self.peer_props_in_containing_connections
        all_peers_set = self.peer_props.project_on_one_dimension("src_peers") |\
            self.peer_props.project_on_one_dimension("dst_peers")
        for pod in all_peers_set:
            if isinstance(pod, ClusterEP):
                covered_peer_props |= ConnectivityProperties.make_conn_props_from_dict({"src_peers": PeerSet({pod}),
                                                                                        "dst_peers": PeerSet({pod})})
        self.covered_peer_props = covered_peer_props

    def _compute_peer_pairs_with_partial_ns_expr(self, ns_set, is_src_ns):
        """
        computes and updates self.peer_pairs_with_partial_ns_expr with pairs where only one elem (src/dst)
        can be grouped to an entire namespace
        :param is_src_ns: a bool flag to indicate if computing pairs with src elem grouped as ns (True) or dst (False)
        :return: None
        """
        # pod_set is the set of pods in pairs of peer_pairs_without_ns_expr, within elem type (src/dst) which is not
        # in the grouping computation

        dim_name = "src_peers" if is_src_ns else "dst_peers"
        other_dim_name = "dst_peers" if is_src_ns else "src_peers"
        # We search for partial ns grouping in self.covered_peer_props rather than in self.peer_props_without_ns_expr,
        # thus allowing overlapping of fw rules. Also, we start from optimal order between src_peers and dst_peers,
        # based on whether we search for whole src or dst namespace.
        props = self.covered_peer_props.reorder_by_switching_src_dst_peers() if is_src_ns else self.covered_peer_props
        ns_set_to_peer_set = defaultdict(PeerSet)
        for cube in props:
            conn_cube = props.get_connectivity_cube(cube)
            dim_peers = conn_cube[dim_name]
            other_dim_peers = conn_cube[other_dim_name].canonical_form()
            curr_ns_set = set()
            curr_ns_peers = PeerSet()
            for ns in ns_set:
                ns_peers = PeerSet(self.cluster_info.ns_dict[ns])
                curr_covered = ConnectivityProperties.make_conn_props_from_dict({dim_name: ns_peers,
                                                                                 other_dim_name: other_dim_peers})
                if ns_peers.issubset(dim_peers) and (curr_covered & self.peer_props_without_ns_expr):
                    curr_ns_set.add(ns)
                    curr_ns_peers |= ns_peers
            if curr_ns_set:
                ns_set_to_peer_set[frozenset(curr_ns_set)] |= other_dim_peers
        for curr_ns_set, other_dim_peers in ns_set_to_peer_set.items():
            curr_ns_peers = PeerSet(set.union(*[self.cluster_info.ns_dict[ns] for ns in curr_ns_set]))
            other_dim_peers_without_ip_block = PeerSet(other_dim_peers.get_set_without_ip_block())
            other_dim_peers_ip_block = other_dim_peers.get_ip_block_canonical_form().get_peer_set()
            curr_covered_without_ip_block = \
                ConnectivityProperties.make_conn_props_from_dict({dim_name: curr_ns_peers,
                                                                  other_dim_name: other_dim_peers_without_ip_block})
            curr_covered_ip_block = \
                ConnectivityProperties.make_conn_props_from_dict({dim_name: curr_ns_peers,
                                                                  other_dim_name: other_dim_peers_ip_block})
            # ensure that the found pairs (with and without IpBlocks) are at least partially included
            # in the current connections' properties (rather than being wholly contained
            # in containing connections' properties)
            if self.peer_props_without_ns_expr & curr_covered_without_ip_block:
                self.peer_props_without_ns_expr -= curr_covered_without_ip_block
                self.peer_pairs_with_partial_ns_expr.add((curr_ns_set, other_dim_peers_without_ip_block) if is_src_ns
                                                         else (other_dim_peers_without_ip_block, curr_ns_set))
            if self.peer_props_without_ns_expr & curr_covered_ip_block:
                self.peer_props_without_ns_expr -= curr_covered_ip_block
                self.peer_pairs_with_partial_ns_expr.add((curr_ns_set, other_dim_peers_ip_block) if is_src_ns
                                                         else (other_dim_peers_ip_block, curr_ns_set))

    def get_ns_fw_rules_grouped_by_common_elem(self, is_src_fixed, ns_set, fixed_elem):
        """
        create a  fw-rule from a fixed-elem and  a set of namespaces
        :param is_src_fixed: a flag indicating if the fixed elem is src (True) or dst (False)
        :param ns_set:  a set of namespaces
        :param fixed_elem: the fixed element
        :return: a list with created FWRule
        """
        # currently no grouping of ns-list by labels of namespaces
        grouped_elem = FWRuleElement(ns_set, self.cluster_info)
        if is_src_fixed:
            fw_rule = FWRule(fixed_elem, grouped_elem, self.connections)
        else:
            fw_rule = FWRule(grouped_elem, fixed_elem, self.connections)
        return [fw_rule]

    def _create_fw_elements_by_pods_grouping_by_labels(self, pods_set):
        """
        Group a given set of pods by labels, and create FWRuleElements according to the grouping
        :param PeerSet pods_set: a set of pods to be grouped by labels
        :return: the resulting element list
        """
        res = []
        chosen_rep, remaining_pods = self._get_pods_grouping_by_labels_main(pods_set, set())
        for (key, values, ns_info) in chosen_rep:
            map_simple_keys_to_all_values = self.cluster_info.get_map_of_simple_keys_to_all_values(key, ns_info)
            all_key_values = self.cluster_info.get_all_values_set_for_key_per_namespace(key, ns_info)
            pod_label_expr = LabelExpr(key, set(values), map_simple_keys_to_all_values, all_key_values)
            res.append(PodLabelsElement(pod_label_expr, ns_info, self.cluster_info))
        if remaining_pods:
            res.append(PeerSetElement(PeerSet(remaining_pods)))
        return res

    def _get_pod_level_fw_rules_grouped_by_common_labels(self, is_src_fixed, pods_set, fixed_elem, extra_pods_set,
                                                         make_peer_sets=False):
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
            grouped_elem = PodLabelsElement(pod_label_expr, ns_info, self.cluster_info)
            if is_src_fixed:
                fw_rule = FWRule(fixed_elem, grouped_elem, self.connections)
            else:
                fw_rule = FWRule(grouped_elem, fixed_elem, self.connections)
            res.append(fw_rule)

        # TODO: should avoid having single pods remaining without labels grouping
        # (2) add rules for remaining single pods:
        if make_peer_sets and remaining_pods:
            peer_set_elem = PeerSetElement(PeerSet(remaining_pods))
            if is_src_fixed:
                fw_rule = FWRule(fixed_elem, peer_set_elem, self.connections)
            else:
                fw_rule = FWRule(peer_set_elem, fixed_elem, self.connections)
            res.append(fw_rule)
        else:
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
            res.extend(self._create_fw_rules_from_base_elements(src, dst, self.connections, self.cluster_info,
                                                                self.output_config))
        return res

    def _create_initial_fw_rules_from_peer_props(self, peer_props):
        res = []
        min_peer_props = peer_props.minimize()
        for cube in min_peer_props:
            conn_cube = min_peer_props.get_connectivity_cube(cube)
            src_peers = conn_cube["src_peers"]
            dst_peers = conn_cube["dst_peers"]
            # whole peers sets were handled in self.ns_set_pairs and self.peer_pairs_with_partial_ns_expr
            assert src_peers and dst_peers
            res.extend(self._create_fw_rules_from_base_elements(src_peers, dst_peers, self.connections,
                                                                self.cluster_info, self.output_config))
        return res

    def _create_fw_rules_from_base_elements(self, src, dst, connections, cluster_info, output_config):
        """
        create fw-rules from single pair of base elements (src,dst) and a given connection set
        :param ConnectionSet connections: the allowed connections from src to dst
        :param src: a base-element  of type: ClusterEP/K8sNamespace/ IpBlock
        :param dst: a base-element  of type: ClusterEP/K8sNamespace/IpBlock
        :param cluster_info: an object of type ClusterInfo, with relevant cluster topology info
        :param OutputConfiguration output_config: an object holding output configuration
        :return: list with created fw-rules
        :rtype list[FWRule]
        """
        src_elem = self._create_fw_elements_from_base_element(src, cluster_info, output_config)
        dst_elem = self._create_fw_elements_from_base_element(dst, cluster_info, output_config)
        if src_elem is None or dst_elem is None:
            return []
        return [FWRule(src, dst, connections) for src in src_elem for dst in dst_elem]

    def _create_fw_elements_from_base_element(self, base_elem, cluster_info, output_config):
        """
        create a list of fw-rule-elements from base-element
        :param base_elem: of type ClusterEP/IpBlock/K8sNamespace/DNSEntry
        :param cluster_info: an object of type ClusterInfo, with relevant cluster topology info
        :param OutputConfiguration output_config: an object holding output configuration
          after moving to optimized HC implementation we will never split IpBlocks.
        :return: list fw-rule-elements of type:  list[PodElement]/list[IPBlockElement]/list[FWRuleElement]/list[DNSElement]
        """
        if isinstance(base_elem, ClusterEP):
            return [PodElement(base_elem, output_config.outputEndpoints == 'deployments')]
        elif isinstance(base_elem, IpBlock):
            return [IPBlockElement(base_elem)]
        elif isinstance(base_elem, K8sNamespace):
            return [FWRuleElement({base_elem}, cluster_info)]
        elif isinstance(base_elem, DNSEntry):
            return [DNSElement(base_elem)]
        elif isinstance(base_elem, PeerSet):
            pods = PeerSet(base_elem.get_set_without_ip_block_or_dns_entry())
            ipblocks_and_dns = base_elem - pods
            res = []
            while pods:
                ns = list(pods)[0].namespace
                ns_pods = pods & PeerSet(cluster_info.ns_dict[ns])
                res.extend(self._create_fw_elements_by_pods_grouping_by_labels(ns_pods))
                pods -= ns_pods
            for peer in ipblocks_and_dns:
                res.extend(self._create_fw_elements_from_base_element(peer, cluster_info, output_config))
            return res
        elif isinstance(base_elem, frozenset):  # set of namespaces
            return [FWRuleElement(set(base_elem), cluster_info)]
        # unknown base-elem type
        return None

    def _create_all_initial_fw_rules(self):
        """
        Creating initial fw-rules from base-elements pairs (pod/ns/ip-block/dns-entry)
        :return: a list of initial fw-rules of type FWRule
        :rtype list[FWRule]
        """

        initial_fw_rules = []
        initial_fw_rules.extend(self._create_initial_fw_rules_from_base_elements_list(self.ns_set_pairs))
        initial_fw_rules.extend(self._create_initial_fw_rules_from_peer_props(self.peer_props_without_ns_expr))
        initial_fw_rules.extend(
            self._create_initial_fw_rules_from_base_elements_list(self.peer_pairs_with_partial_ns_expr))
        return initial_fw_rules

    def _add_all_fw_rules(self):
        """
        Computation of fw-rules, following the ns-grouping of peer_pairs.
        Results are at: self.minimized_rules_set
        :return: None
        """
        # create initial fw-rules from ns_set_pairs, peer_pairs_with_partial_ns_expr, peer_props_without_ns_expr
        initial_fw_rules = self._create_all_initial_fw_rules()
        self.minimized_fw_rules = initial_fw_rules
        return  # Tanya: temp
        # TODO - remove the code below after checking and updating all expected results

        # option1 - start computation when src is fixed at first iteration, and merge applies to dst
        option1, convergence_iteration_1 = self._create_merged_rules_set(True, initial_fw_rules)
        # option2 - start computation when dst is fixed at first iteration, and merge applies to src
        option2, convergence_iteration_2 = self._create_merged_rules_set(False, initial_fw_rules)

        # self.post_processing_fw_rules(option1)
        # self.post_processing_fw_rules(option2)

        if self.output_config.fwRulesRunInTestMode:
            # add info for documentation about computation results
            self.results_info_per_option['option1_len'] = len(option1)
            self.results_info_per_option['option2_len'] = len(option2)
            self.results_info_per_option['convergence_iteration_1'] = convergence_iteration_1
            self.results_info_per_option['convergence_iteration_2'] = convergence_iteration_2

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
        peer_set_elems = set(elem for elem in set_for_grouping_elems if isinstance(elem, PeerSetElement))
        pod_and_pod_labels_elems = set(elem for elem in set_for_grouping_elems if
                                       isinstance(elem, (PodElement, PodLabelsElement)))
        ip_block_elems = set(elem for elem in set_for_grouping_elems if isinstance(elem, IPBlockElement))
        dns_elems = set(elem for elem in set_for_grouping_elems if isinstance(elem, DNSElement))
        ns_elems = set_for_grouping_elems - (peer_set_elems | pod_and_pod_labels_elems | ip_block_elems | dns_elems)

        if ns_elems:
            # grouping of ns elements is straight-forward
            ns_set = set.union(*(f.ns_info for f in ns_elems))
            res.extend(self.get_ns_fw_rules_grouped_by_common_elem(src_first, ns_set, fixed_elem))

        for peer_set_elem in peer_set_elems:
            res.extend(self._get_pod_level_fw_rules_grouped_by_common_labels(src_first, peer_set_elem.get_pods_set(),
                                                                             fixed_elem, set(), True))

            # fw_rule = FWRule(fixed_elem, peer_set_elem, self.connections) if src_first else \
            #     FWRule(peer_set_elem, fixed_elem, self.connections)
            # res.append(fw_rule)

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
                    set_for_grouping_pods |= e.get_pods_set()

                # allow borrowing pods for labels-grouping from covered_peer_props
                fixed_elem_pods = fixed_elem.get_pods_set()
                # extra_pods_list is a list of pods sets that are paired with pods in fixed_elem_pods within
                # covered_peer_props
                extra_pods_list = []
                for p in fixed_elem_pods:
                    pods_to_add = self._get_peers_paired_with_given_peer(p, src_first)
                    extra_pods_list.append(pods_to_add)
                # extra_pods_list_common is a set of pods that are paired with all pods in fixed_elem_pods within
                # covered_peer_props
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

        if dns_elems:
            for elem in dns_elems:
                if src_first:  # do we need both if else? , dns_elem may be a dst always
                    res.append(FWRule(fixed_elem, elem, self.connections))
                else:
                    res.append(FWRule(elem, fixed_elem, self.connections))

        return res

    def _get_peers_paired_with_given_peer(self, peer, is_src_peer):
        this_dim = "src_peers" if is_src_peer else "dst_peers"
        other_dim = "dst_peers" if is_src_peer else "src_peers"
        props = self.covered_peer_props & ConnectivityProperties.make_conn_props_from_dict({this_dim: PeerSet({peer})})
        return props.project_on_one_dimension(other_dim)

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
                    # set_for_grouping_elems = set(f.dst for f in initial_fw_rules if elem <= f.src)
                    set_for_grouping_elems = set(f.dst for f in initial_fw_rules if elem == f.src)
                else:
                    # set_for_grouping_elems = set(f.src for f in initial_fw_rules if elem <= f.dst)
                    set_for_grouping_elems = set(f.src for f in initial_fw_rules if elem == f.dst)
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
