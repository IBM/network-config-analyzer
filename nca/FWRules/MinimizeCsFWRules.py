#
# Copyright 2020- IBM Inc. All rights reserved
# SPDX-License-Identifier: Apache2.0
#

from collections import defaultdict
from nca.CoreDS.ConnectivityProperties import ConnectivityProperties
from nca.CoreDS.Peer import IpBlock, ClusterEP, HostEP, DNSEntry, PeerSet, Pod
from nca.Resources.OtherResources.K8sNamespace import K8sNamespace
from .FWRule import FWRuleElement, FWRule, PodElement, PeerSetElement, LabelExpr, PodLabelsElement, IPBlockElement, \
    DNSElement


class MinimizeCsFwRules:
    """
    This is a class for minimizing fw-rules within a specific connection-set
    """

    def __init__(self, cluster_info, output_config):
        """
        create an object of MinimizeCsFwRules
        :param cluster_info:  an object of type ClusterInfo, with relevant cluster topology info
        :param output_config: an OutputConfiguration object

        """
        self.cluster_info = cluster_info
        self.output_config = output_config
        self.peer_props = ConnectivityProperties()
        self.props = ConnectivityProperties()
        self.peer_props_in_containing_props = ConnectivityProperties()
        self.ns_set_pairs = set()
        self.base_elem_pairs = set()
        self.peer_props_without_ns_expr = ConnectivityProperties()
        self.covered_peer_props = ConnectivityProperties()
        self.results_info_per_option = dict()
        self.minimized_fw_rules = []  # holds the computation result of minimized fw-rules

    def compute_minimized_fw_rules_per_prop(self, props, peer_props, peer_props_in_containing_props):
        """
        The main function for creating the minimized set of fw-rules for a given connection set

        :param ConnectivityProperties props: the allowed connections for the given peer pairs
        :param ConnectivityProperties peer_props: peers (src,dst) for which communication is allowed over the given connections
        :param ConnectivityProperties peer_props_in_containing_props: peers in connections that contain the current
               connection set

        class members used in computation of fw-rules:
        self.ns_set_pairs : pairs of sets of namespaces, grouped together
        self.base_elem_pairs: pairs of (peer,ns) or (ns,peer), with ns-grouping for one dimension
        self.peer_props_without_ns_expr: properties containing peers without possible ns/full IpBlock grouping
        self.covered_peer_props: properties of all peer sets for which communication is allowed in current
                                 or containing connection-set

        :return:
        minimized_fw_rules: a list of fw-rules (of type list[FWRule])
        (results_info_per_option: for debugging, dict with some info about the computation)
        """
        self.peer_props = peer_props
        self.props = props
        self.peer_props_in_containing_props = peer_props_in_containing_props
        self.ns_set_pairs = set()
        self.base_elem_pairs = set()
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
        # partition peer_props to ns_set_pairs, base_elem_pairs, peer_props_without_ns_expr
        self._compute_basic_grouping()

        # Creating fw-rules from base-elements pairs (pod/ns/ip-block/dns-entry)
        self.minimized_fw_rules.extend(self._create_fw_rules_from_base_elements_list(self.ns_set_pairs))
        self.minimized_fw_rules.extend(self._create_fw_rules_from_peer_props(self.peer_props_without_ns_expr))
        self.minimized_fw_rules.extend(self._create_fw_rules_from_base_elements_list(self.base_elem_pairs))

    def _compute_basic_grouping(self):
        """
        computation of peer sets with possible grouping by namespaces.
        Results are at: ns_set_pairs, base_elem_pairs, peer_props_without_ns_expr
        :return: None
        """
        self._compute_covered_peer_props()
        # only Pod elements have namespaces (skipping IpBlocks and HostEPs)
        all_src_ns_set = set(src.namespace for src in self.covered_peer_props.project_on_one_dimension("src_peers")
                             if isinstance(src, Pod))
        all_dst_ns_set = set(dst.namespace for dst in self.covered_peer_props.project_on_one_dimension("dst_peers")
                             if isinstance(dst, Pod))
        self._compute_full_ns_grouping(all_src_ns_set, all_dst_ns_set)
        src_peers_without_ns = PeerSet(set(src for src in self.peer_props.project_on_one_dimension("src_peers")
                                           if isinstance(src, (IpBlock, HostEP, DNSEntry))))
        dst_peers_without_ns = PeerSet(set(dst for dst in self.peer_props.project_on_one_dimension("dst_peers")
                                           if isinstance(dst, (IpBlock, HostEP, DNSEntry))))
        props_with_elems_without_ns = \
            ConnectivityProperties.make_conn_props_from_dict({"src_peers": src_peers_without_ns}) |\
            ConnectivityProperties.make_conn_props_from_dict({"dst_peers": dst_peers_without_ns})
        self.peer_props_without_ns_expr |= props_with_elems_without_ns & self.peer_props
        # compute pairs with src as pod/ip-block and dest as namespace
        self._compute_partial_ns_grouping(all_dst_ns_set, False)
        # compute pairs with src as pod/ip-block namespace dest as pod
        if self.peer_props_without_ns_expr:
            self._compute_partial_ns_grouping(all_src_ns_set, True)
        if self.peer_props_without_ns_expr:
            self._compute_full_ipblock_and_dns_grouping(False)
        if self.peer_props_without_ns_expr:
            self._compute_full_ipblock_and_dns_grouping(True)

    def _compute_covered_peer_props(self):
        """
        compute the union (set) of all peer pairs for which communication is allowed in current connection-set (but
        not necessarily only limited to current connection set)
        :return: None
        """
        covered_peer_props = self.peer_props | self.peer_props_in_containing_props
        all_peers_set = self.peer_props.get_all_peers()
        if len(all_peers_set) < 500:
            # optimization - add auto-connections only if not too many peers,
            # otherwise the calculation below is very heavy
            for pod in all_peers_set:
                if isinstance(pod, ClusterEP):
                    covered_peer_props |= ConnectivityProperties.make_conn_props_from_dict({"src_peers": PeerSet({pod}),
                                                                                            "dst_peers": PeerSet({pod})})
        self.covered_peer_props = covered_peer_props

    def _compute_full_ns_grouping(self, all_src_ns_set, all_dst_ns_set):
        """
        Compute pairs of ns sets that are grouped together, according to peer_props,
        while possibly borrowing from covered_peer_props. Put the result in self.ns_set_pairs.
        :param all_src_ns_set: relevant ns set of src peers
        :param all_dst_ns_set: relevant ns set of dst peers
        """
        src_ns_to_dst_ns = defaultdict(set)
        dst_ns_to_src_ns = defaultdict(set)
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
                        dst_ns_to_src_ns[dst_ns].add(src_ns)
                else:
                    self.peer_props_without_ns_expr |= ns_product_props & self.peer_props
        # Try src ns first or dst ns first, and choose the more compact grouping
        final_src_ns_to_dst_ns = defaultdict(set)
        final_dst_ns_to_src_ns = defaultdict(set)
        for src_ns, dst_ns_set in src_ns_to_dst_ns.items():
            final_dst_ns_to_src_ns[frozenset(dst_ns_set)].add(src_ns)
        for dst_ns, src_ns_set in dst_ns_to_src_ns.items():
            final_src_ns_to_dst_ns[frozenset(src_ns_set)].add(dst_ns)
        if len(final_dst_ns_to_src_ns) <= len(final_src_ns_to_dst_ns):
            for dst_ns_set, src_ns_set in final_dst_ns_to_src_ns.items():
                self.ns_set_pairs.add((frozenset(src_ns_set), dst_ns_set))
        else:
            for src_ns_set, dst_ns_set in final_src_ns_to_dst_ns.items():
                self.ns_set_pairs.add((src_ns_set, frozenset(dst_ns_set)))

    @staticmethod
    def is_full_ipblock(ipblock):
        return ipblock == IpBlock.get_all_ips_block() or ipblock == IpBlock.get_all_ips_block(True, False) \
               or ipblock == IpBlock.get_all_ips_block(False, True)

    def _compute_partial_ns_grouping(self, ns_set, is_src_ns):
        """
        computes and updates self.base_elem_pairs with pairs where only one elem (src/dst)
        can be grouped to an entire namespace
        :param is_src_ns: a bool flag to indicate if computing pairs with src elem grouped as ns (True) or dst (False)
        :return: None
        """
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
            for ns in ns_set:
                ns_peers = PeerSet(self.cluster_info.ns_dict[ns])
                if ns_peers.issubset(dim_peers):
                    curr_covered = ConnectivityProperties.make_conn_props_from_dict({dim_name: ns_peers,
                                                                                     other_dim_name: other_dim_peers})
                    if curr_covered & self.peer_props_without_ns_expr:
                        curr_ns_set.add(ns)
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
            peer_props_without_ns_expr_updated = self.peer_props_without_ns_expr - curr_covered_without_ip_block
            if self.peer_props_without_ns_expr != peer_props_without_ns_expr_updated:
                self.peer_props_without_ns_expr = peer_props_without_ns_expr_updated
                self.base_elem_pairs.add((curr_ns_set, other_dim_peers_without_ip_block) if is_src_ns
                                         else (other_dim_peers_without_ip_block, curr_ns_set))
            peer_props_without_ns_expr_updated = self.peer_props_without_ns_expr - curr_covered_ip_block
            if self.peer_props_without_ns_expr != peer_props_without_ns_expr_updated:
                self.peer_props_without_ns_expr = peer_props_without_ns_expr_updated
                self.base_elem_pairs.add((curr_ns_set, other_dim_peers_ip_block) if is_src_ns
                                         else (other_dim_peers_ip_block, curr_ns_set))

    def _compute_full_ipblock_and_dns_grouping(self, is_src_ns):
        """
        computes and updates self.base_elem_pairs with pairs where one elem (src/dst)
        can be grouped to an entire IpBlock
        :param is_src_ns: a bool flag to indicate if computing pairs with src elem grouped as IpBlock (True) or dst (False)
        :return: None
        """

        dim_name = "src_peers" if is_src_ns else "dst_peers"
        other_dim_name = "dst_peers" if is_src_ns else "src_peers"
        # We search for grouping by full IpBlock in self.covered_peer_props rather than in self.peer_props_without_ns_expr,
        # thus allowing overlapping of fw rules. Also, we start from optimal order between src_peers and dst_peers,
        # based on whether we search for full src or dst IpBlock
        props = self.covered_peer_props.reorder_by_switching_src_dst_peers() if is_src_ns else self.covered_peer_props
        ipblock_dnsentry_to_peer_set = defaultdict(PeerSet)
        for cube in props:
            conn_cube = props.get_connectivity_cube(cube)
            dim_peers = conn_cube[dim_name]
            other_dim_peers = conn_cube[other_dim_name].canonical_form()
            ipblock = dim_peers.get_ip_block_canonical_form()
            if self.is_full_ipblock(ipblock):
                self._add_to_map_if_covered(dim_name, ipblock.get_peer_set(), other_dim_name, other_dim_peers,
                                            ipblock_dnsentry_to_peer_set)
            dns_entries = dim_peers.get_dns_entries()
            for dns_entry in dns_entries:
                self._add_to_map_if_covered(dim_name, PeerSet({dns_entry}), other_dim_name, other_dim_peers,
                                            ipblock_dnsentry_to_peer_set)
        for curr_peers, other_dim_peers in ipblock_dnsentry_to_peer_set.items():
            curr_peers = PeerSet(set(curr_peers))  # peel off the frozenset
            curr_covered = ConnectivityProperties.make_conn_props_from_dict({dim_name: curr_peers,
                                                                             other_dim_name: other_dim_peers})
            self.peer_props_without_ns_expr -= curr_covered
            self.base_elem_pairs.add((curr_peers, other_dim_peers) if is_src_ns else (other_dim_peers, curr_peers))

    def _add_to_map_if_covered(self, dim_name, dim_peers, other_dim_name, other_dim_peers, peers_to_peers_map):
        """
        An auxiliary method that checks whether the product of dim_peers and other_dim_peers is covered
        by self.peer_props_without_ns_expr, and adds the peer sets to peers_to_peers_map if True.
        :param str dim_name: the first dimension name
        :param PeerSet dim_peers: a set of peers for the first dimension
        :param str other_dim_name: the second dimension name
        :param PeerSet other_dim_peers: a set of peers for the second dimension
        :param dict peers_to_peers_map: the map from first dimention peers to second dimension peers
        """
        curr_covered = ConnectivityProperties.make_conn_props_from_dict({dim_name: dim_peers,
                                                                         other_dim_name: other_dim_peers})
        if curr_covered & self.peer_props_without_ns_expr:
            peers_to_peers_map[frozenset(dim_peers)] |= other_dim_peers

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
            res.append(PeerSetElement(PeerSet(remaining_pods), self.output_config.outputEndpoints == 'deployments'))
        return res

    def _create_fw_rules_from_base_elements_list(self, base_elems_pairs):
        """
        creating initial fw-rules from base elements
        :param base_elems_pairs: a set of pairs (src,dst) , each of type: Pod/K8sNamespace/IpBlock
        :return: list with created fw-rules
        :rtype list[FWRule]
        """
        res = []
        for (src, dst) in base_elems_pairs:
            res.extend(self._create_fw_rules_from_base_elements(src, dst, self.props, self.cluster_info,
                                                                self.output_config))
        return res

    def _create_fw_rules_from_peer_props(self, peer_props):
        res = []
        # first, try to group peers paired with src/dst ipblocks
        ipblock = IpBlock.get_all_ips_block_peer_set()
        src_ipblock_props = ConnectivityProperties.make_conn_props_from_dict({"src_peers": ipblock}) & peer_props
        if src_ipblock_props:
            peer_props -= src_ipblock_props
            src_ipblock_props = src_ipblock_props.reorder_by_switching_src_dst_peers()
            res.extend(self._create_fw_rules_from_peer_props_aux(src_ipblock_props))
        dst_ipblock_props = ConnectivityProperties.make_conn_props_from_dict({"dst_peers": ipblock}) & peer_props
        if dst_ipblock_props:
            peer_props -= dst_ipblock_props
            res.extend(self._create_fw_rules_from_peer_props_aux(dst_ipblock_props))

        # now group the rest of peers
        if peer_props:
            res.extend(self._create_fw_rules_from_peer_props_aux(peer_props.minimize()))
        return res

    def _create_fw_rules_from_peer_props_aux(self, peer_props):
        res = []
        for cube in peer_props:
            conn_cube = peer_props.get_connectivity_cube(cube)
            src_peers = conn_cube["src_peers"]
            dst_peers = conn_cube["dst_peers"]
            # whole peers sets were handled in self.ns_set_pairs and self.base_elem_pairs
            assert src_peers and dst_peers
            res.extend(self._create_fw_rules_from_base_elements(src_peers, dst_peers, self.props,
                                                                self.cluster_info, self.output_config))
        return res

    def _create_fw_rules_from_base_elements(self, src, dst, props, cluster_info, output_config):
        """
        create fw-rules from single pair of base elements (src,dst) and a given connection set
        :param ConnectivityProperties props: the allowed connections from src to dst
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
        return [FWRule(src, dst, props) for src in src_elem for dst in dst_elem]

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
            pods_set_per_ns = pods_set & PeerSet(self.cluster_info.ns_dict[ns])
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
                remaining_pods -= PeerSet(pods)
            if not remaining_pods:
                break
        return chosen_rep, remaining_pods

    def _print_results_info(self):
        print('----------------')
        print('results_info_per_option: ')
        for key in self.results_info_per_option:
            val = self.results_info_per_option[key]
            print(str(key) + ':' + str(val))
        print('----------------')

    def _print_firewall_rules(self, rules):
        print('-------------------')
        print('rules for connections: ' + str(self.props))
        for rule in rules:
            # filter out rule of a pod to itslef
            # if rule.is_rule_trivial():
            #    continue
            print(rule)
