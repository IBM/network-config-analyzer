#
# Copyright 2020- IBM Inc. All rights reserved
# SPDX-License-Identifier: Apache2.0
#

from nca.CoreDS.ConnectivityProperties import ConnectivityProperties
from nca.CoreDS.Peer import PeerSet
from nca.CoreDS.ProtocolSet import ProtocolSet


class MinimizeBasic:
    """
    This is a base class for minimizing fw-rules/peer sets
    """
    def __init__(self, cluster_info, output_config):
        self.cluster_info = cluster_info
        self.output_config = output_config

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

    @staticmethod
    def fw_rules_to_conn_props(fw_rules, peer_container, connectivity_restriction=None):
        """
        Converting FWRules to ConnectivityProperties format.
        This function is used for comparing FWRules output between original and optimized solutions,
        when optimized_run == 'debug'
        :param MinimizeFWRules fw_rules: the given FWRules.
        :param PeerContainer peer_container: the peer container
        param Union[str,None] connectivity_restriction: specify if connectivity is restricted to
               TCP / non-TCP , or not
        :return: the resulting ConnectivityProperties.
        """
        relevant_protocols = ProtocolSet()
        if connectivity_restriction:
            if connectivity_restriction == 'TCP':
                relevant_protocols.add_protocol('TCP')
            else:  # connectivity_restriction == 'non-TCP'
                relevant_protocols = ProtocolSet.get_non_tcp_protocols()

        res = ConnectivityProperties.make_empty_props()
        if fw_rules.fw_rules_map is None:
            return res
        for fw_rules_list in fw_rules.fw_rules_map.values():
            for fw_rule in fw_rules_list:
                conn_props = fw_rule.conn.convert_to_connectivity_properties(peer_container, relevant_protocols)
                src_peers = fw_rule.src.get_peer_set()
                dst_peers = fw_rule.dst.get_peer_set()
                rule_props = ConnectivityProperties.make_conn_props_from_dict({"src_peers": src_peers,
                                                                               "dst_peers": dst_peers}) & conn_props
                res |= rule_props
        return res
