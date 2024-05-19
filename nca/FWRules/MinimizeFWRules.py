#
# Copyright 2020- IBM Inc. All rights reserved
# SPDX-License-Identifier: Apache2.0
#

from collections import defaultdict
from nca.CoreDS.ConnectivityProperties import ConnectivityProperties
from nca.CoreDS.Peer import IpBlock
from nca.CoreDS.ProtocolSet import ProtocolSet
from .FWRule import FWRule
from .MinimizeCsFWRulesOpt import MinimizeCsFwRulesOpt


class MinimizeFWRules:
    """
    This is a class for minimizing and handling fw-rules globally for all connection sets
    """

    def __init__(self, fw_rules_map, cluster_info, output_config, results_map):
        """
        create n object of MinimizeFWRules
        :param fw_rules_map: a map from ConnectivityProperties to list[FWRule] - the list of minimized fw-rules per props
        :param cluster_info: an object of type ClusterInfo
        :param output_config: an object of type OutputConfiguration
        :param results_map: (temp, for debugging) a map from connection to results info
        """
        self.fw_rules_map = fw_rules_map
        self.cluster_info = cluster_info
        self.output_config = output_config
        self.results_map = results_map

    def get_fw_rules_in_required_format(self, add_txt_header=True, add_csv_header=True, connectivity_restriction=None):
        """
        :param add_txt_header: bool flag to indicate if header of fw-rules query should be added in txt format
        :param add_csv_header: bool flag to indicate if header csv should be added in csv format
        :param Union[str,None] connectivity_restriction: specify if connectivity is restricted to
               TCP / non-TCP , or not
        :return: a string or dict representing the computed minimized fw-rules (in a supported format txt/yaml/csv)
        :rtype: Union[str, dict]
        """
        query_name = self.output_config.queryName
        if self.output_config.configName:
            query_name += ', config: ' + self.output_config.configName
        output_format = self.output_config.outputFormat
        if output_format not in FWRule.supported_formats:
            supported_formats_joined = '\\'.join(FWRule.supported_formats)
            print(f'error: unexpected outputFormat in output configuration value [should be {supported_formats_joined}], '
                  f'value is: {output_format}')
        return self.get_fw_rules_content(query_name, output_format, add_txt_header, add_csv_header, connectivity_restriction)

    def get_fw_rules_content(self, query_name, req_format, add_txt_header, add_csv_header, connectivity_restriction):
        """
        :param query_name: a string of the query name
        :param req_format: a string of the required format, should be in FWRule.supported_formats
        :param add_txt_header:  bool flag to indicate if header of fw-rules query should be added in txt format
        :param add_csv_header: bool flag to indicate if header csv should be added in csv format
        :param Union[str,None] connectivity_restriction: specify if connectivity is restricted to
               TCP / non-TCP , or not
        :return: a dict of the fw-rules if the required format is json or yaml, else
        a string of the query name + fw-rules in the required format
        :rtype: Union[str, dict]
        """
        rules_list = self._get_all_rules_list_in_req_format(req_format)
        key_prefix = '' if connectivity_restriction is None else f'{connectivity_restriction}_'
        header_prefix = ''
        if connectivity_restriction is not None:
            header_prefix = f'For connections of type {connectivity_restriction}, '

        if req_format == 'txt':
            res = ''.join(line for line in sorted(rules_list))
            if add_txt_header:
                res = f'{header_prefix}final fw rules for query: {query_name}:\n' + res
            return res

        elif req_format in ['yaml', 'json']:
            return {f'{key_prefix}rules': rules_list}

        elif req_format in ['csv', 'md']:
            is_csv = req_format == 'csv'
            res = ''
            header_lines = [[header_prefix + query_name] + [''] * (len(FWRule.rule_csv_header) - 1)]
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
        yaml/json -> list of dict objects
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
                rule_obj = rule.get_rule_in_req_format(req_format)
                if (self.output_config.outputEndpoints == 'deployments' and str(rule_obj) not in rules_dict) or (
                        self.output_config.outputEndpoints == 'pods'):
                    rules_list.append(rule_obj)
                    rules_dict[str(rule_obj)] = 1
        return rules_list

    @staticmethod
    def get_minimized_firewall_rules_from_props(props, cluster_info, output_config, peer_container,
                                                connectivity_restriction):
        relevant_protocols = ProtocolSet()
        if connectivity_restriction:
            if connectivity_restriction == 'TCP':
                relevant_protocols.add_protocol('TCP')
            else:  # connectivity_restriction == 'non-TCP'
                relevant_protocols = ProtocolSet.get_non_tcp_protocols()

        peers_to_props = defaultdict(ConnectivityProperties)
        # pick up all connectivity propertoes relating to the same peer set pairs
        for cube in props:
            conn_cube = props.get_connectivity_cube(cube)
            conns, src_peers, dst_peers = \
                ConnectivityProperties.extract_src_dst_peers_from_cube(conn_cube, peer_container, relevant_protocols)
            conn_cube.unset_all_but_peers()
            peers_to_props[ConnectivityProperties.make_conn_props(conn_cube)] |= conns
        # now combine all peer set pairs relating to the same connectivity properties
        props_to_peers = defaultdict(ConnectivityProperties)
        for peers, conns in peers_to_props.items():
            props_to_peers[conns] |= peers
        props_sorted_by_size = list(props_to_peers.items())
        props_sorted_by_size.sort(reverse=True)
        return MinimizeFWRules.minimize_firewall_rules(cluster_info, output_config, props_sorted_by_size)

    @staticmethod
    def minimize_firewall_rules(cluster_info, output_config, props_sorted_by_size):
        """
        Creates the set of minimized fw rules and prints to output
        :param ClusterInfo cluster_info: the cluster info
        :param OutputConfiguration output_config: the output configuration
        :param list props_sorted_by_size: the original connectivity graph in fw-rules format
        :return:  minimize_fw_rules: an object of type MinimizeFWRules holding the minimized fw-rules
        """
        props_containment_map = MinimizeFWRules._build_props_containment_map(props_sorted_by_size)
        fw_rules_map = defaultdict(list)
        results_map = dict()
        minimize_cs_opt = MinimizeCsFwRulesOpt(cluster_info, output_config)
        # build fw_rules_map: per connection - a set of its minimized fw rules
        for props, peer_props in props_sorted_by_size:
            # currently skip "no connections"
            if not props:
                continue
            # TODO: figure out why we have pairs with (ip,ip) ?
            peer_props_in_containing_props = props_containment_map[props]
            fw_rules, results_per_info = minimize_cs_opt.compute_minimized_fw_rules_per_prop(
                props, peer_props, peer_props_in_containing_props)
            fw_rules_map[props] = fw_rules
            results_map[props] = results_per_info

        minimize_fw_rules = MinimizeFWRules(fw_rules_map, cluster_info, output_config, results_map)
        return minimize_fw_rules

    @staticmethod
    def _get_peer_pairs_filtered(peer_pairs):
        """
        Filters out peer pairs where both src and dst are IpBlock
        :param list peer_pairs: the peer pairs to filter
        :return: a filtered set of peer pairs
        """
        return set((src, dst) for (src, dst) in peer_pairs if not (isinstance(src, IpBlock) and isinstance(dst, IpBlock)))

    @staticmethod
    def _build_props_containment_map(props_sorted_by_size):
        """
        Build a map from a connection to a set of peer_pairs from connections it is contained in
        :param list props_sorted_by_size: the connectivity map in fw-rules format
        :return: a map from connectivity properties to a set of peer pairs from containing properties
        """
        props_containment_map = defaultdict(ConnectivityProperties)
        for (props, _) in props_sorted_by_size:
            for (other_props, peer_pairs) in props_sorted_by_size:
                if other_props != props and props.contained_in(other_props):
                    props_containment_map[props] |= peer_pairs
        return props_containment_map
