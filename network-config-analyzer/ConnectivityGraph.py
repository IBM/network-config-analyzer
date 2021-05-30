from collections import defaultdict
from ClusterInfo import ClusterInfo
from ConfigFwRules import ConfigFwRules
from ConnectionSet import ConnectionSet
from Peer import Peer, IpBlock, Pod
from MinimizeFWRules import MinimizeCsFwRules, MinimizeFWRules


class ConnectivityGraph:
    """
    Represents a connectivity digraph, that is a set of labeled edges, where the nodes are peers and
    the labels on the edges are the allowed connections between two peers.
    """

    def __init__(self, all_peers, config_name, allowed_labels, fw_rules_configuration):
        self.connections_to_peers = defaultdict(list)
        if fw_rules_configuration is None:
            fw_rules_configuration = 'config/fw_rules_config.yaml'
            print('warning: no configuration file for fw rules, using default config file: ' + fw_rules_configuration)
        self.config = ConfigFwRules(fw_rules_configuration, config_name)
        self.cluster_info = ClusterInfo(all_peers, allowed_labels, self.config)
        self.config_name = config_name
        self.allowed_labels = allowed_labels

    def add_edge(self, source_peer, dest_peer, connections):
        """
        Adding a labeled edge to the graph
        :param Peer source_peer: The source peer
        :param Peer dest_peer: The dest peer
        :param ConnectionSet connections: The allowed connections from source_peer to dest_peer
        :return: None
        """

        self.connections_to_peers[connections].append((source_peer, dest_peer))

    def output_as_firewall_rules(self, print_to_stdout=True):
        """
        Prints the graph as a set of firewall rules
        :param print_to_stdout: flag to indicate if fw-rules should be printed to stdout
        :return: (txt_res, yaml_res, fw_rules_map)
        txt_res: bool flag indicating if comparison to expected txt output did not fail
        yaml_res: bool flag indicating if comparison to expected yaml output did not fail
        fw_rules_map: map from each connection set to its list of firewall rules
        """

        connections_sorted_by_size = [(conn, peer_pair) for conn, peer_pair in self.connections_to_peers.items()]
        connections_sorted_by_size.sort(reverse=True)

        connections_sorted_by_size = self._merge_ip_blocks(connections_sorted_by_size)

        if self.config.run_in_test_mode:
            # print the original connectivity graph
            for connections, peer_pairs in connections_sorted_by_size:
                for src_peer, dst_peer in peer_pairs:
                    print(f'src: {src_peer}, dest: {dst_peer}, allowed conns: {connections}')
            print('======================================================')
        return self._minimize_firewall_rules(connections_sorted_by_size, print_to_stdout)

    def _minimize_firewall_rules(self, connections_sorted_by_size, print_to_stdout):
        """
        Creates the set of minimized fw rules and prints to output
        :param list connections_sorted_by_size: the original connectivity graph in fw-rules format
        :param print_to_stdout: flag to indicate if fw-rules should be printed to stdout
        :return: txt_res: bool flag indicating if comparison to expected txt output did not fail
                yaml_res: bool flag indicating if comparison to expected yaml output did not fail
                fw_rules_map: map from each connection set to its list of firewall rules
        """
        cs_containment_map = self._build_connections_containment_map(connections_sorted_by_size)
        fw_rules_map = defaultdict(list)
        results_map = dict()
        # build fw_rules_map: per connection - a set of its minimized fw rules
        for connections, peer_pairs in connections_sorted_by_size:
            # currently skip "no connections"
            if not connections.allow_all and not connections.allowed_protocols:
                continue
            # TODO: figure out why we have pairs with (ip,ip) ?
            peer_pairs_filtered = self._get_peer_pairs_filtered(peer_pairs)
            peer_pairs_in_containing_connections = cs_containment_map[connections]
            minimize_cs = MinimizeCsFwRules(peer_pairs_filtered, connections,
                                            peer_pairs_in_containing_connections, self.cluster_info,
                                            self.allowed_labels, self.config)
            fw_rules_map[connections] = minimize_cs.minimized_rules_set
            results_map[connections] = minimize_cs.results_info_per_option

        minimize_fw_rules = MinimizeFWRules(fw_rules_map, self.config_name, self.cluster_info, self.config,
                                            results_map)
        # print the result fw rules to stdout
        if print_to_stdout:
            minimize_fw_rules.print_final_fw_rules()
        if self.config.compare_output_files:
            txt_res, yaml_res = minimize_fw_rules.get_comparison_results()
        else:
            txt_res, yaml_res = True, True
        return txt_res, yaml_res, fw_rules_map

    @staticmethod
    def _get_peer_pairs_filtered(peer_pairs):
        """
        Filters out peer pairs where both src and dst are IpBlock
        :param list peer_pairs: the peer pairs to filter
        :return: a filtered list of peer pairs
        """
        return [(src, dst) for (src, dst) in peer_pairs if not (isinstance(src, IpBlock) and isinstance(dst, IpBlock))]

    def _build_connections_containment_map(self, connections_sorted_by_size):
        """
        Build a map from a connection to a set of peer_pairs from connections it is contained in
        :param list connections_sorted_by_size: the original connectivity graph in fw-rules format
        :return: a map from connection to a set of peer pairs from containing connections
        """
        cs_containment_map = defaultdict(set)
        for (conn, _) in connections_sorted_by_size:
            for (other_conn, peer_pairs) in connections_sorted_by_size:
                if other_conn != conn and conn.contained_in(other_conn):
                    peer_pairs_filtered = self._get_peer_pairs_filtered(peer_pairs)
                    cs_containment_map[conn] = cs_containment_map[conn].union(peer_pairs_filtered)
        return cs_containment_map

    @staticmethod
    def _merge_ip_blocks(connections_sorted_by_size):
        connections_sorted_by_size_new = []
        for connections, peer_pairs in connections_sorted_by_size:
            map_ip_blocks_per_dst = dict()
            map_ip_blocks_per_src = dict()
            merged_peer_pairs = []
            for (src, dst) in peer_pairs:
                if isinstance(src, IpBlock) and isinstance(dst, Pod):
                    if not dst in map_ip_blocks_per_dst:
                        map_ip_blocks_per_dst[dst] = src.copy()
                    else:
                        map_ip_blocks_per_dst[dst] |= src
                elif isinstance(dst, IpBlock) and isinstance(src, Pod):
                    if not src in map_ip_blocks_per_src:
                        map_ip_blocks_per_src[src] = dst.copy()
                    else:
                        map_ip_blocks_per_src[src] |= dst
                else:
                    merged_peer_pairs.append((src, dst))
            for (src, ip_block) in map_ip_blocks_per_src.items():
                merged_peer_pairs.append((src, ip_block))
            for (dst, ip_block) in map_ip_blocks_per_dst.items():
                merged_peer_pairs.append((ip_block, dst))
            connections_sorted_by_size_new.append((connections, merged_peer_pairs))

        return connections_sorted_by_size_new
