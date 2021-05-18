from collections import defaultdict
from ClusterInfo import ClusterInfo
from ConnectionSet import ConnectionSet
from Peer import Peer, IpBlock, Pod
from MinimizeFWRules import MinimizeCsFwRules, MinimizeFWRules


class ConnectivityGraph:
    """
    Represents a connectivity digraph, that is a set of labeled edges, where the nodes are peers and
    the labels on the edges are the allowed connections between two peers.
    """

    def __init__(self, all_peers, config_name, allowed_labels, run_in_test_mode):
        self.connections_to_peers = defaultdict(list)
        self.cluster_info = ClusterInfo(all_peers, allowed_labels)
        self.config_name = config_name
        self.allowed_labels = allowed_labels
        self.run_in_test_mode = run_in_test_mode

    def add_edge(self, source_peer, dest_peer, connections):
        """
        Adding a labeled edge to the graph
        :param Peer source_peer: The source peer
        :param Peer dest_peer: The dest peer
        :param ConnectionSet connections: The allowed connections from source_peer to dest_peer
        :return: None
        """
        added_by_merge = self._add_edge_with_ip_merge(source_peer, dest_peer, connections)
        if not added_by_merge:
            self.connections_to_peers[connections].append((source_peer, dest_peer))

    def output_as_firewall_rules(self):
        """
        Prints the graph as a set of firewall rules
        :return: None
        """
        connections_sorted_by_size = [(conn, peer_pair) for conn, peer_pair in self.connections_to_peers.items()]
        connections_sorted_by_size.sort(reverse=True)

        if self.run_in_test_mode:
            # print the original connectivity graph
            for connections, peer_pairs in connections_sorted_by_size:
                for src_peer, dst_peer in peer_pairs:
                    print(f'src: {src_peer}, dest: {dst_peer}, allowed conns: {connections}')
            print('======================================================')
        self._minimize_firewall_rules(connections_sorted_by_size)

    def _minimize_firewall_rules(self, connections_sorted_by_size):
        """
        Creates the set of minimized fw rules and prints to output
        :param list connections_sorted_by_size: the original connectivity graph in fw-rules format
        :return: None
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
                                            self.allowed_labels, self.run_in_test_mode)
            fw_rules_map[connections] = minimize_cs.minimized_rules_set
            results_map[connections] = minimize_cs.results_info_per_option

        minimize_fw_rules = MinimizeFWRules(fw_rules_map, self.config_name, self.cluster_info, self.run_in_test_mode,
                                            results_map)
        # print the result fw rules to stdout
        minimize_fw_rules.print_final_fw_rules()
        return

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

    def _add_edge_with_ip_merge(self, source_peer, dest_peer, connections):
        """
        Adding a labeled edge to the graph with merge operation for ip-block
        :param Peer source_peer: The source peer
        :param Peer dest_peer: The dest peer
        :param ConnectionSet connections: The allowed connections from source_peer to dest_peer
        :return: True if edge was added with merge operation, False if edge was not added at all
        """
        if isinstance(source_peer, IpBlock) and isinstance(dest_peer, Pod):
            ip_blocks_per_dest = [src for (src, dst) in self.connections_to_peers[connections] if
                                  dst == dest_peer and isinstance(src, IpBlock)]
            merge_possible, merge_result = self._merge_ip_blocks(source_peer, ip_blocks_per_dest)
            if merge_possible:
                self.connections_to_peers[connections] = list(
                    set(self.connections_to_peers[connections]) - set([(ip, dest_peer) for ip in ip_blocks_per_dest]))
                self.connections_to_peers[connections].extend([(ip, dest_peer) for ip in merge_result])
                return True
        elif isinstance(source_peer, Pod) and isinstance(dest_peer, IpBlock):
            ip_blocks_per_src = [dst for (src, dst) in self.connections_to_peers[connections] if
                                 src == source_peer and isinstance(dst, IpBlock)]
            merge_possible, merge_result = self._merge_ip_blocks(dest_peer, ip_blocks_per_src)
            if merge_possible:
                self.connections_to_peers[connections] = list(
                    set(self.connections_to_peers[connections]) - set([(source_peer, ip) for ip in ip_blocks_per_src]))
                self.connections_to_peers[connections].extend([(source_peer, ip) for ip in merge_result])
                return True
        return False

    @staticmethod
    def _merge_ip_blocks(ip, ip_list):
        merged_ip = ip.copy()
        for ip in ip_list:
            merged_ip |= ip
        ip_intervals_list = merged_ip.split()
        merge_success = len(ip_intervals_list) < len(ip_list) + 1
        return merge_success, ip_intervals_list
