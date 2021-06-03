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

    def __init__(self, all_peers, allowed_labels, output_config, query_name):
        """
        Create a ConnectivityGraph object
        :param all_peers: PeerSet with the topology all peers (pods and ip blocks)
        :param allowed_labels: the set of allowed labels to be used in generated fw-rules, extracted from policy yamls
        :param output_config: OutputConfiguration object
        :param query_name: name of the query (str)
        """
        # connections_to_peers holds the connectivity graph
        self.connections_to_peers = defaultdict(list)
        self.output_config = output_config
        self.cluster_info = ClusterInfo(all_peers, allowed_labels)
        self.query_name = query_name
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
        Prints the graph as a set of minimized firewall rules
        :param print_to_stdout: flag to indicate if fw-rules should be printed to stdout
        :return: minimize_fw_rules: an object of type MinimizeFWRules holding the minimized fw-rules
        """

        connections_sorted_by_size = list(self.connections_to_peers.items())
        connections_sorted_by_size.sort(reverse=True)

        connections_sorted_by_size = self._merge_ip_blocks(connections_sorted_by_size)

        if self.output_config.fwRulesRunInTestMode:
            # print the original connectivity graph
            for connections, peer_pairs in connections_sorted_by_size:
                for src_peer, dst_peer in peer_pairs:
                    print(f'src: {src_peer}, dest: {dst_peer}, allowed conns: {connections}')
            print('======================================================')
        # create and print the minimized firewall rules
        return self._minimize_firewall_rules(connections_sorted_by_size, print_to_stdout)

    def _minimize_firewall_rules(self, connections_sorted_by_size, print_to_stdout):
        """
        Creates the set of minimized fw rules and prints to output
        :param list connections_sorted_by_size: the original connectivity graph in fw-rules format
        :param print_to_stdout: flag to indicate if fw-rules should be printed to stdout
        :return:  minimize_fw_rules: an object of type MinimizeFWRules holding the minimized fw-rules
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
                                            self.allowed_labels, self.output_config)
            fw_rules_map[connections] = minimize_cs.minimized_rules_set
            results_map[connections] = minimize_cs.results_info_per_option

        minimize_fw_rules = MinimizeFWRules(fw_rules_map, self.query_name, self.cluster_info, self.output_config,
                                            results_map)
        # print the result fw rules to stdout
        if print_to_stdout:
            minimize_fw_rules.print_final_fw_rules()
        # create a yaml output file of fw-rules if required
        create_output_yaml_file = len(self.output_config.fwRulesYamlOutputPath) > 0
        if create_output_yaml_file and len(self.query_name) > 0:
            minimize_fw_rules.create_output_yaml_file()
        return minimize_fw_rules

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
        """
        Given an input connectivity graph, merge ip-blocks for peer-pairs when possible. e.g. if (pod_x ,
        0.0.0.0-49.49.255.255) and ) and (pod_x, 49.50.0.0-255.255.255.255) are in connections_sorted_by_size[conn],
        then in the output result, only (pod_x, 0.0.0.0-255.255.255.255) will be in: connections_sorted_by_size[conn]

        :param connections_sorted_by_size:  the original connectivity graph : a list of tuples (connection set ,
        peer_pairs), where peer_pairs is a list of (src,dst) tuples :return: connections_sorted_by_size_new : a new
        connectivity graph with merged ip-blocks
        """
        connections_sorted_by_size_new = []
        for connections, peer_pairs in connections_sorted_by_size:
            map_ip_blocks_per_dst = dict()
            map_ip_blocks_per_src = dict()
            merged_peer_pairs = []
            for (src, dst) in peer_pairs:
                if isinstance(src, IpBlock) and isinstance(dst, Pod):
                    if dst not in map_ip_blocks_per_dst:
                        map_ip_blocks_per_dst[dst] = src.copy()
                    else:
                        map_ip_blocks_per_dst[dst] |= src
                elif isinstance(dst, IpBlock) and isinstance(src, Pod):
                    if src not in map_ip_blocks_per_src:
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
