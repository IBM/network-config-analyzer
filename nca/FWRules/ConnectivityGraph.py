#
# Copyright 2020- IBM Inc. All rights reserved
# SPDX-License-Identifier: Apache2.0
#

import itertools
import re
from collections import defaultdict
import networkx
from nca.CoreDS.Peer import IpBlock, ClusterEP, Pod
from .DotGraph import DotGraph
from .MinimizeFWRules import MinimizeCsFwRules, MinimizeFWRules
from .ClusterInfo import ClusterInfo


class ConnectivityGraph:
    """
    Represents a connectivity digraph, that is a set of labeled edges, where the nodes are peers and
    the labels on the edges are the allowed connections between two peers.
    """

    def __init__(self, all_peers, allowed_labels, output_config):
        """
        Create a ConnectivityGraph object
        :param all_peers: PeerSet with the topology all peers (pods and ip blocks)
        :param allowed_labels: the set of allowed labels to be used in generated fw-rules, extracted from policy yamls
        :param output_config: OutputConfiguration object
        """
        # connections_to_peers holds the connectivity graph
        self.connections_to_peers = defaultdict(list)
        self.output_config = output_config
        if self.output_config.fwRulesOverrideAllowedLabels:
            allowed_labels = set(label for label in self.output_config.fwRulesOverrideAllowedLabels.split(','))
        self.cluster_info = ClusterInfo(all_peers, allowed_labels)
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

    def add_edges(self, connections):
        """
        Adding a set of labeled edges to the graph
        :param dict connections: a map from ConnectionSet to (src, dest) pairs
        :return: None
        """
        self.connections_to_peers.update(connections)

    def _get_peer_details(self, peer):
        """
        Get the name of a peer object for connectivity graph, the type and the namespace
        :param Peer peer: the peer object
        :return: tuple(str, str, str )
        str: the peer name
        str: the peer type ip_block, livesim, or pod
        str: namespace name
        """
        nc_name = peer.namespace.name if peer.namespace else ''
        if isinstance(peer, IpBlock):
            return peer.get_ip_range_or_cidr_str(), DotGraph.NodeType.IPBlock, nc_name, peer.get_ip_range_or_cidr_str()
        is_livesim = peer.full_name().endswith('-livesim')
        peer_type = DotGraph.NodeType.Livesim if is_livesim else DotGraph.NodeType.Pod
        if self.output_config.outputEndpoints == 'deployments' and isinstance(peer, Pod):
            name = peer.workload_name
        else:
            name = str(peer)
        text = [t for t in name.split('/') if t != nc_name][0]
        return name, peer_type, nc_name, text

    @staticmethod
    def _creates_cliqued_graph(directed_edges, conn_str):
        """
        A clique is a subset of nodes, where every pair of nodes in the subset has an edge
        This method creates a new graph with cliques. of each clique in the graph:
            1. The original edges of the clique are removed
            2. A clique is represented as one or more new nodes (see comment below*)
            3. All new nodes representing one clique are connected to each other
            4. The original nodes of the clique are connected to one of the clique nodes

        comment: In most cases, when a clique has nodes from different namespaces,
                 the clique will be represent by more than one node.
                 a new node will be created for every namespace


        :param: directed_edges: list of pairs representing the original graph
        return: truple( list, list, list)
        list: list of the directed edges
        list: list of the not directed edges
        list: list of the new nodes that was created to represent the cliques

        """

        min_qlicue_size = 4

        # replacing directed edges with not directed edges:
        not_directed_edges = set(edge for edge in directed_edges if (edge[1], edge[0]) in directed_edges)
        directed_edges = directed_edges - not_directed_edges
        not_directed_edges = set(edge for edge in not_directed_edges if edge[1] < edge[0])

        # find cliques in the graph:
        graph = networkx.Graph()
        graph.add_edges_from(not_directed_edges)
        cliques = networkx.clique.find_cliques(graph)

        cliques_nodes = []
        cliques_edges = set()
        cliques = sorted([sorted(clique) for clique in cliques])
        for clique in cliques:
            if len(clique) < min_qlicue_size:
                continue
            clq_namespaces = sorted(set(peer[1] for peer in clique))
            # the list of new nodes of the clique:
            clique_namespaces_nodes = []
            for namespace_name in clq_namespaces:
                clq_namespace_peers = [peer for peer in clique if peer[1] == namespace_name]
                if len(clq_namespace_peers) > 1:
                    # creates a new clique node for the namespace
                    namespace_clique_name = f'clique_{len(cliques_nodes)}'
                    namespace_clique_node = (namespace_clique_name, namespace_name)
                    cliques_nodes.append(namespace_clique_node)
                    clique_namespaces_nodes.append(namespace_clique_node)

                    # adds edges from the new node to the original clique nodes in the namespace
                    not_directed_edges |= set((namespace_clique_node, node) for node in clq_namespace_peers)
                else:
                    # if the namespace has only one node, we will not add a new clique node
                    # instead we will add it to the clique new nodes:
                    clique_namespaces_nodes.append(clq_namespace_peers[0])

            if len(clique_namespaces_nodes) > 2:
                # creating one more new node,  out of any namespace, and connect it to all other clique new nodes:
                clique_node_name = f'clique_{conn_str}{len(cliques_nodes)}'
                clique_node = (clique_node_name, '')
                cliques_nodes.append(clique_node)
                not_directed_edges |= set((clq_con, clique_node) for clq_con in clique_namespaces_nodes)
            elif len(clique_namespaces_nodes) == 2:
                # if only 2 new nodes - we will just connect them to each other
                cliques_edges.add((clique_namespaces_nodes[0], clique_namespaces_nodes[1]))

            # removing the original edges of the clique:
            not_directed_edges = not_directed_edges - set(itertools.product(clique, clique))

        return directed_edges, not_directed_edges | cliques_edges, cliques_nodes


    def _creates_bicliqued_graph(self, directed_edges, not_directed_edges, conn_str):

        bicliques_nodes = []
        bicliques_edges = set()
        directed_edges = directed_edges | not_directed_edges | set([(edge[1], edge[0]) for edge in not_directed_edges])
        not_directed_edges = set()

        while True:
            all_sources = set([edge[0] for edge in directed_edges])
            src_to_dst_set = {src: frozenset([e[1] for e in directed_edges if e[0] == src]) for src in all_sources}
            all_dst_set = frozenset(src_to_dst_set.values())

            all_bicliques = {frozenset([src for src in all_sources if src_to_dst_set[src] >= dst_set]): dst_set for dst_set in all_dst_set}
            bicliques_ranks = {(src_set, dst_set): len(src_set) * len(dst_set) - len(src_set) - len(dst_set) for src_set, dst_set in all_bicliques.items()}
            best_biclique = max(bicliques_ranks, key=bicliques_ranks.get) if len(bicliques_ranks) else (frozenset(), frozenset())
            if bicliques_ranks.get(best_biclique, -1) < 0:
                break
            directed_edges -= set(itertools.product(best_biclique[0], best_biclique[1]))
            biclique_name = f'biclique_{conn_str}{len(bicliques_nodes)}'
            biclique_node = (biclique_name, '')
            bicliques_nodes.append(biclique_node)
            bicliques_edges |= set([(src, biclique_node) for src in best_biclique[0]])
            bicliques_edges |= set([(biclique_node, dst) for dst in best_biclique[1]])

        # replacing directed edges with not directed edges:
        not_directed_edges = set([edge for edge in directed_edges if (edge[1], edge[0]) in directed_edges])
        directed_edges = directed_edges - not_directed_edges
        not_directed_edges = set([edge for edge in not_directed_edges if edge[1] < edge[0]])

        ####################################################################################

        return directed_edges | bicliques_edges, not_directed_edges, bicliques_nodes

    def _get_equals_peers(self, also_connected):
        all_peers = set(self.cluster_info.all_peers)
        peers_connections = {peer: [] for peer in all_peers}

        for connections, peer_pairs in self.connections_to_peers.items():
            for src_peer, dst_peer in peer_pairs:
                if src_peer != dst_peer and connections:
                    peers_connections[src_peer].append((dst_peer, connections, False))
                    peers_connections[dst_peer].append((src_peer, connections, True))

        peers_connections = {peer: frozenset(connections) for peer, connections in peers_connections.items()}
        equal_pairs = []
        for peer0 in all_peers:
            for peer1 in all_peers:
                if also_connected:
                    pc0 = set(peers_connections[peer0])
                    pc1 = set(peers_connections[peer1])
                    connections01 = set([con[1] for con in pc0 | pc1])

                    missing0 = pc1 - pc0
                    missing1 = pc0 - pc1
                    should_be_missing0 = set([(peer0, con, True) for con in connections01]) | set([(peer0, con, False) for con in connections01])
                    should_be_missing1 = set([(peer1, con, True) for con in connections01]) | set([(peer1, con, False) for con in connections01])
                    same_connection = missing0 == should_be_missing0 and missing1 == should_be_missing1
                    if len(self.connections_to_peers.keys()) == 4 and peer0.name == 'ibm-cloud-provider-ip-169-60-164-10-5c9dd7c9c-r66p2' and peer1.name == 'ibm-cloud-provider-ip-169-60-164-14-6d448884df-vsh47':
                        print('got it')
                else:
                    same_connection = peers_connections[peer0] == peers_connections[peer1]
                if peer0 != peer1 and\
                        same_connection and\
                        peer0.namespace == peer1.namespace and\
                        (peer1, peer0) not in equal_pairs:
                    equal_pairs.append((peer0, peer1))

        graph = networkx.Graph()
        graph.add_edges_from(equal_pairs)
        equal_sets = list(networkx.clique.find_cliques(graph))
        left_out = all_peers - set(graph.nodes)

        return equal_sets + [[p] for p in left_out]


    def get_connectivity_dot_format_str(self, connectivity_restriction=None):
        """
        :param Union[str,None] connectivity_restriction: specify if connectivity is restricted to
               TCP / non-TCP , or not
        :rtype str
        :return: a string with content of dot format for connectivity graph
        """
        restriction_title = f', for {connectivity_restriction} connections' if connectivity_restriction else ''
        query_title = f'{self.output_config.queryName}/' if self.output_config.queryName else ''
        name = f'{query_title}{self.output_config.configName}{restriction_title}'

        group_equal_peers = True
        #group_equal_peers = False
        find_cliques = True
        find_cliques = False
        find_bicliques = True
        find_bicliques = False

        if group_equal_peers:
            #multi_peers = self._get_equals_peers(True)
            multi_peers = self._get_equals_peers(False)
        else:
            multi_peers = [[p] for p in self.cluster_info.all_peers]

        representing_peers = [multi_peer[0] for multi_peer in multi_peers]
        dot_graph = DotGraph(name)
        for multi_peer in multi_peers:
            representing_peer = multi_peer[0]
            representing_peer_name, representing_node_type, representing_nc_name, _ = self._get_peer_details(representing_peer)
            representing_text = set()
            for peer in multi_peer:
                peer_name, node_type, nc_name, text = self._get_peer_details(peer)
                representing_text.add(text)
            if len(representing_text) > 1:
                representing_node_type = DotGraph.NodeType.MultiPod
            dot_graph.add_node(representing_nc_name, representing_peer_name, representing_node_type, representing_text)

        for connections, peer_pairs in self.connections_to_peers.items():
            directed_edges = set()
            # todo - is there a better way to get edge details?
            # we should revisit this code after reformatting connections labels
            conn_str = connections.get_simplified_connections_representation(True)
            conn_str = conn_str.replace("Protocol:", "").replace('All connections', 'All')
            for src_peer, dst_peer in peer_pairs:
                if src_peer != dst_peer and connections and src_peer in representing_peers and dst_peer in representing_peers:
                    src_peer_name, _, src_nc, _ = self._get_peer_details(src_peer)
                    dst_peer_name, _, dst_nc, _ = self._get_peer_details(dst_peer)
                    directed_edges.add(((src_peer_name, src_nc), (dst_peer_name, dst_nc)))

            # replacing directed edges with not directed edges:
            not_directed_edges = set(edge for edge in directed_edges if (edge[1], edge[0]) in directed_edges)
            directed_edges = directed_edges - not_directed_edges
            not_directed_edges = set(edge for edge in not_directed_edges if edge[1] < edge[0])

            if find_cliques:
                directed_edges, not_directed_edges, new_cliques = self._creates_cliqued_graph(directed_edges, conn_str)
            else:
                new_cliques = []

            if find_bicliques:
                directed_edges, not_directed_edges, new_bicliques = self._creates_bicliqued_graph(
                    directed_edges, not_directed_edges, conn_str)
            else:
                new_bicliques = []

            for peer in new_cliques:
                dot_graph.add_node(subgraph=peer[1], name=peer[0], node_type=DotGraph.NodeType.Clique, label=[conn_str])
            for peer in new_bicliques:
                dot_graph.add_node(subgraph=peer[1], name=peer[0], node_type=DotGraph.NodeType.BiClique, label=[conn_str])
            for edge in directed_edges:
                dot_graph.add_edge(src_name=edge[0][0], dst_name=edge[1][0], label=conn_str, is_dir=True)
            for edge in not_directed_edges:
                dot_graph.add_edge(src_name=edge[0][0], dst_name=edge[1][0], label=conn_str, is_dir=False)
        return dot_graph.to_str()

    def get_minimized_firewall_rules(self):
        """
        computes and returns minimized firewall rules from original connectivity graph
        :return: minimize_fw_rules: an object of type MinimizeFWRules holding the minimized fw-rules
        """

        connections_sorted_by_size = list(self.connections_to_peers.items())
        connections_sorted_by_size.sort(reverse=True)

        connections_sorted_by_size = self._merge_ip_blocks(connections_sorted_by_size)

        if self.output_config.fwRulesRunInTestMode:
            # print the original connectivity graph
            lines = set()
            for connections, peer_pairs in connections_sorted_by_size:
                for src_peer, dst_peer in peer_pairs:
                    src_peer_name = self._get_peer_details(src_peer)[0]
                    dst_peer_name = self._get_peer_details(dst_peer)[0]
                    # on level of deployments, omit the 'all connections' between a pod to itself
                    # a connection between deployment to itself is derived from connection between 2 different pods of
                    # the same deployment
                    if src_peer == dst_peer and self.output_config.outputEndpoints == 'deployments':
                        continue
                    lines.add(f'src: {src_peer_name}, dest: {dst_peer_name}, allowed conns: {connections}')
            for line in lines:
                print(line)
            print('======================================================')
        # compute the minimized firewall rules
        return self._minimize_firewall_rules(connections_sorted_by_size)

    def _minimize_firewall_rules(self, connections_sorted_by_size):
        """
        Creates the set of minimized fw rules and prints to output
        :param list connections_sorted_by_size: the original connectivity graph in fw-rules format
        :return:  minimize_fw_rules: an object of type MinimizeFWRules holding the minimized fw-rules
        """
        cs_containment_map = self._build_connections_containment_map(connections_sorted_by_size)
        fw_rules_map = defaultdict(list)
        results_map = dict()
        minimize_cs = MinimizeCsFwRules(self.cluster_info, self.allowed_labels, self.output_config)
        # build fw_rules_map: per connection - a set of its minimized fw rules
        for connections, peer_pairs in connections_sorted_by_size:
            # currently skip "no connections"
            if not connections:
                continue
            # TODO: figure out why we have pairs with (ip,ip) ?
            peer_pairs_filtered = self._get_peer_pairs_filtered(peer_pairs)
            peer_pairs_in_containing_connections = cs_containment_map[connections]
            fw_rules, results_per_info = minimize_cs.compute_minimized_fw_rules_per_connection(
                connections, peer_pairs_filtered, peer_pairs_in_containing_connections)
            fw_rules_map[connections] = fw_rules
            results_map[connections] = results_per_info

        minimize_fw_rules = MinimizeFWRules(fw_rules_map, self.cluster_info, self.output_config,
                                            results_map)
        return minimize_fw_rules

    @staticmethod
    def _get_peer_pairs_filtered(peer_pairs):
        """
        Filters out peer pairs where both src and dst are IpBlock
        :param list peer_pairs: the peer pairs to filter
        :return: a filtered set of peer pairs
        """
        return set((src, dst) for (src, dst) in peer_pairs if not (isinstance(src, IpBlock) and isinstance(dst, IpBlock)))

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
                    cs_containment_map[conn] |= peer_pairs_filtered
        return cs_containment_map

    @staticmethod
    def _merge_ip_blocks(connections_sorted_by_size):
        """
        Given an input connectivity graph, merge ip-blocks for peer-pairs when possible. e.g. if (pod_x ,
        0.0.0.0-49.49.255.255) and ) and (pod_x, 49.50.0.0-255.255.255.255) are in connections_sorted_by_size[conn],
        then in the output result, only (pod_x, 0.0.0.0-255.255.255.255) will be in: connections_sorted_by_size[conn]

        :param connections_sorted_by_size:  the original connectivity graph : a list of tuples
               (connection set ,  peer_pairs), where peer_pairs is a list of (src,dst) tuples
        :return: connections_sorted_by_size_new : a new connectivity graph with merged ip-blocks
        """
        connections_sorted_by_size_new = []
        for connections, peer_pairs in connections_sorted_by_size:
            map_ip_blocks_per_dst = dict()
            map_ip_blocks_per_src = dict()
            merged_peer_pairs = []
            for (src, dst) in peer_pairs:
                if isinstance(src, IpBlock) and isinstance(dst, ClusterEP):
                    if dst not in map_ip_blocks_per_dst:
                        map_ip_blocks_per_dst[dst] = src.copy()
                    else:
                        map_ip_blocks_per_dst[dst] |= src
                elif isinstance(dst, IpBlock) and isinstance(src, ClusterEP):
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

    def conn_graph_has_fw_rules(self):
        """
        :return: bool flag indicating if the given conn_graph has fw_rules (and not considered empty)
        """
        if not self.connections_to_peers:
            return False
        if len((self.connections_to_peers.items())) == 1:
            conn = list(self.connections_to_peers.keys())[0]
            # we currently do not create fw-rules for "no connections"
            if not conn:  # conn is "no connections":
                return False
        return True
