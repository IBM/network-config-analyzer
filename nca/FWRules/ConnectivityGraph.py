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
        Get the name of a peer object for connectivity graph, flag indicating if it is ip-block and the namespace
        :param Peer peer: the peer object
        :return: tuple(str, bool, str )
        str: the peer name
        bool: flag to indicate if peer is ip-block (True) or not (False)
        str: namespace name
        """
        nc_name = peer.namespace.name if peer.namespace else 'external'
        if isinstance(peer, IpBlock):
            return peer.get_ip_range_or_cidr_str(), True, nc_name
        if self.output_config.outputEndpoints == 'deployments' and isinstance(peer, Pod):
            name = peer.workload_name
        else:
            name = str(peer)
        return name, False, nc_name

    def _creates_cliqued_graph(self, directed_edges):
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

        MIN_CLIQUE_SIZE = 4

        # replacing directed edges with not directed edges:
        not_directed_edges = set([edge for edge in directed_edges if (edge[1], edge[0]) in directed_edges])
        directed_edges = directed_edges - not_directed_edges
        not_directed_edges = set([edge for edge in not_directed_edges if edge[1] < edge[0]])

        # find cliques in the graph:
        graph = networkx.Graph()
        graph.add_edges_from(not_directed_edges)
        cliques = list(networkx.clique.find_cliques(graph))

        cliques_nodes = []
        for clique in cliques:
            if len(clique) < MIN_CLIQUE_SIZE:
                continue
            clq_namespaces = set([peer[1] for peer in clique])
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
                    not_directed_edges |= set([(namespace_clique_node, node) for node in clq_namespace_peers])
                else:
                    # if the namespace has only one node, we will not add a new clique node
                    # instead we will add it to the clique new nodes:
                    clique_namespaces_nodes.append(clq_namespace_peers[0])

            if len(clique_namespaces_nodes) > 2:
                # creating one more new node,  out of any namespace, and connect it to all other clique new nodes:
                clique_node_name = f'clique_{len(cliques_nodes)}'
                clique_node = (clique_node_name, '')
                cliques_nodes.append(clique_node)
                not_directed_edges |= set([(clq_con, clique_node) for clq_con in clique_namespaces_nodes])
            elif len(clique_namespaces_nodes) == 2:
                # if only 2 new nodes - we will just connect them to each other
                not_directed_edges.add((clique_namespaces_nodes[0], clique_namespaces_nodes[1]))

            # removing the original edges of the clique:
            not_directed_edges = not_directed_edges - set(itertools.product(clique, clique))

        return directed_edges, not_directed_edges, cliques_nodes

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

        dot_graph = DotGraph(name)
        for peer in self.cluster_info.all_peers:
            peer_name, is_ip_block, nc_name = self._get_peer_details(peer)
            text = [peer_name]
            if not is_ip_block:
                # todo - is there a better way to get peer details?
                text = [text for text in re.split('[/()]+', peer_name) if text != nc_name]
            node_type = 'ip_block' if is_ip_block else 'pod'
            dot_graph.add_node(nc_name, peer_name, node_type, text)

        for connections, peer_pairs in self.connections_to_peers.items():
            directed_edges = set()
            # todo - is there a better way to get edge details?
            # we should revisit this code after reformatting connections labels
            conn_str = connections.get_simplified_connections_representation(True)
            conn_str = conn_str.replace("Protocol:", "").replace('All connections', 'All')
            for src_peer, dst_peer in peer_pairs:
                if src_peer != dst_peer and connections:
                    src_peer_name, _, src_nc = self._get_peer_details(src_peer)
                    dst_peer_name, _, dst_nc = self._get_peer_details(dst_peer)
                    directed_edges.add(((src_peer_name, src_nc), (dst_peer_name, dst_nc)))

            directed_edges, not_directed_edges, new_peers = self._creates_cliqued_graph(directed_edges)

            for peer in new_peers:
                dot_graph.add_node(subgraph=peer[1], name=peer[0], node_type='clq', label=[conn_str])
            for edge in directed_edges:
                dot_graph.add_edge(src_name=edge[0][0], dst_name=edge[1][0], label=conn_str, is_dir=True)
            for edge in not_directed_edges:
                dot_graph.add_edge(src_name=edge[0][0], dst_name=edge[1][0], label=conn_str, is_dir=False)
        output_result = dot_graph.to_str()

        return output_result

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
