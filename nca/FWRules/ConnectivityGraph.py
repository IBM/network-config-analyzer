import os
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
    i = 0
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

    def _get_peer_name(self, peer):
        """
        Get the name of a peer object for connectivity graph + flag indicating if it is ip-block
        :param Peer peer: the peer object
        :return: tuple(str, bool)
        str: the peer name
        bool: flag to indicate if peer is ip-block (True) or not (False)
        """
        nc_name = peer.namespace.name if peer.namespace else 'external'
        if isinstance(peer, IpBlock):
            return peer.get_ip_range_or_cidr_str(), True, [peer.get_ip_range_or_cidr_str()], nc_name
        if self.output_config.outputEndpoints == 'deployments' and isinstance(peer, Pod):
            name = peer.workload_name
        else:
            name = str(peer)
        peer_details = re.split('\/|\(|\)', name)
        peer_details = [line for line in peer_details if line not in ['', nc_name]]
        return name, False, peer_details, nc_name


    def _get_peer_name_old(self, peer):
        """
        Get the name of a peer object for connectivity graph + flag indicating if it is ip-block
        :param Peer peer: the peer object
        :return: tuple(str, bool)
        str: the peer name
        bool: flag to indicate if peer is ip-block (True) or not (False)
        """
        if isinstance(peer, IpBlock):
            return peer.get_ip_range_or_cidr_str(), True
        if self.output_config.outputEndpoints == 'deployments' and isinstance(peer, Pod):
            return peer.workload_name, False
        return str(peer), False

    def _simplify_graph(self, directed_edges):
        not_directed_edges = set([edge for edge in directed_edges if (edge[1], edge[0]) in directed_edges])
        directed_edges = directed_edges - not_directed_edges
        not_directed_edges = set([edge for edge in not_directed_edges if edge[1] < edge[0]])

        new_nodes = []
        G = networkx.Graph()
        G.add_edges_from(not_directed_edges)
        all_cliques = list(networkx.clique.find_cliques(G))
        clique_index = 0
        for clq in all_cliques:
            conn_str = clq[0][2]
            if len(clq) > 4:
                clq_namespaces = set([peer[1] for peer in clq])
                clq_cons = []
                for clq_namespace_name in clq_namespaces:
                    clq_nc_peers = [peer for peer in clq if peer[1] == clq_namespace_name]
                    if len(clq_nc_peers) > 1:
                        namespace_clq_name = f'clique_{clique_index}'
                        clique_index += 1
                        clq_node = (namespace_clq_name, clq_namespace_name, conn_str)
                        new_nodes.append(clq_node)
                        clq_cons.append(clq_node)

                        not_directed_edges |= set([(clq_node, node) for node in clq_nc_peers])
                    else:
                        clq_cons.append(clq_nc_peers[0])

                if len(clq_cons) > 2:
                    clqs_con_name = f'clique_con_{clique_index}'
                    clique_index += 1
                    clqs_con = (clqs_con_name, '', conn_str)
                    new_nodes.append(clqs_con)
                    not_directed_edges |= set([(clq_con, clqs_con) for clq_con in clq_cons])
                elif len(clq_cons) == 2:
                    not_directed_edges.add((clq_cons[0], clq_cons[1]))

                not_directed_edges = not_directed_edges - set(itertools.product(clq, clq))
        return directed_edges, not_directed_edges, new_nodes


    def get_connectivity_dot_format_str(self):
        """
        :return: a string with content of dot format for connectivity graph
        """

        if self.output_config.queryName and self.output_config.configName:
            name = f'{self.output_config.queryName}/{self.output_config.configName}'
        else:
            name = f'{self.output_config.configName}'

        dot_graph = DotGraph(name)
        peer_names_to_nc = {}
        for peer in self.cluster_info.all_peers:
            peer_name, is_ip_block, text, nc_name = self._get_peer_name(peer)
            dot_graph.add_node(nc_name, peer_name, 'ip_block' if is_ip_block else 'pod', text)

        directed_edges = set()
        for connections, peer_pairs in self.connections_to_peers.items():
            conn_str = str(connections).replace("Protocol:", "")
            for src_peer, dst_peer in peer_pairs:
                if src_peer != dst_peer and connections:
                    src_peer_name, _, _, src_nc = self._get_peer_name(src_peer)
                    dst_peer_name, _, _, dst_nc = self._get_peer_name(dst_peer)
                    peer_names_to_nc[src_peer_name] = src_nc
                    peer_names_to_nc[dst_peer_name] = dst_nc
                    directed_edges.add(((src_peer_name, src_nc, conn_str), (dst_peer_name, dst_nc, conn_str)))

        directed_edges, not_directed_edges, new_peers = self._simplify_graph(directed_edges)

        for peer in new_peers:
            dot_graph.add_node(peer[1], peer[0], 'clq', [peer[2]])
        for edge in directed_edges:
            dot_graph.add_edge(edge[0][0], edge[1][0], edge[0][2], True)
        for edge in not_directed_edges:
            dot_graph.add_edge(edge[0][0], edge[1][0], edge[0][2], False)

        output_result = dot_graph.to_str()


        with open('nsa_runs.lst', 'a') as f:
            f.write('printing dot\n')

        e_name = f'gr{ConnectivityGraph.i}{self.output_config.configName}'
        e_name = e_name.replace('/','_').replace('\\','/')
        with open(os.path.join('graphs', f'{e_name}.dot'), 'w') as f:
            f.write(output_result)
        with open(os.path.join('graphs', f'{e_name}_old.dot'), 'w') as f:
            f.write(self._get_connectivity_dot_format_str_old())
        ConnectivityGraph.i += 1
        return output_result




    def _get_connectivity_dot_format_str_old(self):
        """
        :return: a string with content of dot format for connectivity graph
        """
        output_result = f'// The Connectivity Graph of {self.output_config.configName}\n'
        output_result += 'digraph ' + '{\n'
        if self.output_config.queryName and self.output_config.configName:
            output_result += f'\tHEADER [shape="box" label=< <B>{self.output_config.queryName}/' \
                             f'{self.output_config.configName}</B> > fontsize=30 color=webmaroon fontcolor=webmaroon];\n'
        peer_lines = set()
        for peer in self.cluster_info.all_peers:
            peer_name, is_ip_block = self._get_peer_name_old(peer)
            peer_color = "red2" if is_ip_block else "blue"
            peer_lines.add(
                f'\t\"{peer_name}\" [label=\"{peer_name}\" color=\"{peer_color}\" fontcolor=\"{peer_color}\"]\n')

        edge_lines = set()
        for connections, peer_pairs in self.connections_to_peers.items():
            for src_peer, dst_peer in peer_pairs:
                if src_peer != dst_peer and connections:
                    src_peer_name, _ = self._get_peer_name_old(src_peer)
                    dst_peer_name, _ = self._get_peer_name_old(dst_peer)
                    line = '\t'
                    line += f'\"{src_peer_name}\"'
                    line += ' -> '
                    line += f'\"{dst_peer_name}\"'
                    conn_str = str(connections).replace("Protocol:", "")
                    line += f' [label=\"{conn_str}\" color=\"gold2\" fontcolor=\"darkgreen\"]\n'
                    edge_lines.add(line)
        output_result += ''.join(line for line in sorted(list(peer_lines))) + \
                         ''.join(line for line in sorted(list(edge_lines))) + '}\n\n'
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
                    src_peer_name = self._get_peer_name(src_peer)[0]
                    dst_peer_name = self._get_peer_name(dst_peer)[0]
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
