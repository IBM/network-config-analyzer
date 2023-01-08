#
# Copyright 2020- IBM Inc. All rights reserved
# SPDX-License-Identifier: Apache2.0
#

from collections import defaultdict
from nca.CoreDS.Peer import Peer, IpBlock, PeerSet, ClusterEP, Pod
from nca.CoreDS.PortSet import PortSet
from nca.CoreDS.ConnectionSet import ConnectionSet
from nca.CoreDS.ProtocolSet import ProtocolSet
from nca.CoreDS.TcpLikeProperties import TcpLikeProperties
from nca.CoreDS.ICMPDataSet import ICMPDataSet
from .MinimizeFWRules import MinimizeCsFwRules, MinimizeFWRules
from .ClusterInfo import ClusterInfo


class ConnectivityGraphPrototype:
    def __init__(self, output_config):
        """
        Create a ConnectivityGraph object
        :param output_config: OutputConfiguration object
        """
        # connections_to_peers holds the connectivity graph
        self.output_config = output_config

    def _get_peer_name(self, peer):
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


class ConnectivityGraph(ConnectivityGraphPrototype):
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
        super().__init__(output_config)
        self.connections_to_peers = defaultdict(list)
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

    def add_edges_from_cube_dict(self, peer_container, cube_dict):
        """
        Add edges to the graph according to the give cube
        :param peer_container: the peer_container containing all possible peers
        :param dict cube_dict: the given cube in dictionary format
        """
        new_cube_dict = cube_dict.copy()
        src_peers = new_cube_dict.get('src_peers')
        if src_peers:
            new_cube_dict.pop('src_peers')
        else:
            src_peers = peer_container.get_all_peers_group(True)
        dst_peers = new_cube_dict.get('dst_peers')
        if dst_peers:
            new_cube_dict.pop('dst_peers')
        else:
            dst_peers = peer_container.get_all_peers_group(True)
        protocols = new_cube_dict.get('protocols')
        if protocols:
            new_cube_dict.pop('protocols')

        if not protocols and not new_cube_dict:
            conns = ConnectionSet(True)
        else:
            conns = ConnectionSet()
            protocol_names = ProtocolSet.get_protocol_names_from_interval_set(protocols) if protocols else ['TCP']
            for protocol in protocol_names:
                if new_cube_dict:
                    conns.add_connections(protocol, TcpLikeProperties.make_tcp_like_properties_from_dict(peer_container,
                                                                                                         new_cube_dict))
                else:
                    if ConnectionSet.protocol_supports_ports(protocol):
                        conns.add_connections(protocol, TcpLikeProperties.make_all_properties())
                    elif ConnectionSet.protocol_is_icmp(protocol):
                        conns.add_connections(protocol, TcpLikeProperties.make_all_properties())
                    else:
                        conns.add_connections(protocol, True)
        for src_peer in src_peers:
            for dst_peer in dst_peers:
                self.connections_to_peers[conns].append((src_peer, dst_peer))

    def get_connectivity_dot_format_str(self):
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
            peer_name, is_ip_block = self._get_peer_name(peer)
            peer_color = "red2" if is_ip_block else "blue"
            peer_lines.add(f'\t\"{peer_name}\" [label=\"{peer_name}\" color=\"{peer_color}\" '
                           f'fontcolor=\"{peer_color}\"]\n')

        edge_lines = set()
        for connections, peer_pairs in self.connections_to_peers.items():
            for src_peer, dst_peer in peer_pairs:
                if src_peer != dst_peer and connections:
                    src_peer_name, _ = self._get_peer_name(src_peer)
                    dst_peer_name, _ = self._get_peer_name(dst_peer)
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

    def convert_to_tcp_like_properties(self, peer_container):
        """
        Used for testing of the optimized solution: converting connectivity graph back to TcpLikeProperties
        :param peer_container: The peer container
        :return: TcpLikeProperties representing the connectivity graph
        """
        res = TcpLikeProperties.make_empty_properties()
        for item in self.connections_to_peers.items():
            if item[0].allow_all:
                for peer_pair in item[1]:
                    res |= TcpLikeProperties.make_tcp_like_properties(peer_container,
                                                                      src_peers=PeerSet({peer_pair[0]}),
                                                                      dst_peers=PeerSet({peer_pair[1]}),
                                                                      exclude_same_src_dst_peers=False)
            else:
                for prot in item[0].allowed_protocols.items():
                    protocols = ProtocolSet()
                    protocols.add_protocol(prot[0])
                    if isinstance(prot[1], bool):
                        for peer_pair in item[1]:
                            res |= TcpLikeProperties.make_tcp_like_properties(peer_container, protocols=protocols,
                                                                              src_peers=PeerSet({peer_pair[0]}),
                                                                              dst_peers=PeerSet({peer_pair[1]}),
                                                                              exclude_same_src_dst_peers=False)
                        continue
                    for cube in prot[1]:
                        cube_dict = prot[1].get_cube_dict_with_orig_values(cube)
                        cube_dict["protocols"] = protocols
                        for peer_pair in item[1]:
                            new_cube_dict = cube_dict.copy()
                            new_cube_dict["src_peers"] = PeerSet({peer_pair[0]})
                            new_cube_dict["dst_peers"] = PeerSet({peer_pair[1]})
                            res |= TcpLikeProperties.make_tcp_like_properties_from_dict(peer_container, new_cube_dict)
        return res

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
                    src_peer_name, _ = self._get_peer_name(src_peer)
                    dst_peer_name, _ = self._get_peer_name(dst_peer)
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


class ConnectivityGraphOptimized(ConnectivityGraphPrototype):
    """
    Represents an optimized connectivity digraph, that is a set of labeled edges, where the nodes are sets of peers
    and the labels on the edges are the allowed connections between the two sets of peers.
    """

    def __init__(self, output_config):
        """
        Create a ConnectivityGraph object
        :param output_config: OutputConfiguration object
        """
        super().__init__(output_config)
        self.edges = []  # the list of tuples(src_peers, dst_peers, connections)
        self.peer_sets = set()  # the set of all src/dst PeerSets in the graph

    def get_peer_set_names(self, peer_set):
        """
        Convert a given peer_set to a string format for the output
        :param peer_set: the given peer_set
        :return: the string describing the given peer_set
        """
        res_names = ''
        res_is_only_ip_block = True
        res_is_only_pods = True
        for peer in peer_set:
            peer_name, is_ip_block = self._get_peer_name(peer)
            res_names += ', ' + peer_name if res_names else peer_name
            res_is_only_ip_block &= is_ip_block
            res_is_only_pods &= not is_ip_block
        return res_names, res_is_only_ip_block, res_is_only_pods

    def add_edge(self, cube_dict):
        """
        Adding a labeled edge to the graph
        :param dict cube_dict: The map from all every dimension to its values
        :return: None
        """
        new_cube_dict = cube_dict.copy()
        src_peers = new_cube_dict.get('src_peers') or PeerSet()
        dst_peers = new_cube_dict.get('dst_peers') or PeerSet()
        self.peer_sets.add(src_peers)
        self.peer_sets.add(dst_peers)
        if src_peers:
            new_cube_dict.pop('src_peers')
        if dst_peers:
            new_cube_dict.pop('dst_peers')
        self.edges.append((src_peers, dst_peers, new_cube_dict))

    def get_connectivity_dot_format_str(self):
        """
        :return: a string with content of dot format for connectivity graph
        """
        output_result = f'// The Connectivity Graph of {self.output_config.configName}\n'
        output_result += 'digraph ' + '{\n'
        if self.output_config.queryName and self.output_config.configName:
            output_result += f'\tHEADER [shape="box" label=< <B>{self.output_config.queryName}/' \
                            f'{self.output_config.configName}</B> > fontsize=30 color=webmaroon fontcolor=webmaroon];\n'
        peer_set_lines = set()
        for peer_set in self.peer_sets:
            peer_set_name, is_only_ip_block, is_only_pods = self.get_peer_set_names(peer_set)
            peer_color = "red2" if is_only_ip_block else "blue" if is_only_pods else "black"
            peer_set_lines.add(f'\t\"{peer_set_name}\" [label=\"{peer_set_name}\" color=\"{peer_color}\" '
                               f'fontcolor=\"{peer_color}\"]\n')

        edge_lines = set()
        for src_peer_set, dst_peer_set, cube_dict in self.edges:
            if src_peer_set != dst_peer_set and cube_dict:
                src_peers_names, _, _ = self.get_peer_set_names(src_peer_set)
                dst_peers_names, _, _ = self.get_peer_set_names(dst_peer_set)
                line = '\t'
                line += f'\"{src_peers_names}\"'
                line += ' -> '
                line += f'\"{dst_peers_names}\"'
                conn_str = str(cube_dict).replace("protocols:", "")
                line += f' [label=\"{conn_str}\" color=\"gold2\" fontcolor=\"darkgreen\"]\n'
                edge_lines.add(line)
        output_result += ''.join(line for line in sorted(list(peer_set_lines))) + \
                         ''.join(line for line in sorted(list(edge_lines))) + '}\n\n'
        return output_result

    def get_connectivity_txt_format_str(self):
        """
        :return: a string with content of txt format for connectivity graph
        """
        output_result = ''
        for src_peer_set, dst_peer_set, cube_dict in self.edges:
            src_peers_names, _, _ = self.get_peer_set_names(src_peer_set)
            dst_peers_names, _, _ = self.get_peer_set_names(dst_peer_set)
            output_result += "src_pods: [" + src_peers_names + "] "
            output_result += "dst_pods: [" + dst_peers_names + "] "
            conn_str = str(cube_dict).replace("protocols:", "")
            output_result += "conn: " + conn_str if cube_dict else "All connections"
            output_result += '\n'
        return output_result
