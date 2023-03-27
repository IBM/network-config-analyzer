#
# Copyright 2022 - IBM Inc. All rights reserved
# SPDX-License-Identifier: Apache2.0
#

from nca.Utils.Utils import Singleton
from nca.Utils.NcaLogger import NcaLogger
from nca.CoreDS.Peer import PeerSet


class ExplPolicies:
    """
    ExplPolicies holds the policies affecting peers in relation to other peers.
    That is, for each peer it holds all the peers in it's egress and ingress and the policies that has effect on the connection
    to that peers.
    """
    def __init__(self):
        self.egress_dst = {}
        self.ingress_src = {}
        self.all_policies = set()

    @staticmethod
    def _add_policy(peer_set, peer_list, policy_name):
        """
        Adds a policy to the list of affecting policies, for each peer in the peer_set
        :param PeerSet peer_set: a set of peers to add the policy to
        :param dict peer_list: a list of peers that holds the policies affecting them
        :param str policy_name: the policy to add
        """
        for peer in peer_set:
            peer_name = peer.full_name()
            if not peer_list.get(peer_name):
                peer_list[peer_name] = set()
            peer_list[peer_name].add(policy_name)

    def add_policy(self, policy_name, egress_dst, ingress_src):
        """
        Adds a given policy to the relevant peer lists (egress list, ingress list)
        :param str policy_name: name of the policy
        :param dict egress_dst: the set of egress destinations peers to add the policy too
        :param dict ingress_src: the set of ingress source peers to add the policy too
        """
        self.all_policies.add(policy_name)

        if egress_dst:
            self._add_policy(egress_dst, self.egress_dst, policy_name)

        if ingress_src:
            self._add_policy(ingress_src, self.ingress_src, policy_name)


class ExplTracker(metaclass=Singleton):
    """
    The Explainability Tracker is used for tracking the elements and their configuration
    so it will be able to specify which configurations are responsible for each peer and each connection
    or lack of connection between them.

    The ExplTracker is Singletone
    """

    def __init__(self):
        self.ExplDescriptorContainer = {}
        self.ExplPeerToPolicyContainer = {}
        self._is_active = False
        self.conns = {}

        self.add_item('', 'Default-Policy', 0)

    def activate(self):
        """
        Make the ExplTracker active
        """
        self._is_active = True

    def is_active(self):
        """
        Return the active state of the ExplTracker
        :return: bool
        """
        return self._is_active

    def add_item(self, path, name, ln):
        """
        Adds an item describing a configuration block
        :param str path: the path to the configuration file
        :param str name: the name of the configuration block (doc)
        :param int ln: the line starting the configuration block in it's file
        """
        if name:
            self.ExplDescriptorContainer[name] = {'path': path, 'line': ln}
        else:
            NcaLogger().log_message(f'Explainability error: configuration-block name can not be empty',
                                    level='E')

    def add_peer_policy(self, peer, policy_name, egress_dst, ingress_src):
        """
        Add a new policy to a peer
        :param Peer peer: peer object
        :param srt policy_name: name of the policy
        :param egress_dst: a list of peers that the given policy affect, egress wise.
        :param ingress_src: a list of peers that the given policy affect, ingress wise.
        """
        peer_name = peer.full_name()
        if self.ExplDescriptorContainer.get(peer_name):
            if not self.ExplPeerToPolicyContainer.get(peer_name):
                self.ExplPeerToPolicyContainer[peer_name] = ExplPolicies()
            self.ExplPeerToPolicyContainer[peer_name].add_policy(policy_name,
                                                                 egress_dst,
                                                                 ingress_src,
                                                                 )

    @staticmethod
    def extract_peers(conns):
        """
        Utility function to extract the peer names held in a connectivity element
        :param ConnectivityProperties conns:
        :return: PeerSet src_peers, PeerSet dst_peers: sets of collected peers
        """
        src_peers = PeerSet()
        dst_peers = PeerSet()
        for cube in conns:
            conn_cube = conns.get_connectivity_cube(cube)
            src_peers |= conn_cube["src_peers"]
            dst_peers |= conn_cube["dst_peers"]
        return src_peers, dst_peers

    def set_connections(self, conns):
        """
        Update the calculated connections into ExplTracker
        :param ConnectivityProperties conns: the connectivity mapping calculated by the query
        """
        self.conns = conns

    def are_peers_connected(self, src, dst):
        """
        Check if a given pair of peers are connected
        :param str src: name of the source peer
        :param str dst: name of the destination peer
        :return: bool: True for connected, False for disconnected
        """
        if not self.conns:
            NcaLogger().log_message(f'Explainability error: Connections were not set yet, but peer query was called',
                                    level='E')
        for cube in self.conns:
            conn = self.conns.get_cube_dict(cube)
            src_peers = conn['src_peers']
            dst_peers = conn['dst_peers']
            if src in src_peers and dst in dst_peers:
                return True
        return False

    def add_default_policy(self, currents, peers, is_ingress):
        """
        Add the default policy to the peers which were not affected by a specific policy.
        :param PeerSet currents: the peers to add the policy too
        :param PeerSet peers: the adjacent peers the default policy nakes a connection with
        :param is_ingress: is this an ingress or egress policy
        """
        if is_ingress:
            ingress_src = peers
            egress_dst = {}
        else:
            ingress_src = {}
            egress_dst = peers

        for peer in currents:
            self.add_peer_policy(peer,
                                 'Default-Policy',
                                 egress_dst,
                                 ingress_src,
                                 )

    def prepare_node_str(self, direction, node_name, results):
        """
        A utility function to help format a node explainability description
        :param str direction: src/dst
        :param str node_name: the name of the node currently described
        :param str results: the names of the configurations affecting this node
        :return str: string with the description
        """
        out = []
        if direction:
            out = [f'\n({direction}){node_name}:']
        for name in results:
            path = self.ExplDescriptorContainer.get(name).get("path")
            if path == '':  # special element (like Default Policy)
                out.append(f'{name}')
            else:
                out.append(f'{name}: line {self.ExplDescriptorContainer.get(name).get("line")} '
                           f'in file {path}')
        return out

    def explain(self, nodes):
        """
        The magic function to explain the connectivity or the LACK of it between the given nodes
        It has 2 modes:
            single node - if a single node is given, all the configurations on that node are displayed.
            two nodes - if 2 nodes are given, either they hava a connection between them and the configurations responsible for
                        the connection are displayed. or, they lack a connection, in which case, all affecting configurations
                        on those 2 nodes are displayed.
        :param list(str) nodes: nodes to explain
        :return: str: the explanation out string
        """
        out = []
        if len(nodes) < 1:
            return out
        elif len(nodes) > 2:
            NcaLogger().log_message(f'Explainability error: only 1 or 2 nodes are allowed for explainability query,'
                                    f' found {len(nodes)} ', level='E')
            return out
        for node in nodes:
            if not self.ExplDescriptorContainer.get(node):
                NcaLogger().log_message(f'Explainability error - {node} was not found in the connectivity results', level='E')
                return out
            if not self.ExplPeerToPolicyContainer.get(node):
                NcaLogger().log_message(f'Explainability error - {node} has no explanability results', level='E')
                return out

        src_node = nodes[0]
        if len(nodes) == 2:
            # 2 nodes scenario
            dst_node = nodes[1]
            if self.are_peers_connected(src_node, dst_node):
                # connection valid
                out.append(f'\nConfigurations affecting the connectivity between (src){src_node} and (dst){dst_node}:')
                src_results = self.ExplPeerToPolicyContainer[src_node].egress_dst.get(dst_node)
                dst_results = self.ExplPeerToPolicyContainer[dst_node].ingress_src.get(src_node)
            else:
                out.append(f'\nConfigurations affecting the LACK of connectivity between (src){src_node} and (dst){dst_node}:')
                src_results = self.ExplPeerToPolicyContainer[src_node].all_policies
                dst_results = self.ExplPeerToPolicyContainer[dst_node].all_policies

            src_results.add(src_node)
            dst_results.add(dst_node)
            out.extend(self.prepare_node_str('src', src_node, src_results))
            out.extend(self.prepare_node_str('dst', dst_node, dst_results))
        else:  # only one node
            results = self.ExplPeerToPolicyContainer[src_node].all_policies
            out.append(f'\nConfigurations affecting {src_node}:')
            out.extend(self.prepare_node_str(None, src_node, results))

        return out
