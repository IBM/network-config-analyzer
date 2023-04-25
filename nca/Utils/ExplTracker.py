#
# Copyright 2022 - IBM Inc. All rights reserved
# SPDX-License-Identifier: Apache2.0
#

from nca.Utils.Utils import Singleton
from nca.Utils.NcaLogger import NcaLogger
from nca.CoreDS.Peer import PeerSet, Pod
from bs4 import BeautifulSoup
from bs4.element import Tag


class ExplTracker(metaclass=Singleton):
    """
    The Explainability Tracker is used for tracking the elements and their configuration
    so it will be able to specify which configurations are responsible for each peer and each connection
    or lack of connection between them.

    The ExplTracker is Singletone
    Members:
            ExplDescriptorContainer - A container for all expl' items' in the system.
            Each entry has a peer or a policy with their name, file and line number of the configurations.

            ExplPeerToPolicyContainer - A container for finding the affecting policies from peers in egress and ingress
            For each peer name it has a ExplPolicies class object with 3 items:
                    all_policies - a set of all the policies affecting the current peer
                    egress_dst - a dict of destination peers allowed in the current peer's egress and for each of them,
                                 the policies that allows it
                    ingress_src - a dict of source peers allowed in the current peer's ingress and for each of them,
                                 the policies that allows it
            That way, when given a src and dst peers we can extract which policies allow the connection in each side.
            When there is no connection, we list all the policies that affect the peers, so the user may have all the info
            to find problems.

            _is_active - flag for checking if expl' was activated

            all_conns - all the calculated connection. This is used to shortcut the check if 2 peers are connected or not

            all_peers - all the peers. This is used for the explain-all feature.

            ep - endpoints configurations (use either full_name for pod mode, or workload_name for deployments mode)
    """

    def __init__(self, ep=''):
        self.ExplDescriptorContainer = {}
        self.ExplPeerToPolicyContainer = {}
        self._is_active = False
        self.all_conns = {}
        self.all_peers = {}
        self.ep = ep

        self.add_item('', 'Default-Policy', 0)

    class ExplPolicies:
        """
        ExplPolicies holds the policies affecting peers in relation to other peers.
        That is, for each peer it holds all the peers in its egress and ingress and the policies
        that has effect on the connection to that peers.
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
                peer_name = ExplTracker().get_peer_ep_name(peer)
                if not peer_list.get(peer_name):
                    peer_list[peer_name] = set()
                # We don't want Default-Policy if we have any other policy,
                # so we first remove it and then add the policy (even if we currently add
                # the Default-Policy itself).
                peer_list[peer_name].discard('Default-Policy')
                peer_list[peer_name].add(policy_name)

        def add_policy(self, policy_name, egress_dst, ingress_src):
            """
            Adds a given policy to the relevant peer lists (egress list, ingress list)
            :param str policy_name: name of the policy
            :param PeerSet egress_dst: the set of egress destinations peers to add the policy too
            :param PeerSet ingress_src: the set of ingress source peers to add the policy too
            """
            self.all_policies.add(policy_name)

            if egress_dst:
                self._add_policy(egress_dst, self.egress_dst, policy_name)

            if ingress_src:
                self._add_policy(ingress_src, self.ingress_src, policy_name)

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

    def derive_item(self, new_name):
        """
        Handles resources that change their name after parsing, like virtual-service
        that adds the service name and /allowed
        :param str new_name: the name for the new derived element
        """
        name_parts = new_name.split('/')
        name = name_parts[0]
        if self.ExplDescriptorContainer.get(name):
            self.ExplDescriptorContainer[new_name] = {'path': self.ExplDescriptorContainer[name].get('path'),
                                                      'line': self.ExplDescriptorContainer[name].get('line')
                                                      }
        else:
            NcaLogger().log_message(f'Explainability error: derived item {new_name} found no base item',
                                    level='E')

    def add_peer_policy(self, peer_name, policy_name, egress_dst, ingress_src):
        """
        Add a new policy to a peer
        :param str peer_name: peer name to add the policy to
        :param srt policy_name: name of the policy
        :param egress_dst: a list of peers that the given policy affect, egress wise.
        :param ingress_src: a list of peers that the given policy affect, ingress wise.
        """
        if self.ExplDescriptorContainer.get(peer_name):
            if not self.ExplPeerToPolicyContainer.get(peer_name):
                self.ExplPeerToPolicyContainer[peer_name] = self.ExplPolicies()
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

    def set_connections_and_peers(self, conns, peers):
        """
        Update the calculated connections and topology peers into ExplTracker
        :param ConnectivityProperties conns: the connectivity mapping calculated by the query
        :param PeerSet peers: all the peers in the container
        """
        self.all_conns = conns
        self.all_peers = peers
        # add all missing 'special' peers (like 0.0.0.0/0) with default policy.
        for peer in self.all_peers:
            peer_name = self.get_peer_ep_name(peer)
            if not self.ExplPeerToPolicyContainer.get(peer_name):
                if not self.ExplDescriptorContainer.get(peer_name):
                    self.add_item('', peer_name, 0)
                self.add_default_policy(PeerSet([peer]), peers, False)
                self.add_default_policy(peers, PeerSet([peer]), True)

    def are_peers_connected(self, src, dst):
        """
        Check if a given pair of peers are connected
        :param str src: name of the source peer
        :param str dst: name of the destination peer
        :return: bool: True for connected, False for disconnected
        """
        if not self.all_conns:
            NcaLogger().log_message(f'Explainability error: Connections were not set yet, but peer query was called',
                                    level='E')
        for cube in self.all_conns:
            src_peers_names = []
            dst_peers_names = []
            conn_cube = self.all_conns.get_connectivity_cube(cube)
            src_peers = conn_cube['src_peers']
            dst_peers = conn_cube['dst_peers']
            for peer in src_peers:
                src_peers_names.append(self.get_peer_ep_name(peer))
            for peer in dst_peers:
                dst_peers_names.append(self.get_peer_ep_name(peer))
            if src in src_peers_names and dst in dst_peers_names:
                return True
        return False

    def add_default_policy(self, src, dst, is_ingress):
        """
        Add the default policy to the peers which were not affected by a specific policy.
        :param PeerSet src: the peer list for the source of the policy
        :param PeerSet dst: the peer list for the destination of the policy
        :param is_ingress: is this an ingress or egress policy
        """
        if is_ingress:
            nodes = dst
            egress_list = {}
            ingress_list = src
        else:
            nodes = src
            egress_list = dst
            ingress_list = {}

        for node in nodes:
            # we dont add Default-Policy if there is already an explicit
            # policy allowing the connectivity
            if self.is_policy_list_empty(self.get_peer_ep_name(node), is_ingress):
                node_name = self.get_peer_ep_name(node)
                self.add_peer_policy(node_name,
                                     'Default-Policy',
                                     egress_list,
                                     ingress_list,
                                     )

    def is_policy_list_empty(self, node_name, check_ingress):
        """
        A service function to check if the expl' list of ingress or egress is empty.
        :param node_name: the node to check
        :param check_ingress: list to check (ingress or egress)
        :return:
        """
        peer = self.ExplPeerToPolicyContainer.get(node_name)
        if peer:
            if check_ingress and peer.ingress_src:
                return False
            if not check_ingress and peer.egress_dst:
                return False
        return True

    def prepare_node_str(self, node_name, results, direction=None):
        """
        A utility function to help format a node explainability description
        :param str node_name: the name of the node currently described
        :param str results: the names of the configurations affecting this node
        :param str direction: src/dst
        :return str: string with the description
        """
        out = []
        if direction:
            out = [f'\n({direction}){node_name}:']
        for name in results:
            if not self.ExplDescriptorContainer.get(name):
                out.append(f'{name} - explainability entry not found')
                continue
            path = self.ExplDescriptorContainer.get(name).get("path")
            if path == '':  # special element (like Default Policy)
                out.append(f'{name}')
            else:
                out.append(f'{name}: line {self.ExplDescriptorContainer.get(name).get("line")} '
                           f'in file {path}')
        return out

    def get_peer_ep_name(self, peer):
        """
        Get the name of the peer based on the endpoints configurations:
        full_name for Pods mode
        workload_name for Deployments mode
        :param peer: the peer to query
        :return: string: name of peer
        """
        if self.ep == 'deployments' and isinstance(peer, Pod):
            return peer.workload_name
        else:
            return peer.full_name()

    def explain_all(self):
        """
        Get a full expl' description of all the peers in the connectivity map
        :return: string: xml format of all the expl' entries for every 2 nodes.
        """
        soup = BeautifulSoup(features='xml')
        entry_id = 0
        # use the peer names as defined in the endpoints configuration,
        # also use one peer for each deployment
        peer_names = set()
        for peer in self.all_peers:
            peer_names.add(self.get_peer_ep_name(peer))

        for peer1 in peer_names:
            for peer2 in peer_names:
                if peer1 == peer2:
                    text = self.explain([peer1])
                else:
                    text = self.explain([peer1, peer2])
                # Create the XML entry element
                entry = soup.new_tag('entry')
                entry_id += 1
                entry['id'] = str(entry_id)
                entry['src'] = peer1
                entry['dst'] = peer2
                text_elem = Tag(soup, name='text')
                text_elem.string = text
                entry.append(text_elem)
                soup.append(entry)
        return soup.prettify()

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
        if len(nodes) < 1:
            return ''
        elif len(nodes) > 2:
            NcaLogger().log_message(f'Explainability error: only 1 or 2 nodes are allowed for explainability query,'
                                    f' found {len(nodes)} ', level='E')
            return ''

        src_node = nodes[0]
        if src_node == 'ALL':
            out = self.explain_all()
            return out

        for node in nodes:
            if not self.ExplDescriptorContainer.get(node):
                NcaLogger().log_message(f'Explainability error - {node} was not found in the connectivity results', level='E')
                return ''
            if not self.ExplPeerToPolicyContainer.get(node):
                NcaLogger().log_message(f'Explainability error - {node} has no explanability results', level='E')
                return ''

        out = []
        if len(nodes) == 2:
            # 2 nodes scenario
            dst_node = nodes[1]
            if self.are_peers_connected(src_node, dst_node):
                # connection valid
                out.append(f'Configurations affecting the connectivity between (src){src_node} and (dst){dst_node}:')
                src_results = self.ExplPeerToPolicyContainer[src_node].egress_dst.get(dst_node)
                dst_results = self.ExplPeerToPolicyContainer[dst_node].ingress_src.get(src_node)
            else:
                out.append(f'Configurations affecting the LACK of connectivity between (src){src_node} and (dst){dst_node}:')
                src_results = self.ExplPeerToPolicyContainer[src_node].all_policies
                dst_results = self.ExplPeerToPolicyContainer[dst_node].all_policies

            src_results.add(src_node)
            dst_results.add(dst_node)
            out.extend(self.prepare_node_str(src_node, src_results, 'src'))
            out.extend(self.prepare_node_str(dst_node, dst_results, 'dst'))
        else:  # only one node
            results = self.ExplPeerToPolicyContainer[src_node].all_policies
            out.append(f'Configurations affecting {src_node}:')
            out.extend(self.prepare_node_str(src_node, results))

        # convert the list of expl' directives into string
        out = '\n'.join(out)
        return out
