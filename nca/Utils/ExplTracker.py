#
# Copyright 2022 - IBM Inc. All rights reserved
# SPDX-License-Identifier: Apache2.0
#

from nca.Utils.Utils import Singleton
from nca.Utils.NcaLogger import NcaLogger
from nca.CoreDS.Peer import PeerSet, IpBlock
from bs4 import BeautifulSoup
from bs4.element import Tag
from nca.CoreDS.ConnectivityProperties import ConnectivityProperties


class ExplTracker(metaclass=Singleton):
    """
    The Explainability Tracker is used for tracking the elements and their configuration,
    so it will be able to specify which configurations are responsible for each peer and each connection
    or lack of connection between them.

    The ExplTracker is Singleton
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

    DEFAULT_POLICY = 'Default-Policy'
    SUPPORTED_OUTPUT_FORMATS = ['txt', 'txt_no_fw_rules']

    def __init__(self, ep=''):

        self.ExplDescriptorContainer = dict()  # a map from str (resource/policy name) to a dict object with entries:
        # 'path','line','workload_name'
        self.ExplPeerToPolicyContainer = dict()  # a map from str (peer name) to ExplPolicies object
        self._is_active = False
        self.all_conns = None
        self.all_peers = None
        self.ep = ep

    class ExplPolicies:
        """
        ExplPolicies holds the policies affecting peers in relation to other peers.
        That is, for each peer it holds all the peers in its egress and ingress and the policies
        that has effect on the connection to that peers.
        """

        def __init__(self):
            self.egress_dst = dict()  # a map from str (peer name) to a set of str (policy names)
            self.ingress_src = dict()  # a map from str (peer name) to a set of str (policy names)
            self.all_policies = set()

        @staticmethod
        def _add_policy_to_map(peer_set, peer_map, policy_name):
            """
            Adds a policy to the map of affecting policies, for each peer in the peer_set
            :param PeerSet peer_set: a set of peers to add the policy to
            :param dict peer_map: a map of peer-to-policies that holds the policies affecting each peer
            :param str policy_name: the policy to add
            """
            for peer in peer_set:
                peer_name = peer.full_name()
                if not peer_map.get(peer_name):
                    peer_map[peer_name] = set()
                # We don't want Default-Policy if we have any other policy,
                # so we first remove it and then add the policy (even if we currently add
                # the Default-Policy itself).
                peer_map[peer_name].discard(ExplTracker.DEFAULT_POLICY)
                peer_map[peer_name].add(policy_name)

        def add_policy(self, policy_name, egress_dst, ingress_src):
            """
            Adds a given policy to the relevant peer-to-policies map (egress map, ingress map)
            :param str policy_name: name of the policy
            :param PeerSet egress_dst: the set of egress destinations peers to add the policy too
            :param PeerSet ingress_src: the set of ingress source peers to add the policy too
            """
            self.all_policies.add(policy_name)

            if egress_dst:
                self._add_policy_to_map(egress_dst, self.egress_dst, policy_name)

            if ingress_src:
                self._add_policy_to_map(ingress_src, self.ingress_src, policy_name)

    def _reset(self):
        self.ExplDescriptorContainer = {}
        self.ExplPeerToPolicyContainer = {}
        self._is_active = False
        self.all_conns = None
        self.all_peers = None
        self.ep = ''
        self.explain_all_results = ''

        self.add_item('', 0, self.DEFAULT_POLICY)

    def activate(self):
        """
        Make the ExplTracker active
        """
        self._reset()
        self._is_active = True

    def set_endpoints(self, ep):
        """
        Set the endpoints configuration
        """
        self.ep = ep

    def is_active(self):
        """
        Return the active state of the ExplTracker
        :return: bool
        """
        return self._is_active

    def is_output_format_supported(self, output_format):
        """
        Checks if the given output format is supported
        :param string output_format: the output format to check
        :return: True/False
        """
        return output_format in self.SUPPORTED_OUTPUT_FORMATS

    def add_item(self, path, ln, full_name, workload_name=''):
        """
        Adds an item describing a configuration block
        :param str path: the path to the configuration file
        :param int ln: the line starting the configuration block in its file
        :param str full_name: the full name of the configuration block (doc)
        :param str workload_name: the workload name of the configuration block (doc)
        """
        if full_name:
            # When DirScanner iterates over a directory it fetches files with Windows path.
            # We need to convert it to Linux path.
            path = path.replace('\\', '/')
            # handle Livesim special case, where we need the full path to access the file,
            # but for testing we need it to be environment agnostic.
            _, middle, relative_path = path.rpartition("network-config-analyzer")
            if middle:
                path = "network-config-analyzer" + relative_path
            self.ExplDescriptorContainer[full_name] = {'path': path, 'line': ln, 'workload_name': workload_name}
        else:
            NcaLogger().log_message('Explainability error: configuration-block name can not be empty', level='E')

    def derive_item(self, new_name):
        """
        Handles resources that change their name after parsing, like virtual-service
        that adds the service name and suffix "/allowed"
        Expecting the original name to be before the "/" character.
        :param str new_name: the name for the new derived element
        """
        name_parts = new_name.split('/')
        name = name_parts[0]
        if self.ExplDescriptorContainer.get(name):
            self.ExplDescriptorContainer[new_name] = {'path': self.ExplDescriptorContainer[name].get('path'),
                                                      'line': self.ExplDescriptorContainer[name].get('line'),
                                                      'base_name': name
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
        else:
            NcaLogger().log_message(f'Explainability error: Trying to add policy {policy_name} to peer {peer_name},'
                                    f' but peer not found in Expl Database', level='E')

    def extract_peers(self, conns):
        """
        Utility function to extract the peer names held in a connectivity element
        :param ConnectivityProperties conns:
        :return: PeerSet src_peers, PeerSet dst_peers: sets of collected peers
        """
        src_peers = PeerSet()
        dst_peers = PeerSet()
        for cube in conns:
            conn_cube = conns.get_connectivity_cube(cube)
            src_peers |= conn_cube["src_peers"] if conn_cube["src_peers"] else self.all_peers
            dst_peers |= conn_cube["dst_peers"] if conn_cube["dst_peers"] else self.all_peers
        return src_peers, dst_peers

    def set_peers(self, peers):
        """
        Update the peers into ExplTracker
        :param PeerSet peers: all the peers in the container
        """
        self.all_peers = peers

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
            peer_name = peer.full_name()
            if not self.ExplPeerToPolicyContainer.get(peer_name):
                if not self.ExplDescriptorContainer.get(peer_name):
                    self.add_item('', 0, peer_name)
                self.add_default_policy(PeerSet([peer]), peers, False)
                self.add_default_policy(peers, PeerSet([peer]), True)

    def _get_peer_by_name(self, peer_name):
        """
        Get Peer objects from all_peers by peer name.
        :param str peer_name: the name of the peer to retrieve
        :return: peer object
        """
        for peer in self.all_peers:
            if peer.full_name() == peer_name:
                return peer
        return None

    def are_peers_connected(self, src, dst):
        """
        Check if a given pair of peers are connected
        :param str src: name of the source peer
        :param str dst: name of the destination peer
        :return: bool: True for connected, False for disconnected
        """
        if not self.all_conns and not self.all_peers:
            NcaLogger().log_message('Explainability error: Connections were not set yet, but peer query was called', level='E')

        src_peer = self._get_peer_by_name(src)
        dst_peer = self._get_peer_by_name(dst)

        return True if self.all_conns & ConnectivityProperties.make_conn_props_from_dict(
            {"src_peers": PeerSet({src_peer}), "dst_peers": PeerSet({dst_peer})}) else False

    def add_policy_to_peers(self, policy):
        for peer in policy.selected_peers:
            src_peers, _ = self.extract_peers(policy.optimized_allow_ingress_props())
            _, dst_peers = self.extract_peers(policy.optimized_allow_egress_props())
            peer_name = peer.full_name()
            self.add_peer_policy(peer_name, policy.name, dst_peers, src_peers)

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
            # we don't add Default-Policy if there is already an explicit
            # policy allowing the connectivity
            if self.is_policy_list_empty(node.full_name(), is_ingress):
                node_name = node.full_name()
                self.add_peer_policy(node_name,
                                     ExplTracker.DEFAULT_POLICY,
                                     egress_list,
                                     ingress_list,
                                     )

    def is_policy_list_empty(self, node_name, check_ingress):
        """
        A service function to check if the expl' list of ingress or egress is empty.
        :param str node_name: the node to check
        :param bool check_ingress: list to check (ingress or egress)
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
        :param list results: the names of the configurations affecting this node
        :param str direction: src/dst
        :return str: string with the description
        """
        if len(results) < 2:
            NcaLogger().log_message(f'Explainability error: There are no Policy or Node configurations. got only'
                                    f' {len(results)} results,')

        out = []
        if direction:
            out = [f'\n({direction}){self.get_printout_ep_name(node_name)}:']
        if self.ExplDescriptorContainer.get(node_name).get("path") == '':
            out.append('IP blocks have no configurations')
            return ""
        for index, name in enumerate(results):
            ep_name = name
            if index == 0:
                # results always starts with the policy configurations - make a headline
                out.append('Policy Configurations:')
            if index > 0 and index == len(results)-1:
                # the last one is always the resource configuration - make a headline
                out.append('Resource Configurations:')
                ep_name = self.get_printout_ep_name(name)
            if not self.ExplDescriptorContainer.get(name):
                out.append(f'{ep_name} - explainability entry not found')
                continue
            base_name = self.ExplDescriptorContainer.get(name).get("base_name")
            if base_name:
                ep_name = base_name
            path = self.ExplDescriptorContainer.get(name).get("path")
            if path == '':  # special element (like Default Policy)
                out.append(f'{ep_name}')
            else:
                out.append(f'{ep_name}: line {self.ExplDescriptorContainer.get(name).get("line")} '
                           f'in file {path}')
        return out

    def get_printout_ep_name(self, peer):
        """
        Get the name of the peer based on the endpoints configurations:
        full_name for Pods mode
        workload_name for Deployments mode
        :param peer: the peer to query
        :return: string: name of peer
        """
        if self.ep == 'deployments':
            printout_name = self.ExplDescriptorContainer.get(peer).get('workload_name')
            if printout_name == '':
                printout_name = peer
            return printout_name
        else:
            return peer

    def explain_all(self):
        """
        Get a full expl' description of all the peers in the connectivity map
        :return: string: xml format of all the expl' entries for every 2 nodes.
        """
        soup = BeautifulSoup(features='html')
        entry_id = 0
        # use the peer names as defined in the end-points configuration,
        # also use one peer for each deployment
        peer_names = set()
        deployment_names = set()
        for peer in self.all_peers:
            # if in deployments mode, use one pod from each deployment
            deployment_name = self.get_printout_ep_name(peer.full_name())
            if isinstance(peer, IpBlock):
                deployment_name = peer.name
            if self.ep == 'deployments' and deployment_name in deployment_names:
                continue
            deployment_names.add(deployment_name)
            peer_names.add(peer.full_name())
        peer_names = sorted(list(peer_names))

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
                entry['src'] = self.get_printout_ep_name(peer1)
                entry['dst'] = self.get_printout_ep_name(peer2)
                text_elem = Tag(soup, name='text')
                text_elem.string = text
                entry.append(text_elem)
                soup.append(entry)

        self.explain_all_results = soup.prettify()
        return self.explain_all_results

    def get_working_ep_name(self, name):
        """
        if ep is in 'deployments' mode, the given name will be the workload name but the full name is always used as index
        :param name: str: the name to convert to full_name (it is not already the full name)
        :return: str: full name of the element
        """

        # Replace '[' with '(' and ']' with ')'
        name = name.replace('[', '(').replace(']', ')')

        if self.ep == 'deployments':
            # convert from workload name to fullname
            for fullname, data in self.ExplDescriptorContainer.items():
                workload_name = data.get('workload_name')
                if name == workload_name or name == fullname:
                    # found the workload name, return its fullname
                    # or, it has no workload name
                    return fullname
            return ''
        else:
            # we are in 'pods' mode so the name is already the fullname
            return name

    def explain(self, nodes):
        """
        The magic function to explain the connectivity or the LACK of it between the given nodes
        It has 2 modes:
            single node - if a single node is given, all the configurations on that node are displayed.
            two nodes - if 2 nodes are given, either they hava a connection between them and the configurations responsible for
                        the connection are displayed. or, they lack a connection, in which case, all affecting configurations
                        on those 2 nodes are displayed.
            All nodes - if the single node get the value 'ALL', all the topology will be explained.
        :param list(str) nodes: nodes to explain
        :return: str: the explanation out string
        """
        if len(nodes) < 1:
            return ''
        elif len(nodes) > 2:
            NcaLogger().log_message(f'Explainability error: only 1 or 2 nodes are allowed for explainability query,'
                                    f' found {len(nodes)} ', level='E')
            return ''

        if nodes[0] == 'ALL':
            out = self.explain_all()
            return out

        src_node = self.get_working_ep_name(nodes[0])
        for node in nodes:
            ep_node = self.get_working_ep_name(node)
            if not self.ExplDescriptorContainer.get(ep_node):
                NcaLogger().log_message(f'Explainability error - {node} '
                                        f'was not found in the connectivity results', level='E')
                return ''
            if not self.ExplPeerToPolicyContainer.get(ep_node):
                NcaLogger().log_message(f'Explainability error - {self.node} '
                                        f'has no explanability results', level='E')
                return ''

        out = []
        if len(nodes) == 2:
            # 2 nodes scenario
            dst_node = self.get_working_ep_name(nodes[1])
            if self.are_peers_connected(src_node, dst_node):
                # connection valid
                out.append(f'\nConfigurations affecting the connectivity between '
                           f'(src){self.get_printout_ep_name(src_node)} and (dst){self.get_printout_ep_name(dst_node)}:')
                src_results = self.ExplPeerToPolicyContainer[src_node].egress_dst.get(dst_node)
                dst_results = self.ExplPeerToPolicyContainer[dst_node].ingress_src.get(src_node)
            else:
                out.append(f'Configurations affecting the LACK of connectivity between '
                           f'(src){self.get_printout_ep_name(src_node)} and (dst){self.get_printout_ep_name(dst_node)}:')
                src_results = self.ExplPeerToPolicyContainer[src_node].all_policies
                dst_results = self.ExplPeerToPolicyContainer[dst_node].all_policies

            src_results = sorted(list(src_results)) if src_results else []
            src_results.append(src_node)
            dst_results = sorted(list(dst_results)) if dst_results else []
            dst_results.append(dst_node)
            out.extend(self.prepare_node_str(src_node, src_results, 'src'))
            out.extend(self.prepare_node_str(dst_node, dst_results, 'dst'))
        else:  # only one node
            results = self.ExplPeerToPolicyContainer[src_node].all_policies
            results = sorted(list(results))
            results.append(src_node)
            out.append(f'Configurations affecting {self.get_printout_ep_name(src_node)}:')
            out.extend(self.prepare_node_str(src_node, results))

        # convert the list of expl' directives into string
        out = '\n'.join(out)
        return out
