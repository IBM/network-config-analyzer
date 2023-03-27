#
# Copyright 2022 - IBM Inc. All rights reserved
# SPDX-License-Identifier: Apache2.0
#

from nca.Utils.Utils import Singleton
from nca.Utils.NcaLogger import NcaLogger


class ExplDescriptor:
    def __init__(self, name, config_code, config_file):
        self.name = name
        self.config_code = config_code
        self.config_file = config_file

    def __get__(self, obj, type=None) -> object:
        return self.config_code, self.config_file

    def __set__(self, obj, value) -> None:
        raise AttributeError("Cannot change values, ExplDescriptor is read only")

    def get_name(self):
        return self.name


class ExplPolicies:
    def __init__(self):
        self.egress_dst = {}
        self.ingress_src = {}
        self.all_policies = set()

    @staticmethod
    def _add_policy(peer_set, peer_list, policy_name):
        for peer in peer_set:
            peer_name = peer.full_name()
            if not peer_list.get(peer_name):
                peer_list[peer_name] = set()
            peer_list[peer_name].add(policy_name)

    def add_policy(self, policy_name, egress_dst, ingress_src):

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
    """

    def __init__(self):
        self.ExplDescriptorContainer = {}
        self.ExplPeerToPolicyContainer = {}
        self._is_active = False
        self.conns = {}

        self.add_item('', 'Default-Policy', 0)

    def activate(self):
        self._is_active = True

    def is_active(self):
        return self._is_active

    def get_path_from_deployment(self, content):
        return self.ExplDescriptorContainer[content.get('metadata').get('name')].get('path')

    def add_item(self, path, name, ln):
        self.ExplDescriptorContainer[name] = {'path': path, 'line': ln}

    def add_peer_policy(self, peer, policy_name, egress_dst, ingress_src):
        peer_name = peer.full_name()
        if self.ExplDescriptorContainer.get(peer_name):
            if not self.ExplPeerToPolicyContainer.get(peer_name):
                self.ExplPeerToPolicyContainer[peer_name] = ExplPolicies()
            self.ExplPeerToPolicyContainer[peer_name].add_policy(policy_name,
                                                                 egress_dst,
                                                                 ingress_src,
                                                                 )

    def set_connections(self, conns):
        self.conns = conns
        pass

    def are_peers_connected(self, src, dst):
        if not self.conns:
            NcaLogger().log_message(f'Explainability error: Connections were not set yet, but peer query was called',
                                    level='E')
        for cube in self.conns:
            conn = self.conns.get_cube_dict(cube)
            src_peers = conn.get('src_peers').split(',')
            dst_peers = conn.get('dst_peers').split(',')
            if src in src_peers and dst in dst_peers:
                return True
        return False

    def add_default_policy(self, currents, peers, is_ingress):

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
