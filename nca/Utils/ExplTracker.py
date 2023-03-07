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


class ExplPeer(ExplDescriptor):
    pass


class ExplPolicy(ExplDescriptor):
    pass


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

    def activate(self):
        self._is_active = True

    def is_active(self):
        return self._is_active

    def get_path_from_deployment(self, content):
        return self.ExplDescriptorContainer[content.get('metadata').get('name')].get('path')

    def add_item(self, path, content, name, ln):
        if path == '':
            path = self.get_path_from_deployment(content)
        self.ExplDescriptorContainer[name] = {'path': path, 'line': ln}

    def add_peer_policy(self, peer, policy):
        peer_name = peer.name
        policy_name = policy.name
        if not self.ExplPeerToPolicyContainer.get(peer_name):
            self.ExplPeerToPolicyContainer[peer_name] = set()
        self.ExplPeerToPolicyContainer[peer_name].add(policy_name)

    def explain(self, nodes):
        if len(nodes) < 1:
            return
        elif len(nodes) > 2:
            NcaLogger().log_message(f'Explainability error: only 1 or 2 nodes are allowed for explainability query,'
                                    f' found {len(nodes)} ', level='E')
            return
        results = {}
        for node in nodes:
            if not self.ExplDescriptorContainer.get(node):
                NcaLogger().log_message(f'Explainability error: {node} was not found in the connectivity results', level='E')
                return
            results[node] = self.ExplDescriptorContainer.get(node)
            for policy in self.ExplPeerToPolicyContainer.get(node):
                results[policy] = self.ExplDescriptorContainer.get(policy)
        out = []
        if len(nodes) == 1:
            out.append(f'Configurations affecting node {nodes[0]}: \n')
        else:
            out.append(f'Configurations affecting the connectivity between {nodes[0]} and {nodes[1]}:')
        for name in results.keys():
            out.append(f'{name}: line {results.get(name).get("line")} in file {results.get(name).get("path")}')

        return out
