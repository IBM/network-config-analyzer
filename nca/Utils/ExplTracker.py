#
# Copyright 2022 - IBM Inc. All rights reserved
# SPDX-License-Identifier: Apache2.0
#

from nca.Utils.NcaLogger import Singleton


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

    def get_path_from_deployment(self, content):
        return self.ExplDescriptorContainer[content.get('metadata').get('name')].get('path')

    def add_item(self, path, content, name):
        if path == '':
            path = self.get_path_from_deployment(content)
        self.ExplDescriptorContainer[name] = {'path': path, 'content': content}

    def add_peer_policy(self, peer, policy):
        peer_name = peer.name
        policy_name = policy.name
        if not self.ExplPeerToPolicyContainer.get(peer_name):
            self.ExplPeerToPolicyContainer[peer_name] = set()
        self.ExplPeerToPolicyContainer[peer_name].add(policy_name)

