#
# Copyright 2020- IBM Inc. All rights reserved
# SPDX-License-Identifier: Apache2.0
#

from dataclasses import dataclass
from enum import Enum
from nca.CoreDS.Peer import PeerSet
from nca.CoreDS.MinDFA import MinDFA


class Gateway:
    """
    A class for keeping some elements of parsed Istio Gateway, needed for building GatewayPolicy.
    """

    class GatewayType(Enum):
        """
        Possible gateway types
        """
        Ingress = 0
        Egress = 1

    @dataclass
    class Server:
        """
        A class that holds server attributes of a Gateway, as described in
        https://istio.io/latest/docs/reference/config/networking/gateway/#Server
        """
        @dataclass
        class GatewayPort:
            number: int
            protocol: str
            name: str

        port: GatewayPort  # the port field is not currently used.
        hosts_dfa: MinDFA or None = None
        name: str = ''

        def add_host(self, host_dfa):
            """
            Add host_dfa to the server
            :param MinDFA host_dfa:
            :return:
            """
            if self.hosts_dfa:
                self.hosts_dfa |= host_dfa
            else:
                self.hosts_dfa = host_dfa

    def __init__(self, name, namespace):
        """
        Create a Gateway
        :param str name: the gateway name
        :param K8sNamespace namespace: the gateway namespace
        """
        self.name = name  # the name of the gateway, as appears in the metadata
        self.namespace = namespace  # the namespace of the gateway, as appears in the metadata
        self.type = None  # whether this is an ingress gateway or an egress gateway
        # the 'peers' field defines the set of pods on which this gateway is applied.
        # It is calculated from Gateway.selector attribute, as described in
        # https://istio.io/latest/docs/reference/config/networking/gateway/#Gateway
        self.peers = PeerSet()
        self.servers = []  # a list of servers, where a server is described in Gateway.Server above.
        # the 'all_hosts_dfa' field is calculated as the union of 'hosts_dfa' field of all servers of this gateway.
        # It is used for matching the gateway to virtual services that reference it.
        self.all_hosts_dfa = None

    def full_name(self):
        """
        :return str: the full gateway name in <namespace>/<name> format
        """
        return str(self.namespace) + '/' + self.name

    def add_server(self, server):
        """
        Add a server and collect its host_dfa into one dfa
        :param Gateway.Server server: a server to add
        """
        self.servers.append(server)
        if self.all_hosts_dfa:
            self.all_hosts_dfa |= server.hosts_dfa
        else:
            self.all_hosts_dfa = server.hosts_dfa
