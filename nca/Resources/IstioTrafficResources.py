#
# Copyright 2020- IBM Inc. All rights reserved
# SPDX-License-Identifier: Apache2.0
#

from dataclasses import dataclass
from nca.CoreDS.Peer import PeerSet
from nca.CoreDS.PortSet import PortSet
from nca.CoreDS.MinDFA import MinDFA


# TODO: istio_root_namespace should be configurable from istio configuration, currently using default value for it
# If namespace is set to istio root namespace, the policy object applies to all namespaces in a mesh
istio_root_namespace = 'istio-config'


class Gateway:
    """
    A class for keeping some elements of parsed Istio Gateway, needed for building IngressPolicy
    """

    @dataclass
    class Server:
        @dataclass
        class GatewayPort:
            number: int
            protocol: str
            name: str

        port: GatewayPort  # the port field is not currently  used.
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
        self.name = name
        self.namespace = namespace
        self.peers = PeerSet()
        self.servers = []
        self.all_hosts_dfa = None

    def full_name(self):
        """
        :return str: the full gateway name in <namespace>/<name> format
        """
        return (str(self.namespace) + '/' if self.namespace else '') + self.name

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


class VirtualService:
    """
    A class for keeping some elements of parsed Istio VirtualService, needed for building IngressPolicy
    """

    @dataclass
    class Destination:
        """
        A class for keeping a parsed HTTP/TLS/TCP route destination of a VirtualService
        """
        name: str
        pods: PeerSet
        ports: PortSet

    class Route:
        """
        A base class for various route kinds (HTTPRoute/TLSRoute/TCPRoute) of a VirtualService
        """

        def __init__(self):
            self.destinations = []

        def add_destination(self, name, pods, port):
            """
            Adds the route destination to HTTP/TLS/TCP route
            :param str name: a name of a service representing this destination
            :param PeerSet pods: the destination pods
            :param int/str port: the destination port
            """
            rule_ports = PortSet()
            if port:
                rule_ports.add_port(port)  # may be either a number or a named port
            self.destinations.append(VirtualService.Destination(name, pods, rule_ports))

    class HTTPRoute(Route):
        """
        A class for keeping a parsed http route of a VirtualService
        """
        def __init__(self):
            super().__init__()
            self.uri_dfa = None
#            self.scheme_dfa = None  # not supported yet
            self.methods = None
#            self.authority_dfa = None  # not supported yet

        def add_uri_dfa(self, uri_dfa):
            """
            Adds an uri_dfa (to be used as a 'path' property of the connections) to the http route
            :param MinDFA uri_dfa: the uri_dfa to add
            """
            if self.uri_dfa:
                self.uri_dfa |= uri_dfa
            else:
                self.uri_dfa = uri_dfa

        def add_methods(self, methods):
            """
            Adds methods to the http route
            :param MethodSet methods: the methods to add
            """
            if self.methods:
                self.methods |= methods
            else:
                self.methods = methods.copy()

    class TLSRoute(Route):
        """
        A class for keeping a parsed tls route of a VirtualService
        """

        def __init__(self):
            super().__init__()
            self.all_sni_hosts_dfa = None
            self.gateway_names = []

    def __init__(self, name, namespace):
        """
        Create a VirtualService
        :param str name: the name of the VirtualService
        :param K8sNamespace namespace: the namespace of the VirtualService
        """
        self.name = name
        self.namespace = namespace
        self.hosts_dfa = []
        self.gateway_names = []
        self.http_routes = []
        self.tls_routes = []

    def full_name(self):
        """
        :return str: the full name of the VirtualService in the format <namespace>/<name>
        """
        return str(self.namespace) + '/' + self.name

    def add_host_dfa(self, host_dfa):
        """
        Add host dfa to the list of host dfas of the VirtualService
        :param MinDFA host_dfa: the host dfa to add
        :return:
        """
        self.hosts_dfa.append(host_dfa)

    def add_http_route(self, route):
        """
        Add http route to the list of all http routes of the VirtualService
        :param HttpRoute route: the route to add
        """
        self.http_routes.append(route)

    def add_tls_route(self, route):
        """
        Add tls route to the list of all tls routes of the VirtualService
        :param TLSRoute route: the route to add
        """
        self.tls_routes.append(route)

    @staticmethod
    def add_gateway(gtw_namespace, gtw_name, result):
        """
        Add gateway full name to the list of gateway names of the VirtualService
        :param K8sNamespace gtw_namespace: the gateway namespace
        :param str gtw_name: the gateway name
        :param result: the object to add the gateway to (assuming it has 'gateway_names' attribute).
        """
        result.gateway_names.append(str(gtw_namespace) + '/' + gtw_name)

    @staticmethod
    def add_mesh(result):
        """
        Add mesh gateway to the list of gateway names of the VirtualService
        :param result: the object to add the gateway to (assuming it has 'gateway_names' attribute).
        """
        result.gateway_names.append("mesh")
