#
# Copyright 2020- IBM Inc. All rights reserved
# SPDX-License-Identifier: Apache2.0
#

from dataclasses import dataclass
from nca.CoreDS.Peer import PeerSet
from nca.CoreDS.PortSet import PortSet
from nca.CoreDS.MinDFA import MinDFA
from .K8sService import K8sService


# TODO: istio_root_namespace should be configurable from istio configuration, currently using default value for it
# If namespace is set to istio root namespace, the policy object applies to all namespaces in a mesh
istio_root_namespace = 'istio-config'


class Gateway:
    """
    A class for keeping some elements of parsed Istio Gateway, needed for building IstioGatewayPolicy
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


class VirtualService:
    """
    A class for keeping some elements of parsed Istio VirtualService, needed for building IstioGatewayPolicy
    """

    @dataclass
    class HTTPRouteDestination:
        """
        A class for keeping a parsed http route destination of a VirtualService
        """
        service: K8sService
        port: PortSet

    class HTTPRoute:
        """
        A class for keeping a parsed http route of a VirtualService
        """
        def __init__(self):
            self.uri_dfa = None
#            self.scheme_dfa = None  # not supported yet
            self.methods = None
#            self.authority_dfa = None  # not supported yet
            self.destinations = []

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

        def add_destination(self, service, port):
            """
            Adds the http route destination to http route
            :param K8sService service: the service part of the destination
            :param int/str port: the port part of the destination
            :return:
            """
            rule_ports = PortSet()
            if port:
                rule_ports.add_port(port)  # may be either a number or a named port
            self.destinations.append(VirtualService.HTTPRouteDestination(service, rule_ports))

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

    def add_gateway(self, gtw_namespace, gtw_name):
        """
        Add gateway full name to the list of gateway names of the VirtualService
        :param K8sNamespace gtw_namespace: the gateway namespace
        :param str gtw_name: the gateway name
        """
        self.gateway_names.append(str(gtw_namespace) + '/' + gtw_name)

    def add_http_route(self, route):
        """
        Add http route to the list of all routes of the VirtualService
        :param HttpRoute route: the route to add
        """
        self.http_routes.append(route)
