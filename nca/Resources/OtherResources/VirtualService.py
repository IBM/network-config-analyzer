#
# Copyright 2020- IBM Inc. All rights reserved
# SPDX-License-Identifier: Apache2.0
#

from dataclasses import dataclass
from nca.CoreDS.Peer import PeerSet
from nca.CoreDS.PortSet import PortSet


class VirtualService:
    """
    A class for keeping some elements of parsed Istio VirtualService, needed for building GatewayPolicy
    """

    @dataclass
    class Destination:
        """
        A class for keeping a parsed HTTP/TLS/TCP route destination of a VirtualService.
        It originates from Destination attribute of a virtual service, as described in
        https://istio.io/latest/docs/reference/config/networking/virtual-service/#Destination;
        'name' field is taken directly as 'Destination.host' attribute,
        whereas 'pods' field is calculated from 'Destination.host' attribute, by mapping it to a local service
        or to a remote dns entry;
        finally, 'ports' field is taken directly from 'Destination.port' attribute.
        """
        line_number: int  # line number of this destination inside the virtual service resource file
        name: str
        pods: PeerSet
        ports: PortSet

        def is_egress_gateway(self):
            return self.name == 'istio-egressgateway.istio-system.svc.cluster.local'

    class Route:
        """
        A class for holding (some of) the attributes of various route kinds (HTTPRoute/TLSRoute/TCPRoute)
        of a VirtualService. Some fields of this class are unique to a certain types of routes; they have values
        in relevant types of routes, while being None in other types of routes.
        During parsing, all Route lists are built for every virtual service, keeping those attributes that are needed
        for building GatewayPolicies. On the second phase, GatewayPolicies are built from every Route.
        """

        def __init__(self, line_number):
            self.line_number = line_number  # line number of this route inside the virtual service resource file
            # 'is_internal_dest' field represents whether the destination if to internal (True)
            # or external (False) service. It is True for Ingress flow routes, as well as for mesh-to-egress-gateway
            # routes of Egress flow. It is False for egress-gateway-to-dns-service routes of Egress flow.
            self.is_internal_dest = None
            # 'destinations' field is a list of possible Destinations (as described in VirtualService.Destination above.
            self.destinations = []
            # 'uri_dfa' and 'methods' fields originate from 'uri' and 'method' attribute respectively
            # of HTTPMatchRequest of a virtual service, as described in
            # https://istio.io/latest/docs/reference/config/networking/virtual-service/#HTTPMatchRequest
            # They are rlevant only for HTTP types of routes.
            self.uri_dfa = None
            self.methods = None
            # 'all_sni_hosts_dfa' field is relevant only in TLS routes. It originates from 'sniHosts' attribute of
            # TLSMatchAttributes, as described in
            # https://istio.io/latest/docs/reference/config/networking/virtual-service/#TLSMatchAttributes
            # In case of TLS routes, it refines the 'hosts_dfa' field of a virtual service, and is assigned to
            # 'hosts' attribute of the resulting gateway policy connections.
            self.all_sni_hosts_dfa = None
            self.gateway_names = []  # list of gateways full names in format "namespace/name"

        def add_destination(self, line_number, name, pods, port, is_internal_dest):
            """
            Adds the route destination to HTTP/TLS/TCP route
            :param str name: a name of a service representing this destination
            :param PeerSet pods: the destination pods
            :param int/str port: the destination port
            :param bool is_internal_dest: True if the destination is an internal service, False for external services.
            """
            rule_ports = PortSet()
            if port:
                rule_ports.add_port(port)  # may be either a number or a named port
            self.destinations.append(VirtualService.Destination(line_number, name, pods, rule_ports))
            if self.is_internal_dest is None:
                self.is_internal_dest = is_internal_dest
            else:
                # assuming no both ingress and egress flows in the same route
                assert self.is_internal_dest == is_internal_dest

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

    def __init__(self, name, namespace, file_name):
        """
        Create a VirtualService
        :param str name: the name of the VirtualService
        :param K8sNamespace namespace: the namespace of the VirtualService
        """
        self.name = name  # the name of the virtual service, as appears in the metadata
        self.namespace = namespace  # the namespace of the virtual service, as appears in the metadata
        self.file_name = file_name  # the name of the resource file containing this virtual service
        # the 'hosts_dfa' field originates in VirtualService.hosts attribute, as described in
        # https://istio.io/latest/docs/reference/config/networking/virtual-service/#VirtualService
        # It is used for matching gateways to this virtual service, as well as for 'hosts' attribute
        # of the resulting gateway policy connections.
        self.hosts_dfa = []
        self.gateway_names = []  # list of gateways full names in format "namespace/name"
        self.http_routes = []  # a list of HTTP routes of this virtual service. See Route description above.
        self.tls_routes = []  # a list of TLS routes of this virtual service
        self.tcp_routes = []  # a list of TCP routes of this virtual service

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

    def add_tcp_route(self, route):
        """
        Add tls route to the list of all tls routes of the VirtualService
        :param TLSRoute route: the route to add
        """
        self.tcp_routes.append(route)

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
        :param VirtualService.Route result: the object to add the gateway to (assuming it has 'gateway_names' attribute)
        """
        if 'mesh' not in result.gateway_names:
            result.gateway_names.append('mesh')
