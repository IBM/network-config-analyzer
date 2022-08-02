#
# Copyright 2020- IBM Inc. All rights reserved
# SPDX-License-Identifier: Apache2.0
#

from GenericIngressLikeYamlParser import GenericIngressLikeYamlParser
from IstioTrafficResources import Gateway, VirtualService
from DimensionsManager import DimensionsManager
from MinDFA import MinDFA
from IngressPolicy import IngressPolicy
from Peer import PeerSet
from functools import reduce


class IstioTrafficResourcesYamlParser(GenericIngressLikeYamlParser):
    """
    A parser for Istio traffic resources for ingress and egress
    """

    def __init__(self, peer_container):
        """
        :param PeerContainer peer_container: The ingress policy will be evaluated against this set of peers
        """
        GenericIngressLikeYamlParser.__init__(self, peer_container)
        self.namespace = None
        self.gateways = {}  # a map from a name to a Gateway
        self.virtual_services = {}  # a map from a name to a VirtualService

    def add_gateway(self, gateway):
        """
        Adds a Gateway to the internal parser db
        (to be later used for locating the gateways referenced by virtual services)
        :param Gateway gateway: the gateway to add
        """
        self.gateways[gateway.full_name()] = gateway

    def get_gateway(self, gtw_full_name):
        """
        Return a Gateway by its full name or None if not found.
        :param str gtw_full_name: the gateway full name
        :return Gateway: the found Gateway / None
        """
        return self.gateways.get(gtw_full_name)

    def parse_gateway(self, gateway_resource, gateway_file_name):
        """
        Parses a gateway resource object and adds the parsed Gateway object to self.gateways
        :param dict gateway_resource: the gateway object to parse
        :param str gateway_file_name: the name of the gateway resource file (for reporting errors and warnings)
        """
        self.set_file_name(gateway_file_name)  # for error/warning messages

        if gateway_resource.get('kind') != 'Gateway' or 'networking.istio.io' not in gateway_resource.get('apiVersion'):
            return  # Not an Istio Gateway object

        metadata = gateway_resource.get('metadata')
        if not metadata:
            return
        gtw_name = metadata.get('name')
        if not gtw_name:
            return
        gtw_namespace = self.peer_container.get_namespace(metadata.get('namespace', 'default'))
        gtw_spec = gateway_resource.get('spec')
        if not gtw_spec:
            self.warning(f'Spec is missing or null in Gateway {gtw_name}. Ignoring the gateway')
            return

        gateway = Gateway(gtw_name, gtw_namespace)
        selector = gtw_spec.get('selector')
        if not selector:
            self.warning(f'Selector is missing or null in Gateway {gtw_name}. Ignoring the gateway')
            return
        peers = self.peer_container.get_all_peers_group()
        for key, val in selector.items():
            peers &= self.peer_container.get_peers_with_label(key, [val])
        if not peers:
            self.warning(f'Selector {selector} does not reference any pods in Gateway {gtw_name}. Ignoring the gateway')
            return

        gateway.peers = peers
        servers = gtw_spec.get('servers')
        if servers is None:
            self.warning(f'servers is missing or null in Gateway {gtw_name}. Ignoring the gateway')
            return

        for i, server in enumerate(servers, start=1):
            port = self.parse_gateway_port(server)
            if not port:
                self.warning(f'port is missing or null in server #{i} of Gateway {gtw_name}. Ignoring the server')
                return
            gtw_server = Gateway.Server(port)
            gtw_server.name = server.get('name')
            hosts = server.get('hosts')
            if hosts:
                for host in hosts:
                    host_dfa = self.parse_host_value(host, gateway_resource)
                    if host_dfa:
                        gtw_server.add_host(host_dfa)

            gateway.add_server(gtw_server)
        self.add_gateway(gateway)

    def parse_host_value(self, host, resource):
        """
        For 'hosts' dimension of type MinDFA -> return a MinDFA, or None for all values
        :param str host: input regex host value
        :param dict resource: the parsed gateway object
        :return: Union[MinDFA, None] object
        """
        namespace_and_name = host.split('/', 1)
        if len(namespace_and_name) > 1:
            self.syntax_error(f'Host {host}: namespace is not supported yet', resource)
        return self.parse_regex_host_value(host, resource)

    def parse_gateway_port(self, server):
        port = server.get('port')
        if not port:
            return None
        number = port.get('number')
        protocol = port.get('protocol')
        name = port.get('name')
        if port.get('targetPort'):
            self.warning('targetPort is not supported yet in Gateway server', server)
        return Gateway.GatewayPort(number, protocol, name)

    def add_virtual_service(self, vs):
        """
        Adds a virtual service by its full name
        :param VirtualService vs: the virtual service to add
        """
        self.virtual_services[vs.full_name()] = vs

    def parse_virtual_service(self, vs_resource, vs_file_name):
        """
        Parses a virtual service resource object and and adds the parsed VirtualService object to self.virtual_services
        :param dict vs_resource: the virtual service object to parse
        :param str vs_file_name: the name of the virtual service resource file
        """
        self.set_file_name(vs_file_name)  # for error/warning messages

        if vs_resource.get('kind') != 'VirtualService' or 'networking.istio.io' not in vs_resource.get('apiVersion'):
            return  # Not an Istio VirtualService object

        metadata = vs_resource.get('metadata')
        if not metadata:
            return
        vs_name = metadata.get('name')
        if not vs_name:
            return
        vs_namespace = self.peer_container.get_namespace(metadata.get('namespace', 'default'))
        vs_spec = vs_resource.get('spec')
        if not vs_spec:
            self.warning(f'Spec is missing or null in VirtualService {vs_name}. Ignoring the VirtualService.')
            return

        vs = VirtualService(vs_name, vs_namespace)
        hosts = vs_spec.get('hosts')
        if hosts:
            for host in hosts:
                host_dfa = self.parse_host_value(host, vs_resource)
                if host_dfa:
                    vs.add_host_dfa(host_dfa)

        self.parse_vs_gateways(vs, vs_spec)
        self.parse_vs_http_route(vs, vs_spec)
        self.add_virtual_service(vs)

    def parse_vs_gateways(self, vs, vs_spec):
        """
        Parses gateways list of the given virtual service and adds it to internal gateways list
        :param VirtualService vs: the partially parsed VirtualService
        :param dict vs_spec: the virtual service resource
        """
        gateways = vs_spec.get('gateways')
        if gateways:
            for gtw in gateways:
                if gtw == 'mesh':
                    # TODO - implement 'mesh' in gateways
                    self.warning(f'"mesh" value of the gateways is not yet supported '
                                 f'(referenced in the VirtualService {vs.full_name()}). Ignoring it.')
                else:
                    gtw_name = gtw
                    gtw_namespace = vs.namespace
                    splitted_gtw = gtw.split('/', 1)
                    if len(splitted_gtw) == 2:
                        gtw_namespace = self.peer_container.get_namespace(splitted_gtw[0])
                        gtw_name = splitted_gtw[1]
                    vs.add_gateway(gtw_namespace, gtw_name)

    def parse_vs_http_route(self, vs, vs_spec):
        """
        Parses http attribute of the given virtual service and adds the parsed http_route to internal http_routes list
        :param VirtualService vs: the partially parsed VirtualService
        :param dict vs_spec: the virtual service resource
        """
        http = vs_spec.get('http')
        if http:
            for route in http:
                http_route = VirtualService.HTTPRoute()
                self.parse_http_match_request(route, http_route, vs)
                self.parse_http_route_destinations(route, http_route, vs)

                delegate = route.get('delegate')
                if delegate:
                    self.warning(f'"delegate" is not yet supported in HTTPRoute '
                                 f'(referenced in the VirtualService {vs.full_name()}). Ignoring it.')

                mirror = route.get('mirror')
                if mirror:
                    self.warning(f'"mirror" is not yet supported in HTTPRoute '
                                 f'(referenced in the VirtualService {vs.full_name()}). Ignoring it.')

                headers = route.get('headers')
                if headers:
                    self.warning(f'"headers" are not yet supported in HTTPRoute '
                                 f'(referenced in the VirtualService {vs.full_name()}). Ignoring them.')

                vs.add_http_route(http_route)

    def parse_istio_regex_string(self, resource, attr_name, vs_name):
        """
        Parse StringMatch of HttpMatchRequest, as defined in:
        https://istio.io/latest/docs/reference/config/networking/virtual-service/#HTTPMatchRequest
        :param dict resource: the HttpMatchRequest resource
        :param str attr_name: the name of the StringMatch attribute
        :param str vs_name: the name of the VirtualService containing this HttpMatchRequest
        :return MinDFA: the StringMatch attribute converted to the MinDFA format
        """
        res = resource.get(attr_name)
        if not res:
            return None
        items = list(res.items())
        if len(items) != 1:
            self.warning(f'Wrong format of {attr_name} referenced in the VirtualService {vs_name}.')
            return None
        regex = items[0][1]
        if items[0][0] == 'exact':
            pass
        elif items[0][0] == 'prefix':
            regex += DimensionsManager().default_dfa_alphabet_str
        elif items[0][0] == 'regex':
            regex.replace('.', DimensionsManager().default_dfa_alphabet_chars)
            if attr_name == 'uri' and resource.get('ignoreUriCase') == 'True':
                # https://github.com/google/re2/wiki/Syntax#:~:text=group%3B%20non%2Dcapturing-,(%3Fflags%3Are),-set%20flags%20during
                regex = '(?i:' + regex + ')'
        else:
            self.warning(f'Illegal attribute {items[0]} in the VirtualService {vs_name}. Ignoring.')
            return None
        return MinDFA.dfa_from_regex(regex)

    def parse_http_match_request(self, route, parsed_route, vs):
        """
        Parse HttpMatchRequest of a VirtualService and add the result to parsed_route
        :param dict route: the HttpRoute resource, as defined in
        https://istio.io/latest/docs/reference/config/networking/virtual-service/#HTTPRoute
        :param HTTPRoute parsed_route: the output parsed http route to contain the parsed attributes
        :param VirtualService vs: the virtual service containing this HttpMatchRequest
        """
        match = route.get('match')
        if not match:
            return
        for item in match:
            uri_dfa = self.parse_istio_regex_string(item, 'uri', vs.full_name())
            if uri_dfa:
                parsed_route.add_uri_dfa(uri_dfa)
            if item.get('scheme'):
                self.warning(f'"scheme" is not yet supported in HTTPMatchRequest '
                             f'(referenced in the VirtualService {vs.full_name()}). Ignoring it.')
            method_dfa = self.parse_istio_regex_string(item, 'method', vs.full_name())
            if method_dfa:
                parsed_route.add_method_dfa(method_dfa)
            if item.get('authority'):
                self.warning(f'"authority" is not yet supported in HTTPMatchRequest '
                             f'(referenced in the VirtualService {vs.full_name()}). Ignoring it.')
            if item.get('headers'):
                self.warning(f'"headers" are not yet supported in HTTPMatchRequest '
                             f'(referenced in the VirtualService {vs.full_name()}). Ignoring them.')
            if item.get('withoutHeaders'):
                self.warning(f'"withoutHeaders" are not yet supported in HTTPMatchRequest '
                             f'(referenced in the VirtualService {vs.full_name()}). Ignoring them.')
            if item.get('port'):
                self.warning(f'"port" is not yet supported in HTTPMatchRequest '
                             f'(referenced in the VirtualService {vs.full_name()}). Ignoring it.')
            if item.get('sourceLabels'):
                self.warning(f'"sourceLabels" are not yet supported in HTTPMatchRequest '
                             f'(referenced in the VirtualService {vs.full_name()}). Ignoring them.')
            if item.get('gateways'):
                self.warning(f'"gateways" are not yet supported in HTTPMatchRequest '
                             f'(referenced in the VirtualService {vs.full_name()}). Ignoring them.')
            if item.get('queryParams'):
                self.warning(f'"queryParams" are not yet supported in HTTPMatchRequest '
                             f'(referenced in the VirtualService {vs.full_name()}). Ignoring them.')
            if item.get('sourceNamespace'):
                self.warning(f'"sourceNamespace" is not yet supported in HTTPMatchRequest '
                             f'(referenced in the VirtualService {vs.full_name()}). Ignoring it.')

    def parse_http_route_destinations(self, route, parsed_route, vs):
        """
        Parse HTTPRouteDestination of a VirtualService and add the result to parsed_route
        :param dict route: the HttpRoute resource, as defined in
        https://istio.io/latest/docs/reference/config/networking/virtual-service/#HTTPRoute
        :param HTTPRoute parsed_route: the output parsed http route to contain the parsed attributes
        :param VirtualService vs: the virtual service containing this HttpMatchRequest
        """
        http_route_dest = route.get('route')
        if not http_route_dest:
            return
        for item in http_route_dest:
            dest = item.get('destination')
            if not dest:
                self.warning(f'Missing destination in HTTPRouteDestination in the VirtualService {vs.full_name()}. '
                             f'Ignoring http route.')
                return
            service = self.parse_service(dest, vs)
            if not service:
                self.syntax_error(f'Missing service referenced in {dest} in the VirtualService {vs.full_name()}', route)
            target_port = None
            port = dest.get('port')
            if port:
                port_num = port.get('number')
                if port_num:
                    service_port = service.get_port_by_number(port_num)
                    if not service_port:
                        self.syntax_error(f'Missing port {port_num} in the service', service)
                    target_port = service_port.target_port
            parsed_route.add_destination(service, target_port)

            if item.get('headers'):
                self.warning(f'"headers" are not yet supported in HTTPRouteDestination '
                             f'(referenced in the VirtualService {vs.full_name()}). Ignoring them.')

    def parse_service(self, dest, vs):
        """
        Parse Destination resource of the VirtualService and return a service corresponding to it
        :param dict dest: the destination resource, as defined in
        https://istio.io/latest/docs/reference/config/networking/virtual-service/#Destination
        :param vs: the VirtualService contining this destinatnion
        :return K8sService: the service corresponding to the given destination resource
        """
        host = dest.get('host')
        if not host:
            return None
        # according to https://kubernetes.io/docs/concepts/overview/working-with-objects/namespaces/
        # check for <service-name>.<namespace-name>.svc.cluster.local
        splitted_host = host.split('.')
        if len(splitted_host) == 5 and splitted_host[2] == 'svc' and splitted_host[3] == 'cluster' \
                and splitted_host[4] == 'local':
            service_name = splitted_host[0]
            namespace = self.peer_container.get_namespace(splitted_host[1])
        else:
            service_name = host
            namespace = vs.namespace
        return self.peer_container.get_service_by_name_and_ns(service_name, namespace)

    def make_allowed_connections(self, vs, host_dfa):
        """
        Create allowed connections of the given VirtualService
        :param VirtualService vs: the given VirtualService and the given hosts
        :param MinDFA host_dfa: the hosts attribute
        :return: TcpLikeProperties with TCP allowed connections
        """
        allowed_conns = None
        for http_route in vs.http_routes:
            for dest in http_route.destinations:
                conns = self._make_tcp_like_properties(dest.port, dest.service.target_pods, http_route.uri_dfa,
                                                       host_dfa, http_route.method_dfa)
                if not allowed_conns:
                    allowed_conns = conns
                else:
                    allowed_conns |= conns
        return allowed_conns

    def create_istio_traffic_policies(self):
        """
        Create IngressPolicies according to the parsed Gateways and VirtualServices
        :return list[IngressPolicy]: the resulting policies
        """

        if not self.gateways:
            self.syntax_error('No valid Gateways found')
        if not self.virtual_services:
            self.syntax_error('No valid VirtualServices found')

        result = []
        for vs in self.virtual_services.values():
            gateways = []
            for gtw_name in vs.gateway_names:
                gtw = self.get_gateway(gtw_name)
                if gtw:
                    gateways.append(gtw)
                else:
                    self.warning(f'Missing gateway {gtw_name}, referenced in the VirtualService {vs.full_name()}. '
                                 f'Ignoring the gateway')

            # build peers+hosts partition peers_to_hosts
            peers_to_hosts = {}
            for host_dfa in vs.hosts_dfa:
                gtw_peers = [gtw.peers for gtw in gateways if host_dfa.contained_in(gtw.all_hosts_dfa)]
                if gtw_peers:
                    peers = reduce(PeerSet.__or__, gtw_peers)
                    if peers_to_hosts.get(peers):
                        peers_to_hosts[peers] |= host_dfa
                    else:
                        peers_to_hosts[peers] = host_dfa

            for peer_set, host_dfa in peers_to_hosts.items():
                deny_policy = IngressPolicy(vs.name + '/' + str(host_dfa) + '/deny', vs.namespace,
                                            IngressPolicy.ActionType.Deny)
                deny_policy.selected_peers = peer_set
                deny_policy.add_rules(self._make_deny_rules(self.make_allowed_connections(vs, host_dfa)))
                deny_policy.findings = self.warning_msgs
                result.append(deny_policy)
        return result
