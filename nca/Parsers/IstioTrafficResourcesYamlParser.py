#
# Copyright 2020- IBM Inc. All rights reserved
# SPDX-License-Identifier: Apache2.0
#

from functools import reduce
from nca.CoreDS.DimensionsManager import DimensionsManager
from nca.CoreDS.MinDFA import MinDFA
from nca.CoreDS.Peer import PeerSet
from nca.CoreDS.MethodSet import MethodSet
from nca.Resources.IstioTrafficResources import Gateway, VirtualService
from nca.Resources.IngressPolicy import IngressPolicy
from nca.Resources.NetworkPolicy import NetworkPolicy
from .GenericIngressLikeYamlParser import GenericIngressLikeYamlParser


class IstioTrafficResourcesYamlParser(GenericIngressLikeYamlParser):
    """
    A parser for Istio traffic resources for ingress and egress
    """

    def __init__(self, peer_container):
        """
        :param PeerContainer peer_container: The ingress policy will be evaluated
        against this set of peers
        """
        GenericIngressLikeYamlParser.__init__(self, peer_container)
        self.namespace = None
        self.gateways = {}  # a map from a name to a Gateway
        self.virtual_services = {}  # a map from a name to a VirtualService
        # missing_istio_gw_pods_with_labels is map from key to value of labels
        # of gateway resource that has no matching pods
        self.missing_istio_gw_pods_with_labels = {}

    def add_gateway(self, gateway):
        """
        Adds a Gateway to the internal parser db
        (to be later used for locating the gateways referenced by virtual services)
        :param Gateway gateway: the gateway to add
        """
        self.gateways[gateway.full_name()] = gateway

    def get_gateway(self, gtw_full_name):
        """
        Returns a Gateway by its full name or None if not found.
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
        gtw_name, gtw_ns = self.parse_generic_yaml_objects_fields(gateway_resource, ['Gateway'],
                                                                  ['networking.istio.io/v1alpha3',
                                                                   'networking.istio.io/v1beta1'], 'istio', True)
        if gtw_name is None:
            return None  # not an Istio Gateway
        gtw_namespace = self.peer_container.get_namespace(gtw_ns)
        gateway = Gateway(gtw_name, gtw_namespace)

        gtw_spec = gateway_resource['spec']
        self.check_fields_validity(gtw_spec, f'the spec of Gateway {gateway.full_name()}',
                                   {'selector': [1, dict], 'servers': [1, list]})
        selector = gtw_spec['selector']
        peers = self.peer_container.get_all_peers_group()
        for key, val in selector.items():
            selector_peers = self.peer_container.get_peers_with_label(key, [val])
            if not selector_peers:
                self.missing_istio_gw_pods_with_labels[key] = val
            else:
                peers &= selector_peers
        if not peers:
            self.warning(f'selector {selector} does not reference any pods in Gateway {gtw_name}. Ignoring the gateway')
            return

        gateway.peers = peers
        self.parse_gateway_servers(gtw_name, gtw_spec, gateway)
        self.add_gateway(gateway)

    def parse_gateway_servers(self, gtw_name, gtw_spec, gateway):
        """
        Parses servers list in Gateway resource.
        :param gtw_name: the gateway name
        :param gtw_spec: the gateway spec
        :param gateway: the parsed gateway, to include the resulting parsed servers
        """
        servers = gtw_spec['servers']

        for i, server in enumerate(servers, start=1):
            self.check_fields_validity(server, f'the server #{i} of the  Gateway {gtw_name}',
                                       {'port': 1, 'bind': [0, str], 'hosts': [1, list], 'tls': 0, 'name': [0, str]})
            port = self.parse_gateway_port(server)
            gtw_server = Gateway.Server(port)
            gtw_server.name = server.get('name')
            hosts = server['hosts']
            for host in hosts or []:
                host_dfa = self.parse_host_value(host, gtw_spec)
                if host_dfa:
                    gtw_server.add_host(host_dfa)
            if not gtw_server.hosts_dfa:
                self.syntax_error(f'no valid hosts found for the server {gtw_server.name or i} '
                                  f'of the Gateway {gtw_name}')
            gateway.add_server(gtw_server)

    def parse_host_value(self, host, resource):
        """
        For 'hosts' dimension of type MinDFA -> return a MinDFA, or None for all values
        :param str host: input regex host value
        :param dict resource: the parsed gateway object
        :return: Union[MinDFA, None] object
        """
        namespace_and_name = host.split('/', 1)
        if len(namespace_and_name) > 1:
            self.warning(f'host {host}: namespace is not supported yet. Ignoring the host', resource)
            return None
        return self.parse_regex_host_value(host, resource)

    def parse_gateway_port(self, server):
        port = server['port']
        self.check_fields_validity(port, f'the port of the server {server}',
                                   {'number': [1, int], 'protocol': [1, str], 'name': [1, str], 'targetPort': [3, str]})
        number = port['number']
        protocol = port['protocol']
        name = port['name']
        return Gateway.Server.GatewayPort(number, protocol, name)

    def add_virtual_service(self, vs):
        """
        Adds a virtual service by its full name
        :param VirtualService vs: the virtual service to add
        """
        self.virtual_services[vs.full_name()] = vs

    def parse_virtual_service(self, vs_resource, vs_file_name):
        """
        Parses a virtual service resource object and adds the parsed VirtualService object to self.virtual_services
        :param dict vs_resource: the virtual service object to parse
        :param str vs_file_name: the name of the virtual service resource file
        """
        self.set_file_name(vs_file_name)  # for error/warning messages
        vs_name, vs_ns = self.parse_generic_yaml_objects_fields(vs_resource, ['VirtualService'],
                                                                ['networking.istio.io/v1alpha3',
                                                                 'networking.istio.io/v1beta1'], 'istio', True)
        if vs_name is None:
            return None  # Not an Istio VirtualService object
        vs_namespace = self.peer_container.get_namespace(vs_ns)
        vs = VirtualService(vs_name, vs_namespace)

        vs_spec = vs_resource['spec']
        self.check_fields_validity(vs_spec, f'VirtualService {vs.full_name()}',
                                   {'hosts': [0, list], 'gateways': [0, list], 'http': 0, 'tls': 3, 'tcp': 3,
                                    'exportTo': [3, str]})
        hosts = vs_spec.get('hosts')
        for host in hosts or []:
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
        for gtw in gateways or []:
            if gtw == 'mesh':
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
        for route in http or []:
            self.check_fields_validity(route, f'HTTPRroute in the VirtualService {vs.full_name()}',
                                       {'name': [0, str], 'match': 0, 'route': 0, 'redirect': 3, 'delegate': 3,
                                        'rewrite': 3, 'timeout': 3, 'retries': 3, 'fault': 3, 'mirror': 3,
                                        'mirrorPercentage': 3, 'corsPolicy': 3, 'headers': 3})
            http_route = VirtualService.HTTPRoute()
            self.parse_http_match_request(route, http_route, vs)
            self.parse_http_route_destinations(route, http_route, vs)
            vs.add_http_route(http_route)

    def parse_istio_regex_string(self, resource, attr_name, vs_name):
        """
        Parse StringMatch of HttpMatchRequest, as defined in:
        https://istio.io/latest/docs/reference/config/networking/virtual-service/#HTTPMatchRequest
        :param dict resource: the HttpMatchRequest resource
        :param str attr_name: the name of the StringMatch attribute
        :param str vs_name: the name of the VirtualService containing this HttpMatchRequest
        :return MinDFA or MethodSet: the StringMatch attribute converted to the MinDFA format
        or to the MethodSet format (in case of the 'method' attribute)
        """
        res = resource.get(attr_name)
        if not res:
            return None
        items = list(res.items())
        if len(items) != 1:
            self.warning(f'wrong format of {attr_name} referenced in the VirtualService {vs_name}.')
            return None
        regex = items[0][1]
        if items[0][0] == 'exact':
            pass
        elif items[0][0] == 'prefix':
            if attr_name == 'uri':
                return self.get_path_prefix_dfa(regex)
            regex += MinDFA.default_alphabet_regex
        elif items[0][0] == 'regex':
            regex.replace('.', MinDFA.default_dfa_alphabet_chars)
            if attr_name == 'uri' and resource.get('ignoreUriCase') == 'True':
                # https://github.com/google/re2/wiki/Syntax#:~:text=group%3B%20non%2Dcapturing-,(%3Fflags%3Are),-set%20flags%20during
                regex = '(?i:' + regex + ')'
        else:
            self.warning(f'illegal attribute {items[0]} in the VirtualService {vs_name}. Ignoring.')
            return None
        if attr_name == 'method':
            methods = MethodSet()
            methods.add_methods_from_regex(regex)
            return methods
        else:
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
            self.check_fields_validity(item, f'HTTPMatchRequest in the VirtualService {vs.full_name()}',
                                       {'name': [0, str], 'uri': 0, 'scheme': 3, 'method': 0, 'authority': 3,
                                        'headers': [3, dict], 'withoutHeaders': 3, 'port': [3, int],
                                        'sourceLabels': [3, dict], 'gateways': [3, list],
                                        'queryParams': [3, dict], 'sourceNamespace': [3, str]})
            uri_dfa = self.parse_istio_regex_string(item, 'uri', vs.full_name())
            if uri_dfa:
                parsed_route.add_uri_dfa(uri_dfa)
            methods = self.parse_istio_regex_string(item, 'method', vs.full_name())
            if methods:
                parsed_route.add_methods(methods)

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
            self.check_fields_validity(item, f'destination in route in VirtualService {vs.full_name()}',
                                       {'destination': 1, 'weight': [0, int], 'headers': [3, dict]})
            dest = item['destination']
            self.check_fields_validity(dest, f'destination in route in VirtualService {vs.full_name()}',
                                       {'host': [1, str], 'subset': [3, str], 'port': 0})
            service = self.parse_service(dest, vs)
            if not service:
                self.warning(f'The service referenced in http destination {dest} in the VirtualService {vs.full_name()}'
                             f' does not exist. This HTTPRouteDestination will be ignored', route)
                continue
            target_port = None
            port = dest.get('port')
            if port:
                port_num = port.get('number')
                if port_num:
                    service_port = service.get_port_by_number(port_num)
                    if not service_port:
                        self.syntax_error(f'missing port {port_num} in the service', service)
                    target_port = service_port.target_port
            if not target_port:  # either port or port.number is missing
                # check if this service exposes a single port
                service_port = service.get_single_port()
                if service_port:
                    target_port = service_port.target_port
                    self.warning(f'using single exposed port {target_port} for service {dest} '
                                 f'in the VirtualService {vs.full_name()}', route)
                else:
                    self.warning(f'missing port for service {dest} in the VirtualService {vs.full_name()}', route)
            parsed_route.add_destination(service, target_port)

    def parse_service(self, dest, vs):
        """
        Parse Destination resource of the VirtualService and return a service corresponding to it
        :param dict dest: the destination resource, as defined in
        https://istio.io/latest/docs/reference/config/networking/virtual-service/#Destination
        :param vs: the VirtualService contining this destinatnion
        :return K8sService: the service corresponding to the given destination resource
        """
        host = dest['host']
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
                                                       host_dfa, http_route.methods)
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
            self.warning('no valid Gateways found. Ignoring istio ingress traffic')
            return []
        if not self.virtual_services:
            self.warning('no valid VirtualServices found. Ignoring istio ingress traffic')
            return []

        result = []
        used_gateways = set()
        for vs in self.virtual_services.values():
            vs_policies = []
            gateways = []
            for gtw_name in vs.gateway_names:
                gtw = self.get_gateway(gtw_name)
                if gtw:
                    gateways.append(gtw)
                else:
                    self.warning(f'missing gateway {gtw_name}, referenced in the VirtualService {vs.full_name()}. '
                                 f'Ignoring the gateway')
            if not gateways:
                self.warning(f'virtual service {vs.full_name()} does not have valid gateways and is ignored')
                continue
            used_gateways.update(gateways)
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
                res_policy = IngressPolicy(vs.name + '/' + str(host_dfa) + '/allow', vs.namespace,
                                           IngressPolicy.ActionType.Allow)
                res_policy.policy_kind = NetworkPolicy.PolicyType.Ingress
                res_policy.selected_peers = peer_set
                allowed_conns = self.make_allowed_connections(vs, host_dfa)
                if allowed_conns:
                    res_policy.add_rules(self._make_allow_rules(allowed_conns))
                    res_policy.findings = self.warning_msgs
                    vs_policies.append(res_policy)
            if not vs_policies:
                self.warning(f'virtual service {vs.full_name()} does not affect traffic and is ignored')
            result.extend(vs_policies)
        unused_gateways = set(self.gateways.values()) - used_gateways
        if unused_gateways:
            self.warning(f'the following gateways have no virtual services attached: '
                         f'{",".join([gtw.full_name() for gtw in unused_gateways])}')
        if not result:
            self.warning('no valid VirtualServices found. Ignoring istio ingress traffic')
        return result
