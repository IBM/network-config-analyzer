#
# Copyright 2020- IBM Inc. All rights reserved
# SPDX-License-Identifier: Apache2.0
#

import re
from functools import reduce
from nca.CoreDS.MinDFA import MinDFA
from nca.CoreDS.MethodSet import MethodSet
from nca.Resources.OtherResources.VirtualService import VirtualService
from .GenericGatewayYamlParser import GenericGatewayYamlParser


class IstioVirtualServiceYamlParser(GenericGatewayYamlParser):
    """
    A parser for Istio VirtualService resources.
    (see https://github.com/istio/api/blob/master/networking/v1alpha3/virtual_service.proto)
    Currently VirtualService  is supported in the context of Istio's Ingress/Egress gateway configuration only.
    """

    def __init__(self, peer_container):
        """
        :param PeerContainer peer_container: The ingress policy will be evaluated
        against this set of peers
        """
        GenericGatewayYamlParser.__init__(self, peer_container)
        self.virtual_services = {}  # a map from a name to a VirtualService

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
                                   {'hosts': [0, list], 'gateways': [0, list], 'http': 0, 'tls': 0, 'tcp': 0,
                                    'exportTo': [3, list]})
        # field 'hosts' is the destination hosts to which traffic is being sent (from the original http request)
        # (see https://github.com/istio/api/blob/bb3cb9c034df2b5cc1de1d77689d201a0cf961c5/networking/v1alpha3/
        #      virtual_service.proto#L209-L238)
        # Hosts field is used for matching virtual services to gateways (whenever 'gateways' field is specified
        # in the virtual service). Also, the matched hosts appear in the 'hosts' attribute of the connections.
        hosts = vs_spec.get('hosts')
        for host in hosts or []:
            host_dfa = self.parse_host_value(host, vs_resource)
            if host_dfa:
                vs.add_host_dfa(host_dfa)

        # gateways field: A single VirtualService is used to configure connectivity of sidecars inside the mesh as well
        # as for one or more gateways (with the matching hosts)
        self.parse_vs_gateways(vs.namespace, vs_spec, vs, True)
        self.parse_vs_http_route(vs, vs_spec)
        self.parse_vs_tls_route(vs, vs_spec)
        self.parse_vs_tcp_route(vs, vs_spec)
        self.add_virtual_service(vs)

    def parse_vs_gateways(self, namespace, resource_spec, result, are_global_gtw=False):
        """
        Parses gateway list of the given resource (either global gateways of the virtual service or gateways in one of
        HTTPRoute/TLSRoute/TCPRoute resources of the virtual service) and adds it to the corresponding
        internal gateway list
        :param K8sNamespace namespace: the virtual service namespace
        :param dict resource_spec: the resource containing gateways to parse
        :param Union[VirtualService, VirtualService.Route] result: the object to put the resulting gateways to
        :param bool are_global_gtw: whether the parsed list is a global virtual service gateway list
        """
        gateways = resource_spec.get('gateways')
        if not gateways:
            # When this field is omitted, the default gateway (mesh) will be used,
            # which would apply the rule to all sidecars in the mesh, as appears in the description below
            # https://istio.io/latest/docs/reference/config/networking/virtual-service/#VirtualService
            if are_global_gtw:
                VirtualService.add_mesh(result)
            return
        for gtw in gateways:
            if gtw == 'mesh':
                VirtualService.add_mesh(result)
            else:
                gtw_name = gtw
                gtw_namespace = namespace
                splitted_gtw = gtw.split('/', 1)
                if len(splitted_gtw) == 2:
                    gtw_namespace = self.peer_container.get_namespace(splitted_gtw[0])
                    gtw_name = splitted_gtw[1]
                VirtualService.add_gateway(gtw_namespace, gtw_name, result)

    def parse_vs_http_route(self, vs, vs_spec):
        """
        Parses http attribute of the given virtual service and adds the parsed route to internal http_routes list
        :param VirtualService vs: the VirtualService object to add the parsed http route to
        :param dict vs_spec: the virtual service resource containing http route resource to parse
        """
        http = vs_spec.get('http')
        for route in http or []:
            self.check_fields_validity(route, f'HTTPRroute in the VirtualService {vs.full_name()}',
                                       {'name': [0, str], 'match': 0, 'route': 0, 'redirect': 3, 'delegate': 3,
                                        'rewrite': 0, 'timeout': 0, 'retries': 0, 'fault': 0, 'mirror': 3,
                                        'mirrorPercentage': 0, 'corsPolicy': 3, 'headers': 3})
            http_route = VirtualService.Route()
            self.parse_http_match_request(route, http_route, vs)
            self.parse_route_destinations(route, http_route, vs, True)
            vs.add_http_route(http_route)

    def parse_vs_tls_route(self, vs, vs_spec):
        """
        Parses tls attribute of the given virtual service and adds the parsed route to internal tls_routes list
        :param VirtualService vs: the VirtualService object to add the parsed tls route to
        :param dict vs_spec: the virtual service resource containing tls route resource to parse
        """
        tls = vs_spec.get('tls')
        for route in tls or []:
            self.check_fields_validity(route, f'TLSRroute in the VirtualService {vs.full_name()}',
                                       {'match': 0, 'route': 0})
            tls_route = self.parse_tls_match_attributes(route, vs)
            if tls_route:
                self.parse_route_destinations(route, tls_route, vs, False)
                vs.add_tls_route(tls_route)

    def parse_vs_tcp_route(self, vs, vs_spec):
        """
        Parses tcp attribute of the given virtual service and adds the parsed route to internal tcp_routes list
        :param VirtualService vs: the VirtualService object to add the parsed tcp route to
        :param dict vs_spec: the virtual service resource containing tcp route resource to parse
        """
        tcp = vs_spec.get('tcp')
        for route in tcp or []:
            self.check_fields_validity(route, f'TLSRroute in the VirtualService {vs.full_name()}',
                                       {'match': 0, 'route': 0})
            tcp_route = VirtualService.Route()
            self.parse_l4_match_attributes(route, tcp_route, vs)
            self.parse_route_destinations(route, tcp_route, vs, False)
            vs.add_tcp_route(tcp_route)

    def parse_istio_regex_string(self, resource, attr_name, vs_name):
        """
        Parse StringMatch of HttpMatchRequest, as defined in:
        https://istio.io/latest/docs/reference/config/networking/virtual-service/#HTTPMatchRequest
        :param dict resource: the HttpMatchRequest resource
        :param str attr_name: the name of the StringMatch attribute
        :param str vs_name: the name of the VirtualService containing this HttpMatchRequest
        :return Union[MinDFA, MethodSet]: the StringMatch attribute converted to the MinDFA format
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

    def parse_http_match_request(self, route, result_route, vs):
        """
        Parse HttpMatchRequest of a VirtualService and add the result to result_route
        :param dict route: the HttpRoute resource, as defined in
        https://istio.io/latest/docs/reference/config/networking/virtual-service/#HTTPRoute
        :param VirtualService.Route result_route: the output parsed http route to contain the parsed attributes
        :param VirtualService vs: the virtual service containing this HttpMatchRequest
        """
        match = route.get('match')
        if not match:
            return
        for item in match:
            self.check_fields_validity(item, f'HTTPMatchRequest in the VirtualService {vs.full_name()}',
                                       {'name': [0, str], 'uri': 0, 'scheme': 3, 'method': 0, 'authority': 3,
                                        'headers': [3, dict], 'withoutHeaders': 3, 'port': [3, int],
                                        'sourceLabels': [3, dict], 'gateways': [0, list],
                                        'queryParams': [3, dict], 'sourceNamespace': [3, str]})
            uri_dfa = self.parse_istio_regex_string(item, 'uri', vs.full_name())
            if uri_dfa:
                result_route.add_uri_dfa(uri_dfa)
            methods = self.parse_istio_regex_string(item, 'method', vs.full_name())
            if methods:
                result_route.add_methods(methods)
            else:
                result_route.add_methods(MethodSet(True))
            # gateways field: Names of gateways where the rule should be applied. Gateway names in the top-level
            # gateways field of the VirtualService (if any) are overridden.
            self.parse_vs_gateways(vs.namespace, item, result_route)

    def parse_tls_match_attributes(self, route, vs):
        """
        Parse TLSMatchRequest of a VirtualService and return the parsed result
        :param dict route: the TLSRoute resource, as defined in
        https://istio.io/latest/docs/reference/config/networking/virtual-service/#TLSRoute
        :param VirtualService vs: the virtual service containing this TLSMatchRequest
        :return: union[VirtualService.Route, None] the parsed tls_route
        """
        match = route.get('match')
        if not match:
            return None
        tls_route = VirtualService.Route()
        for item in match:
            self.check_fields_validity(item, f'TLSMatchAttributes in the VirtualService {vs.full_name()}',
                                       {'sniHosts': [1, list], 'destinationSubnets': [3, list], 'port': [3, int],
                                        'sourceLabels': [3, dict], 'gateways': [0, list], 'sourceNamespace': [3, str]})
            # TODO - understand 'destinationSubnets' usage
            sni_hosts = item.get('sniHosts')
            for sni_host in sni_hosts or []:
                sni_host_dfa = self.parse_host_value(sni_host, match)
                if tls_route.all_sni_hosts_dfa:
                    tls_route.all_sni_hosts_dfa |= sni_host_dfa
                else:
                    tls_route.all_sni_hosts_dfa = sni_host_dfa
            vs_all_hosts_dfa = reduce(MinDFA.__or__, vs.hosts_dfa)
            if not tls_route.all_sni_hosts_dfa.contained_in(vs_all_hosts_dfa):
                self.warning('sniHosts mentioned in the tls.match are not a subset of hosts. This match will be ignored',
                             vs)
                return None
            # gateways field: Names of gateways where the rule should be applied. Gateway names in the top-level
            # gateways field of the VirtualService (if any) are overridden.
            self.parse_vs_gateways(vs.namespace, item, tls_route)
        return tls_route

    def parse_l4_match_attributes(self, route, result_route, vs):
        """
        Parse TLSMatchRequest of a VirtualService and return the parsed result
        :param dict route: the TLSRoute resource, as defined in
        https://istio.io/latest/docs/reference/config/networking/virtual-service/#TLSRoute
        :param VirtualService.Route result_route: the output parsed tcp route to contain the parsed attributes
        :param VirtualService vs: the virtual service containing this TLSMatchRequest
        """
        match = route.get('match')
        if not match:
            return None
        for item in match:
            self.check_fields_validity(item, f'L4MatchAttributes in the VirtualService {vs.full_name()}',
                                       {'destinationSubnets': [3, list], 'port': [3, int],
                                        'sourceLabels': [3, dict], 'gateways': [0, list], 'sourceNamespace': [3, str]})
            # TODO - understand 'destinationSubnets' usage
            # gateways field: Names of gateways where the rule should be applied. Gateway names in the top-level
            # gateways field of the VirtualService (if any) are overridden.
            self.parse_vs_gateways(vs.namespace, item, result_route)

    def parse_route_destinations(self, route, result_route, vs, is_http_route):
        """
        Parse Destination / RootDestination of a VirtualService, as defined in
        https://istio.io/latest/docs/reference/config/networking/virtual-service/#HTTPRouteDestination
        or
        https://istio.io/latest/docs/reference/config/networking/virtual-service/#RouteDestination
        and add the result to result_route
        :param dict route: the HTTPRoute/TLSRoot resource, as defined in
        https://istio.io/latest/docs/reference/config/networking/virtual-service/#HTTPRoute
        or
        https://istio.io/latest/docs/reference/config/networking/virtual-service/#TLSRoute
        :param VirtualService.Route result_route: the output parsed route to contain the parsed attributes
        :param VirtualService vs: the virtual service containing this HttpMatchRequest
        :param bool is_http_route: whether the given route is HTTPRoute (True) or TLSRoute/TCPRoute (False)
        """
        route_dest = route.get('route')
        if not route_dest:
            return
        for item in route_dest:
            if is_http_route:
                self.check_fields_validity(item, f'destination in http route in VirtualService {vs.full_name()}',
                                           {'destination': 1, 'weight': [0, int], 'headers': [3, dict]})
            else:
                self.check_fields_validity(item, f'destination in tls/tcp route in VirtualService {vs.full_name()}',
                                           {'destination': 1, 'weight': [0, int]})
            dest = item['destination']
            self.check_fields_validity(dest, f'destination in route in VirtualService {vs.full_name()}',
                                       {'host': [1, str], 'subset': [3, str], 'port': 0})
            self.parse_destination(dest, vs, result_route)

    def parse_destination(self, dest, vs, result_route):
        """
        Parse Destination resource of the VirtualService and return a service corresponding to it
        :param dict dest: the destination resource, as defined in
        https://istio.io/latest/docs/reference/config/networking/virtual-service/#Destination
        :param vs: the VirtualService contining this destinatnion
        :param VirtualService.Route result_route: the output route to contain the parsed attributes
        """
        host = dest['host']
        port = dest.get('port')
        port_num = None
        if port:
            port_num = port.get('number')
        assert not re.search("\\*", host)
        if self.is_local_service(host):
            service = self.get_local_service(host, vs.namespace)
            if not service:
                self.warning(f'The service referenced in destination {dest} in the VirtualService {vs.full_name()}'
                             f' does not exist. This Destination will be ignored', dest)
                return
            target_port = None
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
                                 f'in the VirtualService {vs.full_name()}', dest)
                else:
                    self.warning(f'missing port for service {dest} in the VirtualService {vs.full_name()}', dest)
            result_route.add_destination(host, service.target_pods, target_port, True)
        else:  # should be DNS entry
            dns_entries = self.peer_container.get_dns_entry_peers_matching_host_name(host)
            if not dns_entries:
                self.warning(f'The host {host} mentioned in the VirtualService {vs.full_name()} '
                             f'does not match any existing dns entry. This Destination will be ignored', dest)
                return
            result_route.add_destination(host, dns_entries, port_num, False)

    @staticmethod
    def is_local_service(host):
        # according to https://kubernetes.io/docs/concepts/overview/working-with-objects/namespaces/
        # check for <service-name>.<namespace-name>.svc.cluster.local
        if re.search("\\*", host):  # regular expression
            return False
        splitted_host = host.split('.')
        if len(splitted_host) == 5 and splitted_host[2] == 'svc' and splitted_host[3] == 'cluster' \
                and splitted_host[4] == 'local':  # local with name and namespace given
            return True
        elif len(splitted_host) > 1:  # DNS entry
            return False
        else:  # local without namespace given
            return True

    def get_local_service(self, host, ns):
        # according to https://kubernetes.io/docs/concepts/overview/working-with-objects/namespaces/
        # check for <service-name>.<namespace-name>.svc.cluster.local
        splitted_host = host.split('.')
        if len(splitted_host) == 5 and splitted_host[2] == 'svc' and splitted_host[3] == 'cluster' \
                and splitted_host[4] == 'local':  # local with name and namespace given
            service_name = splitted_host[0]
            namespace = self.peer_container.get_namespace(splitted_host[1])
        else:  # local without namespace given
            assert len(splitted_host) == 1  # not a DNS entry
            service_name = host
            namespace = ns
        assert service_name and namespace
        return self.peer_container.get_service_by_name_and_ns(service_name, namespace)
