#
# Copyright 2020- IBM Inc. All rights reserved
# SPDX-License-Identifier: Apache2.0
#

import re
from functools import reduce
from nca.CoreDS.MinDFA import MinDFA
from nca.CoreDS.Peer import PeerSet
from nca.CoreDS.MethodSet import MethodSet
from nca.CoreDS.ConnectivityCube import ConnectivityCube
from nca.CoreDS.ConnectivityProperties import ConnectivityProperties
from nca.CoreDS.ConnectionSet import ConnectionSet
from nca.CoreDS.ProtocolSet import ProtocolSet
from nca.Resources.VirtualService import VirtualService
from nca.Resources.IstioGatewayPolicy import IstioGatewayPolicy, IstioGatewayPolicyRule
from nca.Resources.NetworkPolicy import NetworkPolicy
from .GenericIngressLikeYamlParser import GenericIngressLikeYamlParser


class IstioVirtualServiceYamlParser(GenericIngressLikeYamlParser):
    """
    A parser for Istio traffic resources for ingress and egress
    """
    protocol_name = 'TCP'  # TODO = should it be always TCP?
    protocols = ProtocolSet.get_protocol_set_with_single_protocol(protocol_name)

    def __init__(self, peer_container):
        """
        :param PeerContainer peer_container: The ingress policy will be evaluated
        against this set of peers
        """
        GenericIngressLikeYamlParser.__init__(self, peer_container)
        self.virtual_services = {}  # a map from a name to a VirtualService
        self.gtw_parser = None

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
        hosts = vs_spec.get('hosts')
        for host in hosts or []:
            host_dfa = self.parse_host_value(host, vs_resource)
            if host_dfa:
                vs.add_host_dfa(host_dfa)

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
        :param result: the object to put the resulting gateways to
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

    # Second phase - creation of policies from parsed gateways and virtual services

    def create_istio_traffic_policies(self, gtw_parser):
        """
        Create IngressPolicies according to the parsed Gateways and VirtualServices
        :param IstioGatewayYamlParser gtw_parser: the gateway parser containing parsed gateways
        :return list[IstioGatewayPolicy]: the resulting policies
        """
        if not self.virtual_services:
            self.warning('no valid VirtualServices found. Ignoring istio ingress/egress traffic')
            return []

        if not gtw_parser:
            self.warning('no valid Gateways found. Ignoring istio ingress/egress traffic')
            return []

        self.gtw_parser = gtw_parser
        result = []
        used_gateways = set()
        for vs in self.virtual_services.values():
            global_vs_gtw_to_hosts = self.pick_vs_gateways_by_hosts(vs, vs.gateway_names)
            if not global_vs_gtw_to_hosts:
                self.warning(f'virtual service {vs.full_name()} does not match valid gateways and will be ignored')
                continue

            used_gateways.update(set(global_vs_gtw_to_hosts.keys()))
            vs_policies = self.create_route_policies(vs, vs.http_routes, global_vs_gtw_to_hosts, used_gateways)
            vs_policies.extend(self.create_route_policies(vs, vs.tls_routes, global_vs_gtw_to_hosts, used_gateways))
            vs_policies.extend(self.create_route_policies(vs, vs.tcp_routes, global_vs_gtw_to_hosts, used_gateways))
            if vs_policies:
                result.extend(vs_policies)
            else:
                self.warning(f'virtual service {vs.full_name()} does not affect traffic and is ignored')

        deny_mesh_to_ext_policy = self.create_deny_mesh_to_ext_policy()
        if deny_mesh_to_ext_policy:
            result.append(deny_mesh_to_ext_policy)

        unused_gateways = self.gtw_parser.get_all_gateways() - used_gateways
        if unused_gateways:
            self.warning(f'the following gateways have no virtual services attached: '
                         f'{",".join([gtw.full_name() for gtw in unused_gateways])}')
        if not result:
            self.warning('no valid VirtualServices found. Ignoring istio ingress traffic')
        else:
            result[0].findings = self.warning_msgs
        return result

    def pick_vs_gateways_by_hosts(self, vs, gateway_names):
        """
        Given a list of gateway names, retrieves the gateways that match the virtual service by hosts
        or gives a warning for non-existing or non-matching ones
        :param VirtualService vs: the virtual service that references the gateways in the list
        :param list[str] gateway_names: the given gateway names list
        :return: dict: the map from gateways to the matching hosts.
        """

        gtw_to_hosts = {}
        vs_all_hosts_dfa = reduce(MinDFA.__or__, vs.hosts_dfa)
        for gtw_name in gateway_names:
            if gtw_name == 'mesh':
                continue
            gtw = self.gtw_parser.get_gateway(gtw_name)
            if gtw:
                matching_hosts = gtw.all_hosts_dfa & vs_all_hosts_dfa
                if matching_hosts:
                    gtw_to_hosts[gtw] = matching_hosts
                else:
                    self.warning(f'Gateway {gtw_name}, referenced in the VirtualService {vs.full_name()} '
                                 f'does not match to the VirtualService by hosts. Ignoring the gateway')
            else:
                self.warning(f'missing gateway {gtw_name}, referenced in the VirtualService {vs.full_name()}. '
                             f'Ignoring the gateway')
        return gtw_to_hosts

    @staticmethod
    def init_mesh_to_egress_policy(vs, selected_peers):
        """
        Initialization of IstioGatewayPolicy for holding connections from mesh to egress gateway
        :param VirtualService vs: the virtual service that defines the connections from mesh to egress gateway
        :param PeerSet selected_peers: egress gateway pods
        :return: the resulting IstioGatewayPolicy
        """
        mesh_to_egress_policy = IstioGatewayPolicy(vs.name + '/mesh/egress/allow', vs.namespace,
                                                   IstioGatewayPolicy.ActionType.Allow)
        mesh_to_egress_policy.policy_kind = NetworkPolicy.PolicyType.IstioGatewayPolicy
        # We model egress flow relatively to egress gateways pods (i.e. they are the selected_peers);
        # since the flow is into those selected peers, the policy will affect ingress.
        mesh_to_egress_policy.affects_ingress = True
        mesh_to_egress_policy.selected_peers = selected_peers
        return mesh_to_egress_policy

    def create_deny_mesh_to_ext_policy(self):
        """
        Create policy for representation of the denied connections from mesh to DNS nodes
        :return: the resulting IstioGatewayPolicy
        """
        source_peers = self.peer_container.get_all_peers_group() - self.gtw_parser.get_egress_gtw_pods()
        dns_peers = self.peer_container.get_all_dns_entries()
        if not dns_peers:
            # This is not an egress flow
            return None
        deny_mesh_to_ext_policy = IstioGatewayPolicy('mesh/external/deny', self.peer_container.get_namespace('default'),
                                                     IstioGatewayPolicy.ActionType.Deny)
        deny_mesh_to_ext_policy.policy_kind = NetworkPolicy.PolicyType.IstioGatewayPolicy
        # External (DNS) pods are the selected_peers
        # Note: This is a Deny policy. selected_peers will not be captured (due to conditional captured function)
        deny_mesh_to_ext_policy.affects_ingress = True
        deny_mesh_to_ext_policy.selected_peers = dns_peers
        opt_props = ConnectivityProperties.make_conn_props_from_dict({"src_peers": source_peers,
                                                                      "dst_peers": dns_peers})
        deny_mesh_to_ext_policy.add_ingress_rule(IstioGatewayPolicyRule(source_peers, ConnectionSet(True), opt_props))
        return deny_mesh_to_ext_policy

    @staticmethod
    def init_route_conn_cube(route):
        """
        Initialize ConnectivityCube according to the given route attributes
        :param VirtualService.Route route: the given route
        :return: the resulting ConnectivityCube
        """
        conn_cube = ConnectivityCube()
        if route.all_sni_hosts_dfa:
            conn_cube["hosts"] = route.all_sni_hosts_dfa
        if route.uri_dfa:
            conn_cube["paths"] = route.uri_dfa
        if route.methods:
            conn_cube["methods"] = route.methods
        return conn_cube

    def create_gtw_to_mesh_policies(self, vs, route, route_cnt, gtw_to_hosts, used_gateways):
        """
        Create internal policies representing connections from gateways to mesh described by the given http/tls/tcp route.
        :param VirtualService vs: the virtual service holding the given route
        :param Route route: the given http/tls/tcp route from which policies should be created
        :param int route_cnt: the index (starting from 1) if the given route inside this virtual service routes
        :param dict gtw_to_hosts: a map from gateways to hosts relevant for this route
        :param set(Gateway) used_gateways: a set of used gateways, to be updated by adding gateways
               referenced by these routes
        :return: list[IstioGatewayPolicy] the resulting list of policies
        """
        result = []
        this_route_conn_cube = self.init_route_conn_cube(route)
        for gtw, host_dfa in gtw_to_hosts.items():
            # Modeling connections from ingress gateway nodes to internal service nodes (Ingress flow) or
            # from egress gateway nodes to external service nodes (DNS nodes) (Egress flow).
            if route.all_sni_hosts_dfa:
                host_dfa &= route.all_sni_hosts_dfa
                if not host_dfa:
                    continue
            used_gateways.add(gtw)
            res_policy = IstioGatewayPolicy(f'{vs.full_name()}/route_{route_cnt}/{gtw.full_name()}/{str(host_dfa)}/allow',
                                            vs.namespace, IstioGatewayPolicy.ActionType.Allow)
            # We model ingress/egress flow relatively to the gateways pods (which are the selected_peers);
            # since in this case the gateway pods are the source pods, the policy will affect egress.
            res_policy.policy_kind = NetworkPolicy.PolicyType.IstioGatewayPolicy
            res_policy.affects_egress = True
            res_policy.selected_peers = gtw.peers
            for dest in route.destinations:
                this_dest_conn_cube = this_route_conn_cube.copy()
                this_dest_conn_cube.update({"hosts": host_dfa, "dst_ports": dest.ports})
                conns = ConnectionSet()
                conns.add_connections(self.protocol_name, ConnectivityProperties.make_conn_props(this_dest_conn_cube))
                this_dest_conn_cube.update({"src_peers": gtw.peers, "dst_peers": dest.pods, "protocols": self.protocols})
                opt_props = ConnectivityProperties.make_conn_props(this_dest_conn_cube)
                res_policy.add_egress_rule(IstioGatewayPolicyRule(dest.pods, conns, opt_props))
            result.append(res_policy)
        return result

    def create_route_policies(self, vs, routes, global_vs_gtw_to_hosts, used_gateways):
        """
        Create internal policies representing connections described by the given http/tls/tcp routes.
        :param VirtualService vs: the virtual service holding the given routes
        :param list[Route] routes: the given http/tls/tcp routes from which policies should be created
        :param dict global_vs_gtw_to_hosts: a map from gateways to hosts relevant for this virtual service
        :param set(Gateway) used_gateways: a set of used gateways, to be updated by adding gateways
               referenced by these routes
        :return: list[IstioGatewayPolicy] the resulting list of policies
        """
        result = []
        global_has_mesh = 'mesh' in vs.gateway_names
        local_peers = self.peer_container.get_all_peers_group()
        egress_gtw_pods = self.gtw_parser.get_egress_gtw_pods()
        mesh_to_egress_policy = self.init_mesh_to_egress_policy(vs, egress_gtw_pods)

        for route_cnt, route in enumerate(routes, start=1):
            if route.gateway_names:  # override global gateways
                has_mesh = 'mesh' in route.gateway_names
                gtw_to_hosts = self.pick_vs_gateways_by_hosts(vs, route.gateway_names)
            else:  # use global gateways
                has_mesh = global_has_mesh
                gtw_to_hosts = global_vs_gtw_to_hosts
            if not has_mesh and not gtw_to_hosts:  # when no gateways are given, the default is mesh
                has_mesh = True
            result.extend(self.create_gtw_to_mesh_policies(vs, route, route_cnt, gtw_to_hosts, used_gateways))
            # Modeling connections from mesh to (egress) gateway nodes (which should be identified) (Egress flow).
            # Not modelling other connections from mesh to internal nodes here.
            # Modeling deny all connections from mesh to external service nodes (DNS nodes) (Egress flow).
            this_route_conn_cube = self.init_route_conn_cube(route)
            for dest in route.destinations:
                if not route.is_internal_dest:
                    continue  # external dest cannot be an egress gateway pod
                if has_mesh and dest.pods.issubset(egress_gtw_pods):
                    # add a rule to mesh_to_egress_policy
                    this_dest_conn_cube = this_route_conn_cube.copy()
                    this_dest_conn_cube["dst_ports"] = dest.ports
                    conns = ConnectionSet()
                    conns.add_connections(self.protocol_name, ConnectivityProperties.make_conn_props(this_dest_conn_cube))
                    this_dest_conn_cube.update({"src_peers": local_peers, "dst_peers": dest.pods,
                                                "protocols": self.protocols})
                    opt_props = ConnectivityProperties.make_conn_props(this_dest_conn_cube)
                    mesh_to_egress_policy.add_ingress_rule(IstioGatewayPolicyRule(local_peers, conns, opt_props))

        if mesh_to_egress_policy.has_allow_rules():
            result.append(mesh_to_egress_policy)
        return result
