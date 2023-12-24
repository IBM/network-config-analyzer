#
# Copyright 2020- IBM Inc. All rights reserved
# SPDX-License-Identifier: Apache2.0
#

from functools import reduce
from nca.CoreDS.MinDFA import MinDFA
from nca.CoreDS.ConnectivityCube import ConnectivityCube
from nca.CoreDS.ConnectivityProperties import ConnectivityProperties
from nca.CoreDS.ConnectionSet import ConnectionSet
from nca.CoreDS.ProtocolSet import ProtocolSet
from nca.Resources.PolicyResources.GatewayPolicy import GatewayPolicy, GatewayPolicyRule
from nca.Resources.PolicyResources.NetworkPolicy import NetworkPolicy
from nca.Resources.OtherResources.Gateway import Gateway


class IstioGatewayPolicyGenerator:
    """
    This class creates GatewayPolicies from the parsed Gateways and VirtualServices.
    These GatewayPolicies have a style of network policies, and they model the connectivity logic as defined
    by the combination of the gateways and the virtual services.
    """
    protocol_name = 'TCP'  # TODO = should it be always TCP?
    protocols = ProtocolSet.get_protocol_set_with_single_protocol(protocol_name)

    def __init__(self, gtw_parser, vs_parser):
        """
        :param IstioGatewayParser gtw_parser: the gateway parser containing the parsed gateways.
        :param IstioVirtualServiceParser vs_parser: the virtual service parser containing the parsed virtual services.
        """
        self.gtw_parser = gtw_parser
        self.vs_parser = vs_parser

    def create_istio_gateway_policies(self):
        """
        The main function for IstioGatewayPolicyGenerator.
        Create GatewayPolicies according to the parsed Istio Gateway and VirtualService resources.
        Capturing traffic routing only in the context of gateways (ingress/egress).
        :return list[GatewayPolicy]: the resulting policies
        """
        if not self.gtw_parser or not self.gtw_parser.gateways:
            self.vs_parser.warning('no valid Gateways found. Ignoring istio ingress/egress gateway traffic')
            return []

        if not self.vs_parser or not self.vs_parser.virtual_services:
            self.gtw_parser.warning('no valid VirtualServices found. Ignoring istio ingress/egress gateway traffic')
            return []

        result = []
        # used_gateways collects the gateways used by the analysis of virtual services connectivity  
        used_gateways = set()
        for vs in self.vs_parser.virtual_services.values():
            global_vs_gtw_to_hosts = self.pick_vs_gateways_by_hosts(vs, vs.gateway_names)
            used_gateways.update(set(global_vs_gtw_to_hosts.keys()))
            # only_local_traffic is a bool flag that gets updated by the function create_route_policies()
            # it represents whether the current virtual service configures connectivity only inside the mesh
            # (internal routing rules, without gateways involved)
            only_local_traffic = False
            # create gateway policies for every instance of a route rule within a virtual service
            vs_policies = self.create_route_policies(vs, vs.http_routes, global_vs_gtw_to_hosts, used_gateways,
                                                     only_local_traffic)
            vs_policies.extend(self.create_route_policies(vs, vs.tls_routes, global_vs_gtw_to_hosts, used_gateways,
                                                          only_local_traffic))
            vs_policies.extend(self.create_route_policies(vs, vs.tcp_routes, global_vs_gtw_to_hosts, used_gateways,
                                                          only_local_traffic))
            if vs_policies:
                result.extend(vs_policies)
            else:
                if only_local_traffic:
                    self.vs_parser.warning(f'The virtual service {vs.full_name()} defines '
                                           f'only local (mesh-to-mesh) traffic that is ignored', vs)
                else:
                    self.vs_parser.warning(f'The virtual service {vs.full_name()} does not affect traffic '
                                           f'and is ignored', vs)

        unused_gateways = self.gtw_parser.get_all_gateways() - used_gateways
        if unused_gateways:
            self.vs_parser.warning(f'the following gateways have no virtual services attached: '
                                   f'{",".join([gtw.full_name() for gtw in unused_gateways])}')
        if not result:
            self.vs_parser.warning('no valid VirtualServices found. Ignoring istio ingress/egress gateway traffic')
        else:
            result[0].findings = self.gtw_parser.warning_msgs + self.vs_parser.warning_msgs
        return result

    def pick_vs_gateways_by_hosts(self, vs, gateway_names):
        """
        Given a list of gateway names, retrieves the gateways that match the virtual service by hosts
        or gives a warning for non-existing or non-matching ones
        :param VirtualService vs: the virtual service that references the gateways in the list
        :param list[str] gateway_names: the given gateway names list
        :return: dict (Gateway, MinDFA): the map from gateways to the matching hosts.
        """

        gtw_to_hosts = {}
        vs_all_hosts_dfa = reduce(MinDFA.__or__, vs.hosts_dfa)
        for gtw_name in gateway_names:
            if gtw_name == 'mesh':
                continue
            gtw = self.gtw_parser.get_gateway(gtw_name)
            if gtw:
                # Matching gateway hosts to virtual service hosts,
                # as described in https://istio.io/latest/docs/reference/config/networking/gateway/#Server:
                # "A VirtualService must be bound to the gateway and must have one or more hosts that match the hosts
                # specified in a server".
                matching_hosts = gtw.all_hosts_dfa & vs_all_hosts_dfa
                if matching_hosts:
                    gtw_to_hosts[gtw] = matching_hosts
                else:
                    self.vs_parser.warning(f'Gateway {gtw_name}, referenced in the VirtualService {vs.full_name()} '
                                           f'does not match to the VirtualService by hosts. Ignoring the gateway')
            else:
                self.vs_parser.warning(f'missing gateway {gtw_name}, referenced in the VirtualService {vs.full_name()}.'
                                       f' Ignoring the gateway')
        return gtw_to_hosts

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

    @staticmethod
    def init_gtw_to_mesh_policy(vs, route_cnt, gtw):
        """
        Create and initialize gtw-to-mesh allow policy
        :param VirtualService vs: the virtual service defining this policy
        :param int route_cnt: the index of route inside the virtual service, for which the policy is being created
        :param Gateway gtw: the gateway relevant to this policy
        :return: the created GatewayPolicy
        """
        allow_policy = GatewayPolicy(f'Allow policy for virtual service {vs.full_name()}, '
                                     f'route number {route_cnt}, gateway {gtw.full_name()}',
                                     vs.namespace, GatewayPolicy.ActionType.Allow)
        # We model ingress/egress flow relatively to the gateways pods (which are the selected_peers);
        # since in this case the gateway pods are the source pods, the policy will affect egress.
        allow_policy.policy_kind = NetworkPolicy.PolicyType.GatewayPolicy
        allow_policy.affects_egress = True
        allow_policy.selected_peers = gtw.peers
        return allow_policy

    def init_deny_policy(self, vs, route_cnt, egress_gtw):
        """
        Create and initialize mesh-to-dns deny policy
        :param VirtualService vs: the virtual service defining this policy
        :param int route_cnt: the index of route inside the virtual service, for which the policy is being created
        :param Gateway egress_gtw: the egress gateway relevant to this policy
        :return: the created GatewayPolicy
        """
        deny_policy = GatewayPolicy(f'Deny policy from mesh to DNS entries for virtual service {vs.full_name()}, '
                                    f'route number {route_cnt}, gateway {egress_gtw.full_name()}',
                                    vs.namespace, GatewayPolicy.ActionType.Deny)
        # We model ingress/egress flow relatively to the gateways pods (which are the selected_peers);
        # since in this case the gateway pods are the source pods, the policy will affect egress.
        deny_policy.policy_kind = NetworkPolicy.PolicyType.GatewayPolicy
        deny_policy.affects_egress = True
        deny_policy.selected_peers = self.vs_parser.peer_container.get_all_peers_group() - egress_gtw.peers
        return deny_policy

    def create_allow_rule(self, source_peers, dest, this_route_conn_cube, is_ingress):
        """
        Create a rule representing allowed connections between source peers and dest peers.
        :param PeerSet source_peers: the source peers
        :param VirtualService.Destination dest: the destination, including peers and ports
        :param this_route_conn_cube: additional attributes for this connection
        :param is_ingress: whether this is an ingress (True) or egress (False) rule
        :return: the resulting GatewayPolicyRule
        """
        conn_cube = this_route_conn_cube.copy()
        conn_cube["dst_ports"] = dest.ports
        conns = ConnectionSet()
        conns.add_connections(self.protocol_name, ConnectivityProperties.make_conn_props(conn_cube))
        conn_cube.update({"src_peers": source_peers, "dst_peers": dest.pods, "protocols": self.protocols})
        opt_props = ConnectivityProperties.make_conn_props(conn_cube)
        if is_ingress:
            return GatewayPolicyRule(source_peers, conns, opt_props)
        else:
            return GatewayPolicyRule(dest.pods, conns, opt_props)

    @staticmethod
    def create_deny_rule(source_peers, dst_peers):
        """
        Create a rule for representation of the denied connections from between given mesh and DNS nodes
        :return: the resulting GatewayPolicyRule
        """
        opt_props = ConnectivityProperties.make_conn_props_from_dict({"src_peers": source_peers,
                                                                      "dst_peers": dst_peers})
        return GatewayPolicyRule(dst_peers, ConnectionSet(True), opt_props)

    def create_gtw_to_mesh_and_deny_policies(self, vs, route, route_cnt, gtw_to_hosts, used_gateways):
        """
        Create internal policies representing connections from gateways to mesh,
        described by the given http/tls/tcp route.
        When relevant, create also deny policies from mesh to the mentioned DNS entries.
        :param VirtualService vs: the virtual service holding the given route
        :param Route route: the given http/tls/tcp route from which policies should be created
        :param int route_cnt: the index (starting from 1) if the given route inside this virtual service routes
        :param dict(Gateway, MinDFA) gtw_to_hosts: a map from gateways to hosts relevant for this route
        :param set(Gateway) used_gateways: a set of used gateways, to be updated by adding gateways
               referenced by these routes
        :return: list[GatewayPolicy] the resulting list of policies
        """
        result = []
        # this_route_conn_cube initialized based on the match request properties from the rule (hosts,paths,methods)
        this_route_conn_cube = self.init_route_conn_cube(route)
        for gtw, host_dfa in gtw_to_hosts.items():
            # Modeling connections from ingress gateway nodes to internal service nodes (Ingress flow) or
            # from egress gateway nodes to external service nodes (DNS nodes) (Egress flow).
            # In both cases, these connections are originated from VirtualService bound to a Gateway.
            # The VirtualService configures the routing rules from the gateway to its destinations,
            # given the request attributes.
            # Here we convert these routing rules to connectivity policies that allow the connections from the gateway
            # to its destinations on the relevant connectivity attributes.
            if route.all_sni_hosts_dfa:
                # in case of TLS route, sniHosts must be a subset of hosts, as described in
                # https://istio.io/latest/docs/reference/config/networking/virtual-service/#TLSMatchAttributes
                # according to this, we assume that sniHosts must be used instead of hosts (for matching
                # to relevant gateways and for being used as a connections' attribute).
                # the conjunction below may be empty for some gateways, which are therefore not matched and
                # should be skipped
                host_dfa &= route.all_sni_hosts_dfa
                if not host_dfa:
                    continue
            this_route_conn_cube["hosts"] = host_dfa
            used_gateways.add(gtw)
            allow_policy = self.init_gtw_to_mesh_policy(vs, route_cnt, gtw)
            deny_policy = None
            if gtw.type == Gateway.GatewayType.Egress:  # deny mesh-to-dns policy is created only in egress flow
                assert not route.is_internal_dest
                deny_policy = self.init_deny_policy(vs, route_cnt, gtw)
            for dest in route.destinations:
                allow_policy.add_egress_rule(self.create_allow_rule(gtw.peers, dest, this_route_conn_cube, False))
                if deny_policy:
                    deny_policy.add_egress_rule(self.create_deny_rule(deny_policy.selected_peers, dest.pods))
            result.append(allow_policy)
            if deny_policy:
                result.append(deny_policy)
        if not result:
            self.vs_parser.warning(f"The route number {route_cnt} of the virtual service {vs.full_name()} "
                                   f"does not define any connections and will be ignored")
        return result

    def create_mesh_to_egress_policy(self, vs, route_cnt, this_route_conn_cube, dest):
        """
        Initialization of GatewayPolicy for holding connections from mesh to egress gateway
        :param VirtualService vs: the virtual service that defines the connections from mesh to egress gateway
        :param int route_cnt: the index of the route for which the policy is being created
        :param ConnectivityCube this_route_conn_cube: a cube holding this route attributes
        :param VirtualService.Destination dest: the destination (representing an egress gateway)
        :return: the resulting GatewayPolicy
        """
        local_peers = self.vs_parser.peer_container.get_all_peers_group()
        mesh_to_egress_policy = GatewayPolicy(f'Allow policy for virtual service {vs.full_name()}, '
                                              f'route number {route_cnt} destination {dest.name}',
                                              vs.namespace, GatewayPolicy.ActionType.Allow)
        mesh_to_egress_policy.policy_kind = NetworkPolicy.PolicyType.GatewayPolicy
        # We model egress flow relatively to egress gateways pods (i.e. they are the selected_peers);
        # since the flow is into those selected peers, the policy will affect ingress.
        mesh_to_egress_policy.affects_ingress = True
        mesh_to_egress_policy.selected_peers = dest.pods
        mesh_to_egress_policy.add_ingress_rule(self.create_allow_rule(local_peers, dest, this_route_conn_cube, True))
        return mesh_to_egress_policy

    def create_route_policies(self, vs, routes, global_vs_gtw_to_hosts, used_gateways, only_local_traffic):
        """
        Create internal gateway policies representing connections described by the given http/tls/tcp routes.
        :param VirtualService vs: the virtual service holding the given routes
        :param list[Route] routes: the given http/tls/tcp routes from which policies should be created
        :param dict(Gateway, MinDFA) global_vs_gtw_to_hosts: a map from gateways to hosts
            relevant to this virtual service
        :param set(Gateway) used_gateways: a set of used gateways, to be updated by adding gateways
               referenced by these routes
        :param bool only_local_traffic: an output flag indicating whether this route contains
               only the (ignored) mesh-to-mesh traffic
        :return: list[GatewayPolicy] the resulting list of policies
        """
        result = []
        global_has_mesh = 'mesh' in vs.gateway_names
        has_gateways = len(vs.gateway_names) > 1 if global_has_mesh else bool(vs.gateway_names)
        mesh_to_mesh_warning_printed = False  # to avoid multiple printing of this warning

        for route_cnt, route in enumerate(routes, start=1):
            if route.gateway_names:  # override global gateways
                has_mesh = 'mesh' in route.gateway_names
                has_gateways |= (len(route.gateway_names) > 1 if has_mesh else bool(route.gateway_names))
                gtw_to_hosts = self.pick_vs_gateways_by_hosts(vs, route.gateway_names)
            else:  # use global gateways
                has_mesh = global_has_mesh
                gtw_to_hosts = global_vs_gtw_to_hosts
            if not has_mesh and not has_gateways:  # when no gateways are given, the default is mesh
                has_mesh = True
            # The following call to 'create_gtw_to_mesh_and_deny_policies' creates the following gateway policies:
            # 1. in case of ingress flow, it creates allow policies modeling connections from the ingress gateway
            #  to mesh internal nodes;
            # 2. in case of egress flow, it creates allow policies modeling connections from egress gateway
            # to external dns nodes, as well as deny policies modeling denied connections from mesh to mentioned
            # dns nodes.
            result.extend(self.create_gtw_to_mesh_and_deny_policies(vs, route, route_cnt, gtw_to_hosts, used_gateways))
            # Modeling connections from mesh to (egress) gateway nodes (which should be identified) (Egress flow).
            # Not modelling other connections from mesh to internal nodes here.
            # Modeling deny all connections from mesh to the mentioned external service nodes (DNS nodes) (Egress flow).
            this_route_conn_cube = self.init_route_conn_cube(route)
            for dest in route.destinations:
                if not route.is_internal_dest:
                    continue  # external dest were already handled by create_gtw_to_mesh_policies
                if has_mesh:
                    if dest.is_egress_gateway():
                        result.append(self.create_mesh_to_egress_policy(vs, route_cnt, this_route_conn_cube, dest))
                    elif not mesh_to_mesh_warning_printed:  # we do not handle mesh-to-mesh traffic
                        self.vs_parser.warning(f'The internal (mesh-to-mesh) traffic redirection mentioned in the '
                                               f'VirtualService {vs.full_name()} in route {route_cnt} '
                                               f'is not currently supported and will be ignored', vs)
                        mesh_to_mesh_warning_printed = True

        only_local_traffic |= (not has_gateways) and mesh_to_mesh_warning_printed
        return result
