#
# Copyright 2020- IBM Inc. All rights reserved
# SPDX-License-Identifier: Apache2.0
#

from nca.CoreDS.Peer import PeerSet
from nca.Resources.OtherResources.Gateway import Gateway
from .GenericIngressLikeYamlParser import GenericIngressLikeYamlParser


class IstioGatewayYamlParser(GenericIngressLikeYamlParser):
    """
    A parser for Istio gateway resource.
    Currently we support only standard istio ingress or egress gateways, which are identified by
    'istio: ingressgateway' or 'istio: egressgateway' selectors correspondingly.
    """

    def __init__(self, peer_container):
        """
        :param PeerContainer peer_container: The ingress policy will be evaluated
        against this set of peers
        """
        GenericIngressLikeYamlParser.__init__(self, peer_container)
        self.gateways = {}  # a map from a name to a Gateway
        # missing_istio_gw_pods_with_labels is a set of labels - (key,value) pairs
        # of gateway resource that has no matching pods
        self.missing_istio_gw_pods_with_labels = set()

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

    def get_all_gateways(self):
        """
        Returns a set of all gateways
        """
        return set(self.gateways.values())

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
            # currently we support only standard istio ingress or egress gateways, which are identified by
            # 'istio: ingressgateway' or 'istio: egressgateway' selectors correspondingly.
            if key == 'istio':
                if val == 'ingressgateway':
                    gateway.type = Gateway.GatewayType.Ingress
                elif val == 'egressgateway':
                    gateway.type = Gateway.GatewayType.Egress
            selector_peers = self.peer_container.get_peers_with_label(key, [val])
            if not selector_peers:
                self.missing_istio_gw_pods_with_labels.add((key, val))
                peers = PeerSet()
            else:
                peers &= selector_peers
        if not gateway.type:
            self.warning(f'The gateway {gtw_name} is not a standard istio ingress/egress gateway, and it is ignored')
            return
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

    def parse_gateway_port(self, server):
        port = server['port']
        self.check_fields_validity(port, f'the port of the server {server}',
                                   {'number': [1, int], 'protocol': [1, str], 'name': [1, str], 'targetPort': [3, str]})
        number = port['number']
        protocol = port['protocol']
        name = port['name']
        return Gateway.Server.GatewayPort(number, protocol, name)
