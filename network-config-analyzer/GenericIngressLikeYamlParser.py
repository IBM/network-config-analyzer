#
# Copyright 2020- IBM Inc. All rights reserved
# SPDX-License-Identifier: Apache2.0
#
import re

from MinDFA import MinDFA
from DimensionsManager import DimensionsManager
from GenericYamlParser import GenericYamlParser
from IngressPolicy import IngressPolicyRule
from Peer import PeerSet, IpBlock
from PeerContainer import PeerContainer
from PortSet import PortSet
from MethodSet import MethodSet
from ConnectionSet import ConnectionSet
from TcpLikeProperties import TcpLikeProperties


class GenericIngressLikeYamlParser(GenericYamlParser):
    """
    A parser for Ingress like objects (common for k8s ingress and Istio ingress)
    """

    def __init__(self, peer_container, ingress_file_name=''):
        """
        :param PeerContainer peer_container: The ingress policy will be evaluated against this set of peers
        :param str ingress_file_name: The name of the ingress resource file
        """
        GenericYamlParser.__init__(self, ingress_file_name)
        self.peer_container = peer_container
        self.namespace = None
        self.default_backend_peers = PeerSet()
        self.default_backend_ports = PortSet()

    def parse_regex_host_value(self, regex_value, rule):
        """
        for 'hosts' dimension of type MinDFA -> return a MinDFA, or None for all values
        :param str regex_value: input regex host value
        :param dict rule: the parsed rule object
        :return: Union[MinDFA, None] object
        """
        if regex_value is None:
            return None  # to represent that all is allowed, and this dimension can be inactive in the generated cube

        allowed_chars = "[\\w]"
        allowed_chars_with_star_regex = "[*" + DimensionsManager().default_dfa_alphabet_chars + "]*"
        if not re.fullmatch(allowed_chars_with_star_regex, regex_value):
            self.syntax_error(f'Illegal characters in host {regex_value}', rule)

        # convert regex_value into regex format supported by greenery
        regex_value = regex_value.replace(".", "[.]")
        if '*' in regex_value:
            if not regex_value.startswith('*'):
                self.syntax_error(f'Illegal host value pattern: {regex_value}')
            regex_value = regex_value.replace("*", allowed_chars + '*')
        return MinDFA.dfa_from_regex(regex_value)

    def _make_tcp_like_properties(self, dest_ports, peers, paths_dfa=None, hosts_dfa=None, methods_dfa=None):
        """
        get TcpLikeProperties with TCP allowed connections, corresponding to input properties cube.
        TcpLikeProperties should not contain named ports: substitute them with corresponding port numbers, per peer
        :param PortSet dest_ports: ports set for dest_ports dimension (possibly containing named ports)
        :param PeerSet peers: the set of (target) peers
        :param MinDFA paths_dfa: MinDFA obj for paths dimension
        :param MinDFA hosts_dfa: MinDFA obj for hosts dimension
        :return: TcpLikeProperties with TCP allowed connections, corresponding to input properties cube
        """
        assert peers
        base_peer_set = self.peer_container.peer_set.copy()
        base_peer_set.add(IpBlock.get_all_ips_block())
        if not dest_ports.named_ports:
            peers_interval = base_peer_set.get_peer_interval_of(peers)
            return TcpLikeProperties(source_ports=PortSet(True), dest_ports=dest_ports,
                                     methods=methods_dfa if methods_dfa else MethodSet(True),
                                     paths=paths_dfa, hosts=hosts_dfa, peers=peers_interval,
                                     base_peer_set=base_peer_set)
        assert not dest_ports.port_set
        assert len(dest_ports.named_ports) == 1
        port = list(dest_ports.named_ports)[0]
        tcp_properties = None
        for peer in peers:
            named_ports = peer.get_named_ports()
            real_port = named_ports.get(port)
            if not real_port:
                self.warning(f'Missing named port {port} in the pod {peer}. Ignoring the pod')
                continue
            if real_port[1] != 'TCP':
                self.warning(f'Illegal protocol {real_port[1]} in the named port {port} ingress target pod {peer}.'
                             f'Ignoring the pod')
                continue
            peer_in_set = PeerSet()
            peer_in_set.add(peer)
            ports = PortSet()
            ports.add_port(real_port[0])
            props = TcpLikeProperties(source_ports=PortSet(True), dest_ports=ports, methods=MethodSet(True),
                                      paths=paths_dfa, hosts=hosts_dfa,
                                      peers=base_peer_set.get_peer_interval_of(peer_in_set),
                                      base_peer_set=base_peer_set)
            if tcp_properties:
                tcp_properties |= props
            else:
                tcp_properties = props

        return tcp_properties

    def _make_allow_rules(self, allowed_conns):
        """
        Make deny rules from the given connections
        :param TcpLikeProperties allowed_conns: the given allowed connections
        :return: the list of deny IngressPolicyRules
        """
        return self._make_rules_from_conns(allowed_conns)

    def _make_rules_from_conns(self, tcp_conns):
        """
        Make IngressPolicyRules from the given connections
        :param TcpLikeProperties tcp_conns: the given connections
        :return: the list of IngressPolicyRules
        """
        peers_to_conns = {}
        res = []
        # extract peers dimension from cubes
        for cube in tcp_conns:
            ports = None
            paths = None
            hosts = None
            peer_set = None
            for i, dim in enumerate(tcp_conns.active_dimensions):
                if dim == "dst_ports":
                    ports = cube[i]
                elif dim == "paths":
                    paths = cube[i]
                elif dim == "hosts":
                    hosts = cube[i]
                elif dim == "peers":
                    peer_set = PeerSet(set(tcp_conns.base_peer_set.get_peer_list_by_indices(cube[i])))
                else:
                    assert False
            if not peer_set:
                peer_set = self.peer_container.peer_set.copy()
            port_set = PortSet()
            port_set.port_set = ports
            port_set.named_ports = tcp_conns.named_ports
            port_set.excluded_named_ports = tcp_conns.excluded_named_ports
            new_conns = self._get_connection_set_from_properties(port_set, paths_dfa=paths, hosts_dfa=hosts)
            if peers_to_conns.get(peer_set):
                peers_to_conns[peer_set] |= new_conns  # optimize conns for the same peers
            else:
                peers_to_conns[peer_set] = new_conns
        for peer_set, conns in peers_to_conns.items():
            res.append(IngressPolicyRule(peer_set, conns))
        return res
