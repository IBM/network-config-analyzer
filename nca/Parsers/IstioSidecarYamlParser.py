#
# Copyright 2020- IBM Inc. All rights reserved
# SPDX-License-Identifier: Apache2.0
#
import re
from nca.CoreDS.Peer import PeerSet
from nca.Resources.NetworkPolicy import NetworkPolicy
from nca.Resources.IstioSidecar import IstioSidecar, IstioSidecarRule
from .IstioGenericYamlParser import IstioGenericYamlParser, istio_root_namespace


class IstioSidecarYamlParser(IstioGenericYamlParser):
    """
    A parser for Istio Sidecar objects
    """
    def __init__(self, policy, peer_container, file_name=''):
        IstioGenericYamlParser.__init__(self, policy, peer_container, file_name)
        self.peers_referenced_by_labels = PeerSet()  # set of the peers which were selected specifically in the sidecars
        # (with workloadSelector)
        self.specific_sidecars = []  # list of sidecars with workload-selectors within
        self.default_sidecars = []   # list of selector-less sidecars, i.e. that belong to specific namespaces
        # (other than istio_root_namespace), and not containing workload-selectors within
        self.global_default_sidecars = []  # list of selector-less sidecars in istio_root_namespace,
        # i.e. applied to all namespaces
        self.referenced_namespaces = set()  # set of namespaces that already have default sidecar

    def reset(self, policy, peer_container, file_name=''):
        """
        starts a new parser with a new sidecar policy, keeping the private attributes of self
        """
        IstioGenericYamlParser.__init__(self, policy, peer_container, file_name)

    def _validate_and_partition_host_format(self, host):
        """
        Check the validity of <namespace>/<dnsName> host format
        :param str host : single host value
        :return: namespace and dnsName - the parts of the host value
        :rtype: (str, str)
        """
        if host.count('/') != 1:
            self.syntax_error(f'Illegal host format "{host}". Host format must be namespace/dnsName', self)

        host_parts = list(filter(None, host.split('/')))
        if not len(host_parts) == 2:
            self.syntax_error(f'Illegal host format "{host}". Host must include both namespace and dnsName', self)

        return host_parts[0], host_parts[1]

    def _get_peers_from_host_namespace(self, namespace):
        """
        returns all the services' peers in the specified namespace/s
        The namespace can be set to *, ., or ~, representing any, the current, or no namespace, respectively
        :param str namespace: the namespace value
        :return: set of peers of services in the specified namespace value or empty PeerSet if no matching peers
        and a boolean value indicating if the sidecar is global with a host's namespace equal to '.'
        :rtype: (PeerSet, bool)
        """
        # since hosts expose services, target_peers of relevant services are returned in this method
        supported_chars = ('*', '.', '~')
        if any(s in namespace for s in supported_chars) and not len(namespace) == 1:
            self.syntax_error(f'unsupported regex pattern for namespace "{namespace}"', self)
        if namespace == '*':
            return self.peer_container.get_all_services_target_peers(), False
        if namespace == '.':
            # if the sidecar is global and ns is '.', then allow egress traffic only in the same namespace,
            # we return all matching peers in the mesh and later will compare namespaces to allow connections
            if str(self.namespace) == istio_root_namespace:
                return self.peer_container.get_all_services_target_peers(), True
            return self.peer_container.get_services_target_peers_in_namespace(self.namespace), False
        if namespace == '~':
            return PeerSet(), False

        ns_obj = self.peer_container.get_namespace(namespace)
        # get_namespace prints a msg to stderr if the namespace is missing from the configuration
        return self.peer_container.get_services_target_peers_in_namespace(ns_obj), False

    def _validate_dns_name_pattern(self, dns_name):
        """
        Check validity of dns_name containing as following:
        The dnsName should be specified using FQDN format,
        optionally including a wildcard character in the left-most component.
        Set the dnsName to * to select all services from the specified namespace
        :param str dns_name: a dnsName
        """
        alphabet_str = dns_name if not dns_name == '*' else None
        # assuming wildcard char may be only *
        if '*' in dns_name:
            if not ((dns_name.startswith('*.') and dns_name.count('*') == 1) or dns_name == '*'):
                self.syntax_error(f'Illegal host value pattern: "{dns_name}"', self)
            if dns_name.startswith('*.'):
                alphabet_str = dns_name.split('*.')[1]

        # the dnsName in the internal case form looks like <service_name>.<domain>.svc.cluster.local
        # also FQDN for external hosts is of the format [hostname].[domain].[tld]
        # The entire FQDN has a max length of 255 characters.
        if alphabet_str:
            fqdn_regex = r"(?=.{1,254}$)[A-Za-z0-9]([-A-Za-z0-9]*[A-Za-z0-9])?(\.[A-Za-z0-9]([-A-Za-z0-9]*[A-Za-z0-9])?)*[.]?"
            if alphabet_str.count('.') == 0 or not re.fullmatch(fqdn_regex, alphabet_str):
                self.syntax_error(f'Illegal host value pattern: "{dns_name}", '
                                  f'dnsName must be specified using FQDN format and has a max length of 255 characters', self)

    def _get_peers_from_host_dns_name(self, dns_name, host_peers):
        """
        Return the workload instances of the service in the given dns_name
        :param str dns_name: the service given in the host
        :param PeerSet host_peers: peers that already match the namespace part of the host,
        to reduce for matching the dns_name too
        :rtype: PeerSet
        """
        # supported dns_name format is fqdn with:
        # 1. internal k8s services pattern <service_name>.<domain>.svc.cluster.local, the only relevant
        # part of it is <service_name>
        # 2. external dns name (<>.<>.<>)
        if dns_name == '*':  # * means all services in namespace, all already in host_peers
            return host_peers
        if 'svc.cluster.local' in dns_name:  # internal service case
            if dns_name.startswith('*.'):  # all services in namespace, already in host_peers
                return host_peers
            service_name = dns_name.split('.')[0]
            return host_peers & self.peer_container.get_target_pods_with_service_name(service_name)

        # dns entry case
        return host_peers & self.peer_container.get_dns_entry_peers_matching_host_name(dns_name)

    def _parse_egress_rule(self, egress_rule):
        """
        Parse a single egress rule, producing a IstioSidecarRule
        :param dict egress_rule: The dict with the egress rule (IstioEgressListener) fields
        :return: A IstioSidecarRule with the proper PeerSet
        :rtype: IstioSidecarRule
        """
        # currently only hosts is considered in the rule parsing, other fields are ignored
        allowed_keys = {'port': [3, dict], 'bind': [3, str], 'captureMode': [3, str], 'hosts': [1, list]}
        self.check_fields_validity(egress_rule, 'Istio Egress Listener', allowed_keys)

        hosts = egress_rule.get('hosts')
        if not hosts:
            self.syntax_error('One or more service hosts to be exposed by the listener are required', egress_rule)
        res_peers = PeerSet()
        special_res_peers = PeerSet()
        for host in hosts:
            # Services in the specified namespace matching dnsName will be exposed.
            namespace, dns_name = self._validate_and_partition_host_format(host)
            host_peers, special_case_host = self._get_peers_from_host_namespace(namespace)
            self._validate_dns_name_pattern(dns_name)
            if host_peers:  # if there are services in the specified namespace
                host_peers = self._get_peers_from_host_dns_name(dns_name, host_peers)
            if special_case_host:
                special_res_peers |= host_peers
            else:
                res_peers |= host_peers

        return IstioSidecarRule(res_peers, special_res_peers)

    def _check_and_save_sidecar_if_top_priority(self, curr_sidecar):
        """
        Istio sidecar rules:
        1- Each Workload may be selected by one sidecar only. (the first sidecar that was injected selecting it)
        2- Each namespace can have only one Sidecar configuration without any workloadSelector.
        (the first sidecar that was injected in the namespace)
        this def checks if current sidecar is top priority for its namespace or workloads.
        - If the sidecar is selector-less, i.e. default sidecar, it will be considered only if it is the first default sidecar
         in the current namespace, otherwise will be ignored and a warning message is printed
        - if the sidecar with workloadSelector:
        for each selected peer, if this is not the first sidecar selecting this peer, then warn and remove it from the
        current sidecar's selected peers
        :param IstioSidecar curr_sidecar: the sidecar parsed in self
        """
        if curr_sidecar.default_sidecar:
            if self.namespace in self.referenced_namespaces:
                self.syntax_error(f'Namespace "{str(self.namespace)}" already has a Sidecar configuration '
                                  f'without any workloadSelector. \n'
                                  f'"{curr_sidecar.full_name()}" leads to an ambiguous system behaviour.', curr_sidecar)
                return
            self.referenced_namespaces.add(self.namespace)
            return

        prior_referenced_by_label = curr_sidecar.selected_peers & self.peers_referenced_by_labels
        if prior_referenced_by_label:
            self.syntax_error(f'Peers {", ".join([peer.full_name() for peer in prior_referenced_by_label])} '
                              f'already have a Sidecar configuration selecting them. \n '
                              f'Sidecar: "{curr_sidecar.full_name()}" leads to an ambiguous system behaviour.', curr_sidecar)
            curr_sidecar.selected_peers -= self.peers_referenced_by_labels
        self.peers_referenced_by_labels |= curr_sidecar.selected_peers

    def _parse_outbound_traffic_policy(self, outbound_traffic_policy):
        """
        determines the OutboundTrafficPolicy mode of the serviceEntry by parsing its OutboundTrafficPolicy if found,
        otherwise istio's default mode
        :param Union[dict, None] outbound_traffic_policy: the OutboundTrafficPolicy field to parse or None if not found
        :rtype: IstioSidecar.OutboundMode
        """
        # by default, istio configures the envoy proxy to passthrough requests for unknown services
        mode = IstioSidecar.OutboundMode.ALLOW_ANY
        if outbound_traffic_policy:
            self.check_fields_validity(outbound_traffic_policy, 'OutboundTrafficPolicy', {'mode': [0, str]},
                                       {'mode': ['ALLOW_ANY', 'REGISTRY_ONLY']})
            mode = \
                IstioSidecar.OutboundMode.REGISTRY_ONLY if outbound_traffic_policy.get('mode', 'ALLOW_ANY') == 'REGISTRY_ONLY'\
                else IstioSidecar.OutboundMode.ALLOW_ANY
        return mode

    def parse_policy(self):
        """
        Parses the input object to create a IstioSidecar object and adds the resulting IstioSidecar object
        to specific / default sidecar list
        """
        policy_name, policy_ns = self.parse_generic_yaml_objects_fields(self.policy, ['Sidecar'],
                                                                        ['networking.istio.io/v1alpha3',
                                                                         'networking.istio.io/v1beta1'], 'istio', True)
        if policy_name is None:
            return None  # not an Istio Sidecar
        warn_if_missing = policy_ns != istio_root_namespace
        self.namespace = self.peer_container.get_namespace(policy_ns, warn_if_missing)
        res_policy = IstioSidecar(policy_name, self.namespace)
        res_policy.policy_kind = NetworkPolicy.PolicyType.IstioSidecar

        sidecar_spec = self.policy['spec']
        # currently, supported fields in spec are workloadSelector and egress
        allowed_spec_keys = {'workloadSelector': [0, dict], 'ingress': [3, list], 'egress': [0, list],
                             'outboundTrafficPolicy': [0, dict]}

        self.check_fields_validity(sidecar_spec, 'Sidecar spec', allowed_spec_keys)
        res_policy.affects_egress = sidecar_spec.get('egress') is not None

        workload_selector = sidecar_spec.get('workloadSelector')
        res_policy.default_sidecar = workload_selector is None
        if str(self.namespace) == istio_root_namespace and workload_selector is not None:
            self.syntax_error('Global Sidecar configuration should not have any workloadSelector.')
        res_policy.selected_peers = self.update_policy_peers(workload_selector, 'labels')

        # istio ref declares both following statements:
        # 1.sidecar with workloadSelector takes precedence on a default sidecar. Handled in the following called method
        self._check_and_save_sidecar_if_top_priority(res_policy)
        # 2.  If egress is not specified, inherits the system detected defaults
        # from the namespace-wide or the global default Sidecar. However, istio does not merge User-defined sidecars.
        # (See Clarification: https://discuss.istio.io/t/istio-sidecar-doc-description-vs-live-cluster-behavior/13849)
        for egress_rule in sidecar_spec.get('egress') or []:
            res_policy.add_egress_rule(self._parse_egress_rule(egress_rule))

        res_policy.outbound_mode = self._parse_outbound_traffic_policy(sidecar_spec.get('outboundTrafficPolicy'))
        res_policy.findings = self.warning_msgs
        res_policy.referenced_labels = self.referenced_labels
        if res_policy.default_sidecar:
            if str(self.namespace) == istio_root_namespace:
                self.global_default_sidecars.append(res_policy)
            else:
                self.default_sidecars.append(res_policy)
        else:
            self.specific_sidecars.append(res_policy)

    def get_istio_sidecars(self):
        """
        returns list of all the sidecars that were parsed from the input resources, after refining the final
        selected peers of each.
        Since when determining the Sidecar configuration to be applied to a workload instance, preference will be given to
        the resource with a workloadSelector that selects this workload instance, over a Sidecar configuration
        without any workloadSelector, the refining will go as following:
        - peers that appear in specific sidecars will be taken as is (they were refined during parsing)
        - for remaining peers, preference will be given to default sidecars over global ones
        :rtype: list[IstioSidecar]
        """

        # 1st priority: specific sidecars
        # their selected_peers were already refined during parse_policy()
        res = []
        for sidecar in self.specific_sidecars:
            sidecar.create_opt_egress_props(self.peer_container)
            res.append(sidecar)
        referenced_peers = self.peers_referenced_by_labels.copy()
        # 2nd priority: default sidecars
        # refine their selected_peers according to sidecar order in the config and previously referenced peers
        for sidecar in self.default_sidecars:
            if sidecar.selected_peers & referenced_peers:
                sidecar.selected_peers -= referenced_peers
            referenced_peers |= sidecar.selected_peers
            sidecar.create_opt_egress_props(self.peer_container)
            res.append(sidecar)

        # the lowest priority - global default sidecars
        # refine their selected_peers according to sidecar order in the config and previously referenced peers
        for sidecar in self.global_default_sidecars:
            if sidecar.selected_peers & referenced_peers:
                sidecar.selected_peers -= referenced_peers
            referenced_peers |= sidecar.selected_peers
            sidecar.create_opt_egress_props(self.peer_container)
            res.append(sidecar)

        return res
