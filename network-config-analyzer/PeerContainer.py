#
# Copyright 2020- IBM Inc. All rights reserved
# SPDX-License-Identifier: Apache2.0
#
from sys import stderr
import yaml
from Peer import PeerSet, Pod, IpBlock, HostEP
from K8sNamespace import K8sNamespace
from GenericYamlParser import GenericYamlParser
from K8sServiceYamlParser import K8sServiceYamlParser
from CmdlineRunner import CmdlineRunner
from GenericTreeScanner import TreeScannerFactory


class PeerContainer:
    """
    This class holds a representation of the network topology: the set of eps and how they are partitioned to namespaces
    It also provides various services to build the topology from files and to filter the eps by labels and by namespaces
    """
    pod_creation_resources = ['Deployment', 'ReplicaSet', 'StatefulSet', 'DaemonSet', 'Job', 'CronJob',
                              'ReplicationController']

    def __init__(self, ns_resources=None, peer_resources=None, config_name='global'):
        """
        create a PeerContainer object
        :param list ns_resources: the list of namespace resources
        :param list peer_resources: the list of peer resources
        :param str config_name: the config name
        """
        self.peer_set = PeerSet()
        self.namespaces = {}  # mapping from namespace name to the actual K8sNamespace object
        self.services = {}  # mapping from service name to the actual K8sService object
        self.representative_peers = {}
        if ns_resources:
            self._set_namespace_list(ns_resources)
        if peer_resources:
            self._set_peer_list(peer_resources, config_name)
            # look for service resources under 'peer_resources' files
            services = K8sServiceYamlParser.parse_service_resources(peer_resources)
            self.set_services_and_populate_target_pods(services)

    def __eq__(self, other):
        if isinstance(other, PeerContainer):
            return self.peer_set == other.peer_set and self.namespaces == other.namespaces and self.services == other.services
        return NotImplemented

    def load_ns_from_live_cluster(self):
        yaml_file = CmdlineRunner.get_k8s_resources('namespace')
        ns_code = yaml.load(yaml_file, Loader=yaml.SafeLoader)
        self.set_namespaces(ns_code)

    def load_peer_from_k8s_live_cluster(self):
        peer_code = yaml.load(CmdlineRunner.get_k8s_resources('pod'), Loader=yaml.SafeLoader)
        self.add_eps_from_yaml(peer_code)

    def _add_namespace(self, ns_object, generic_list):
        """
        Adds a single namespace to the container
        :param dict ns_object: The Namespace resource to add
        :param bool generic_list: When list has the generic kind 'List', we have to check the resource kind
        :return: None
        """
        if generic_list and ns_object.get('kind') != 'Namespace':
            return
        metadata = ns_object.get('metadata', {})
        ns_name = metadata.get('name', '')
        namespace = K8sNamespace(ns_name)
        labels = metadata.get('labels', {})
        for key, val in labels.items():
            namespace.set_label(key, val)
        self.namespaces[ns_name] = namespace

    def set_namespaces(self, ns_list):
        """
        Given a NamespaceList resource, adds all namespaces in the list to the container
        :param dict ns_list: The NamespaceList resource
        :return: None
        """
        if not isinstance(ns_list, dict):
            return

        for namespace in ns_list.get('items', []):
            self._add_namespace(namespace, ns_list.get('kind') == 'List')

    def _set_namespace_list(self, ns_resources_list):
        """
        Populates the set of namespaces in the container from one of the following resources:
         - git path of yaml file or a directory with yamls
         - local file (yaml or json) or a local directory containing yamls
         - query of the cluster
        :param list ns_resources_list: The namespace resource to be used.
            If set to 'k8s', will query cluster using kubectl
        :return: None
        """
        if not ns_resources_list:
            self.load_ns_from_live_cluster()

        for ns_resources in ns_resources_list:
            # load from live cluster
            if ns_resources == 'k8s':
                self.load_ns_from_live_cluster()
            else:
                resource_scanner = TreeScannerFactory.get_scanner(ns_resources)
                if resource_scanner is None:
                    continue
                yaml_files = resource_scanner.get_yamls()
                for yaml_file in yaml_files:
                    for ns_code in yaml_file.data:
                        if isinstance(ns_code, dict) and ns_code.get('kind') in {'NamespaceList', 'List'}:
                            self.set_namespaces(ns_code)

    def _set_peer_list(self, peer_resources_list, config_name):
        """
        Populates the set of peers in the container from one of the following resources:
         - git path of yaml file or a directory with yamls
         - local file (yaml or json) or a local directory containing yamls
         - query of the cluster
        :param list peer_resources_list: list of peer resources to use.
        If set to 'k8s'/'calico'  query cluster using kubectl/calicoctl
        :param srt config_name: The config name
        :return: None
        """

        if not peer_resources_list:
            self.load_peer_from_k8s_live_cluster()

        for peer_resources in peer_resources_list:
            # load from live cluster
            if peer_resources == 'calico':
                for peer_type in ['wep', 'hep', 'networkset', 'globalnetworkset']:
                    peer_code = yaml.load(CmdlineRunner.get_calico_resources(peer_type), Loader=yaml.SafeLoader)
                    self.add_eps_from_yaml(peer_code)
            elif peer_resources == 'k8s':
                self.load_peer_from_k8s_live_cluster()
            else:
                resource_scanner = TreeScannerFactory.get_scanner(peer_resources)
                if resource_scanner is None:
                    continue
                for yaml_file in resource_scanner.get_yamls():
                    self.add_eps_from_yaml(yaml_file.data)

        print(f'{config_name}: cluster has {self.get_num_peers()} unique endpoints, '
              f'{self.get_num_namespaces()} namespaces')

    def set_services_and_populate_target_pods(self, srv_list):
        """
        Populates services from the given service list,
        and for every service computes and populates its target pods.
        :param list srv_list: list of service in K8sService format
        :return: None
        """
        for srv in srv_list:
            # check and update namespace
            srv.namespace = self.get_namespace(srv.namespace.name)
            # populate target ports
            if srv.selector:
                srv.target_pods = self.peer_set
            for key, val in srv.selector.items():
                srv.target_pods &= self.get_peers_with_label(key, [val], GenericYamlParser.FilterActionType.In,
                                                             srv.namespace)
            # remove target_pods that don't contain named ports referenced by target_ports
            for port in srv.ports.values():
                if not isinstance(port.target_port, str):
                    continue
                # check if all pods include this named port, and remove those that don't
                pods_to_remove = PeerSet()
                for pod in srv.target_pods:
                    pod_named_port = pod.named_ports.get(port.target_port)
                    if not pod_named_port:
                        print(f'Warning: The named port {port.target_port} referenced in Service {srv.name}'
                              f' is not defined in the pod {pod}. Ignoring the pod')
                        pods_to_remove.add(pod)
                srv.target_pods -= pods_to_remove

            self.services[srv.full_name()] = srv

    def delete_all_namespaces(self):
        if self.get_num_peers() > 0:  # Only delete namespaces if no peers are present
            return False
        self.namespaces.clear()
        return True

    def get_namespace(self, ns_name):
        """
        Get a K8sNamespace object for a given namespace name. If namespace is missing, then add it
        :param str ns_name: The name of the required namespace
        :return: A relevant K8sNamespace
        :rtype: K8sNamespace
        """
        if ns_name not in self.namespaces:
            print('Namespace', ns_name, 'is missing from the network configuration', file=stderr)
            namespace = K8sNamespace(ns_name)
            self.namespaces[ns_name] = namespace
        return self.namespaces[ns_name]

    def get_namespaces(self):
        return self.namespaces

    def _add_peer(self, peer):
        """
        Adds a specific peer to the container. Makes sure that no more than two isomorphic peers are added
        (we leave two isomorphic peers to model the connections between them)
        :param Endpoint peer: The peer to add
        :return: None
        """
        canonical_form = peer.canonical_form()
        peers_with_same_canonical_form = self.representative_peers.get(canonical_form, 0)
        if peers_with_same_canonical_form >= 2:  # We allow at most 2 peers from each equivalence group
            return
        self.representative_peers[canonical_form] = peers_with_same_canonical_form + 1
        self.peer_set.add(peer)

    def _add_pod_from_yaml(self, pod_object):
        """
        Add a K8s Pod to the container based on the given resource instance
        :param dict pod_object: The pod object to add
        :return: None
        """
        metadata = pod_object.get('metadata', {})
        pod_name = metadata.get('name', '')
        pod_namespace = self.get_namespace(metadata.get('namespace', 'default'))
        kind = pod_object.get('kind')

        owner_name = ''
        owner_kind = ''
        owner_references = metadata.get('ownerReferences', [])
        if owner_references:
            owner_name = owner_references[0].get('name', '')  # take the first owner
            owner_kind = owner_references[0].get('kind', '')

        service_account_name = ''
        if kind == 'Pod':
            # serviceAccountName for a Pod:
            service_account_name = pod_object['spec'].get('serviceAccountName', 'default')
        elif kind in PeerContainer.pod_creation_resources:
            # serviceAccountName for a Deployment:
            template_spec = pod_object['spec'].get('template', {}).get('spec', {})
            service_account_name = template_spec.get('serviceAccountName', 'default')

        pod = Pod(pod_name, pod_namespace, owner_name, owner_kind, service_account_name)
        labels = metadata.get('labels', {})
        for key, val in labels.items():
            pod.set_label(key, val)

        containers = pod_object['spec'].get('containers', {})
        for container in containers:
            for port in container.get('ports', {}):
                pod.add_named_port(port.get('name'), port.get('containerPort'), port.get('protocol', 'TCP'))
        self._add_peer(pod)

    def _add_wep_from_yaml(self, wep_object):
        """
        Add a Calico WorkloadEndpoint to the container based on the given resource instance
        :param dict wep_object: The wep object to add
        :return: None
        """
        metadata = wep_object.get('metadata', {})
        spec = wep_object.get('spec', {})
        wep_namespace = self.get_namespace(metadata.get('namespace', 'default'))
        wep_name = spec.get('pod', '')
        wep = Pod(wep_name, wep_namespace)
        # TODO: handle Pod's serviceAccountName: A wep definition includes a pod field which points to the
        #  corresponding k8s Pod resource.

        labels = metadata.get('labels', {})
        for key, val in labels.items():
            wep.set_label(key, val)

        for port in spec.get('ports', []):
            wep.add_named_port(port.get('name'), port.get('port'), port.get('protocol', 'TCP'))

        for profile in spec.get('profiles', []):
            wep.add_profile(profile)

        self._add_peer(wep)

    def _add_hep_from_yaml(self, hep_object):
        """
        Add a Calico HostEndpoint to the container based on the given resource instance
        :param dict hep_object: The hep object to add
        :return: None
        """
        metadata = hep_object.get('metadata', {})
        spec = hep_object.get('spec', {})
        hep_name = metadata.get('name', '')
        hep = HostEP(hep_name)

        labels = metadata.get('labels', {})
        for key, val in labels.items():
            hep.set_label(key, val)

        for port in spec.get('ports', []):
            hep.add_named_port(port.get('name'), port.get('port'), port.get('protocol', 'TCP'))

        for profile in spec.get('profiles', []):
            hep.add_profile(profile)

        self._add_peer(hep)

    def _add_networkset_from_yaml(self, networkset_object):
        """
        Add a Calico NetworkSet to the container based on the given resource instance
        :param dict networkset_object: The networkSet object to add
        :return: None
        """
        kind = networkset_object.get('kind')
        is_global = kind == 'GlobalNetworkSet'
        metadata = networkset_object.get('metadata', {})
        spec = networkset_object.get('spec', {})
        name = metadata.get('name', '')
        if name == '':
            print('NetworkSet must have a name', file=stderr)
            return
        if is_global:
            namespace = None
        else:
            namespace_name = metadata.get('namespace', 'default')
            namespace = self.get_namespace(namespace_name)
        ipb = IpBlock(name=name, namespace=namespace, is_global=is_global)
        labels = metadata.get('labels', {})
        if not labels:
            print(f'NetworkSet {name} should have labels', file=stderr)
        for key, val in labels.items():
            ipb.set_label(key, val)
        cidrs = spec.get('nets', {})
        for cidr in cidrs:
            ipb.add_cidr(cidr)
        self._add_peer(ipb)

    def _add_pod_from_workload_yaml(self, workload_resource):
        """
        Add K8s Pods to the container based on the given workload resource
        Reference: https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.20/#podtemplatespec-v1-core
        :param workload_resource: A workload resource object
        :return: None
        """
        metadata = workload_resource.get('metadata', {})
        workload_name = metadata.get('name', '')
        pod_namespace = self.get_namespace(metadata.get('namespace', 'default'))

        workload_spec = workload_resource.get('spec', {})
        replicas = workload_spec.get('replicas', 1)

        if workload_resource.get('kind') == 'Job':
            # Reference: https://kubernetes.io/docs/concepts/workloads/controllers/job/
            parallelism = workload_spec.get('parallelism', 1)
            if parallelism == 0:
                return  # paused job, no pods are generated
            replicas = parallelism
        if workload_resource.get('kind') == 'CronJob':
            workload_spec = workload_spec.get('jobTemplate', {}).get('spec', {})

        template_spec = workload_spec.get('template', {}).get('spec', {})
        service_account_name = template_spec.get('serviceAccountName', 'default')

        replicas = min(replicas, 2)  # We allow at most 2 peers from each equivalence group
        for pod_index in range(1, replicas + 1):
            pod = Pod(f'{workload_name}-{pod_index}', pod_namespace, workload_name, workload_resource.get('kind'),
                      service_account_name)
            pod_template = workload_spec.get('template', {})
            labels = pod_template.get('metadata', {}).get('labels', {})
            for key, val in labels.items():
                pod.set_label(key, val)
            pod_containers = pod_template.get('spec', {}).get('containers', [])
            for container in pod_containers:
                for port in container.get('ports', []):
                    pod.add_named_port(port.get('name'), port.get('containerPort'), port.get('protocol', 'TCP'))
            self._add_peer(pod)

    def add_eps_from_yaml(self, yaml_obj, kind_override=None):
        """
        Takes a yaml object (typically a dict or a list) and creates appropriate endpoints from it
        :param yaml_obj: A python object generated by yaml.load()
        :param kind_override: if set, ignoring the object kind and using this param instead
        :return: None
        """
        if not isinstance(yaml_obj, dict):
            try:
                for ep_sub_list in yaml_obj:  # e.g. when we have a list of lists - call recursively for each list
                    self.add_eps_from_yaml(ep_sub_list)
            except TypeError:
                pass
            return

        kind = yaml_obj.get('kind') if not kind_override else kind_override
        if kind in ['List', 'PodList', 'WorkloadEndpointList', 'HostEndpointList', 'NetworkSetList', 'GlobalNetworkSetList']:
            for endpoint in yaml_obj.get('items', []):
                self.add_eps_from_yaml(endpoint, kind[:-4])
        elif kind == 'Pod':
            self._add_pod_from_yaml(yaml_obj)
        elif kind in PeerContainer.pod_creation_resources:
            self._add_pod_from_workload_yaml(yaml_obj)
        elif kind == 'WorkloadEndpoint':
            self._add_wep_from_yaml(yaml_obj)
        elif kind == 'HostEndpoint':
            self._add_hep_from_yaml(yaml_obj)
        elif kind in ['NetworkSet', 'GlobalNetworkSet']:
            self._add_networkset_from_yaml(yaml_obj)

    def delete_all_peers(self):
        self.peer_set.clear()
        self.representative_peers.clear()
        return True

    def get_num_peers(self):
        return len(self.peer_set)

    def get_num_namespaces(self):
        return len(self.namespaces)

    def clear_pods_extra_labels(self):
        for peer in self.peer_set:
            peer.clear_extra_labels()

    def get_peers_with_label(self, key, values, action=GenericYamlParser.FilterActionType.In, namespace=None):
        """
        Return all peers that have a specific key-value label (in a specific namespace)
        :param str key: The relevant key
        :param list[str] values: A list of possible values to match
        :param FilterActionType action: how to filter the values
        :param K8sNamespace namespace: If not None, only consider peers in this namespace
        :return PeerSet: All peers that (do not) have the key-value as their label
        """
        res = PeerSet()
        for peer in self.peer_set:
            # Note: It seems as if the semantics of NotIn is "either key does not exist, or its value is not in values"
            # Reference: https://kubernetes.io/docs/concepts/overview/working-with-objects/labels/
            if namespace is not None and peer.namespace != namespace:
                continue
            if action == GenericYamlParser.FilterActionType.In:
                if peer.labels.get(key) in values or peer.extra_labels.get(key) in values:
                    res.add(peer)
            elif action == GenericYamlParser.FilterActionType.NotIn:
                if peer.labels.get(key) not in values and peer.extra_labels.get(key) not in values:
                    res.add(peer)
            elif action == GenericYamlParser.FilterActionType.Contain:
                if values[0] in peer.labels.get(key, '') or values[0] in peer.extra_labels.get(key, ''):
                    res.add(peer)
            elif action == GenericYamlParser.FilterActionType.StartWith:
                if peer.labels.get(key, '').startswith(values[0]) or peer.extra_labels.get(key, '').startswith(
                        values[0]):
                    res.add(peer)
            elif action == GenericYamlParser.FilterActionType.EndWith:
                if peer.labels.get(key, '').endswith(values[0]) or peer.extra_labels.get(key, '').endswith(values[0]):
                    res.add(peer)
        return res

    def get_peers_with_key(self, namespace, key, does_not_exist):
        """
        Return all peers (possibly in a given namespace) that have a specific key in their labels
        :param K8sNamespace namespace: If not none - only include peers in this namespace
        :param str key: The relevant key
        :param bool does_not_exist: Whether to only include peers that do not have this key
        :return PeerSet: All peers that (do not) have the key
        """
        res = PeerSet()
        for peer in self.peer_set:
            if namespace is not None and peer.namespace != namespace:
                continue
            if (key in peer.labels or key in peer.extra_labels) ^ does_not_exist:
                res.add(peer)
        return res

    def get_namespace_pods_with_label(self, key, values, action=GenericYamlParser.FilterActionType.In):
        """
        Return all pods in namespace with a given key-value label
        :param str key: The relevant key
        :param list[str] values: possible values for the key
        :param FilterActionType action: how to filter the values
        :return PeerSet: All pods in namespaces that have (or not) the given key-value label
        """
        res = PeerSet()
        for peer in self.peer_set:
            if peer.namespace is None:
                continue
            # Note: It seems as if the semantics of NotIn is "either key does not exist, or its value is not in values"
            # Reference: https://kubernetes.io/docs/concepts/overview/working-with-objects/labels/
            if action == GenericYamlParser.FilterActionType.In:
                if peer.namespace.labels.get(key, '') in values:
                    res.add(peer)
            elif action == GenericYamlParser.FilterActionType.NotIn:
                if peer.namespace.labels.get(key, '') not in values:
                    res.add(peer)
            elif action == GenericYamlParser.FilterActionType.Contain:
                if values[0] in peer.namespace.labels.get(key, ''):
                    res.add(peer)
            elif action == GenericYamlParser.FilterActionType.StartWith:
                if peer.namespace.labels.get(key, '').startswith(values[0]):
                    res.add(peer)
            elif action == GenericYamlParser.FilterActionType.EndWith:
                if peer.namespace.labels.get(key, '').endswith(values[0]):
                    res.add(peer)
        return res

    def get_namespace_pods_with_key(self, key, does_not_exist):
        """
        Return all pods in namespaces that have a given key
        :param str key: The relevant key
        :param bool does_not_exist: whether to check for the inexistence of this key
        :return PeerSet: All pods in namespace with (or without) the given key
        """
        res = PeerSet()
        for peer in self.peer_set:
            if peer.namespace is None:
                continue
            if (key in peer.namespace.labels) ^ does_not_exist:
                res.add(peer)
        return res

    def get_namespace_pods(self, namespace):
        """
        Return all pods that are in a given namespace
        :param K8sNamespace namespace: The target namespace
        :return PeerSet: All pods in the namespace
        """
        if namespace is None:
            return self.get_all_peers_group()
        res = PeerSet()
        for peer in self.peer_set:
            if peer.namespace == namespace:
                res.add(peer)
        return res

    def get_pods_with_service_account_name(self, sa_name, namespace_str):
        """
        Return all pods that are with a service account name in a given namespace
        :param sa_name: string  the service account name
        :param namespace_str:  string  the namespace str
        :rtype PeerSet
        """
        res = PeerSet()
        for peer in self.peer_set:
            if isinstance(peer, Pod) and peer.service_account_name == sa_name and peer.namespace.name == namespace_str:
                res.add(peer)
        return res

    def get_profile_pods(self, profile_name, first_profile_only):
        """
        Return all the pods that have a specific profile assigned
        :param str profile_name: The name of the target profile
        :param bool first_profile_only: whether to only consider the first profile of each pod
        :return PeerSet: The set of pods with the given profile
        """
        res = PeerSet()
        for peer in self.peer_set:
            if peer.has_profiles():
                if first_profile_only:
                    if peer.get_first_profile_name() == profile_name:
                        res.add(peer)
                else:
                    if profile_name in peer.profiles:
                        res.add(peer)
        return res

    def get_all_peers_group(self, add_external_ips=False, include_globals=True):
        """
        Return all peers known in the system
        :param bool add_external_ips: Whether to also add the full range of ips
        :param bool include_globals: Whether to include global peers
        :return PeerSet: The required set of peers
        """
        res = PeerSet()
        for peer in self.peer_set:
            if include_globals or not peer.is_global_peer():
                res.add(peer)
        if add_external_ips:
            res.add(IpBlock.get_all_ips_block())
        return res

    def get_all_global_peers(self):
        """
        Return all global peers known in the system
        :return PeerSet: The required set of peers
        """
        res = PeerSet()
        for peer in self.peer_set:
            if peer.is_global_peer():
                res.add(peer)
        return res

    def get_all_namespaces_str_list(self):
        return list(self.namespaces.keys())
