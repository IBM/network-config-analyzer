#
# Copyright 2020- IBM Inc. All rights reserved
# SPDX-License-Identifier: Apache2.0
#

from fnmatch import fnmatch
import os
from sys import stderr
from pathlib import Path
import yaml
from Peer import PeerSet, Pod, IpBlock, HostEP
from K8sNamespace import K8sNamespace
from CmdlineRunner import CmdlineRunner
from GitScanner import GitScanner


class PeerContainer:
    """
    This class holds a representation of the network topology: the set of eps and how they are partitioned to namespaces
    It also provides various services to build the topology from files and to filter the eps by labels and by namespaces
    """
    def __init__(self, ns_resources=None, peer_resources=None, config_name='global'):
        self.peer_set = PeerSet()
        self.namespaces = {}  # mapping from namespace name to the actual K8sNamespace object
        self.representative_peers = {}
        if ns_resources:
            self._set_namespace_list(ns_resources)
        if peer_resources:
            self._set_peer_list(peer_resources, config_name)

    def __eq__(self, other):
        if isinstance(other, PeerContainer):
            return self.peer_set == other.peer_set and self.namespaces == other.namespaces
        return NotImplemented

    @staticmethod
    def locate_kube_config_file():
        """
        Locates the kubectl configuration file and stores it in the environment variable KUBECONFIG
        :return:  None
        """
        default_location = os.path.expanduser(os.environ.get('KUBECONFIG', '~/.kube/config'))
        if os.path.exists(default_location):
            os.environ['KUBECONFIG'] = default_location
            return

        home_dir = os.path.expanduser('~/.kube')
        for file in os.listdir(home_dir):
            if fnmatch(file, 'kube-config*.yml'):
                kube_config_file = os.path.join(home_dir, file)
                os.environ['KUBECONFIG'] = kube_config_file
                return
        raise Exception('Failed to locate Kubernetes configuration files')

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

    def _set_namespace_list(self, ns_resources):
        """
        Populates the set of namespaces in the container from one of the following resources:
         - git path of yaml file or a directory with yamls
         - local file (yaml or json) or a local directory containing yamls
         - query of the cluster
        :param str ns_resources: The namespace resource to be used. If set to 'k8s', will query cluster using kubectl
        :return: None
        """
        # load from git
        if ns_resources.startswith('https://github'):
            self._set_namespace_list_from_github(ns_resources)

        # load from local file
        elif os.path.isfile(ns_resources):
            with open(ns_resources) as yaml_file:
                code = yaml.load_all(yaml_file, Loader=yaml.SafeLoader)
                for ns_code in code:
                    if isinstance(ns_code, dict) and ns_code.get('kind') in {'NamespaceList', 'List'}:
                        self.set_namespaces(ns_code)

        # load from local directory
        elif os.path.isdir(ns_resources):
            for path in Path(ns_resources).glob('**/*.yaml'):
                with open(path) as yaml_file:
                    code = yaml.load_all(yaml_file, Loader=yaml.SafeLoader)
                    for ns_code in code:
                        if isinstance(ns_code, dict) and ns_code.get('kind') in {'NamespaceList', 'List'}:
                            self.set_namespaces(ns_code)

        # load from live cluster
        elif not ns_resources or ns_resources == 'k8s':
            self.locate_kube_config_file()
            yaml_file = CmdlineRunner.get_k8s_resources('namespace')
            ns_code = yaml.load(yaml_file, Loader=yaml.SafeLoader)
            self.set_namespaces(ns_code)

    def _set_peer_list(self, peer_resources, config_name):
        """
        Populates the set of peers in the container from one of the following resources:
         - git path of yaml file or a directory with yamls
         - local file (yaml or json) or a local directory containing yamls
         - query of the cluster
        :param str peer_resources: peer resource to use. If set to 'k8s'/'calico'  query cluster using kubectl/calicoctl
        :param srt config_name: The config name
        :return: None
        """
        # load from git
        if peer_resources.startswith('https://github'):
            self._set_peer_list_from_github(peer_resources)

        # load from local file
        elif os.path.isfile(peer_resources):
            with open(peer_resources) as yaml_file:
                code = yaml.load_all(yaml_file, Loader=yaml.SafeLoader)
                for peer_code in code:
                    if isinstance(peer_code, dict):
                        self.add_eps_from_list(peer_code)
                    elif isinstance(peer_code, list):
                        for ep_list in peer_code:
                            self.add_eps_from_list(ep_list)

        # load from local directory
        elif os.path.isdir(peer_resources):
            for path in Path(peer_resources).glob('**/*.yaml'):
                with open(path) as yaml_file:
                    code = yaml.load_all(yaml_file, Loader=yaml.SafeLoader)
                    for peer_code in code:
                        self.add_eps_from_list(peer_code)

        # load from live cluster
        elif peer_resources == 'calico':
            for peer_type in ['wep', 'hep', 'networkset', 'globalnetworkset']:
                peer_code = yaml.load(CmdlineRunner.get_calico_resources(peer_type), Loader=yaml.SafeLoader)
                self.add_eps_from_list(peer_code)
        elif not peer_resources or peer_resources == 'k8s':
            self.locate_kube_config_file()
            peer_code = yaml.load(CmdlineRunner.get_k8s_resources('pod'), Loader=yaml.SafeLoader)
            self.add_eps_from_list(peer_code)

        print(f'{config_name}: cluster has {self.get_num_peers()} unique endpoints, '
              f'{self.get_num_namespaces()} namespaces')

    def _set_namespace_list_from_github(self, url):
        """
        Extracting the set of namespaces from a git repo
        :param str url: a path to a yaml file or a directory in git
        :return: None
        """
        yaml_files = GitScanner(url).get_yamls_in_repo()
        for yaml_file in yaml_files:
            for resource in yaml_file.data:
                if isinstance(resource, dict) and resource.get('kind') in {'List', 'NamespaceList'}:
                    self.set_namespaces(resource)

    def _set_peer_list_from_github(self, url):
        """
        Extracting the set of pods from a git repo
        :param str url: a path to a yaml file or a directory in git
        :return: None
        """
        yaml_files = GitScanner(url).get_yamls_in_repo()
        for yaml_file in yaml_files:
            for resource in yaml_file.data:
                if isinstance(resource, dict):
                    kind = resource.get('kind')
                    if kind == 'PodList':
                        self.add_eps_from_list(resource)
                    if kind in ['Deployment', 'ReplicaSet', 'StatefulSet', 'DaemonSet',
                                'Job', 'CronJob', 'ReplicationController']:
                        self._add_pod_from_workload_yaml(resource)

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

        owner_name = ''
        owner_kind = ''
        owner_references = metadata.get('ownerReferences', [])
        if owner_references:
            owner_name = owner_references[0].get('name', '')  # take the first owner
            owner_kind = owner_references[0].get('kind', '')

        pod = Pod(pod_name, pod_namespace, owner_name, owner_kind)
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
        replicas = min(replicas, 2)  # We allow at most 2 peers from each equivalence group

        for pod_index in range(1, replicas+1):
            pod = Pod(f'{workload_name}-{pod_index}', pod_namespace, workload_name, workload_resource.get('kind'))
            pod_template = workload_spec.get('template', {})
            labels = pod_template.get('metadata', {}).get('labels', {})
            for key, val in labels.items():
                pod.set_label(key, val)

            pod_containers = pod_template.get('spec', {}).get('containers', [])
            for container in pod_containers:
                for port in container.get('ports', []):
                    pod.add_named_port(port.get('name'), port.get('containerPort'), port.get('protocol', 'TCP'))

            self._add_peer(pod)

    def add_eps_from_list(self, ep_list):
        """
        Takes a resource-list object and adds all endpoints in the list to the container
        :param ep_list: A resource list object
        :return: None
        """
        if not ep_list:
            return

        if not isinstance(ep_list, dict):
            for ep_sub_list in ep_list:  # we must have a list of lists here - call recursively for each list
                self.add_eps_from_list(ep_sub_list)
            return

        kind = ep_list.get('kind')
        if kind in ['PodList', 'List']:  # 'List' for the case of live cluster
            for endpoint in ep_list.get('items', []):
                self._add_pod_from_yaml(endpoint)
        elif kind in ['Deployment', 'ReplicaSet', 'StatefulSet', 'DaemonSet', 'Job', 'CronJob',
                      'ReplicationController']:
            self._add_pod_from_workload_yaml(ep_list)
        elif kind in ['WorkloadEndpointList', 'HostEndpointList']:
            is_calico_wep = kind == 'WorkloadEndpointList'
            is_calico_hep = kind == 'HostEndpointList'
            for endpoint in ep_list.get('items', []):
                if is_calico_wep:
                    self._add_wep_from_yaml(endpoint)
                elif is_calico_hep:
                    self._add_hep_from_yaml(endpoint)
        elif kind in ['NetworkSetList', 'GlobalNetworkSetList']:
            for networkset in ep_list.get('items', []):
                self._add_networkset_from_yaml(networkset)
        elif kind in ['NetworkSet', 'GlobalNetworkSet']:
            self._add_networkset_from_yaml(ep_list)
        else:
            print(kind, ' is not supported ', file=stderr)

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

    def get_peers_with_label(self, key, values, not_in=False, namespace=None):
        """
        Return all peers that have a specific key-value label (in a specific namespace)
        :param str key: The relevant key
        :param list[str] values: A list of possible values to match
        :param bool not_in: If True, reverse logic - exclude peers with the given values
        :param K8sNamespace namespace: If not None, only consider peers in this namespace
        :return PeerSet: All peers that (do not) have the key-value as their label
        """
        res = PeerSet()
        for peer in self.peer_set:
            # Note: It seems as if the semantics of NotIn is "either key does not exist, or its value is not in values"
            # Reference: https://kubernetes.io/docs/concepts/overview/working-with-objects/labels/
            if namespace is not None and peer.namespace != namespace:
                continue
            if (peer.labels.get(key) in values or peer.extra_labels.get(key) in values) ^ not_in:
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

    def get_namespace_pods_with_label(self, key, values, not_in=False):
        """
        Return all pods in namespace with a given key-value label
        :param str key: The relevant key
        :param list[str] values: possible values for the key
        :param bool not_in: whether to exclude the given values
        :return PeerSet: All pods in namespaces that have (or not) the given key-value label
        """
        res = PeerSet()
        for peer in self.peer_set:
            if peer.namespace is None:
                continue
            # Note: It seems as if the semantics of NotIn is "either key does not exist, or its value is not in values"
            # Reference: https://kubernetes.io/docs/concepts/overview/working-with-objects/labels/
            if (key in peer.namespace.labels and peer.namespace.labels[key] in values) ^ not_in:
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
