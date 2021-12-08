#
# Copyright 2020- IBM Inc. All rights reserved
# SPDX-License-Identifier: Apache2.0
#

import sys

from OutputConfiguration import OutputConfiguration
from PeerContainer import PeerContainer
from NetworkConfig import NetworkConfig
from NetworkConfigQueryRunner import NetworkConfigQueryRunner


class CLExecute:
    """
    A class for running queries from commandline
    """
    def __init__(self, base_ns_list=None, base_pod_list=None, ns_list=None, pod_list=None, output_format='txt', output_path=None, pr_url=None):
        self.base_peer_container = PeerContainer(base_ns_list, base_pod_list)
        self.peer_container = PeerContainer(ns_list, pod_list)
        self.output_config = OutputConfiguration({'outputFormat': output_format, 'outputPath': output_path,
                                                  'prURL': pr_url})

    def execute_single_config_query(self, query_name, np1_list):
        """
        Runs a query on single set of policies
        :param str query_name: the name of the arg.query
        :param str np1_list: set of policies
        :rtype: int
        """
        network_config1 = NetworkConfig(np1_list, self.peer_container, [np1_list])
        return NetworkConfigQueryRunner(query_name, [network_config1], self.output_config).run_query() > 0

    def execute_pair_configs_query(self, query_name, np1_list_location, np2_list_location):
        """
        Runs an pair configs query between two sets of policies
        :param str query_name: the name of the arg.query
        :param str np1_list_location: First set of policies
        :param str np2_list_location:  Second set of policies
        :return: result of executing the query
        :rtype: int
        """
        peer_container1 = self.peer_container if query_name != 'semanticDiff' else self.base_peer_container
        network_config1 = NetworkConfig(np1_list_location, peer_container1, [np1_list_location])
        network_config2 = NetworkConfig(np2_list_location, self.peer_container, [np2_list_location])
        if query_name in {'permits', 'forbids'} and not network_config2:
            print(f'\nThere are no NetworkPolicies in {np1_list_location}. No traffic is specified for {query_name}.\n')
            sys.exit(1)
        return NetworkConfigQueryRunner(query_name, [network_config1, network_config2], self.output_config).run_query(True)
