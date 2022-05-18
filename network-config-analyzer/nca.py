#
# Copyright 2020- IBM Inc. All rights reserved
# SPDX-License-Identifier: Apache2.0
#

import argparse
import sys
import time
import os
from SchemeRunner import SchemeRunner
from RESTServer import RestServer
from OutputConfiguration import OutputConfiguration
from NetworkConfig import NetworkConfig
from NetworkConfigQueryRunner import NetworkConfigQueryRunner
from ResourcesHandler import ResourcesHandler


def _valid_path(path_location, allow_ghe=False, allowed_platforms=None):
    """
    A validator for paths in the command line, raising an exception if the path is invalid
    :param str path_location: The path to validate
    :param bool allow_ghe: Whether to allow url to github
    :param list allowed_platforms: list of allowed platforms, sublist of ['k8s', 'calico', 'istio']
    :return: The argument path_location
    :rtype: str
    :raises: argparse.ArgumentTypeError when path is invalid
    """
    if allow_ghe and path_location.startswith(('https://github', 'https://raw.githubusercontent')):
        return path_location
    if allowed_platforms and path_location in allowed_platforms:
        return path_location
    if not os.path.exists(path_location):
        raise argparse.ArgumentTypeError(path_location + ' is not a valid path')
    return path_location


def _network_policies_valid_path(path_location):
    """
    validation for paths of Network policies in the command line
    """
    if not path_location:  # when empty, expecting policies from resources list
        return path_location
    return _valid_path(path_location, allow_ghe=True, allowed_platforms=['k8s', 'calico', 'istio'])


def _pod_list_valid_path(path_location):
    """
    validation for paths of pod lists in the command line
    """
    return _valid_path(path_location, allow_ghe=True, allowed_platforms=['k8s', 'calico'])


def _namespace_list_valid_path(path_location):
    """
    validation for paths of namespaces list in the command line
    """
    return _valid_path(path_location, allow_ghe=True, allowed_platforms=['k8s'])


def _resource_list_valid_path(path_location):
    """
    validation for paths of resources list in the command line
    """
    return _valid_path(path_location, allow_ghe=True, allowed_platforms=['k8s', 'calico', 'istio'])


def _do_every(period, func, *args):
    def _g_tick():
        start_time = time.time()
        count = 0
        while True:
            count += 1
            yield max(start_time + count * period - time.time(), 0)

    sleep_for = _g_tick()
    while True:
        func(*args)
        time.sleep(next(sleep_for))


def _execute_single_config_query(query_name, network_config, output_config, expected_output=None):
    """
    Runs a query on single set of policies
    :param str query_name: the name of the arg.query
    :param NetworkConfig network_config : the network configuration
    :param OutputConfiguration output_config: dict object
    :param str expected_output: a file path to the expected output
    :rtype: int
    """
    res, comparing_err = NetworkConfigQueryRunner(query_name, [network_config], expected_output,
                                                  output_config).run_query()
    expected_res_bit = res > 0
    return 2 * comparing_err + expected_res_bit


def _execute_pair_configs_query(query_name, configs_array, output_config, expected_output=None):
    """
    Runs a query between two network configs
    :param str query_name: the name of the arg.query
    :param list configs_array : the array of the two network configs
    :param OutputConfiguration output_config: dict object
    :param str expected_output: a file path to the expected output
    :return: result of executing the query
    :rtype: int
    """
    res, comparing_err = NetworkConfigQueryRunner(query_name, configs_array, expected_output,
                                                  output_config).run_query(True)
    return 2 * comparing_err + res


def run_args(args):
    """
    Given the parsed cmdline, decide what to run
    :param Namespace args: argparse-style parsed cmdline
    :return: The number of queries with unexpected value (if a scheme file is used) or
             the query result (if command-line queries are used)
    :rtype: int
    """
    if args.scheme:
        return SchemeRunner(args.scheme, args.output_format, args.file_out).run_scheme()
    ns_list = args.ns_list
    pod_list = args.pod_list
    resource_list = args.resource_list

    output_config = OutputConfiguration({'outputFormat': args.output_format or 'txt',
                                         'outputPath': args.file_out or None,
                                         'prURL': args.pr_url or None,
                                         'outputEndpoints': args.output_endpoints})
    expected_output = None
    # default values are for sanity query
    # np_list will be taken as args.<query_name> if it is not equal to the args parser's const value i.e ['']
    np_list = args.sanity if args.sanity != [''] else None
    pair_query_flag = False
    query_name = 'sanity'
    base_as_second = False

    if args.equiv is not None:
        np_list = args.equiv if args.equiv != [''] else None
        query_name = 'twoWayContainment'
        pair_query_flag = True
        base_as_second = True

    if args.interferes is not None:
        np_list = args.interferes if args.interferes != [''] else None
        query_name = 'interferes'
        pair_query_flag = True
        base_as_second = True

    if args.forbids is not None:
        np_list = args.forbids if args.forbids != [''] else None
        query_name = 'forbids'
        pair_query_flag = True

    if args.permits is not None:
        np_list = args.permits if args.permits != [''] else None
        query_name = 'permits'
        pair_query_flag = True

    if args.connectivity is not None:
        np_list = args.connectivity if args.connectivity != [''] else None
        query_name = 'connectivityMap'
        pair_query_flag = False
        expected_output = args.expected_output or None

    if args.semantic_diff is not None:
        np_list = args.semantic_diff if args.semantic_diff != [''] else None
        query_name = 'semanticDiff'
        pair_query_flag = True
        expected_output = args.expected_output or None

    resources_handler = ResourcesHandler()
    network_config = resources_handler.get_network_config(np_list, ns_list, pod_list, resource_list,
                                                          save_flag=pair_query_flag)
    if pair_query_flag:
        base_np_list = args.base_np_list
        base_resource_list = args.base_resource_list
        base_ns_list = args.base_ns_list
        base_pod_list = args.base_pod_list
        base_network_config = resources_handler.get_network_config(base_np_list, base_ns_list, base_pod_list,
                                                                   base_resource_list)
        if base_as_second:
            network_configs_array = [network_config, base_network_config]
        else:
            network_configs_array = [base_network_config, network_config]
        return _execute_pair_configs_query(query_name, network_configs_array,
                                           output_config, expected_output)

    return _execute_single_config_query(query_name, network_config, output_config, expected_output)


def nca_main(argv=None):
    """
    This is the single entry point for NCA
    :param list[str] argv: command-line arguments (None means using sys.argv)
    :return: The number of queries with unexpected value (if a scheme file is used) or
             the query result (if command-line queries are used)
    :rtype: int
    """
    os.environ['PATH'] = '.' + os.pathsep + os.environ.get('PATH', '.')  # for running kubectl and calicoctl

    parser = argparse.ArgumentParser(description='An analyzer for network connectivity configuration')
    parser.add_argument('--period', type=int,
                        help='Run NCA with specified arguments every specified number of minutes', default=0)
    manual_or_automatic = parser.add_mutually_exclusive_group(required=False)
    manual_or_automatic.add_argument('--scheme', '-s', type=_valid_path,
                                     help='A YAML scheme file, describing verification goals')
    manual_or_automatic.add_argument('--sanity', nargs='?', const='', type=_network_policies_valid_path,
                                     action='append',
                                     help='Network policies (file/dir/GHE url/cluster-type) for sanity checking')
    manual_or_automatic.add_argument('--connectivity', type=_network_policies_valid_path, nargs='?', const='',
                                     action='append',
                                     help='Network policies (file/dir/GHE url/cluster-type) for connectivity map')
    manual_or_automatic.add_argument('--semantic_diff', type=_network_policies_valid_path, nargs='?', const='',
                                     action='append',
                                     help='Network policies (file/dir/GHE url/cluster-type) for semantic-diff')
    manual_or_automatic.add_argument('--equiv', type=_network_policies_valid_path, nargs='?', const='',
                                     action='append',
                                     help='Network policies (file/dir/GHE url/cluster-type) for equivalence checking')
    manual_or_automatic.add_argument('--interferes', type=_network_policies_valid_path, nargs='?', const='',
                                     action='append',
                                     help='Network policies (policy name/file/dir/GHE url/cluster-type) '
                                          'for interference checking')
    manual_or_automatic.add_argument('--forbids', type=_network_policies_valid_path, nargs='?', const='',
                                     action='append',
                                     help='Network policies (policy name/file/dir/GHE url/cluster-type) '
                                          'specifying forbidden connections')
    manual_or_automatic.add_argument('--permits', type=_network_policies_valid_path, nargs='?', const='',
                                     action='append',
                                     help='Network policies (policy name/file/dir/GHE url/cluster-type) '
                                          'specifying permitted connections')
    manual_or_automatic.add_argument('--daemon', action='store_true', help='Run NCA as a daemon with REST API')
    parser.add_argument('--base_np_list', '-b', type=_network_policies_valid_path, action='append',
                        help='Filesystem or GHE location of base network policies '
                             'for equiv/interferes/forbids/permits/semantic_diff check (default: k8s cluster)')
    parser.add_argument('--base_resource_list', '-rb', type=_resource_list_valid_path, action='append',
                        help='Network policies entries or Filesystem or GHE location of base network resources ')
    parser.add_argument('--base_pod_list', '-pb', type=_pod_list_valid_path, action='append',
                        help='A file/GHE url/cluster-type to read old pod list from. Used for semantic_diff '
                             '(may be specified multiple times)')
    parser.add_argument('--base_ns_list', '-nb', type=_namespace_list_valid_path, action='append',
                        help='A file/GHE url/cluster-type to read old namespace list from. Used for semantic_diff '
                             '(may be used multiple times)')
    parser.add_argument('--ns_list', '-n', type=_namespace_list_valid_path, action='append',
                        help='A file/GHE url/cluster-type to read namespace list from '
                             '(may be specified multiple times)')
    parser.add_argument('--pod_list', '-p', type=_pod_list_valid_path, action='append',
                        help='A file/GHE url/cluster-type to read pod list from (may be specified multiple times)')
    parser.add_argument('--resource_list', '-r', type=_resource_list_valid_path, action='append',
                        help='Network policies entries or Filesystem or GHE location of base network resources ')
    parser.add_argument('--ghe_token', '--gh_token', type=str, help='A valid token to access a GitHub repository')
    parser.add_argument('--output_format', '-o', type=str,
                        help='Output format specification (txt, csv, md, dot or yaml). The default is txt.')
    parser.add_argument('--file_out', '-f', type=str, help='A file path to which output is redirected')
    parser.add_argument('--expected_output', type=str, help='A file path of the expected query output,'
                                                            'relevant only with --connectivity and --semantic_diff')
    parser.add_argument('--pr_url', type=str, help='The full api url for adding a PR comment')
    parser.add_argument('--return_0', action='store_true', help='Force a return value 0')
    parser.add_argument('--output_endpoints', choices=['pods', 'deployments'],
                        help='Choose endpoints type in output (pods/deployments)', default='deployments')

    args = parser.parse_args(argv)

    if args.ghe_token:
        os.environ['GHE_TOKEN'] = args.ghe_token

    if args.daemon:
        return RestServer(args.ns_list, args.pod_list, args.resource_list).run()

    if args.period <= 0:
        ret_val = run_args(args)
        return 0 if args.return_0 else ret_val

    _do_every(args.period * 60, run_args, args)
    return 0


if __name__ == "__main__":
    sys.exit(nca_main())
