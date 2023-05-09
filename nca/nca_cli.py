#
# Copyright 2020- IBM Inc. All rights reserved
# SPDX-License-Identifier: Apache2.0
#

import argparse
import time
import os
import sys
import traceback
from sys import stderr
from pathlib import Path
from nca.CoreDS.Peer import BasePeerSet
from nca.Utils.OutputConfiguration import OutputConfiguration
from nca.NetworkConfig.NetworkConfigQueryRunner import NetworkConfigQueryRunner
from nca.NetworkConfig.ResourcesHandler import ResourcesHandler
from nca.SchemeRunner import SchemeRunner
from nca.Utils.ExplTracker import ExplTracker


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
    res, comparing_err, query_not_executed = NetworkConfigQueryRunner(query_name, [network_config], expected_output,
                                                                      output_config).run_query()
    expected_res_bit = res > 0
    return _compute_return_value(expected_res_bit, comparing_err, query_not_executed)


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
    res, comparing_err, query_not_executed = NetworkConfigQueryRunner(query_name, configs_array, expected_output,
                                                                      output_config).run_query(True)
    return _compute_return_value(res, comparing_err, query_not_executed)


def _compute_return_value(query_result, comparing_err, not_executed):
    """
    return the exit code of running the query combined of :
    - query result (first bit of the result)
    - comparing error flag (second bit)
    - query not-executed flag (third bit)
    """
    return 4 * not_executed + 2 * comparing_err + query_result


def _make_recursive(path_list):
    """
    when a directory is given (from the CLI), add '**' so subdirectories will also be scanned.
    :param list path_list: list of paths
    :return: list: the given list of paths with '**' at the end of dir paths
    """
    if path_list:
        for index, path in enumerate(path_list):
            if os.path.isdir(path):
                path_list[index] = str(path) + '**'
    return path_list


def run_args(args):
    """
    Given the parsed cmdline, decide what to run
    :param Namespace args: argparse-style parsed cmdline
    :return: The number of queries with unexpected value (if a scheme file is used) or
             the query result (if command-line queries are used)
    :rtype: int
    """
    # reset the singleton before running a new shceme or cli query
    # so that configs from certain run do not affect a potential following run.
    BasePeerSet.reset()
    if args.scheme:
        return SchemeRunner(args.scheme, args.output_format, args.file_out, args.optimized_run).run_scheme()
    ns_list = args.ns_list
    pod_list = args.pod_list
    resource_list = args.resource_list

    output_config = OutputConfiguration({'outputFormat': args.output_format or 'txt',
                                         'outputPath': args.file_out or None,
                                         'prURL': args.pr_url or None,
                                         'outputEndpoints': args.output_endpoints,
                                         'subset': {},
                                         'explain': [],
                                         'excludeIPv6Range': not args.print_ipv6})
    expected_output = None
    # default values are for sanity query
    # np_list will be taken as args.<query_name> if it is not equal to the args parser's const value i.e ['']
    np_list = args.sanity if args.sanity != [''] else None
    pair_query_flag = False
    query_name = 'sanity'
    base_as_second = False

    if args.deployment_subset is not None:
        output_config['subset'].update({'deployment_subset': args.deployment_subset})

    if args.namespace_subset is not None:
        output_config['subset'].update({'namespace_subset': args.namespace_subset})

    if args.label_subset is not None:
        # labels are stored in a dict. Here they are deserialized from string
        all_labels = []
        for label_subset in args.label_subset:
            lbl_list = str(label_subset).split(',')
            lbl_dict = {}
            for lbl in lbl_list:
                key, value = lbl.split(':')
                lbl_dict[key] = value
            all_labels.append(lbl_dict)
        output_config['subset'].update({'label_subset': all_labels})

    if args.explain is not None:
        output_config['explain'] = args.explain
        ExplTracker(output_config.outputEndpoints).activate()

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
    network_config = resources_handler.get_network_config(_make_recursive(np_list), _make_recursive(ns_list),
                                                          _make_recursive(pod_list), _make_recursive(resource_list),
                                                          save_flag=pair_query_flag, optimized_run=args.optimized_run)
    if pair_query_flag:
        base_np_list = args.base_np_list
        base_resource_list = args.base_resource_list
        base_ns_list = args.base_ns_list
        base_pod_list = args.base_pod_list
        base_network_config = resources_handler.get_network_config(_make_recursive(base_np_list),
                                                                   _make_recursive(base_ns_list),
                                                                   _make_recursive(base_pod_list),
                                                                   _make_recursive(base_resource_list),
                                                                   optimized_run=args.optimized_run)
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
    parser.add_argument('--explain', '-expl', type=str,
                        help='A node or 2 nodes (a connection), to explain the configurations affecting them')
    parser.add_argument('--deployment_subset', '-ds', type=str,
                        help='A list of deployment names to subset the query by')
    parser.add_argument('--namespace_subset', '-nss', type=str,
                        help='A list of namespaces to subset the query by')
    parser.add_argument('--label_subset', '-lss', type=str, action='append',
                        help='A list of labels to subset the query by')
    parser.add_argument('--ghe_token', '--gh_token', type=str, help='A valid token to access a GitHub repository')
    parser.add_argument('--output_format', '-o', type=str,
                        help='Output format specification (txt, txt_no_fw_rules, csv, md, dot, jpg or yaml). '
                             'The default is txt.')
    parser.add_argument('--file_out', '-f', type=str, help='A file path to which output is redirected')
    parser.add_argument('--expected_output', type=str, help='A file path of the expected query output,'
                                                            'relevant only with --connectivity and --semantic_diff')
    parser.add_argument('--pr_url', type=str, help='The full api url for adding a PR comment')
    parser.add_argument('--return_0', action='store_true', help='Force a return value 0')
    parser.add_argument('--version', '-v', action='store_true', help='Print version and exit')
    parser.add_argument('--debug', '-d', action='store_true', help='Print debug information')
    parser.add_argument('--output_endpoints', choices=['pods', 'deployments'],
                        help='Choose endpoints type in output (pods/deployments)', default='deployments')
    parser.add_argument('--optimized_run', '-opt', type=str,
                        help='Whether to run optimized run (-opt=true), original run (-opt=false) - the default '
                             'or the comparison of the both (debug)', default='false')
    parser.add_argument('--print_ipv6', action='store_true', help='Display IPv6 addresses connections too. '
                                                                  'If the policy reference IPv6 addresses, '
                                                                  'their connections will be printed anyway')

    args = parser.parse_args(argv)

    if args.version:
        version_file_path = Path(__file__).parent.resolve() / 'VERSION.txt'
        with open(version_file_path) as version_file:
            print(f'NCA version {version_file.readline()}')
        return 0

    if args.ghe_token:
        os.environ['GHE_TOKEN'] = args.ghe_token

    try:
        if args.period <= 0:
            ret_val = run_args(args)
            return 0 if args.return_0 else ret_val

        _do_every(args.period * 60, run_args, args)
    except Exception as e:
        print(f'Error: {e}', file=stderr)
        if args.debug:
            print(traceback.format_exc(), file=stderr)
        return 0 if args.return_0 else 7
    return 0


if __name__ == "__main__":
    sys.exit(nca_main())
