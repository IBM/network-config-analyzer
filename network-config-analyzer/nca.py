#
# Copyright 2020- IBM Inc. All rights reserved
# SPDX-License-Identifier: Apache2.0
#

import argparse
import sys
import time
import os
from SchemeRunner import SchemeRunner
from CLExecute import CLExecute
from RESTServer import RestServer


def _valid_path(path_location, allow_ghe=False, allow_k8s=False, allow_calico=False):
    """
    A validator for paths in the command line, raising an exception if the path is invalid
    :param str path_location: The path to validate
    :param bool allow_ghe: Whether to allow url to github
    :param bool allow_k8s: whether to allow the string 'k8s'
    :param bool allow_calico:  whether to allow the string 'calico'
    :return: The argument path_location
    :rtype: str
    :raises: argparse.ArgumentTypeError when path is invalid
    """
    if allow_ghe and path_location.startswith('https://github'):
        return path_location
    if allow_k8s and path_location == 'k8s':
        return path_location
    if allow_calico and path_location == 'calico':
        return path_location
    if not os.path.exists(path_location):
        raise argparse.ArgumentTypeError(path_location + ' is not a valid path')
    return path_location


def _ghe_or_k8s_or_calico_or_valid_path(path_location):
    return _valid_path(path_location, allow_ghe=True, allow_k8s=True, allow_calico=True)


def _k8s_or_calico_or_valid_path(path_location):
    return _valid_path(path_location, allow_k8s=True, allow_calico=True)


def _k8s_or_valid_path(path_location):
    return _valid_path(path_location, allow_k8s=True)


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

    base_np_list = args.base_np_list or 'k8s'
    cl_execute = CLExecute(args.ns_list, args.pod_list, args.output_format, args.file_out, args.pr_url)
    if args.equiv:
        return cl_execute.equivalence(args.equiv, base_np_list)

    if args.interferes:
        return cl_execute.interferes(args.interferes, base_np_list)

    if args.forbids:
        return cl_execute.forbids(args.forbids, base_np_list)

    if args.permits:
        return cl_execute.permits(args.permits, base_np_list)

    if args.connectivity:
        return cl_execute.connectivity_map(args.connectivity)

    if args.semantic_diff:
        return cl_execute.semantic_diff(args.semantic_diff, base_np_list)

    return cl_execute.sanity(args.sanity or 'k8s')


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
    manual_or_automatic.add_argument('--sanity', type=_ghe_or_k8s_or_calico_or_valid_path,
                                     help='Network policies (file/dir/GHE url/cluster-type) for sanity checking')
    manual_or_automatic.add_argument('--connectivity', type=_ghe_or_k8s_or_calico_or_valid_path,
                                     help='Network policies (file/dir/GHE url/cluster-type) for connectivity map')
    manual_or_automatic.add_argument('--semantic_diff', type=_ghe_or_k8s_or_calico_or_valid_path,
                                     help='Network policies (file/dir/GHE url/cluster-type) for semantic-diff')
    manual_or_automatic.add_argument('--equiv', type=_ghe_or_k8s_or_calico_or_valid_path,
                                     help='Network policies (file/dir/GHE url/cluster-type) for equivalence checking')
    manual_or_automatic.add_argument('--interferes', type=str, help='Network policies '
                                     '(policy name/file/dir/GHE url/cluster-type) for interference checking')
    manual_or_automatic.add_argument('--forbids', type=str, help='Network policies '
                                     '(policy name/file/dir/GHE url/cluster-type) specifying forbidden connections')
    manual_or_automatic.add_argument('--permits', type=str, help='Network policies '
                                     '(policy name/file/dir/GHE url/cluster-type) specifying permitted connections')
    manual_or_automatic.add_argument('--daemon', action='store_true', help='Run NCA as a daemon with REST API')
    parser.add_argument('--base_np_list', '-b', type=_ghe_or_k8s_or_calico_or_valid_path, default='k8s',
                        help='Filesystem or GHE location for equiv/interference check (default: k8s cluster)')
    parser.add_argument('--ns_list', '-n', type=_ghe_or_k8s_or_calico_or_valid_path,
                        help='A file/cluster-type to read namespace list from')
    parser.add_argument('--pod_list', '-p', type=_ghe_or_k8s_or_calico_or_valid_path,
                        help='A file/cluster-type to read pod list from')
    parser.add_argument('--ghe_token', '--gh_token', type=str, help='A valid token to access a GitHub repository')
    parser.add_argument('--output_format', '-o', type=str, default='txt',
                        help='Output format specification (txt or yaml). The default is txt.')
    parser.add_argument('--file_out', '-f', type=str, help='A file path to which output is redirected')
    parser.add_argument('--pr_url', type=str, help='The full api url for adding a PR comment')

    args = parser.parse_args(argv)

    if args.ghe_token:
        os.environ['GHE_TOKEN'] = args.ghe_token

    if args.daemon:
        return RestServer(args.ns_list, args.pod_list).run()

    if args.ns_list is None:
        args.ns_list = 'k8s'
    if args.pod_list is None:
        args.pod_list = 'k8s'

    if args.period <= 0:
        return run_args(args)

    _do_every(args.period * 60, run_args, args)
    return 0


if __name__ == "__main__":
    sys.exit(nca_main())
