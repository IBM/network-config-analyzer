#
# Copyright 2020- IBM Inc. All rights reserved
# SPDX-License-Identifier: Apache2.0
#

"""
Utility class to execute the cmdline executables 'kubectl' and 'calicoctl'
"""

import subprocess
import os
import sys
from fnmatch import fnmatch


class CmdlineRunner:
    """
    A stateless class with only static functions to easily get k8s and calico resources using kubectl and calicoctl
    """
    # a static variable to indicate if we want to ignore errors from running executable command - i.e. run silently
    ignore_live_cluster_err = False

    @staticmethod
    def run_and_get_output(cmdline_list, check_for_silent_exec=False):
        """
        Run an executable with specific arguments and return its output to stdout
        if a communicate error occurs, it will be ignored in case this is a silent try to communicate with live cluster,
        otherwise, will be printed to stderr
        :param list[str] cmdline_list: A list of arguments, the first of which is the executable path
        :param check_for_silent_exec: when true consider the static variable that indicates whether to ignore errors
        or not
        :return: The executable's output to stdout ( a list-resources on success, otherwise empty value)
        :rtype: str
        """
        cmdline_process = subprocess.Popen(cmdline_list, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = cmdline_process.communicate()
        print_err_flag = \
            not check_for_silent_exec or (check_for_silent_exec and not CmdlineRunner.ignore_live_cluster_err)
        if err and print_err_flag:
            print(err.decode().strip('\n'), file=sys.stderr)
        return out

    @staticmethod
    def search_file_in_path(filename, search_path):
        """
        Given a search path, find file with requested name
        :param str filename: The filename to search for
        :param str search_path: The directories to search the file in, as a ':'-separated string
        :return: The first path on which the file was found. If not found, simply returns filename (hopefully it works)
        :rtype: str
        """
        for path in search_path.split(os.pathsep):
            candidate = os.path.join(path, filename)
            if os.path.exists(candidate):
                return os.path.abspath(candidate)
        return filename

    @staticmethod
    def get_calico_resources(resource):
        """
        Run calicoctl to get the list of available instances of a given resource
        :param str resource: The name of the resource
        :return: The output of 'calicoctl get' (should be a list-resource)
        """
        calicoctl_exec = CmdlineRunner.search_file_in_path('calicoctl', os.environ.get('PATH', '.'))
        cmdline_list = [calicoctl_exec, 'get', resource, '-o', 'yaml']
        if resource in ['networkPolicy', 'wep']:
            cmdline_list.append('--all-namespaces')
        return CmdlineRunner.run_and_get_output(cmdline_list)

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
        raise FileNotFoundError('Failed to locate Kubernetes configuration files')

    @staticmethod
    def get_k8s_resources(resources):
        """
        Run kubectl to get the list of available instances of a given resource
        :param list resources: The list of resource names
        :return: The output of 'kubectl get' (should be a list-resource)
        """
        CmdlineRunner.locate_kube_config_file()
        cmdline_list = ['kubectl', 'get', ','.join([r for r in resources]), '-o=json']
        if set(['networkPolicy', 'authorizationPolicy', 'pod', 'ingress', 'Gateway', 'VirtualService', 'sidecar',
                'service', 'serviceentry']).intersection(resources):
            cmdline_list.append('--all-namespaces')
        return CmdlineRunner.run_and_get_output(cmdline_list, check_for_silent_exec=True)

    @staticmethod
    def resolve_helm_chart(chart_dir):
        """
        Run helm to get the resoled yaml files from the chart
        :param str chart_dir: The name of the chart file
        :return: The resolved yaml files generated from the chart file
        """
        cmdline_list = ['helm', 'template', 'nca-extract', chart_dir]
        return CmdlineRunner.run_and_get_output(cmdline_list)
