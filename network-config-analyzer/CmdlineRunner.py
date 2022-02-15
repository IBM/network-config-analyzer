#
# Copyright 2020- IBM Inc. All rights reserved
# SPDX-License-Identifier: Apache2.0
#

"""
Utility class to execute the cmdline executables 'kubectl' and 'calicoctl'
"""

import subprocess
import os
from fnmatch import fnmatch


class CmdlineRunner:
    """
    A stateless class with only static functions to easily get k8s and calico resources using kubectl and calicoctl
    """
    @staticmethod
    def run_and_get_output(cmdline_list):
        """
        Run an executable with specific arguments and return its output to stdout
        :param list[str] cmdline_list: A list of arguments, the first of which is the executable path
        :return: The executable's output to stdout
        :rtype: str
        """
        cmdline_process = subprocess.Popen(cmdline_list, stdout=subprocess.PIPE)
        return cmdline_process.communicate()[0]

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
        raise Exception('Failed to locate Kubernetes configuration files')

    @staticmethod
    def get_k8s_resources(resource):
        """
        Run kubectl to get the list of available instances of a given resource
        :param str resource: The name of the resource
        :return: The output of 'kubectl get' (should be a list-resource)
        """
        CmdlineRunner.locate_kube_config_file()
        cmdline_list = ['kubectl', 'get', resource, '-o=json']
        if resource in ['networkPolicy', 'authorizationPolicy', 'pod']:
            cmdline_list.append('--all-namespaces')
        return CmdlineRunner.run_and_get_output(cmdline_list)
