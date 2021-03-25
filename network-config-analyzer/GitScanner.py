#
# Copyright 2020- IBM Inc. All rights reserved
# SPDX-License-Identifier: Apache2.0
#

from dataclasses import dataclass
import os
from sys import stderr
from urllib.parse import urlparse
from github import Github, GithubException
import yaml


@dataclass
class YamlFile:
    """
    A class for holding the retrieved data of a yaml file from git repo
    """
    data: object
    path: str


class GitScanner:
    """
    A class for reading yaml files from a git repo
    """
    def __init__(self, url):
        self.url = url
        if url.endswith('/'):
            url = url[:-1]
        parsed_url = urlparse(url)
        ghe_base_url = parsed_url.scheme + '://' + parsed_url.hostname + '/api/v3'
        self.url_path = parsed_url.path.split('/', maxsplit=5)
        if len(self.url_path) < 3:
            raise Exception(f'Bad GitHub URL: {url}')
        self.ghe = Github(base_url=ghe_base_url, login_or_token=os.environ.get('GHE_TOKEN'))
        self.repo = self._get_repo()
        self.ref = self.url_path[4] if len(self.url_path) >= 5 else 'master'

    def _get_repo(self):
        """
        :return: An instance of the Repository API class matching the repository in the url
        :rtype: github.Repository.Repository
        """
        try:
            org = self.ghe.get_organization(str(self.url_path[1]))
        except GithubException:
            try:
                org = self.ghe.get_user(self.url_path[1])
            except GithubException:
                org = None
        if org is None:
            raise Exception(f'GitHub URL {self.url} does not point to a valid repository')

        try:
            repo = org.get_repo(str(self.url_path[2]))
        except GithubException:
            repo = None
        if repo is None:
            raise Exception(f'GitHub URL {self.url} does not point to a valid repository')
        return repo

    def _yield_yaml_file(self, path):
        file_contents = self.repo.get_contents(path, self.ref)
        try:
            yield YamlFile(yaml.load_all(file_contents.decoded_content, Loader=yaml.SafeLoader), file_contents.path)
        except yaml.YAMLError:
            print('Bad yaml file:', path, file=stderr)
            return

    def _scan_dir_in_repo(self, path, recursive):
        if path and not path.endswith('/'):
            path += '/'
        git_tree = self.repo.get_git_tree(self.ref, True)
        for element in git_tree.tree:
            if element.type != 'blob':
                continue
            if not element.path.startswith(path):
                continue
            if not element.path.endswith('.yaml') and not element.path.endswith('.yml'):
                continue
            if not recursive and element.path.count('/') != path.count('/'):
                continue

            yield from self._yield_yaml_file(element.path)

    def get_yamls_in_repo(self):
        """
        Call this function to get a generator for all yamls in the repo
        """
        is_file = False
        path_in_repo = ''
        if len(self.url_path) == 4:
            if self.url_path[3] != '**':
                raise Exception(f'Bad GitHub URL: {self.url}')
            path_in_repo = '**'
        elif len(self.url_path) >= 5:
            is_file = (self.url_path[3] == 'blob')
            path_in_repo = '' if len(self.url_path) == 5 else self.url_path[5]

        if is_file:
            return self._yield_yaml_file(path_in_repo)
        if path_in_repo.endswith('**'):
            return self._scan_dir_in_repo(path_in_repo[:-2], True)  # path_in_repo without **
        return self._scan_dir_in_repo(path_in_repo, False)
