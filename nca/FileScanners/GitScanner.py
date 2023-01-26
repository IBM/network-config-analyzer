#
# Copyright 2020- IBM Inc. All rights reserved
# SPDX-License-Identifier: Apache2.0
#

import os
from urllib.parse import urlparse
from urllib.request import urlopen
from ghapi.all import GhApi
from .GenericTreeScanner import GenericTreeScanner


class GitScanner(GenericTreeScanner):
    """
    A class for reading yaml files from a git repo
    """
    raw_github_content_prefix = 'https://raw.githubusercontent'

    def __init__(self, url):
        self.url = url
        if url.startswith(self.raw_github_content_prefix):
            if not self.is_yaml_file(url):
                raise Exception(f'Bad Raw Content - GitHub URL: {url}')
        else:
            if url.endswith('/'):
                url = url[:-1]
            parsed_url = urlparse(url)
            if parsed_url.hostname == 'github.com':
                ghe_base_url = 'https://api.github.com'
            else:
                ghe_base_url = parsed_url.scheme + '://' + str(parsed_url.hostname) + '/api/v3'
            self.url_path = parsed_url.path.split('/', maxsplit=5)
            if len(self.url_path) < 3:
                raise Exception(f'Bad GitHub URL: {url}')
            self.ghe = GhApi(gh_host=ghe_base_url, owner=self.url_path[1], repo=self.url_path[2],
                             token=os.environ.get('GHE_TOKEN'))
            self.ref = 'heads/' + (self.url_path[4] if len(self.url_path) >= 5 else 'master')

    def _scan_dir_in_repo(self, path, recursive):
        if path and not path.endswith('/'):
            path += '/'
        ref = self.ghe.git.get_ref(ref=self.ref)
        git_tree = self.ghe.git.get_tree(tree_sha=ref.object.sha, recursive='True')
        for element in git_tree.tree:
            if element.type != 'blob':
                continue
            if not element.path.startswith(path):
                continue
            if not GenericTreeScanner.is_yaml_file(element.path):
                continue
            if not recursive and element.path.count('/') != path.count('/'):
                continue

            yield from self._yield_yaml_file(element.path, self.ghe.get_content(path=element.path))

    def get_yamls(self):
        """
        Call this function to get a generator for all yamls in the repo
        """
        if self.url.startswith(self.raw_github_content_prefix):
            return self._yield_yaml_file(self.url, urlopen(self.url))

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
            return self._yield_yaml_file(path_in_repo, self.ghe.get_content(path_in_repo))
        if path_in_repo.endswith('**'):
            return self._scan_dir_in_repo(path_in_repo[:-2], True)  # path_in_repo without **
        return self._scan_dir_in_repo(path_in_repo, False)
