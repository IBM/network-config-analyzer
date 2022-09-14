#
# Copyright 2020- IBM Inc. All rights reserved
# SPDX-License-Identifier: Apache2.0
#
class OutputFilesFlags:
    """
       A singleton class to store flags associated with actual and expected output files
       these flags might be passed with the run_all_tests script and handled by nca classes
    """

    # the inner class is needed to make the outer class a singleton
    class __OutputFilesFlags:
        def __init__(self):
            self.create_expected_files = False
            self.update_expected_files = False

    instance = None

    def __init__(self):
        if not OutputFilesFlags.instance:
            OutputFilesFlags.instance = OutputFilesFlags.__OutputFilesFlags()

    def __getattr__(self, attr):
        return getattr(self.instance, attr)

    def __setattr__(self, name, value):
        return setattr(self.instance, name, value)
