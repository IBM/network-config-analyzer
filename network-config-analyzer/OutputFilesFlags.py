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
            self.clean_actual_files = True
            self.running_all_tests = False

        def set_update_expected_out_files(self, update_files):
            self.update_expected_files = update_files

        def set_create_expected_out_files(self, create_files):
            self.create_expected_files = create_files

        def set_clean_actual_out_files(self, clean_files):
            self.clean_actual_files = clean_files

        def set_running_all_tests(self, regression_flag):
            self.running_all_tests = regression_flag

        def get_update_expected_out_files(self):
            return self.update_expected_files

        def get_create_expected_out_files(self):
            return self.create_expected_files

        def get_clean_actual_out_files(self):
            return self.clean_actual_files

        def get_running_all_tests(self):
            return self.running_all_tests

    instance = None

    def __init__(self):
        if not OutputFilesFlags.instance:
            OutputFilesFlags.instance = OutputFilesFlags.__OutputFilesFlags()

    def __getattr__(self, attr):
        return getattr(self.instance, attr)
