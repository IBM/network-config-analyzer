import argparse
import contextlib
import traceback
import sys
import os
from fnmatch import fnmatch
from os import path
from shutil import copyfile
from time import time

import yaml
from ruamel.yaml import YAML
from contextlib import redirect_stdout

sys.path.append(os.path.dirname(os.path.dirname(os.path.realpath(__file__))))
sys.path.append(os.path.join(os.path.dirname(os.path.dirname(os.path.realpath(__file__))), 'network-config-analyzer'))
from nca import nca_main

"""
script should be run with one of the following combinations:

run_all_tests.py --type=general --action=run_tests
run_all_tests.py --type=output --action=run_tests
run_all_tests.py --type=fw_rules_assertions --action=run_tests
run_all_tests.py --type=output --action=override_expected_output
run_all_tests.py --type=output --action=add_new_output_tests

"""

# TODO: add documentation

class TestArgs:
    def __init__(self, args):
        self.args = args

    def get_arg_value(self, arg_str):
        for index, arg in enumerate(self.args):
            if arg == arg_str:
                arg_val = self.args[index + 1]
                return True, arg_val
        return False, ''

    # assuming that out_file as arg to cli test is a base name, with no path involved
    def has_out_file_arg(self):
        return self.get_arg_value('-f')

    def has_out_format_arg(self):
        return self.get_arg_value('-o')

    def has_out_format_arg_with_val(self, out_format_val):
        _, actual_val = self.has_out_format_arg()
        return actual_val == out_format_val


class CliQuery:
    def __init__(self, test_dict, cli_tests_base_dir, actual_output_dir, test_name):
        self.cli_tests_base_dir = cli_tests_base_dir
        self.test_dict = test_dict
        self.actual_output_dir = actual_output_dir
        self.args = test_dict['args'].split()
        self.query_name = self.test_dict['name']
        self.test_name = test_name
        for idx, arg in enumerate(self.args):
            if '/' in arg and not arg.startswith('https://github'):
                self.args[idx] = os.path.join(self.cli_tests_base_dir, arg)
        self.args_obj = TestArgs(self.args)
        self.stdout_redirection_path = ''
        self.list_expected_output_files = self._get_list_of_expected_output_files()

    def _get_list_of_expected_output_files(self):
        has_out_file_arg, out_file_arg_str = self.args_obj.has_out_file_arg()
        if has_out_file_arg:
            return [out_file_arg_str]
        else:
            stdout_file = self.query_name + '__stdout_output.txt'
            self.stdout_redirection_path = stdout_file
            return [stdout_file]


class SchemeFile:
    def __init__(self, scheme_filename, test_args, actual_output_dir):
        self.scheme_filename = scheme_filename
        self.args = test_args
        self.test_args_obj = TestArgs(test_args)
        self.actual_output_dir = actual_output_dir
        self.stdout_redirection_path = ''
        self.list_expected_output_files = self._get_list_of_expected_output_files()
        self.test_name = self.get_test_name()

    # get an informative test name, which apart from the scheme file name, includes cli args if used
    def get_test_name(self):
        has_out_format, out_format = self.test_args_obj.has_out_format_arg()
        has_out_file, out_file = self.test_args_obj.has_out_file_arg()
        args_str = ''
        if has_out_format:
            args_str += f' -o {out_format} '
        if has_out_format:
            args_str += f' -f {os.path.basename(out_file)} '
        test_name = f'{self.scheme_filename} [{args_str}]' if args_str else self.scheme_filename
        return test_name

    def _get_list_of_expected_output_files(self):
        res = []
        has_out_file_arg, out_file_arg_str = self.test_args_obj.has_out_file_arg()
        if has_out_file_arg:
            return [os.path.basename(out_file_arg_str)]
        res.append(self.get_stdout_output_file())
        self.stdout_redirection_path = os.path.join(self.actual_output_dir, self.get_stdout_output_file())
        res.extend(self.get_output_files_from_output_config())
        return res

    def get_stdout_output_file(self):
        # currently stdout is always txt file
        return os.path.basename(self.scheme_filename).replace(".yaml", "__stdout_output.txt")

    def update_arg_at_scheme_file_output_config(self, arg_name, arg_value):
        with open(self.scheme_filename, 'r') as scheme_file:
            scheme = yaml.safe_load(scheme_file)
            for query in scheme['queries']:
                if 'outputConfiguration' in query:
                    output_config = query['outputConfiguration']
                    output_config.update({arg_name: arg_value})
                else:
                    query.update({'outputConfiguration': {arg_name: arg_value}})
        with open(self.scheme_filename, 'w') as scheme_file:
            yaml.dump(scheme, scheme_file, default_flow_style=False, sort_keys=False)

    @staticmethod
    def is_valid_output_format_per_query(out_format, query_type):
        if query_type == 'connectivityMap' and out_format not in ['txt', 'yaml', 'csv', 'md', 'dot']:
            return False
        if query_type == 'semanticDiff' and out_format not in ['txt', 'yaml', 'csv', 'md']:
            return False
        if query_type == 'Other' and out_format != 'txt':
            return False
        return True

    # get only output files from outputConfig that are expected to be created,
    # thus with valid output format per query type
    # TODO: if all queries are semantic-diff and out_format is dot from cli arg, then output path file will not be created
    def get_output_files_from_output_config(self):
        res = []
        with open(self.scheme_filename, 'r') as scheme_file:
            scheme = yaml.safe_load(scheme_file)
            for query in scheme.get('queries', []):
                query_type = 'Other'
                if 'connectivityMap' in query:
                    query_type = 'connectivityMap'
                if 'semanticDiff' in query:
                    query_type = 'semanticDiff'
                if 'outputConfiguration' in query:
                    output_config = query['outputConfiguration']
                    output_path = output_config.get('outputPath')
                    out_format = output_config.get('outputFormat', 'txt')
                    if output_path and output_path not in res and self.is_valid_output_format_per_query(out_format,
                                                                                                        query_type):
                        res.append(output_path)
        return res


# general test: comparison of numerical result (nca return value) to expected value
# most of the test flow is common to other tests types
class GeneralTest:
    def __init__(self, test_name, test_queries_obj, expected_result):
        self.test_name = test_name  # str
        self.test_queries_obj = test_queries_obj  # SchemeFile or CliQuery
        self.result = None  # tuple of (numerical result, test runtime)
        self.numerical_result = None  # assigned with numerical result after test run
        self.start_time = None
        self.nca_res = None
        self.expected_result = expected_result
        self.test_type = 'general'
        self.result_details = None

    def initialize_test(self):
        # due to 'append' behavior - for output test, delete output files from prev runs
        if isinstance(self, OutputTest):
            self._delete_all_actual_output_files()
        self._update_required_scheme_file_config_args(True)
        print('------------------------------------')
        print('Running testcase', self.test_name)
        self.start_time = time()

    def run_all_test_flow(self, all_results):
        # should be overriden by inheriting classes
        self.initialize_test()
        self.run_test()
        self.evaluate_test_results()
        self.finalize_test()
        all_results[self.test_name] = self.result
        return self.numerical_result

    def test_passed(self):
        return self.numerical_result == 0

    def run_nca(self):
        return nca_main(self.test_queries_obj.args)

    def run_test(self):
        self.nca_res = self.run_nca()  # either run a scheme or a query, with relevant args

    # update self.numerical_result, return true if test passed
    def evaluate_test_results(self):
        self.numerical_result = 1 if self.nca_res != self.expected_result else 0

    def finalize_test(self):
        if not self.test_passed():
            print('Testcase', self.test_name, 'failed', file=sys.stderr)
        else:
            print('Testcase', self.test_name, 'passed')
        self.result = (self.numerical_result, time() - self.start_time, self.result_details)
        # after test run - delete output files for non-output tests, and for successful output tests
        if (isinstance(self, OutputTest) and self.numerical_result == 0) or not isinstance(self, OutputTest):
            self._delete_all_actual_output_files()
        self._update_required_scheme_file_config_args(False)

    def _delete_all_actual_output_files(self):
        for out_file in self.test_queries_obj.list_expected_output_files:
            out_file_actual = os.path.join(self.test_queries_obj.actual_output_dir, out_file)
            if path.isfile(out_file_actual):
                os.remove(out_file_actual)

    def _update_required_scheme_file_config_args(self, before_test_run):
        if isinstance(self.test_queries_obj, SchemeFile):
            if isinstance(self, OutputTest):
                if self.test_queries_obj.test_args_obj.has_out_format_arg_with_val('dot'):
                    self.test_queries_obj.update_arg_at_scheme_file_output_config('connectivitySortDotOutput',
                                                                                  before_test_run)
            if isinstance(self, AssertionTest):
                self.test_queries_obj.update_arg_at_scheme_file_output_config('fwRulesRunInTestMode',
                                                                              before_test_run)


# output test: comparison of actual output files and stdout output to expected output files
# relevant for queries: connectivity, semantic-diff
class OutputTest(GeneralTest):
    def __init__(self, test_name, test_queries_obj, expected_output_dir, actual_output_dir):
        super().__init__(test_name, test_queries_obj, None)
        self.expected_output_dir = expected_output_dir
        self.actual_output_dir = actual_output_dir
        self.test_type = 'output'
        self.compared_files_results = {}  # dict from file name to comparison result (bool)

    def run_test(self):
        if self.test_queries_obj.stdout_redirection_path:
            with open(self.test_queries_obj.stdout_redirection_path, 'w') as f:
                with redirect_stdout(f):
                    res = self.run_nca()
        else:
            res = self.run_nca()
        self.nca_res = res

    def evaluate_test_results(self):
        self.numerical_result = 0
        output_files = self.test_queries_obj.list_expected_output_files
        for out_file in output_files:
            expected_out_file = os.path.join(self.expected_output_dir, out_file)
            actual_out_file = os.path.join(self.actual_output_dir, out_file)
            comparison_res = self.compare_files(actual_out_file, expected_out_file)
            self.compared_files_results[out_file] = comparison_res
            if not comparison_res:
                # consider as one test failure, even if multiple output files fail in comparison on this test
                self.numerical_result = 1
        res = self.numerical_result == 0
        self.result_details = self.compared_files_results

    # action is either 'override_expected_output' or 'add_new_output_tests'
    def update_expected_output(self, action):
        # run test flow without its output
        # TODO: redirect stderr also?
        with contextlib.redirect_stdout(None):
            self.run_all_test_flow({})
        # based on test result, apply override / add new test expected output
        if not self.test_passed():
            for file, res in self.compared_files_results.items():
                actual_out_file = os.path.join(self.actual_output_dir, file)
                expected_out_file = os.path.join(self.expected_output_dir, file)
                if not res:
                    if action == 'override_expected_output' or (
                            action == 'add_new_output_tests' and not os.path.exists(expected_out_file)):
                        copyfile(actual_out_file, expected_out_file)
                        print(f'copying out file from {actual_out_file} to {expected_out_file} ')
                os.remove(actual_out_file)
        print(f'done with update_expected_output on test: {self.test_name}')

    @staticmethod
    def compare_files(output_filename, golden_filename):
        """
        Compares an output file from this test run to a golden-result file
        :param str output_filename: An output file of the current run
        :param str golden_filename: The golden-result file to compare against
        :return bool: True if files are identical, False otherwise (and prints the first line that has a diff)
        """
        print('Comparing output file {0} to expected-results file {1}'.format(output_filename, golden_filename))
        if not path.isfile(output_filename):
            print(f'Error: Output file {output_filename} not found')
            return False
        with open(output_filename) as output_file:
            output_file_lines = output_file.readlines()
        try:
            with open(golden_filename) as golden_file:
                for golden_file_line_num, golden_file_line in enumerate(golden_file):
                    if golden_file_line_num >= len(output_file_lines):
                        print('Error: Expected results have more lines than actual results')
                        return False
                    if golden_file_line != output_file_lines[golden_file_line_num]:
                        print('Error: Result mismatch at line {}'.format(golden_file_line_num + 1))
                        print(golden_file_line)
                        print(output_file_lines[golden_file_line_num])
                        return False
        except FileNotFoundError:
            print('Error: Expected results file not found')
            return False
        return True


# for fw-rules - activate assertions for testing in fwRulesTestMode
class AssertionTest(GeneralTest):
    def __init__(self, test_name, test_queries_obj):
        super().__init__(test_name, test_queries_obj, None)
        self.assertion_error = None

    def run_test(self):
        try:
            self.nca_res = self.run_nca()
        except AssertionError:
            _, _, tb = sys.exc_info()
            traceback.print_tb(tb)  # Fixed format
            tb_info = traceback.extract_tb(tb)
            filename, line, func, text = tb_info[-1]
            self.assertion_error = f'An error occurred on file {filename} line {line} in statement {text}'

    def evaluate_test_results(self):
        self.numerical_result = 0 if self.assertion_error is None else 1


class TestsRunner:
    def __init__(self, spec_file, tests_type, action):
        self.spec_file = spec_file
        self.all_results = {}
        self.global_res = 0
        self.tests_type = tests_type  # general / output / fw_rules_assertions
        self.action = action

    def run_tests(self):
        with open(self.spec_file) as doc:
            code = YAML().load_all(doc)
            for tests_spec in next(iter(code)):
                self.run_tests_spec(tests_spec)
        if self.action == 'run_tests':
            self.print_results()

    def print_results(self):
        print('\n\nSummary\n-------')
        total_time = 0.
        for testcase, result in self.all_results.items():
            print('{0:180}{1} ({2:.2f} seconds)'.format(testcase, 'Passed' if result[0] == 0 else 'Failed', result[1]))
            # currently result[2] is results details, only relevant for output tests
            if result[2]:
                print('Compared output files and their comparison result:')
                for f, comparison_res in result[2].items():
                    print('{0:180}{1} '.format(f, comparison_res))
            total_time += result[1]

        if self.global_res:
            print('{0} tests failed ({1:.2f} seconds)'.format(self.global_res, total_time))
        else:
            print('All tests passed ({:.2f} seconds)'.format(total_time))

    def run_tests_spec(self, tests_spec):
        # name = tests_spec.get('name', None)
        tests_queries_type = tests_spec.get('type', None)  # scheme or cmdline
        tests_root_dir = tests_spec.get('root', None)
        files_list = tests_spec.get('files_list', None)
        # args only relevant for output tests:
        tests_expected_output_dir = tests_spec.get('expected_output', None)
        out_format_arg = tests_spec.get('out_format_arg',
                                        None)  # a list of possible formats to use from cli args in test run
        add_out_path_arg = tests_spec.get('add_out_path_arg',
                                          None)  # a flag to indicate if shoud usr out_file args from cli args in test run

        base_dir = os.path.abspath(os.path.dirname(sys.argv[0]))
        for root, _, files in os.walk(tests_root_dir):
            for file in files:
                if files_list and os.path.basename(file) not in files_list:
                    continue
                if tests_queries_type == 'scheme' and not fnmatch(file, '*-scheme.yaml'):
                    continue
                file_path = os.path.join(base_dir, root, file)
                self.run_test_per_file(file_path, tests_queries_type, tests_root_dir, tests_expected_output_dir,
                                       out_format_arg, add_out_path_arg)

    def create_and_run_test_obj(self, test_queries_obj_list, tests_expected_output_dir, expected_res):
        for test_queries_obj in test_queries_obj_list:
            test_obj = None
            if self.tests_type == 'general':
                test_obj = GeneralTest(test_queries_obj.test_name, test_queries_obj, expected_res)
            elif self.tests_type == 'fw_rules_assertions':
                test_obj = AssertionTest(test_queries_obj.test_name, test_queries_obj)
            elif self.tests_type == 'output':
                test_obj = OutputTest(test_queries_obj.test_name, test_queries_obj, tests_expected_output_dir,
                                      self.get_actual_output_dir())
            if self.action == 'run_tests':
                self.global_res += test_obj.run_all_test_flow(self.all_results)
            elif self.action in {'override_expected_output', 'add_new_output_tests'}:
                test_obj.update_expected_output(self.action)

    # given a scheme file or a cmdline file, run all relevant tests
    def run_test_per_file(self, test_file, tests_queries_type, tests_root_dir, tests_expected_output_dir,
                          out_format_arg,
                          add_out_path_arg):
        if tests_queries_type == 'scheme':
            if self.tests_type in {'general', 'fw_rules_assertions'}:
                scheme_obj_list = [
                    SchemeFile(test_file, self._get_scheme_test_args(test_file), self.get_actual_output_dir())]
            else:
                scheme_obj_list = self.get_scheme_obj_list_for_test(test_file, out_format_arg, add_out_path_arg)
            self.create_and_run_test_obj(scheme_obj_list, tests_expected_output_dir, 0)

        elif tests_queries_type == 'cmdline':
            with open(test_file) as doc:
                code = YAML().load_all(doc)
                for test in next(iter(code)):
                    query_name = test.get('name', '')
                    cli_test_name = f'{os.path.basename(test_file)}, query name: {query_name}'
                    cliQuery = CliQuery(test, tests_root_dir, self.get_actual_output_dir(), cli_test_name)
                    self.create_and_run_test_obj([cliQuery], tests_expected_output_dir, test.get('expected', None))

    @staticmethod
    def _get_scheme_test_args(test_file, out_format_arg=None, out_path_arg=None):
        res = ['--scheme', test_file]
        if out_format_arg is not None:
            res.append('-o')
            res.append(out_format_arg)
        if out_path_arg is not None:
            res.append('-f')
            res.append(out_path_arg)
        return res

    # may require to create multiple tests for scheme file, if out_format_arg_list has > 1 out formats to test with
    def get_scheme_obj_list_for_test(self, test_file, out_format_arg_list, add_out_path_arg):
        res = []
        if out_format_arg_list:
            for out_format in out_format_arg_list:
                out_file_arg = self.get_out_file_arg(add_out_path_arg, test_file, out_format)
                test_args = self._get_scheme_test_args(test_file, out_format, out_file_arg)
                scheme_obj = SchemeFile(test_file, test_args, self.get_actual_output_dir())
                res.append(scheme_obj)
        else:
            out_file_arg = self.get_out_file_arg(add_out_path_arg, test_file)
            test_args = self._get_scheme_test_args(test_file, None, out_file_arg)
            scheme_obj = SchemeFile(test_file, test_args, self.get_actual_output_dir())
            res = [scheme_obj]
        return res

    # out file name as arg in cli args for scheme file
    @staticmethod
    def get_output_file_name_arg(scheme_filename, out_format_arg='txt'):
        suffix = f'_output.{out_format_arg}'
        return os.path.basename(scheme_filename).replace(".yaml", suffix)

    def get_out_file_arg(self, add_out_path_arg_flag, test_file, out_format='txt'):
        out_file_name = os.path.join(self.get_actual_output_dir(), self.get_output_file_name_arg(test_file, out_format))
        return None if not add_out_path_arg_flag else out_file_name

    @staticmethod
    def get_actual_output_dir():
        return os.getcwd()



# special flags for output tests:
# override expected output: for every difference in actual output vs expected output, override expected output with new actual output
# add new output tests: for every missing expected output file, create expected output file from actual output file

def main(argv=None):
    print(os.path.dirname(os.path.realpath(__file__)))
    os.exit(0)

    test_type_and_spec_dict = {'general': 'general_tests_spec.yaml', 'output': 'output_tests_spec.yaml',
                               'fw_rules_assertions': 'fw_rules_assertions_tests_spec.yaml'}

    parser = argparse.ArgumentParser(description='Testing for analyzer for network connectivity configuration')
    parser.add_argument('--type', choices=['general', 'output', 'fw_rules_assertions'], help='Choose test types to run',
                        default='general')
    parser.add_argument('--action', choices=['run_tests', 'override_expected_output', 'add_new_output_tests'],
                        default='run_tests',
                        help='Choose action')

    args = parser.parse_args(argv)

    test_type = args.type
    action = args.action

    if action != 'run_tests' and test_type != 'output':
        print(f'action: {action} is not supported with test type: {test_type}')
        sys.exit(1)

    sepc_file = os.path.join( os.path.dirname(os.path.realpath(__file__)),  test_type_and_spec_dict[test_type])
    tests_runner = TestsRunner(sepc_file, test_type, action)
    tests_runner.run_tests()

    return 0


if __name__ == "__main__":
    sys.exit(main())
