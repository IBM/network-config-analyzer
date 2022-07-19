import argparse
import traceback
import sys
import os
from fnmatch import fnmatch
from os import path
import time
import yaml
import csv
from ruamel.yaml import YAML

sys.path.append(os.path.dirname(os.path.dirname(os.path.realpath(__file__))))
sys.path.append(os.path.join(os.path.dirname(os.path.dirname(os.path.realpath(__file__))), 'network-config-analyzer'))
from nca import nca_main
from CmdlineRunner import CmdlineRunner
from OutputFilesFlags import OutputFilesFlags

"""
The script runs tests based on tests specification in 'all_tests_spec.yaml'
script should be run with one of the following types:
    run_all_tests.py --type=general (default)
    run_all_tests.py --type=k8s_live_general  
    run_all_tests.py --type=fw_rules_assertions 
    
    optional flags:
    --check_run_time    (will print a list of tests with unexpected run time 
                         performance in tests/tests_failed_runtime_check.csv)
    --category          (when specified with one of the values: k8s, calico or istio, 
                        the script will run the set of tests which are relevant to that category)
    --create_expected_output_files (when expected output is specified, but does not exist will be auto created. 
                                    relevant only for connectivityMap/SemanticDiff queries)
    --override_expected_output_files (when expected output is specified, will be updated. 
                                    relevant only for connectivityMap/SemanticDiff queries)

"""


class TestArgs:
    def __init__(self, args, base_dir=None):
        self.args = args
        if base_dir:
            self._fix_path_args_with_base_dir(base_dir)

    def _fix_path_args_with_base_dir(self, base_dir):
        for idx, arg in enumerate(self.args):
            if '/' in arg and not arg.startswith(('https://github', 'https://raw.githubusercontent')):
                self.args[idx] = os.path.join(base_dir, arg)

    def get_arg_value(self, arg_str_list):
        for index, arg in enumerate(self.args):
            if arg in arg_str_list:
                arg_val = self.args[index + 1]
                return True, arg_val
        return False, ''


class CliQuery:
    def __init__(self, test_dict, cli_tests_base_dir, test_name):
        self.test_dict = test_dict
        self.query_name = self.test_dict['name']
        self.test_name = test_name
        self.args_obj = TestArgs(test_dict['args'].split(), cli_tests_base_dir)


class SchemeFile:
    def __init__(self, scheme_filename):
        self.test_name = scheme_filename
        test_args = ['--scheme', self.test_name]
        self.args_obj = TestArgs(test_args)

    def update_arg_at_scheme_file_output_config(self, arg_name, arg_value):
        with open(self.test_name, 'r') as scheme_file:
            scheme = yaml.safe_load(scheme_file)
            for query in scheme['queries']:
                if 'outputConfiguration' in query:
                    output_config = query['outputConfiguration']
                    output_config.update({arg_name: arg_value})
                else:
                    query.update({'outputConfiguration': {arg_name: arg_value}})
        with open(self.test_name, 'w') as scheme_file:
            yaml.dump(scheme, scheme_file, default_flow_style=False, sort_keys=False)


# general test: comparison of numerical result (nca return value) to expected value
# most of the test flow is common to other tests types
class GeneralTest:

    def __init__(self, test_name, test_queries_obj, expected_result, check_run_time, required_output_config_flag, test_category=None):
        self.test_name = test_name  # str
        self.test_queries_obj = test_queries_obj  # SchemeFile or CliQuery
        self.result = None  # tuple of (numerical result, test runtime, performance issue indicator)
        self.numerical_result = None  # assigned with numerical result after test run
        self.start_time = None
        self.nca_res = None
        self.new_tests_error = 0
        self.expected_result = expected_result  # integer - expected return value from nca
        self.check_run_time = check_run_time
        self.required_output_config_flag = required_output_config_flag
        self.test_category = test_category

    def initialize_test(self):
        self._update_required_scheme_file_config_args(True)
        print('------------------------------------')
        print('Running testcase', self.test_name)
        self.start_time = time.time()

    def run_all_test_flow(self, all_results):
        # should be overriden by inheriting classes
        self.initialize_test()
        self.run_test()
        self.evaluate_test_results()
        self.finalize_test()
        all_results[self.test_name] = self.result
        return self.numerical_result, self.new_tests_error

    def test_passed(self):
        return self.numerical_result == 0

    def run_nca(self):
        return nca_main(self.test_queries_obj.args_obj.args)

    def run_test(self):
        self.nca_res = self.run_nca()  # either run a scheme or a query, with relevant args

    # update self.numerical_result, return true if test passed
    def evaluate_test_results(self):
        self.numerical_result = 1 if self.nca_res != self.expected_result else 0

    def _get_expected_test_run_time(self):
        expected_time_file_name = f'./expected_runtime/{self.test_category}_tests_expected_runtime.csv'
        with open(expected_time_file_name, 'r') as csv_file:
            csv_reader = csv.reader(csv_file)
            for row in csv_reader:
                current_test = row[0] if 'cmdline_' in row[0] else os.path.abspath(row[0])
                if current_test == self.test_name:
                    return float(row[1])
        csv_file.close()
        return 0.0

    def _execute_run_time_compare(self, actual_run_time):
        test_performance_error = 0
        output_file = f'./{self.test_category}_tests_failed_runtime_check.csv'
        write_header = False
        expected_run_time = self._get_expected_test_run_time()
        if expected_run_time == 0.0:
            self.new_tests_error += 1
        if actual_run_time >= expected_run_time * 2:
            if not path.isfile(output_file):
                write_header = True
            with open(output_file, 'a', newline='') as csv_file:
                csv_writer = csv.writer(csv_file)
                if write_header:
                    csv_writer.writerow(['test_name', 'expected_run_time (seconds)', 'actual_run_time (seconds)'])
                csv_writer.writerow([self.test_name, expected_run_time, f'{actual_run_time:.2f}'])
            csv_file.close()
            if expected_run_time > 0 and actual_run_time > expected_run_time * 5:
                print(f'Error : Conducted Performance issue, {self.test_name} took too long to finish ')
                test_performance_error += 1
        return test_performance_error

    def finalize_test(self):
        if not self.test_passed():
            print('Testcase', self.test_name, 'failed', file=sys.stderr)
        else:
            print('Testcase', self.test_name, 'passed')
        actual_run_time = time.time() - self.start_time
        performance_error = 0
        if self.check_run_time:
            performance_error = self._execute_run_time_compare(actual_run_time)
        self.result = (self.numerical_result, actual_run_time, performance_error)
        self._update_required_scheme_file_config_args(False)

    def _update_required_scheme_file_config_args(self, before_test_run):
        if self.required_output_config_flag is not None:
            if isinstance(self.test_queries_obj, SchemeFile):
                self.test_queries_obj.update_arg_at_scheme_file_output_config(self.required_output_config_flag,
                                                                              before_test_run)


# for fw-rules - activate assertions for testing in fwRulesTestMode
class AssertionTest(GeneralTest):
    def __init__(self, test_name, test_queries_obj, required_output_config_flag):
        super().__init__(test_name, test_queries_obj, None, None, required_output_config_flag)
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


class TestFilesSpec(dict):
    def __init__(self, tests_spec_dict=None):
        default_tests_spec = {'type': None, 'root': None, 'files_list': None, 'activate_output_config_flag': None}
        super().__init__(default_tests_spec)
        if tests_spec_dict is not None:
            self.update(tests_spec_dict)

    def __getattr__(self, name):
        return super().__getitem__(name)


class TestsRunner:
    def __init__(self, spec_file, tests_type, check_run_time, category):
        self.spec_file = spec_file
        self.all_results = {}
        self.global_res = 0
        self.new_tests_error = 0
        self.tests_type = tests_type  # general / k8s_live_general / output / fw_rules_assertions
        self.test_files_spec = None
        self.check_run_time = check_run_time
        self.category = category

    @staticmethod
    def k8s_apply_resources(yaml_file):
        if yaml_file:
            cmdline_list = ['kubectl', 'apply', f'-f{yaml_file}']
            CmdlineRunner.run_and_get_output(cmdline_list)

    def set_k8s_cluster_config(self, cluster_config):
        self.k8s_apply_resources(cluster_config.get('pods', ''))
        self.k8s_apply_resources(cluster_config.get('policies', ''))
        time.sleep(10)  # make sure all pods are up and running

    def _remove_failed_run_time_files(self):
        """
        removes the <category>_tests_failed_runtime_check.csv if exists from previous run
        """
        failed_runtime_files = ['./k8s_tests_failed_runtime_check.csv', './calico_tests_failed_runtime_check.csv',
                                './istio_tests_failed_runtime_check.csv']
        if self.category:
            files_to_remove = [f'{self.category}_tests_failed_runtime_check.csv']
        else:
            files_to_remove = failed_runtime_files
        for file_name in files_to_remove:
            if path.isfile(file_name):
                os.remove(file_name)

    def run_tests(self):
        if self.check_run_time:
            self._remove_failed_run_time_files()
        with open(self.spec_file, 'r') as doc:
            spec_all = yaml.safe_load(doc)
            spec_per_type = spec_all.get(self.tests_type, {})
            for test_spec in spec_per_type:
                if self.tests_type == 'k8s_live_general':
                    self.set_k8s_cluster_config(test_spec.get('cluster_config', {}))
                self.run_tests_spec(test_spec)

        self.print_results()

    def print_test_result_details(self, test):
        """
        prints the name of test Passed/Failed (test run-time)
        :param str test : test name
        :rtype float: the time it took to run the test
        """
        result = self.all_results[test]
        print('{0:180} ({1:.2f} seconds)'.format(test, result[1]))
        return result[1]

    def print_results(self):
        passed_tests = [test for test, result in self.all_results.items() if result[0] == 0]
        failed_tests = [test for test, result in self.all_results.items() if not result[0] == 0]
        print('\n\nTests Run Summary\n-------')
        total_time = 0.
        print(f'\nPassed Tests: {len(passed_tests)}\n----------------')
        for testcase in passed_tests:
            total_time += self.print_test_result_details(testcase)

        print(f'\n\nFailed Tests: {len(failed_tests)}\n----------------')
        for testcase in failed_tests:
            total_time += self.print_test_result_details(testcase)

        if self.global_res:
            print('\n{0} tests failed ({1:.2f} seconds)'.format(self.global_res, total_time))
        else:
            print('\nAll tests passed ({:.2f} seconds)'.format(total_time))

        self.print_performance_results()

    def print_performance_results(self):
        if self.check_run_time:
            tests_w_performance_issues = [test for test, result in self.all_results.items() if not result[2] == 0]
            if len(tests_w_performance_issues):
                self.global_res += 1
                print('\nTests Performance Issues:\n-------')
                print(f'\nFailed with Long Runtime Tests: {len(tests_w_performance_issues)}\n----------------')
                for testcase in tests_w_performance_issues:
                    self.print_test_result_details(testcase)

            if self.new_tests_error:
                print('\nError : Some tests were not found in their relevant tests expected runtime file.\n'
                      'You may add them by running either update-tests-expected-runtime.yml '
                      'or reset-tests-expected-runtime.yml workflows')

    def run_tests_spec(self, tests_spec):
        self.test_files_spec = TestFilesSpec(tests_spec)
        for root, _, files in os.walk(self.test_files_spec.root):
            for file in files:
                if self.test_files_spec.files_list and os.path.basename(file) not in self.test_files_spec.files_list:
                    continue
                if self.test_files_spec.type == 'scheme' and not fnmatch(file, '*-scheme.yaml'):
                    continue
                file_path = os.path.join(os.path.abspath(root), file)
                self.run_test_per_file(file_path)

    def create_and_run_test_obj(self, test_queries_obj, expected_res):
        # create test object
        test_obj = None
        test_category = self.category
        required_output_config_flag = self.test_files_spec.activate_output_config_flag
        if self.tests_type in {'general', 'k8s_live_general'}:
            if self.tests_type == 'general' and self.category == '':
                # to enable runtime check when running tests without specifying a category
                test_category = TestsRunner.determine_test_category(test_queries_obj.test_name)
            test_obj = GeneralTest(test_queries_obj.test_name, test_queries_obj, expected_res,
                                   self.check_run_time, required_output_config_flag, test_category)
        elif self.tests_type == 'fw_rules_assertions':
            test_obj = AssertionTest(test_queries_obj.test_name, test_queries_obj, required_output_config_flag)

        numerical_res, new_tests_err = test_obj.run_all_test_flow(self.all_results)
        self.global_res += numerical_res
        self.new_tests_error += new_tests_err

    @staticmethod  # to be used from the update_expected_runtime.py script too
    def determine_test_category(test_name):
        for ctg in ['k8s', 'calico', 'istio']:
            if TestsRunner._test_file_matches_category_general_tests(test_name, ctg):
                return ctg

    @staticmethod
    def _test_file_matches_category_by_file_name(test_file, category):
        # for tests files under fw_rules_tests or k8s_cmdline_tests.yaml
        file_name = os.path.basename(test_file)
        if file_name.startswith(category):
            return True
        if category == 'k8s' and not file_name.startswith(('calico', 'istio')):
            return True
        return False

    @staticmethod
    def _test_file_matches_category_general_tests(test_file, category):
        if category == '':
            return True
        if category + '_testcases' in test_file:
            return True
        if '_testcases' not in test_file:
            return TestsRunner._test_file_matches_category_by_file_name(test_file, category)
        return False

    # given a scheme file or a cmdline file, run all relevant tests
    def run_test_per_file(self, test_file):
        if self.test_files_spec.type == 'scheme':
            if self.tests_type == 'general' and not TestsRunner._test_file_matches_category_general_tests(test_file, self.category):
                return  # test file does not match the running category
            self.create_and_run_test_obj(SchemeFile(test_file), 0)

        elif self.test_files_spec.type == 'cmdline':
            with open(test_file) as doc:
                code = YAML().load_all(doc)
                for test in next(iter(code)):
                    query_name = test.get('name', '')
                    cli_test_name = f'{os.path.basename(test_file)}, query name: {query_name}'
                    cliQuery = CliQuery(test, self.test_files_spec.root, cli_test_name)
                    if self.category == '' or cli_test_name.startswith(self.category):
                        self.create_and_run_test_obj(cliQuery, test.get('expected', 0))


def main(argv=None):
    base_dir = os.path.abspath(os.path.dirname(sys.argv[0]))
    os.chdir(base_dir)

    parser = argparse.ArgumentParser(description='Testing network configuration analyzer')
    parser.add_argument('--type', choices=['general', 'k8s_live_general', 'fw_rules_assertions'],
                        help='Choose test types to run',
                        default='general')
    parser.add_argument('--category', choices=['k8s', 'calico', 'istio'], help='Choose category of tests',
                        default='')
    parser.add_argument('--create_expected_output_files', action='store_true', help='Add missing expected output files')
    parser.add_argument('--override_expected_output_files',
                        action='store_true', help='update existing expected output files')
    parser.add_argument('--check_run_time', action='store_true', help='Print tests_failed_runtime_check.csv, '
                                                   'list of tests with unexpected run time performance')

    args = parser.parse_args(argv)
    test_type = args.type
    category = args.category
    check_run_time = args.check_run_time
    OutputFilesFlags().create_expected_files = args.create_expected_output_files
    OutputFilesFlags().update_expected_files = args.override_expected_output_files
    if category != '' and test_type != 'general':
        print(f'category: {category} is not supported with test type: {test_type}')
    if check_run_time and test_type != 'general':
        print(f'check_run_time flag is not supported with test type: {test_type}')
        sys.exit(1)

    spec_file = 'all_tests_spec.yaml'
    tests_runner = TestsRunner(spec_file, test_type, check_run_time, category)
    tests_runner.run_tests()
    return tests_runner.global_res or tests_runner.new_tests_error


if __name__ == "__main__":
    sys.exit(main())
