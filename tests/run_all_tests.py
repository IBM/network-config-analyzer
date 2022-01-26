import argparse
import shutil
import traceback
import sys
import os
from fnmatch import fnmatch
from os import path
from time import time
from pathlib import Path
import yaml
import csv
from ruamel.yaml import YAML

sys.path.append(os.path.dirname(os.path.dirname(os.path.realpath(__file__))))
sys.path.append(os.path.join(os.path.dirname(os.path.dirname(os.path.realpath(__file__))), 'network-config-analyzer'))
from nca import nca_main
from CmdlineRunner import CmdlineRunner

"""
The script runs tests based on tests specification in 'all_tests_spec.yaml'
script should be run with one of the following types:
    run_all_tests.py --type=general (default)
    run_all_tests.py --type=k8s_live_general  
    run_all_tests.py --type=fw_rules_assertions 
    run_all_test.py --type=output_configuration
    
    optional flags:
    --dont_clean_output_files   (will save output files in tests/actual_output_files.
                                 by default cleaning generated output files)
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
            if '/' in arg and not arg.startswith('https://github'):
                self.args[idx] = os.path.join(base_dir, arg)

    def get_arg_value(self, arg_str_list):
        for index, arg in enumerate(self.args):
            if arg in arg_str_list:
                arg_val = self.args[index + 1]
                return True, arg_val
        return False, ''

    # assuming that out_file as arg to cli test is a base name, with no path involved
    def has_out_file_arg(self):
        return self.get_arg_value(['-f', '--file_out'])

    def has_out_format_arg(self):
        return self.get_arg_value(['-o', '--output_format'])

    def has_out_format_arg_with_val(self, out_format_val):
        _, actual_val = self.has_out_format_arg()
        return actual_val == out_format_val


class CliQuery:
    def __init__(self, test_dict, cli_tests_base_dir, test_name):
        self.test_dict = test_dict
        self.query_name = self.test_dict['name']
        self.test_name = test_name
        self.args_obj = TestArgs(test_dict['args'].split(), cli_tests_base_dir)
        self.list_expected_output_files = self._get_list_of_expected_output_files()

    # should be only the base file names, no full path
    def _get_list_of_expected_output_files(self):
        has_out_file_arg, out_file_arg_str = self.args_obj.has_out_file_arg()
        if has_out_file_arg:
            return [out_file_arg_str]


class SchemeFile:
    def __init__(self, scheme_filename, test_args):
        self.scheme_filename = scheme_filename
        self.args_obj = TestArgs(test_args)
        self.list_expected_output_files = self._get_list_of_expected_output_files()
        self.test_name = self.get_test_name()

    # get an informative test name, which includes cli args if used, apart from the scheme file name
    def get_test_name(self):
        has_out_format, out_format = self.args_obj.has_out_format_arg()
        has_out_file, out_file = self.args_obj.has_out_file_arg()
        args_str = ''
        if has_out_format:
            args_str += f' -o {out_format} '
        if has_out_format:
            args_str += f' -f {os.path.basename(out_file)} '
        test_name = f'{self.scheme_filename} [{args_str}]' if args_str else self.scheme_filename
        return test_name

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

    # get expected output files from outputConfig / output file args, that are expected to be created
    # should be only the base file names, no full path
    def _get_list_of_expected_output_files(self):
        expected_output_files_for_valid_queries = set()
        has_out_file_arg, out_file_arg = self.args_obj.has_out_file_arg()
        if has_out_file_arg:
            return [out_file_arg]
        with open(self.scheme_filename, 'r') as scheme_file:
            scheme = yaml.safe_load(scheme_file)
            for query in scheme.get('queries', []):
                actual_out_path = query.get('outputConfiguration', {}).get('outputPath', None)
                if actual_out_path:
                    expected_output_files_for_valid_queries.add(actual_out_path)
        return list(expected_output_files_for_valid_queries)


# general test: comparison of numerical result (nca return value) to expected value
# most of the test flow is common to other tests types
class GeneralTest:

    def __init__(self, test_name, test_queries_obj, expected_result, clean_out_files, check_run_time, required_output_config_flag, create_files, update_files):
        self.test_name = test_name  # str
        self.test_queries_obj = test_queries_obj  # SchemeFile or CliQuery
        self.result = None  # tuple of (numerical result, test runtime)
        self.numerical_result = None  # assigned with numerical result after test run
        self.start_time = None
        self.nca_res = None
        self.expected_result = expected_result  # integer - expected return value from nca
        self.clean_out_files = clean_out_files
        self.check_run_time = check_run_time
        self.required_output_config_flag = required_output_config_flag
        self.create_files = create_files
        self.update_files = update_files

    def initialize_test(self):
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
        return nca_main(self.test_queries_obj.args_obj.args, self.create_files, self.update_files)

    def move_output_files_to_dedicated_dir(self):
        # move actual out file from current dir to actual_output_files dir
        if self.test_queries_obj.list_expected_output_files is not None:
            for out_file in self.test_queries_obj.list_expected_output_files:
                actual_out_file = TestsRunner.get_actual_out_file_path(out_file)
                if Path(os.path.basename(actual_out_file)).exists():
                    shutil.move(os.path.basename(actual_out_file), actual_out_file)

    def run_test(self):
        self.nca_res = self.run_nca()  # either run a scheme or a query, with relevant args
        self.move_output_files_to_dedicated_dir()

    # update self.numerical_result, return true if test passed
    def evaluate_test_results(self):
        self.numerical_result = 1 if self.nca_res != self.expected_result else 0

    def _get_expected_test_run_time(self):
        expected_time_file_name = "./tests_expected_runtime.csv"
        with open(expected_time_file_name, 'r') as csv_file:
            csv_reader = csv.reader(csv_file)
            for row in csv_reader:
                current_test = row[0] if 'cmdline_' in row[0] else os.path.abspath(row[0])
                if current_test == self.test_name:
                    return float(row[1])
        csv_file.close()
        return 0.0

    def _execute_run_time_compare(self, actual_run_time):
        output_file = "./tests_failed_runtime_check.csv"
        write_header = False
        expected_run_time = self._get_expected_test_run_time()
        if actual_run_time >= expected_run_time * 2:
            if not path.isfile(output_file):
                write_header = True
            with open(output_file, 'a') as csv_file:
                csv_writer = csv.writer(csv_file)
                if write_header:
                    csv_writer.writerow(['test_name', 'expected_run_time (seconds)', 'actual_run_time (seconds)'])
                csv_writer.writerow([self.test_name, expected_run_time, f'{actual_run_time:.2f}'])
            csv_file.close()

    def finalize_test(self):
        if not self.test_passed():
            print('Testcase', self.test_name, 'failed', file=sys.stderr)
        else:
            print('Testcase', self.test_name, 'passed')
        actual_run_time = time() - self.start_time
        self.result = (self.numerical_result, actual_run_time)
        if self.check_run_time:
            self._execute_run_time_compare(actual_run_time)
        if self.clean_out_files:
            self._clean_generated_output_files()
        self._update_required_scheme_file_config_args(False)

    def _clean_generated_output_files(self):
        if self.test_queries_obj.list_expected_output_files is not None:
            for out_file in self.test_queries_obj.list_expected_output_files:
                self._delete_output_file(out_file)

    def _delete_output_file(self, out_file):
        out_file_actual = TestsRunner.get_actual_out_file_path(out_file)
        if path.isfile(out_file_actual):
            os.remove(out_file_actual)

    def _update_required_scheme_file_config_args(self, before_test_run):
        if self.required_output_config_flag is not None:
            if isinstance(self.test_queries_obj, SchemeFile):
                self.test_queries_obj.update_arg_at_scheme_file_output_config(self.required_output_config_flag,
                                                                              before_test_run)


# for fw-rules - activate assertions for testing in fwRulesTestMode
class AssertionTest(GeneralTest):
    def __init__(self, test_name, test_queries_obj, clean_out_files, required_output_config_flag, create_files, update_files):
        super().__init__(test_name, test_queries_obj, None, clean_out_files, None, required_output_config_flag, create_files, update_files)
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
        self.move_output_files_to_dedicated_dir()

    def evaluate_test_results(self):
        self.numerical_result = 0 if self.assertion_error is None else 1


class OutputConfigTest(GeneralTest):
    def __init__(self, test_name, test_queries_obj, expected_res, clean_out_files, required_output_config_flag, create_files, update_files):
        super().__init__(test_name, test_queries_obj, expected_res, clean_out_files, None, required_output_config_flag, create_files, update_files)


class TestFilesSpec(dict):
    def __init__(self, tests_spec_dict=None):
        default_tests_spec = {'type': None, 'root': None, 'expected_output': None, 'out_format_arg': None,
                              'add_out_path_arg': False, 'files_list': None, 'out_path_arg_suffix': '_output',
                              'activate_output_config_flag': None, 'excluded_dirs': None}
        super().__init__(default_tests_spec)
        if tests_spec_dict is not None:
            self.update(tests_spec_dict)

    def __getattr__(self, name):
        return super().__getitem__(name)


class TestsRunner:
    def __init__(self, spec_file, tests_type, clean_out_files, check_run_time, category, create_files, update_files):
        self.spec_file = spec_file
        self.all_results = {}
        self.global_res = 0
        self.tests_type = tests_type  # general / k8s_live_general / output / fw_rules_assertions
        self.test_files_spec = None
        self.clean_out_files = clean_out_files
        self.check_run_time = check_run_time
        self.category = category
        self.create_files = create_files
        self.update_files = update_files

    @staticmethod
    def k8s_apply_resources(yaml_file):
        if yaml_file:
            cmdline_list = ['kubectl', 'apply', f'-f{yaml_file}']
            CmdlineRunner.run_and_get_output(cmdline_list)

    def set_k8s_cluster_config(self, cluster_config):
        self.k8s_apply_resources(cluster_config.get('pods', ''))
        self.k8s_apply_resources(cluster_config.get('policies', ''))

    @staticmethod
    def _remove_failed_run_time_file():
        """
        removes the tests_failed_runtime_check.csv if exists from previous run
        """
        file_name = "./tests_failed_runtime_check.csv"
        if path.isfile(file_name):
            os.remove(file_name)

    def run_tests(self):
        if self.check_run_time:
            self._remove_failed_run_time_file()
        with open(self.spec_file, 'r') as doc:
            spec_all = yaml.safe_load(doc)
            sepc_per_type = spec_all.get(self.tests_type, {})
            for test_spec in sepc_per_type:
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
        print('\n\nSummary\n-------')
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

    def run_tests_spec(self, tests_spec):
        self.test_files_spec = TestFilesSpec(tests_spec)
        for root, _, files in os.walk(self.test_files_spec.root):
            for file in files:
                if self.test_files_spec.files_list and os.path.basename(file) not in self.test_files_spec.files_list:
                    continue
                if self.test_files_spec.type == 'scheme' and not fnmatch(file, '*-scheme.yaml'):
                    continue
                file_path = os.path.join(os.path.abspath(root), file)
                if self.test_files_spec.excluded_dirs and any(dir_name in file_path for dir_name in self.test_files_spec.excluded_dirs):
                    continue
                self.run_test_per_file(file_path)

    def create_and_run_test_obj(self, test_queries_obj_list, expected_res):
        for test_queries_obj in test_queries_obj_list:
            # create test object
            test_obj = None
            required_output_config_flag = self.test_files_spec.activate_output_config_flag
            if self.tests_type in {'general', 'k8s_live_general'}:
                test_obj = GeneralTest(test_queries_obj.test_name, test_queries_obj, expected_res, self.clean_out_files,
                             self.check_run_time, required_output_config_flag, self.create_files, self.update_files)
            elif self.tests_type == 'fw_rules_assertions':
                test_obj = AssertionTest(test_queries_obj.test_name, test_queries_obj, self.clean_out_files,
                                         required_output_config_flag, self.create_files, self.update_files)
            elif self.tests_type == 'output_configuration':
                test_obj = OutputConfigTest(test_queries_obj.test_name, test_queries_obj, expected_res,
                                self.clean_out_files, required_output_config_flag, self.create_files, self.update_files)
            self.global_res += test_obj.run_all_test_flow(self.all_results)

    def _test_file_matches_category_by_file_name(self, test_file):
        # for tests files under fw_rules_tests and output_configs_tests dirs
        if self.category == '':
            return True
        file_name = os.path.basename(test_file)
        if file_name.startswith(self.category):
            return True
        if self.category == 'k8s' and not file_name.startswith(('calico', 'istio')):
            return True
        return False

    def _test_file_matches_category_general_tests(self, test_file):
        if self.category == '':
            return True
        if self.category + '_testcases' in test_file:
            return True
        if '_testcases' not in test_file:
            return self._test_file_matches_category_by_file_name(test_file)
        return False

    # given a scheme file or a cmdline file, run all relevant tests
    def run_test_per_file(self, test_file):
        if self.test_files_spec.type == 'scheme':
            if self.tests_type in {'general', 'fw_rules_assertions'}:
                if self.tests_type == 'general' and not self._test_file_matches_category_general_tests(test_file):
                    return  # test file does not match the running category
                scheme_obj_list = [SchemeFile(test_file, self._get_scheme_test_args(test_file))]
            else:
                scheme_obj_list = self.get_scheme_obj_list_for_test(test_file)
            self.create_and_run_test_obj(scheme_obj_list, 0)

        elif self.test_files_spec.type == 'cmdline':
            with open(test_file) as doc:
                code = YAML().load_all(doc)
                for test in next(iter(code)):
                    query_name = test.get('name', '')
                    cli_test_name = f'{os.path.basename(test_file)}, query name: {query_name}'
                    cliQuery = CliQuery(test, self.test_files_spec.root, cli_test_name)
                    if self.category == '' or cli_test_name.startswith(self.category):
                        self.create_and_run_test_obj([cliQuery], test.get('expected', 0))

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
    def get_scheme_obj_list_for_test(self, test_file):
        res = []
        if self.test_files_spec.out_format_arg:
            for out_format in self.test_files_spec.out_format_arg:
                out_file_arg = self.get_out_file_arg(test_file, out_format)
                test_args = self._get_scheme_test_args(test_file, out_format, out_file_arg)
                scheme_obj = SchemeFile(test_file, test_args)
                res.append(scheme_obj)
        else:
            out_file_arg = self.get_out_file_arg(test_file)
            test_args = self._get_scheme_test_args(test_file, None, out_file_arg)
            scheme_obj = SchemeFile(test_file, test_args)
            res = [scheme_obj]
        return res

    # relevant for a scheme file, when overriding outputConfig with out_file_arg from cli
    def get_out_file_arg(self, test_file, out_format='txt'):
        if self.test_files_spec.add_out_path_arg:
            suffix = f'{self.test_files_spec.out_path_arg_suffix}.{out_format}'
            return os.path.basename(test_file).replace(".yaml", suffix)
        return None

    @staticmethod
    def get_actual_output_dir():
        return os.path.join('.', 'actual_output_files')

    @staticmethod
    def get_actual_out_file_path(out_file):
        return os.path.join(TestsRunner.get_actual_output_dir(), out_file)


def main(argv=None):
    base_dir = os.path.abspath(os.path.dirname(sys.argv[0]))
    os.chdir(base_dir)

    parser = argparse.ArgumentParser(description='Testing network configuration analyzer')
    parser.add_argument('--type', choices=['general', 'k8s_live_general', 'fw_rules_assertions', 'output_configuration'],
                        help='Choose test types to run',
                        default='general')
    parser.add_argument('--category', choices=['k8s', 'calico', 'istio'], help='Choose category of tests',
                        default='')
    parser.add_argument('--dont_clean_output_files', action='store_true', help='Do not clean output files')
    parser.add_argument('--create_expected_output_files', action='store_true', help='Add missing expected output files')
    parser.add_argument('--override_expected_output_files',
                        action='store_true', help='update existing expected output files')
    parser.add_argument('--check_run_time', action='store_true', help='Print tests_failed_runtime_check.csv, '
                                                   'list of tests with unexpected run time performance')

    args = parser.parse_args(argv)
    test_type = args.type
    category = args.category
    clean_out_files = not args.dont_clean_output_files
    check_run_time = args.check_run_time
    create_files = args.create_expected_output_files
    update_files = args.override_expected_output_files
    if category != '' and test_type != 'general':
        print(f'category: {category} is not supported with test type: {test_type}')
    if check_run_time and test_type != 'general':
        print(f'check_run_time flag is not supported with test type: {test_type}')
        sys.exit(1)

    spec_file = 'all_tests_spec.yaml'
    tests_runner = TestsRunner(spec_file, test_type, clean_out_files, check_run_time, category, create_files, update_files)
    tests_runner.run_tests()
    return tests_runner.global_res


if __name__ == "__main__":
    sys.exit(main())
