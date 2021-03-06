import sys
import os
from fnmatch import fnmatch
from os import path
from time import time
import argparse
import yaml
from pathlib import Path

sys.path.append(os.path.join(os.path.dirname(os.path.dirname(os.path.realpath(__file__))), '..'))
sys.path.append(
    os.path.join(os.path.dirname(os.path.dirname(os.path.realpath(__file__))), '..', 'network-config-analyzer'))
from nca import nca_main

supported_formats = ['txt', 'yaml', 'csv', 'md']


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


def update_test_mode_at_scheme_file(scheme_filename, add_test_mode):
    with open(scheme_filename, 'r') as scheme_file:
        scheme = yaml.safe_load(scheme_file)
        for query in scheme['queries']:
            if 'outputConfiguration' in query:
                output_config = query['outputConfiguration']
                output_config.update({'fwRulesRunInTestMode': add_test_mode})
            else:
                query.update({'outputConfiguration': {'fwRulesRunInTestMode': add_test_mode}})
    with open(scheme_filename, 'w') as scheme_file:
        yaml.dump(scheme, scheme_file, default_flow_style=False, sort_keys=False)


def run_simple_test(scheme_filename, args, all_results, test_mode_flag):
    if test_mode_flag:
        update_test_mode_at_scheme_file(scheme_filename, True)
    print('------------------------------------')
    print('Running testcase', scheme_filename, args)
    start_time = time()

    res = nca_main(args)

    test_res = (res != 0)
    if test_res:
        print('Testcase', scheme_filename, 'failed', file=sys.stderr)
    else:
        print('Testcase', scheme_filename, 'passed')
    all_results[scheme_filename] = (test_res, time() - start_time)

    if test_mode_flag:
        update_test_mode_at_scheme_file(scheme_filename, False)
    return test_res


def run_new_output_test(scheme_filename, args, all_results, file_type):
    if file_type not in supported_formats:
        print(f'illegal file type: {file_type}')
        sys.exit()

    print('------------------------------------')
    print('Running testcase', scheme_filename)
    start_time = time()

    nca_main(args)

    test_failure_list = []
    actual_output_file_path = get_output_path(scheme_filename, True, file_type)
    expected_output_file_path = get_output_path(scheme_filename, False, file_type)
    comparison = compare_files(actual_output_file_path, expected_output_file_path)
    if not comparison:
        test_failure_list.append(file_type)
    test_passed = comparison
    test_failure_str = str(test_failure_list)

    test_res = not test_passed
    if test_res:
        print('Testcase', scheme_filename, 'failed at: ', test_failure_str, file=sys.stderr)
    else:
        print('Testcase', scheme_filename, 'passed')
    all_results[scheme_filename + f' , test_type: {file_type}'] = (test_res, time() - start_time)
    if test_passed and os.path.exists(actual_output_file_path):
        os.remove(actual_output_file_path)

    return test_res


def get_output_path(scheme_filename, is_actual, file_type):
    actual_output_dir_name = "actual_output"
    expected_output_dir_name = "expected_output"
    output_file_name = os.path.basename(scheme_filename).replace(".yaml", f"_output.{file_type}")
    if file_type not in supported_formats:
        print(f'illegal file type: {file_type}')
        sys.exit()
    scheme_dir = os.path.dirname(scheme_filename)
    if is_actual:
        return os.path.join(scheme_dir, actual_output_dir_name, output_file_name)
    return os.path.join(scheme_dir, expected_output_dir_name, output_file_name)


def prepare_new_test_if_required(scheme_filename):
    actual_output_dir_name = "actual_output"
    expected_output_dir_name = "expected_output"
    scheme_dir = os.path.dirname(scheme_filename)

    for out_format in supported_formats:
        expected_output_file_path = get_output_path(scheme_filename, False, out_format)
        if not os.path.isfile(expected_output_file_path):
            Path(os.path.join(scheme_dir, expected_output_dir_name)).mkdir(parents=True, exist_ok=True)
            Path(os.path.join(scheme_dir, actual_output_dir_name)).mkdir(parents=True, exist_ok=True)
            # run the test and create the expected results files
            args = get_test_args(scheme_filename, out_format, expected_output_file_path)
            nca_main(args)

    if not os.path.isdir(os.path.join(scheme_dir, actual_output_dir_name)):
        Path(os.path.join(scheme_dir, actual_output_dir_name)).mkdir(parents=True, exist_ok=True)

    for out_format in supported_formats:
        actual_output_file_path = get_output_path(scheme_filename, True, out_format)
        if os.path.isfile(actual_output_file_path):
            os.remove(actual_output_file_path)


def get_test_args(scheme_filename, output_format=None, output_path=None):
    res = ['--scheme', scheme_filename]
    if output_format is not None:
        res.append('-o')
        res.append(output_format)
    if output_path is not None:
        res.append('-f')
        res.append(output_path)
    return res


def main(argv=None):
    base_dir = os.path.abspath(os.path.dirname(sys.argv[0]))
    global_res = 0
    all_results = {}
    print(base_dir)

    parser = argparse.ArgumentParser()
    parser.add_argument("--all", default=False, action="store_true",
                        help="Run all fw-rules tests with output comparison")
    args = parser.parse_args(argv)
    req_format = None

    if args.all:
        run_all_tests = True
        compare_output = True
        test_mode_flag = False
        test_prefix = ''

    else:
        test_prefix = input("Enter test name prefix (empty for all tests):")
        if not test_prefix:
            run_all_tests = True
        else:
            run_all_tests = False
        output_comparison = input("run with output comparison?  (y or n):")
        if output_comparison == 'y':
            compare_output = True
        else:
            compare_output = False
        test_mode_flag = False
        if not compare_output:
            test_mode = input("run with test-mode flag?  (y or n):")
            test_mode_flag = (test_mode == 'y')
            req_format = input("required output format?  (csv/yaml/txt):")

    fw_rules_scheme_files = []
    if req_format not in supported_formats:
        req_format = 'txt'

    for root, _, files in os.walk(base_dir):
        for file in files:
            if not fnmatch(file, '*-scheme.yaml'):
                continue
            scheme_filename = os.path.join(root, file)
            if run_all_tests or file.startswith(test_prefix):
                fw_rules_scheme_files.append(scheme_filename)

    for scheme_filename in fw_rules_scheme_files:
        if compare_output:
            prepare_new_test_if_required(scheme_filename)
            for out_format in supported_formats:
                output_path = get_output_path(scheme_filename, True, out_format)
                global_res += run_new_output_test(scheme_filename,
                                                  get_test_args(scheme_filename, out_format, output_path),
                                                  all_results, out_format)
        else:
            global_res += run_simple_test(scheme_filename, get_test_args(scheme_filename, req_format, None),
                                          all_results, test_mode_flag)

    print('\n\nSummary\n-------')
    total_time = 0.
    for testcase, result in all_results.items():
        print('{0:140}{1} ({2:.2f} seconds)'.format(testcase, 'Passed' if result[0] == 0 else 'Failed', result[1]))
        total_time += result[1]

    if global_res:
        print('{0} tests failed ({1:.2f} seconds)'.format(global_res, total_time))
    else:
        print('All tests passed ({:.2f} seconds)'.format(total_time))

    return global_res


if __name__ == "__main__":
    sys.exit(main())
