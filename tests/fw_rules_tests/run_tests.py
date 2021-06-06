import sys
import os
from fnmatch import fnmatch
from os import path
from time import time
from nca import nca_main
from pathlib import Path


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


def run_simple_test(scheme_filename, args, all_results):
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
    return test_res


def run_new_output_test(scheme_filename, args, all_results, file_type):
    print('------------------------------------')
    print('Running testcase', scheme_filename)
    start_time = time()

    res = nca_main(args)

    test_failure_list = []
    if file_type == 'yaml':
        actual_output_file_path = get_output_path(scheme_filename, True, 'yaml')
        expected_output_file_path = get_output_path(scheme_filename, False, 'yaml')
        # yaml_comparison = compare_yaml_output_files(actual_output_file_path, expected_output_file_path)
        yaml_comparison = compare_files(actual_output_file_path, expected_output_file_path)
        if not yaml_comparison:
            test_failure_list.append('yaml')
        test_passed = yaml_comparison
    elif file_type == 'txt':
        actual_output_file_path = get_output_path(scheme_filename, True, 'txt')
        expected_output_file_path = get_output_path(scheme_filename, False, 'txt')
        txt_comparison = compare_files(actual_output_file_path, expected_output_file_path)
        if not txt_comparison:
            test_failure_list.append('txt')
        test_passed = txt_comparison
    else:
        print(f'illegal file type: {file_type}')
        sys.exit()
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
    if file_type == 'txt':
        output_file_name = os.path.basename(scheme_filename).replace(".yaml", "_output.txt")
    elif file_type == 'yaml':
        output_file_name = os.path.basename(scheme_filename).replace(".yaml", "_output.yaml")
    else:
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

    expected_txt_output_file_path = get_output_path(scheme_filename, False, 'txt')
    if not os.path.isfile(expected_txt_output_file_path):
        Path(os.path.join(scheme_dir, expected_output_dir_name)).mkdir(parents=True, exist_ok=True)
        Path(os.path.join(scheme_dir, actual_output_dir_name)).mkdir(parents=True, exist_ok=True)
        # run the test and create the expected results files
        args = get_test_args(scheme_filename, 'txt', expected_txt_output_file_path)

        nca_main(args)

    expected_yaml_output_file_path = get_output_path(scheme_filename, False, 'yaml')
    if not os.path.isfile(expected_yaml_output_file_path):
        Path(os.path.join(scheme_dir, expected_output_dir_name)).mkdir(parents=True, exist_ok=True)
        Path(os.path.join(scheme_dir, actual_output_dir_name)).mkdir(parents=True, exist_ok=True)
        # run the test and create the expected results files
        args = get_test_args(scheme_filename, 'yaml', expected_yaml_output_file_path)

        nca_main(args)

    if not os.path.isdir(os.path.join(scheme_dir, actual_output_dir_name)):
        Path(os.path.join(scheme_dir, actual_output_dir_name)).mkdir(parents=True, exist_ok=True)

    actual_txt_output_file_path = get_output_path(scheme_filename, True, 'txt')
    actual_yaml_output_file_path = get_output_path(scheme_filename, True, 'yaml')
    if os.path.isfile(actual_txt_output_file_path):
        os.remove(actual_txt_output_file_path)
    if os.path.isfile(actual_yaml_output_file_path):
        os.remove(actual_yaml_output_file_path)


def get_test_args(scheme_filename, output_format=None, output_path=None, test_mode=None):
    res = ['--scheme', scheme_filename]
    if output_format is not None:
        res.append('--o')
        res.append(output_format)
    if output_path is not None:
        res.append('--f')
        res.append(output_path)
    if test_mode is not None and test_mode:
        res.append('--fw_rules_test_mode')
        res.append(str(test_mode))
    return res


def main():
    base_dir = os.path.abspath(os.path.dirname(sys.argv[0]))
    global_res = 0
    all_results = {}
    print(base_dir)

    test_prefix = input("Enter test name prefix (empty for all tests):")

    if len(test_prefix) == 0:
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

    my_files = []

    for root, _, files in os.walk(base_dir):
        for file in files:
            if not fnmatch(file, '*_scheme.yaml'):
                continue
            scheme_filename = os.path.join(root, file)
            # print(scheme_filename)
            if run_all_tests or file.startswith(test_prefix):
                my_files.append(scheme_filename)

    for scheme_filename in my_files:
        # print(scheme_filename)
        # print(os.path.basename(scheme_filename).replace(".yaml", ""))
        if compare_output:
            prepare_new_test_if_required(scheme_filename)
            txt_output_path = get_output_path(scheme_filename, True, 'txt')
            yaml_output_path = get_output_path(scheme_filename, True, 'yaml')
            global_res += run_new_output_test(scheme_filename, get_test_args(scheme_filename, 'txt', txt_output_path),
                                              all_results, 'txt')
            global_res += run_new_output_test(scheme_filename, get_test_args(scheme_filename, 'yaml', yaml_output_path),
                                              all_results, 'yaml')
        else:
            global_res += run_simple_test(scheme_filename, get_test_args(scheme_filename, None, None, test_mode_flag),
                                          all_results)

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
