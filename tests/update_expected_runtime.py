import sys
import os
import csv
import argparse
from run_all_tests import TestsRunner

# global variables - files names
expected_runtime_files_to_logs = {'tests/expected_runtime/calico_tests_expected_runtime.csv': 'tests/calico_log.txt',
                                  'tests/expected_runtime/istio_tests_expected_runtime.csv': 'tests/istio_log.txt',
                                  'tests/expected_runtime/k8s_tests_expected_runtime.csv': 'tests/k8s_log.txt'}
special_test_cases = ('git-resource-test-scheme.yaml', 'git_resources')


def _get_run_log_summary_lines(log_file):
    # getting the runtime of test from the log's summary
    with open(log_file, 'r') as f:
        lines = f.readlines()
    start_idx = 0
    end_idx = -1
    for idx, line in enumerate(lines):
        if 'Passed Tests:' in line:
            start_idx = idx + 1
        if 'Tests Performance Issues:' in line:
            end_idx = idx
    return lines[start_idx:end_idx]


def _get_test_name_from_line(line):
    if 'cmdline_' in line:
        return line.split('(')[0].rstrip()
    else:
        return line.split('/tests/')[1].split('(')[0].rstrip()


def _get_test_run_time_from_line(line):
    run_time = line.split('(')[1].split(' ')[0]
    # multiplying the runtime of tests in the special_test_cases tuple, since their running time may vary for each run
    test_name = _get_test_name_from_line(line)
    if test_name.endswith(special_test_cases):
        run_time = format(float(run_time) * 2, '.2f')
    return run_time


def _get_new_run_time(test_name, log_file):
    lines = _get_run_log_summary_lines(log_file)
    for line in lines:
        if test_name in line:
            return _get_test_run_time_from_line(line)

    return ''  # should not get here


def _update_run_time_in_row(row, new_run_time):
    row_list = row.split(',')
    row_list[1] = new_run_time + '\n'
    return ','.join(row_list)


def _update_or_delete_file_rows(lines_to_update, lines_to_delete, expected_runtime_file):
    print('Updating the runtime of modified tests and deleting the rows of deleted tests (if any)')
    lines_to_delete.sort(reverse=True)
    # get the lines of the tests_expected_runtime.csv file as a list
    with open(expected_runtime_file, 'r') as f:
        lines = f.readlines()
    # update the relevant rows in the lines list
    for line_num, test_name in lines_to_update:
        lines[line_num-1] = _update_run_time_in_row(lines[line_num-1], _get_new_run_time(test_name, expected_runtime_files_to_logs[expected_runtime_file]))
    # delete the rows to delete in the lines list - in descending order
    for line_num in lines_to_delete:
        del lines[line_num - 1]
    # write the new lines list into the file again
    with open(expected_runtime_file, 'w', newline='') as f:
        for line in lines:
            f.write(line)


def _add_test_to_expected_runtime_file(test_name, run_time, expected_runtime_file):
    with open(expected_runtime_file, 'a', newline='') as csv_file:
        csv_writer = csv.writer(csv_file)
        csv_writer.writerow([test_name, run_time])
    csv_file.close()


def _add_cmdline_tests_to_file(expected_runtime_file):
    print('Updating cmdline tests with their new runtime')
    lines = _get_run_log_summary_lines(expected_runtime_files_to_logs[expected_runtime_file])
    for line in lines:
        if 'cmdline_' in line:
            _add_test_to_expected_runtime_file(_get_test_name_from_line(line), _get_test_run_time_from_line(line), expected_runtime_file)


def _update_tests_runtime(modified_tests_list):
    """
    This function updates tests expected runtime files for tests that were changed in recent commits.
    :param modified_tests_list: taken from the output of 'git diff' command. Includes:
    Added tests - a new row of test name and its runtime will be added to the file for each new test.
    Modified tests - this function updates the last runtime of the modified tests in the expected runtime file.
    Note that if the cmdline tests file (k8s_cmdline_tests.yaml) was modified, the function will reset and update
    the runtime for all the queries in the file not only the modified/new ones.
    Renamed tests -  this function adds a new row with the new name of the renamed test in tests_expected_runtime.csv,
    the row with the old name will not be removed as it will not appear in the git diff cmd output.
    Deleted tests - this function removes the rows of deleted tests in tests_expected_runtime.csv.
    """
    lines_to_delete_by_file = {}
    lines_to_update_by_file = {}
    for file in expected_runtime_files_to_logs.keys():
        lines_to_delete_by_file[file] = []
        lines_to_update_by_file[file] = []
    cmdline_flag = False
    cmdline_file = ''
    for test in modified_tests_list:
        test_category = TestsRunner.determine_test_category(test)
        expected_runtime_file = f'tests/expected_runtime/{test_category}_tests_expected_runtime.csv'
        found_test = False
        delete_flag = False
        if not os.path.exists(test):  # Deleted tests
            delete_flag = True
        if 'k8s_cmdline_tests.yaml' in test:  # cmdline tests
            delete_flag = True
            cmdline_flag = True
            cmdline_file = expected_runtime_file
        with open(expected_runtime_file, 'r') as read_obj:
            line_number = 0
            # Read all lines in the file one by one
            for line in read_obj:
                # For each line, check if line contains the test name
                line_number += 1
                test_name = test.split('/', 1)[1]
                if test_name in line:
                    found_test = True
                    if delete_flag:
                        lines_to_delete_by_file[expected_runtime_file].append(line_number)
                    else:  # Modified Tests
                        lines_to_update_by_file[expected_runtime_file].append((line_number, test))
            if not found_test:  # Added Tests / Renamed Tests (the new name)
                print(f'Adding new row for {test} with its expected runtime')
                _add_test_to_expected_runtime_file(test_name, _get_new_run_time(test_name, expected_runtime_files_to_logs[expected_runtime_file]), expected_runtime_file)

    for file in expected_runtime_files_to_logs.keys():
        if lines_to_update_by_file[file] or lines_to_delete_by_file[file]:
            _update_or_delete_file_rows(lines_to_update_by_file[file], lines_to_delete_by_file[file], file)
    if cmdline_flag:
        _add_cmdline_tests_to_file(cmdline_file)


def _reset_expected_runtime_file(expected_runtime_file):
    with open(expected_runtime_file, 'w', newline='') as csv_file:
        csv_writer = csv.writer(csv_file)
        csv_writer.writerow(['test', 'run_time(seconds)'])
    csv_file.close()


def _reset_tests_runtime():
    """
    This function updates tests expected runtime files by resetting the runtime of all existing tests.
    """
    print('Resetting all tests with their last runtime...')
    for runtime_file, log_file in expected_runtime_files_to_logs.items():
        _reset_expected_runtime_file(runtime_file)
        lines = _get_run_log_summary_lines(log_file)
        for line in lines:
            if '-scheme.yaml' in line or 'cmdline_' in line:
                _add_test_to_expected_runtime_file(_get_test_name_from_line(line), _get_test_run_time_from_line(line), runtime_file)


def _sort_expected_runtime_file_lines(expected_runtime_file):
    with open(expected_runtime_file, 'r') as f:
        lines = f.readlines()
    lines_to_sort = lines[1:]
    lines_to_sort.sort()
    with open(expected_runtime_file, 'w', newline='') as f:
        f.write(lines[0])
        for line in lines_to_sort:
            f.write(line)


def main(argv=None):
    base_dir = os.path.split(os.path.abspath(os.path.dirname(sys.argv[0])))[0]
    os.chdir(base_dir)
    parser = argparse.ArgumentParser(description='Updating the tests expected runtime files')
    parser.add_argument('--changed_tests', nargs='+', help='list of the added, modified, deleted or renamed tests.'
                                                           ' Or ALL_TESTS to reset and update runtime for all tests')

    args = parser.parse_args(argv)
    modified_tests_list = args.changed_tests
    print('Starting to update tests expected runtime files:')
    if 'ALL_TESTS' in modified_tests_list:
        _reset_tests_runtime()
    else:
        _update_tests_runtime(modified_tests_list)

    for file in expected_runtime_files_to_logs.keys():
        _sort_expected_runtime_file_lines(file)
    print('Updating tests expected runtime files was successfully completed')
    return 0


if __name__ == "__main__":
    sys.exit(main())
