import sys
import os
import csv
import argparse

# global variables - files names
run_log = 'tests/run_log.txt'
expected_time_file = 'tests/tests_expected_runtime.csv'


def _get_run_log_summary_lines():
    # getting the runtime of test from the log's summary
    with open(run_log, 'r') as f:
        lines = f.readlines()
    start_idx = 0
    for idx, line in enumerate(lines):
        if 'Passed Tests:' in line:
            start_idx = idx + 1
    return lines[start_idx:]


def _get_test_name_from_line(line):
    if 'cmdline_' in line:
        return line.split('(')[0].rstrip()
    else:
        return line.split('/tests/')[1].split('(')[0].rstrip()


def _get_test_run_time_from_line(line):
    return line.split('(')[1].split(' ')[0]


def _get_new_run_time(test_name):
    lines = _get_run_log_summary_lines()
    for line in lines:
        if test_name in line:
            return _get_test_run_time_from_line(line)

    return ''  # should not get here


def _update_run_time_in_row(row, new_run_time):
    row_list = row.split(',')
    row_list[1] = new_run_time + '\n'
    return ','.join(row_list)


def _update_or_delete_file_rows(lines_to_update, lines_to_delete):
    print('Updating the runtime of modified tests and deleting the rows of deleted tests (if any)')
    lines_to_delete.sort(reverse=True)
    # get the lines of the tests_expected_runtime.csv file as a list
    with open(expected_time_file, 'r') as f:
        lines = f.readlines()
    # update the relevant rows in the lines list
    for line_num, test_name in lines_to_update:
        lines[line_num-1] = _update_run_time_in_row(lines[line_num-1], _get_new_run_time(test_name))
    # delete the rows to delete in the lines list - in descending order
    for line_num in lines_to_delete:
        del lines[line_num - 1]
    # write the new lines list into the file again
    with open(expected_time_file, 'w', newline='') as f:
        for line in lines:
            f.write(line)


def _add_test_to_expected_runtime_file(test_name, run_time):
    with open(expected_time_file, 'a', newline='') as csv_file:
        csv_writer = csv.writer(csv_file)
        csv_writer.writerow([test_name, run_time])
    csv_file.close()


def _add_cmdline_tests_to_file():
    print('Updating cmdline tests with their new runtime')
    lines = _get_run_log_summary_lines()
    for line in lines:
        if 'cmdline_' in line:
            _add_test_to_expected_runtime_file(_get_test_name_from_line(line), _get_test_run_time_from_line())


def _update_tests_runtime(modified_tests_list):
    """
    This function updates tests_expected_runtime.csv file for tests that were changed in recent commits.
    :param modified_tests_list: taken from the output of 'git diff' command. Includes:
    Added tests - a new row of test name and its runtime will be added to the file for each new test.
    Modified tests - this function updates the last runtime of the modified tests in the expected runtime file.
    Renamed tests -  this function adds a new row with the new name of the renamed test in tests_expected_runtime.csv,
    the row with the old name will not be removed as it will not appear in the git diff cmd output.
    Deleted tests - this function removes the rows of deleted tests in tests_expected_runtime.csv.
    """
    lines_to_delete = []
    lines_to_update = []
    cmdline_flag = False
    for test in modified_tests_list:
        found_test = False
        delete_flag = False
        if not os.path.exists(test):  # Deleted tests
            delete_flag = True
        if 'k8s_cmdline_tests.yaml' in test:  # cmdline tests
            delete_flag = True
            cmdline_flag = True
        with open(expected_time_file, 'r') as read_obj:
            line_number = 0
            # Read all lines in the file one by one
            for line in read_obj:
                # For each line, check if line contains the test name
                line_number += 1
                test_name = test.split('/', 1)[1]
                if test_name in line:
                    found_test = True
                    if delete_flag:
                        lines_to_delete.append(line_number)
                    else:  # Modified Tests
                        lines_to_update.append((line_number, test))
            if not found_test:  # Added Tests / Renamed Tests (the new name)
                print(f'Adding new row for {test_name} with its expected runtime')
                _add_test_to_expected_runtime_file(test_name, _get_new_run_time(test_name))

    if lines_to_update or lines_to_delete:
        _update_or_delete_file_rows(lines_to_update, lines_to_delete)
    if cmdline_flag:
        _add_cmdline_tests_to_file()


def _reset_expected_runtime_file():
    with open(expected_time_file, 'w', newline='') as csv_file:
        csv_writer = csv.writer(csv_file)
        csv_writer.writerow(['test', 'run_time(seconds)'])
    csv_file.close()


def _reset_tests_runtime():
    print('Resetting all tests with their last runtime...')
    _reset_expected_runtime_file()
    lines = _get_run_log_summary_lines()
    for line in lines:
        if 'tests/' in line or 'cmdline_' in line:
            _add_test_to_expected_runtime_file(_get_test_name_from_line(line), _get_test_run_time_from_line(line))


def main(argv=None):
    base_dir = os.path.split(os.path.abspath(os.path.dirname(sys.argv[0])))[0]
    os.chdir(base_dir)
    parser = argparse.ArgumentParser(description='Updating the tests_expected_runtime.csv file')
    parser.add_argument('--changed_tests', nargs='+', help='list of the added, modified, deleted or renamed tests.'
                                                           ' Or ALL_TESTS to reset and update runtime for all tests')

    args = parser.parse_args(argv)
    modified_tests_list = args.changed_tests
    print('Starting to update tests/tests_expected_runtime.csv file:')
    if 'ALL_TESTS' in modified_tests_list:
        _reset_tests_runtime()
    else:
        _update_tests_runtime(modified_tests_list)

    print('Updating tests_expected_runtime.csv file was successfully completed')
    return 0


if __name__ == "__main__":
    sys.exit(main())
