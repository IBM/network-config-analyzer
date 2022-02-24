import sys
import os
import csv
import argparse

# global variables - files names
run_log = 'tests/run_log.txt'
expected_time_file = 'tests/tests_expected_runtime.csv'


def _get_new_run_time(test_name):
    with open(run_log, 'r') as f:
        lines = f.readlines()
    passed_tests = False
    for line in lines:
        if 'Passed Tests:' in line:
            passed_tests = True
        if passed_tests:  # getting the runtime of test from the log's summary
            if test_name in line:
                return line.split('(')[1].split(' ')[0]

    return ''  # should not get here


def _update_run_time_in_row(row, new_run_time):
    row_list = row.split(',')
    row_list[1] = new_run_time + '\n'
    return ','.join(row_list)


def _update_or_delete_file_rows(lines_to_update, lines_to_delete):
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


def _add_test_to_file(test_name):
    with open(expected_time_file, 'a', newline='') as csv_file:
        csv_writer = csv.writer(csv_file)
        csv_writer.writerow([test_name, _get_new_run_time(test_name)])
    csv_file.close()


def _add_cmdline_tests_to_file():
    with open(run_log, 'r') as f:
        lines = f.readlines()
    passed_tests = False
    for line in lines:
        if 'Passed Tests:' in line:
            passed_tests = True
        if passed_tests:  # getting the runtime of test from the log's summary
            if 'cmdline_' in line:
                test_name = line.split('(')[0].rstrip()
                _add_test_to_file(test_name)


def _update_tests_runtime(modified_tests_list):
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
            if not found_test:  # Added Tests
                _add_test_to_file(test_name)

    _update_or_delete_file_rows(lines_to_update, lines_to_delete)
    if cmdline_flag:
        _add_cmdline_tests_to_file()


def main(argv=None):
    base_dir = os.path.split(os.path.abspath(os.path.dirname(sys.argv[0])))[0]
    os.chdir(base_dir)
    parser = argparse.ArgumentParser(description='Updating the tests_expected_runtime.csv file')
    parser.add_argument('--changed_tests', nargs='+', help='list of the added, modified, deleted or renamed tests')

    args = parser.parse_args(argv)
    modified_tests_list = args.changed_tests

    _update_tests_runtime(modified_tests_list)
    return 0


if __name__ == "__main__":
    sys.exit(main())
