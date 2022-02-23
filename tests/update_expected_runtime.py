import sys
import os
import argparse


def _get_new_run_time(test_name, run_log):
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


def _update_or_delete_file_rows(expected_time_file, lines_to_update, lines_to_delete, run_log):
    lines_to_delete[::-1].sort()
    # get the lines of the csv file as a list
    with open(expected_time_file, 'r') as f:
        lines = f.readlines()
    # update the relevant rows in the lines list
    for line_num, test_name in lines_to_update:
        lines[line_num-1] = _update_run_time_in_row(lines[line_num-1], _get_new_run_time(test_name, run_log))
    # delete the rows to delete in the lines list
    for line_num in lines_to_delete:
        del lines[line_num - 1]
    # write the new lines list into the file again
    with open(expected_time_file, 'w') as f:
        for line in lines:
            f.write(line)


def _update_tests_runtime(run_log, modified_tests_list):
    expected_time_file = "tests/tests_expected_runtime.csv"
    lines_to_delete = []
    lines_to_update = []
    for test in modified_tests_list:
        delete_flag = False
        if not os.path.exists(test):
            delete_flag = True
        with open(expected_time_file, 'r') as read_obj:
            line_number = 0
            # Read all lines in the file one by one
            for line in read_obj:
                # For each line, check if line contains the test name
                line_number += 1
                if test.split('/', 1)[1] in line:
                    if delete_flag:
                        lines_to_delete.append(line_number)
                    else:
                        lines_to_update.append((line_number, test))

    _update_or_delete_file_rows(expected_time_file, lines_to_update, lines_to_delete, run_log)


def main(argv=None):
    base_dir = os.path.split(os.path.abspath(os.path.dirname(sys.argv[0])))[0]
    os.chdir(base_dir)
    parser = argparse.ArgumentParser(description='Updating the tests_expected_runtime.csv file')
    parser.add_argument('--run_log', help='the run log')
    parser.add_argument('--changed_tests', nargs='+', help='list of the added, modified, deleted or renamed tests')

    args = parser.parse_args(argv)
    run_log = args.run_log
    modified_tests_list = args.changed_tests
    if not run_log or not modified_tests_list:
        return 0  # nothing to do

    _update_tests_runtime(run_log, modified_tests_list)
    return 0


if __name__ == "__main__":
    sys.exit(main())
