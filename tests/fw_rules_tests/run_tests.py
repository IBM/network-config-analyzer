import sys
import os
from fnmatch import fnmatch
from time import time
from ruamel.yaml import YAML
from nca import nca_main


def run_test(test_name, args, expected_result, all_results):
    print('------------------------------------')
    print('Running testcase', test_name)
    start_time = time()

    res = nca_main(args)

    test_res = (res != expected_result)
    if test_res:
        print('Testcase', test_name, 'failed', file=sys.stderr)
    else:
        print('Testcase', test_name, 'passed')
    all_results[test_name] = (test_res, time() - start_time)
    return test_res


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
        global_res += run_test(scheme_filename, ['--scheme', scheme_filename], 0, all_results)

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
