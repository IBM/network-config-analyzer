import sys
import os
from fnmatch import fnmatch
from time import time
from ruamel.yaml import YAML

sys.path.append(os.path.dirname(os.path.dirname(os.path.realpath(__file__))))
sys.path.append(os.path.join(os.path.dirname(os.path.dirname(os.path.realpath(__file__))), 'network-config-analyzer'))
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
    for root, _, files in os.walk(base_dir):
        for file in files:
            if not fnmatch(file, '*-scheme.yaml'):
                continue

            scheme_filename = os.path.join(root, file)
            global_res += run_test(scheme_filename, ['--scheme', scheme_filename], 0, all_results)

    with open(os.path.join(base_dir, 'cmdline_tests.yaml')) as doc:
        code = YAML().load_all(doc)
        for test in next(iter(code)):
            args = test['args'].split()
            for idx, arg in enumerate(args):
                if '/' in arg and not arg.startswith('https://github'):
                    args[idx] = os.path.join(base_dir, arg)
            global_res += run_test(test['name'], args, test['expected'], all_results)

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
