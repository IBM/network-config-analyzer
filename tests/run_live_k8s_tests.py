import sys
import os
from fnmatch import fnmatch
from time import time
from ruamel.yaml import YAML
import argparse

sys.path.append(os.path.dirname(os.path.dirname(os.path.realpath(__file__))))
sys.path.append(os.path.join(os.path.dirname(os.path.dirname(os.path.realpath(__file__))), 'network-config-analyzer'))
from nca import nca_main
from nca import _valid_path
from CmdlineRunner import CmdlineRunner

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


def main(argv=None):
    """

    :param argv: command-line arguments (None means using sys.argv)
    :return:
    """
    base_dir = os.path.abspath(os.path.dirname(sys.argv[0]))
    os.chdir(base_dir)

    # Deploy namespaces, pods and network policies
#    namespaces = f'{base_dir}/fw_rules_tests/podlist/poc_ns_list.json'
#    cmdline_list = ['kubectl', 'apply', f'-f{namespaces}']
#    CmdlineRunner.run_and_get_output(cmdline_list)

    pods = f'{base_dir}/fw_rules_tests/podlist/kubernetes-manifests.yaml'
    cmdline_list = ['kubectl', 'apply', f'-f{pods}']
    CmdlineRunner.run_and_get_output(cmdline_list)

    policies = f'{base_dir}/fw_rules_tests/policies/microservices-netpols.yaml'
    cmdline_list = ['kubectl', 'apply', f'-f{policies}']
    CmdlineRunner.run_and_get_output(cmdline_list)

    parser = argparse.ArgumentParser(description='Testing live kubernetes cluster')
    parser.add_argument('--command_line_input', '-i', type=_valid_path,
                        help='A YAML file, describing command-line verification goals')

    global_res = 0
    all_results = {}

    print("base_dir is: ", base_dir)
    print("argv is", argv)
    print("sys.argv is", sys.argv)
    args = parser.parse_args(argv)
    command_line_filename = os.path.join(base_dir, args.command_line_input) if args.command_line_input else ''
    print("Command line filename is: ", command_line_filename)
    if os.path.exists(command_line_filename):
        with open(command_line_filename) as doc:
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
