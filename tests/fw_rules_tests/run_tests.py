import sys
import os
from fnmatch import fnmatch
from os import path
from time import time

import yaml

from nca import nca_main
from pathlib import Path


def run_output_test(test_name, args, all_results):
    actual_output_dir_name = "actual_output"
    expected_output_dir_name = "expected_output"
    yaml_output_file_name = os.path.basename(test_name).replace(".yaml", "_output.yaml")
    scheme_dir = os.path.dirname(test_name)
    actual_yaml_output_file_path = os.path.join(scheme_dir, actual_output_dir_name, yaml_output_file_name)
    update_fw_rules_config_file_with_yaml_output_path(test_name, actual_yaml_output_file_path)
    expected_yaml_output_file_path = os.path.join(scheme_dir, expected_output_dir_name, yaml_output_file_name)
    if os.path.isfile(actual_yaml_output_file_path):
        os.remove(actual_yaml_output_file_path)

    print('------------------------------------')
    print('Running testcase', test_name)
    scheme_dir = os.path.dirname(test_name)

    output_file_name = os.path.basename(test_name).replace(".yaml", "_output.txt")
    actual_output_file_path = os.path.join(scheme_dir, actual_output_dir_name, output_file_name)
    expected_output_file_path = os.path.join(scheme_dir, expected_output_dir_name, output_file_name)
    start_time = time()

    create_test_output(actual_output_file_path, test_name, args)

    test_failure_list = []
    yaml_comparison = compare_yaml_output_files(actual_yaml_output_file_path, expected_yaml_output_file_path)
    if not yaml_comparison:
        test_failure_list.append('yaml')
    txt_comparison = compare_files(actual_output_file_path, expected_output_file_path)
    if not txt_comparison:
        test_failure_list.append('txt')
    test_passed = txt_comparison and yaml_comparison
    test_failure_str = str(test_failure_list)

    test_res = not test_passed
    if test_res:
        print('Testcase', test_name, 'failed at: ', test_failure_str, file=sys.stderr)
    else:
        print('Testcase', test_name, 'passed')
    all_results[test_name] = (test_res, time() - start_time)

    test_files_cleanup(test_name)
    if test_passed:
        delete_actual_output_file(test_name)
    return test_res


def convert_rule_obj_to_str(rule_obj):
    res = ''
    if 'src_ns' in rule_obj:
        res += 'src_ns: ' + ','.join(ns for ns in sorted(rule_obj['src_ns'])) + ';'
    if 'src_pods' in rule_obj:
        res += 'src_pods: ' + ','.join(pod for pod in sorted(rule_obj['src_pods'])) + ';'
    if 'src_ip_block' in rule_obj:
        res += 'src_ip_block: ' + ','.join(ip for ip in sorted(rule_obj['src_ip_block'])) + ';'
    if 'dst_ns' in rule_obj:
        res += 'dst_ns: ' + ','.join(ns for ns in sorted(rule_obj['dst_ns'])) + ';'
    if 'dst_pods' in rule_obj:
        res += 'dst_pods: ' + ','.join(pod for pod in sorted(rule_obj['dst_pods'])) + ';'
    if 'dst_ip_block' in rule_obj:
        res += 'dst_ip_block: ' + ','.join(ip for ip in sorted(rule_obj['dst_ip_block'])) + ';'

    if 'connection' in rule_obj:
        res += 'connection: '
        if rule_obj['connection'][0] == 'All connections':
            res += 'All connections' + ';'
        else:
            for conn_obj in rule_obj['connection']:
                conn_str = ''
                if 'Protocol' in conn_obj:
                    conn_str += 'Protocol: ' + conn_obj['Protocol'] + ';'
                if 'Ports' in conn_obj:
                    conn_str += 'Ports: ' + ','.join(str(ports) for ports in conn_obj['Ports']) + ';'
                res += conn_str
    return res


def compare_yaml_output_rules(expected, actual):
    expected_str_list = []
    actual_str_list = []
    for rule_obj in expected:
        res = convert_rule_obj_to_str(rule_obj)
        expected_str_list.append(res)
    for rule_obj in actual:
        res = convert_rule_obj_to_str(rule_obj)
        actual_str_list.append(res)
    res = (set(expected_str_list) == set(actual_str_list))
    return res


def compare_yaml_output_rules_main(expected, actual):
    if len(expected) != len(actual):
        return False
    for index, expected_query_entry in enumerate(expected):
        actual_query_entry = actual[index]
        if expected_query_entry['query'] != actual_query_entry['query']:
            return False
        if not compare_yaml_output_rules(expected_query_entry['rules'], actual_query_entry['rules']):
            return False
    return True


def compare_yaml_output_files(output_filename, golden_filename):
    with open(output_filename) as f:
        actual_content = yaml.safe_load(f)
    with open(golden_filename) as f:
        expected_content = yaml.safe_load(f)
    res = compare_yaml_output_rules_main(expected_content, actual_content)
    return res


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


# a function to delete files of actual output that exactly match the expected output
def test_files_cleanup(scheme_filename):
    restore_config_files(scheme_filename)
    return


def restore_config_files(scheme_filename):
    root_dir = scheme_filename.split("network-config-analyzer")[0]
    config_files_dir = os.path.join(root_dir, "network-config-analyzer", "tests", "fw_rules_tests", "config")
    for config_file_name in os.listdir(config_files_dir):
        config_file_path = os.path.join(config_files_dir, config_file_name)
        if config_file_name.endswith('yaml'):
            with open(config_file_path) as f:
                config_data_map = yaml.safe_load(f)
                del config_data_map['expected_fw_rules_yaml']
            with open(config_file_path, 'w') as f:
                yaml.dump(config_data_map, f, default_flow_style=False, sort_keys=False)


def update_fw_rules_config_file_with_yaml_output_path(scheme_filename, yaml_output_file_path):
    root_dir = scheme_filename.split("network-config-analyzer")[0]
    config_files_dir = os.path.join(root_dir, "network-config-analyzer", "tests", "fw_rules_tests", "config")
    '''
    # TODO: support also config file that is not default, and appears in the scheme file
    default_config_file_name = "fw_rules_config.yaml"
    if 'semantic_diff' in scheme_filename:
        default_config_file_name = "semantic_diff_fw_rules_config.yaml"
    config_file_path = os.path.join(config_files_dir, default_config_file_name)

    config_files_from_scheme = []
    with open(scheme_filename) as f:
        scheme_file_yaml_content = yaml.safe_load(f)
        if 'queries' in scheme_file_yaml_content:
            for query in scheme_file_yaml_content['queries']:
                if 'fw_rules_configuration' in query:
                    config_files_from_scheme.append(query['fw_rules_configuration'])
    config_file_path_from_scheme = []
    for config_name in config_files_from_scheme:
        full_path = os.path.join( config_files_dir ,os.path.basename(config_name))
        config_file_path_from_scheme.append(full_path)


    # add to config file: expected_fw_rules_yaml: yaml_output_file_path
    '''
    for config_file_name in os.listdir(config_files_dir):
        config_file_path = os.path.join(config_files_dir, config_file_name)
        if config_file_name.endswith('yaml'):
            with open(config_file_path) as f:
                config_data_map = yaml.safe_load(f)
                config_data_map['expected_fw_rules_yaml'] = yaml_output_file_path
            with open(config_file_path, 'w') as f:
                yaml.dump(config_data_map, f, default_flow_style=False, sort_keys=False)

    return


def delete_actual_output_file(scheme_filename):
    output_file_name = os.path.basename(scheme_filename).replace(".yaml", "_output.txt")
    actual_output_dir_name = "actual_output"
    scheme_dir = os.path.dirname(scheme_filename)
    actual_output_file_path = os.path.join(scheme_dir, actual_output_dir_name, output_file_name)
    yaml_output_file_name = os.path.basename(scheme_filename).replace(".yaml", "_output.yaml")
    actual_yaml_output_file_path = os.path.join(scheme_dir, actual_output_dir_name, yaml_output_file_name)
    os.remove(actual_output_file_path)
    os.remove(actual_yaml_output_file_path)


# a function to prepare new test output
def prepare_output_test(scheme_filename):
    #print('prepare_output_test')
    output_file_name = os.path.basename(scheme_filename).replace(".yaml", "_output.txt")
    scheme_dir = os.path.dirname(scheme_filename)
    expected_output_dir_name = "expected_output"
    actual_output_dir_name = "actual_output"
    expected_output_file_path = os.path.join(scheme_dir, expected_output_dir_name, output_file_name)
    actual_output_file_path = os.path.join(scheme_dir, actual_output_dir_name, output_file_name)

    should_run = False
    # prepare expected yaml output in case it does not exist:
    yaml_output_file_name = os.path.basename(scheme_filename).replace(".yaml", "_output.yaml")
    expected_yaml_output_file_path = os.path.join(scheme_dir, expected_output_dir_name, yaml_output_file_name)
    if not os.path.isfile(expected_yaml_output_file_path):
        update_fw_rules_config_file_with_yaml_output_path(scheme_filename, expected_yaml_output_file_path)
        should_run = True
    #print('should_run: ' + str(should_run))
    # prepare expected txt output in case it does not exist:
    if not os.path.isfile(expected_output_file_path) or should_run:
        Path(os.path.join(scheme_dir, expected_output_dir_name)).mkdir(parents=True, exist_ok=True)
        Path(os.path.join(scheme_dir, actual_output_dir_name)).mkdir(parents=True, exist_ok=True)
        create_test_output(expected_output_file_path, scheme_filename, ['--scheme', scheme_filename])
    elif not os.path.isdir(os.path.join(scheme_dir, actual_output_dir_name)):
        Path(os.path.join(scheme_dir, actual_output_dir_name)).mkdir(parents=True, exist_ok=True)


def create_test_output(output_file, test_name, args):
    orig_stdout = sys.stdout
    sys.stdout = open(output_file, 'w')
    nca_main(args)
    sys.stdout = orig_stdout
    return


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
        # print(os.path.basename(scheme_filename).replace(".yaml", ""))
        prepare_output_test(scheme_filename)
        global_res += run_output_test(scheme_filename, ['--scheme', scheme_filename], all_results)

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
