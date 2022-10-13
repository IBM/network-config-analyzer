# TODO: NOTE that every answer that I try to get should be presented in a very clear way. Easy to convey and present.
# TODO: think of the questions that I want to answer with the traces, how do I present that, and do I need to collect
#   any data points that I do not currently have?
# TODO: try to think a little about a plan on how to run the sequence of actions, and try to think about how much
#   time it is going to take to implement.
# TODO: NOTE that the trace files are quite large ~2.5GB. I might want to be careful on how I handle them.
# TODO: I have collected the MinDFAs that appear in the benchmarks. Now what do we do with that? I can discuss that
#   with Adi.
"""
Questions that we want to answer:
1. What are the typical usage profiles that we encounter?
2. What types of string constraints do we get? (constant, prefix, suffix).
3. How many active dimensions does a hyper-cube-set have, and of what types?
"""
import json
import logging
from collections import Counter
from collections.abc import Iterable
from pathlib import Path
from pprint import pprint, pformat

from smt_experiments.canonical_hyper_cube_set_tracker.utils import get_repo_root_dir, get_traces_dir
logging.basicConfig(level=logging.INFO)


def read_trace_data(trace_file: Path):
    trace_data = []
    with trace_file.open('r') as f:
        for line in f.readlines():
            operation_data = json.loads(line)
            trace_data.append(operation_data)
    return trace_data


def get_trace_per_object(trace_data: list[dict]) -> list[tuple[int, list[dict]]]:
    trace_per_object = []
    tracking_dict = {}

    def track_new_object(object_id: int, operation_data: dict):
        if object_id in tracking_dict:
            # we found a new object that was assigned an existing id, save the records and
            # re-initialize
            record = (object_id, tracking_dict[object_id])
            trace_per_object.append(record)
        tracking_dict[object_id] = [operation_data]

    def track_existing_object(object_id: int, operation_data: dict):
        tracking_dict[object_id].append(operation_data)

    for operation_data in trace_data:
        # TODO: I noticed that `create_from_cube` is never called. so we don't need to account for that.
        operation_name = operation_data['operation_name']
        if operation_name == '__init__':
            object_id = operation_data['args'][0]['id']
            track_new_object(object_id, operation_data)

        elif operation_name == 'copy':
            new_object_id = operation_data['result']['id']
            old_object_id = operation_data['args'][0]['id']
            track_new_object(new_object_id, operation_data)
            track_existing_object(old_object_id, operation_data)

        elif operation_data['operation_name'] in ['__and__', '__or__', '__sub__']:
            new_object_id = operation_data['result']['id']
            object1_id = operation_data['args'][0]['id']
            object2_id = operation_data['args'][1]['id']
            track_new_object(new_object_id, operation_data)
            track_existing_object(object1_id, operation_data)
            track_existing_object(object2_id, operation_data)

        else:
            for arg in operation_data['args']:
                if isinstance(arg, dict) and arg['type'] == 'CanonicalHyperCubeSet':
                    object_id = arg['id']
                    track_existing_object(object_id, operation_data)

    for object_id, operations in tracking_dict.items():
        trace_per_object.append((object_id, operations))

    return trace_per_object


def count_operation_sequences(trace_per_object: list[tuple[int, list[dict]]]) -> Counter:
    operation_sequence_counter = Counter()
    for object_id, operation_data_sequence in trace_per_object:
        operation_sequence = tuple(operation_data['operation_name'] for operation_data in operation_data_sequence)
        operation_sequence_counter[operation_sequence] += 1
    return operation_sequence_counter


def iter_benchmark_trace_files() -> Iterable[Path]:
    trace_dir = get_traces_dir()
    yield from trace_dir.rglob('*.trace')


def get_analysis_results_dir() -> Path:
    return get_repo_root_dir() / 'smt_experiments' / 'canonical_hyper_cube_set_tracker' / 'analysis_results'


def get_min_dfa_file() -> Path:
    return get_analysis_results_dir() / 'min_dfa.json'


def collect_all_min_dfa_instances() -> list:
    min_dfa_list = []
    trace_file_list = list(iter_benchmark_trace_files())
    for i, trace_file in enumerate(trace_file_list, 1):
        logging.info(f'collecting MinDFAs instances. {i} out of {len(trace_file_list)}.')
        trace_data = read_trace_data(trace_file)
        for operation_data in trace_data:
            operation_name = operation_data['operation_name']
            if operation_name in ['add_cube', 'add_hole']:
                args = operation_data['args']
                cube = args[1]
                for cube_dim in cube:
                    if cube_dim['type'] == 'MinDFA':
                        min_dfa_list.append(cube_dim)
    with get_min_dfa_file().open('w') as f:
        json.dump(min_dfa_list, f, indent=4)
    return min_dfa_list


def is_regex_constant(regex):
    if isinstance(regex, str):
        return '*' not in regex
    if isinstance(regex, dict):
        return all(is_regex_constant(child) for child in regex['children'])


def analyze_min_dfa_list(min_dfa_list: list[dict] = None):
    # TODO: are there any other questions that we would like to ask?
    if min_dfa_list is None:
        min_dfa_records_file = get_min_dfa_file()
        if not min_dfa_records_file.exists():
            collect_all_min_dfa_instances()

        with min_dfa_records_file.open('r') as f:
            min_dfa_list = json.load(f)

    # how many min_dfa constraints do we have?
    n_min_dfa_constraints = len(min_dfa_list)
    print(f'n_min_dfa_constraints={n_min_dfa_constraints}.')

    # how many only constant constraints do we have?
    n_only_constant = sum(is_regex_constant(min_dfa['regex']) for min_dfa in min_dfa_list)
    print(f'n_only_constant={n_only_constant}.')

    print(f'percentage of constant is {(n_only_constant / n_min_dfa_constraints) * 100:.3f}%.')


def analyze_usage_profiles():
    """Get the most common sequence of operations on a CanonicalHyperCubeSet."""
    # TODO: I got the results for this. How do I use them for the experiments, and how
    #   do I present them?
    trace_files = list(iter_benchmark_trace_files())
    operation_sequence_counter = Counter()
    for i, trace_file in enumerate(trace_files, 1):
        logging.info(f'Analyzing usage profiles. Processing {i} out of {len(trace_files)}.')
        trace_data = read_trace_data(trace_file)
        trace_data_per_object = get_trace_per_object(trace_data)
        operation_sequence_counter += count_operation_sequences(trace_data_per_object)

    most_common = operation_sequence_counter.most_common()
    output_file = get_analysis_results_dir() / 'most_common_operation_sequences.txt'
    with output_file.open('w') as f:
        f.write(pformat(most_common))


def analyze_number_of_dimensions():
    """Analyzes the number of active dimensions that a cube has."""
    # TODO: create a counter of how many dimensions we have for
    #   each that was created.
    # TODO: print the maximal value
    # TODO: how many dimensions of what types?
    # TODO: currently, I decided to skip this.
    # functions that tell us what dimensions are active
    #   1. __init__
    #   2. add_cube
    #   3. add_hole
    trace_files = list(iter_benchmark_trace_files())
    n_active_dims_counter = Counter()
    for i, trace_file in enumerate(trace_files, 1):
        logging.info(f'Analyzing usage profiles. Processing {i} out of {len(trace_files)}.')
        trace_data = read_trace_data(trace_file)
        trace_data_per_object = get_trace_per_object(trace_data)

        n_active_dims_counter += count_operation_sequences(trace_data_per_object)

    most_common = n_active_dims_counter.most_common()
    output_file = get_analysis_results_dir() / 'most_common_operation_sequences.txt'
    with output_file.open('w') as f:
        f.write(pformat(most_common))


def main():
    # analyze_min_dfa_list()
    analyze_usage_profiles()
    # min_dfa_list = collect_all_min_dfa_instances()
    # trace_data = read_trace_data()
    # trace_per_object = get_trace_per_object(trace_data)
    # operation_sequence_counter = count_operation_sequences(trace_per_object)
    # pprint(operation_sequence_counter)


if __name__ == '__main__':
    main()
