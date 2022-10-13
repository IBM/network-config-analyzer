# TODO: the code for analyzing and collecting the traces is a little hacky. Try to make it a little more
#   organized and documented.
# TODO: NOTE that every answer that I try to get should be presented in a very clear way. Easy to convey and present.
# TODO: think of the questions that I want to answer with the traces, how do I present that, and do I need to collect
#   any data points that I do not currently have?
# TODO: try to think a little about a plan on how to run the sequence of actions, and try to think about how much
#   time it is going to take to implement.
# TODO: collect traces from the real benchmarks.
# TODO: NOTE that the trace files are quite large ~2.5GB. I might want to be careful on how I handle them.
"""
Questions that we want to answer:
1. What are the typical usage profiles that we encounter?
2. What types of string constraints do we get? (constant, prefix, suffix).
3. How many active dimensions does a hyper-cube-set have, and of what types?
"""
import json
from collections import Counter
from collections.abc import Iterable
from pathlib import Path
from pprint import pprint, pformat

from smt_experiments.canonical_hyper_cube_set_tracker.utils import get_repo_root_dir, get_traces_dir


def read_trace_data():
    trace_file = get_repo_root_dir() / 'smt_experiments' / 'trace.txt'
    trace_data = []
    with trace_file.open('r') as f:
        for i, line in enumerate(f.readlines()):
            operation_data = json.loads(line)
            trace_data.append(operation_data)
            if i > 5_000:  # TODO: comment this out. this is just for rapid experimentation
                break
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


def collect_all_initial_string_constraints():


def main():
    collect_all_initial_string_constraints()
    # trace_data = read_trace_data()
    # trace_per_object = get_trace_per_object(trace_data)
    # operation_sequence_counter = count_operation_sequences(trace_per_object)
    # pprint(operation_sequence_counter)


if __name__ == '__main__':
    main()
