import json
import time
from dataclasses import dataclass
from enum import Enum, auto
from itertools import product, combinations
from pathlib import Path
from typing import Any, Iterable, Callable


class Timer:
    def __init__(self):
        self.start = 0.0
        self.end = 0.0
        self.elapsed_time = 0.0

    def __enter__(self):
        self.start = time.process_time()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.end = time.process_time()
        self.elapsed_time = self.end - self.start


class EnumWithStr(Enum):
    def __str__(self):
        return self.name.lower()

    def to_json(self):
        return str(self)


class CheckType(EnumWithStr):
    CONTAINED = auto()
    NOT_CONTAINED = auto()


class EngineType(EnumWithStr):
    Z3 = auto()
    OUR = auto()


def get_results_file(experiment_name: str):
    experiment_results_dir = Path('../experiment_results')
    results_file = experiment_results_dir / (experiment_name + '.json')
    return results_file


def get_plot_file(experiment_name: str):
    experiment_results_dir = Path('../plots')
    results_file = experiment_results_dir / (experiment_name + '.png')
    return results_file


def dict_product(options_dict: dict[str, Iterable]) -> Iterable[dict[str, Any]]:
    values_for_each_option = list(options_dict.values())
    for option_values_tuple in product(*values_for_each_option):
        yield dict(zip(options_dict.keys(), option_values_tuple))


def iter_subsets(items: set, min_size: int = 0, max_size: int = None) -> Iterable[tuple]:
    if max_size is None:
        max_size = len(items)
    for subset_size in range(min_size, max_size + 1):
        for combination in combinations(items, subset_size):
            yield combination


def save_results(experiment_result_list: list, experiment_name: str):
    results_file = get_results_file(experiment_name)
    experiment_result_list = to_json_recursive(experiment_result_list)
    with results_file.open('w') as f:
        json.dump(experiment_result_list, f, indent=4)


def load_results(experiment_name: str):
    results_file = get_results_file(experiment_name)
    with results_file.open('r') as f:
        return json.load(f)


def to_json_recursive(data):
    if isinstance(data, (int, float, str, bool)):
        return data

    if hasattr(data, 'to_json'):
        return data.to_json()

    if isinstance(data, dict):
        return {k: to_json_recursive(v) for k, v in data.items()}

    if isinstance(data, Iterable):
        return [to_json_recursive(x) for x in data]

    raise ValueError


def get_y_var_list():
    y_var_list = [
        Variable(
            'creation_time',
            lambda result: result['creation_time']
        ),
        Variable(
            'positive_membership_time',
            lambda result: result['operation_result_dict']['positive_membership']['time']
        ),
        Variable(
            'negative_membership_time',
            lambda result: result['operation_result_dict']['negative_membership']['time']
        ),
        Variable(
            'overall_time',
            lambda result: result['creation_time'] +
                           result['operation_result_dict']['positive_membership']['time'] +
                           result['operation_result_dict']['negative_membership']['time']
        )
    ]
    return y_var_list


@dataclass
class Variable:
    name: str
    compute: Callable


@dataclass
class Operation:
    name: str
    get_input_list: Callable
    run_operation: Callable
    expected_result: Any = None


def get_positive_membership_operation(get_input_list: Callable) -> Operation:
    return Operation(
        name='positive_membership',
        get_input_list=get_input_list,
        run_operation=lambda set_0, element: element in set_0,
        expected_result=True
    )


def get_negative_membership_operation(get_input_list: Callable) -> Operation:
    return Operation(
        name='negative_membership',
        get_input_list=get_input_list,
        run_operation=lambda set_0, element: element in set_0,
        expected_result=False
    )
